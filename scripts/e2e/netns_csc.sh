#!/usr/bin/env bash
# 真实端到端：单 operator + 双 client，netns + 真 TUN + ping (PRD G2/G4/G5)
# 需要 sudo（建 netns/veth/bridge/TUN、改路由）。可重复运行（先 teardown）。
#
#   ns 拓扑（underlay 10.99.0.0/24）：
#     gaso-op  (operator)  10.99.0.1   ─┐
#     gaso-a   (client A)  10.99.0.2   ─┼─ bridge gaso-br (root ns)
#     gaso-b   (client B)  10.99.0.3   ─┘
#   overlay（真 TUN，IP 来自 vnet pool 10.0.200.16/28）：A、B 各自分配
#   验证：A 在 gaso-a 里 ping B 的 overlay IP → 加密数据面 → operator 转发 → B
set -u

# WORK holds the runtime files (binaries, vnet dir, logs). Defaults to a temp
# dir; override with GASO_WORK. Binaries are looked up in $BIN (default: built
# fresh into $WORK from the repo).
WORK=${GASO_WORK:-/tmp/gaso-e2e}
BIN=${GASO_BIN:-$WORK}
mkdir -p "$WORK"
OP=$BIN/gaso-operator
CL=$BIN/gaso-client
ROOT=$WORK/vnets
LOG=$WORK/e2e.log
: > "$LOG"

# Build binaries into $WORK if missing (run from the repo root, or set GASO_BIN).
if [ ! -x "$OP" ] || [ ! -x "$CL" ]; then
  REPO=$(cd "$(dirname "$0")/../.." && pwd)
  echo "==> building binaries into $WORK (from $REPO)"
  ( cd "$REPO" && go build -o "$OP" ./cmd/operator && go build -o "$CL" ./cmd/client ) || {
    echo "!! build failed"; exit 1; }
fi

NS_OP=gaso-op; NS_A=gaso-a; NS_B=gaso-b
BR=gaso-br

log(){ echo "==> $*"; }

teardown(){
  log "teardown"
  sudo pkill -f gaso-operator 2>/dev/null
  sudo ip netns pids $NS_A 2>/dev/null | xargs -r sudo kill 2>/dev/null
  sudo ip netns pids $NS_B 2>/dev/null | xargs -r sudo kill 2>/dev/null
  sudo ip netns pids $NS_OP 2>/dev/null | xargs -r sudo kill 2>/dev/null
  for ns in $NS_OP $NS_A $NS_B; do sudo ip netns del $ns 2>/dev/null; done
  sudo ip link del $BR 2>/dev/null
  for v in veth-op veth-a veth-b; do sudo ip link del $v 2>/dev/null; done
}

if [ "${1:-}" = "down" ]; then teardown; exit 0; fi
teardown   # clean any leftover first

log "1. 生成密钥 + 写 vnet YAML"
OP_KEYS=$($CL genkey); OP_PRIV=$(echo "$OP_KEYS"|awk '/private/{print $2}'); OP_PUB=$(echo "$OP_KEYS"|awk '/public/{print $2}')
A_KEYS=$($CL genkey);  A_PRIV=$(echo "$A_KEYS"|awk '/private/{print $2}');  A_PUB=$(echo "$A_KEYS"|awk '/public/{print $2}')
B_KEYS=$($CL genkey);  B_PRIV=$(echo "$B_KEYS"|awk '/private/{print $2}');  B_PUB=$(echo "$B_KEYS"|awk '/public/{print $2}')
mkdir -p "$ROOT"
cat > "$ROOT/vnet-200.yaml" <<YAML
vni: 200
version: 1
segments:
  - cidr: 10.0.200.0/24
    pool: 10.0.200.16/28
    reserved: [10.0.200.16]
keys:
  - pubkey: "$A_PUB"
  - pubkey: "$B_PUB"
YAML
echo "   op_pub=$OP_PUB"; echo "   A_pub=$A_PUB"; echo "   B_pub=$B_PUB"

log "2. 建 netns + bridge + veth（underlay 10.99.0.0/24）"
sudo ip link add $BR type bridge
sudo ip link set $BR up
for pair in "$NS_OP:veth-op:10.99.0.1" "$NS_A:veth-a:10.99.0.2" "$NS_B:veth-b:10.99.0.3"; do
  ns=${pair%%:*}; rest=${pair#*:}; veth=${rest%%:*}; ip=${rest##*:}
  sudo ip netns add $ns
  sudo ip link add $veth type veth peer name in-$veth
  sudo ip link set $veth master $BR
  sudo ip link set $veth up
  sudo ip link set in-$veth netns $ns
  sudo ip netns exec $ns ip link set in-$veth name eth0
  sudo ip netns exec $ns ip addr add $ip/24 dev eth0
  sudo ip netns exec $ns ip link set eth0 up
  sudo ip netns exec $ns ip link set lo up
done
# 连通性自检
sudo ip netns exec $NS_A ping -c1 -W1 10.99.0.1 >/dev/null 2>&1 && echo "   underlay A→op 通" || { echo "   !! underlay 不通"; teardown; exit 1; }

log "3. 起 operator（gaso-op，单节点 Raft + --root）"
RAFT=10.99.0.1:17000
sudo ip netns exec $NS_OP "$OP" \
  --key "$OP_PRIV" \
  --listen udp://10.99.0.1:18000 \
  --op-listen 10.99.0.1:16677 \
  --root "$ROOT" \
  --raft-bind "$RAFT" --raft-peers "op0@$RAFT" --raft-bootstrap true \
  --log-level info --ipc "$S/op.sock" \
  >> "$LOG" 2>&1 &
echo "   等待选主 + vnet 加载 (3s)"; sleep 3
sudo grep -q "upserted from" "$LOG" && echo "   vnet 已加载进 Raft" || echo "   !! vnet 未加载（看日志）"

log "4. 起 client A（gaso-a，真 TUN）"
sudo ip netns exec $NS_A "$CL" \
  --endpoint 10.99.0.1:18000 --transport udp --vni 200 \
  --key "$A_PRIV" --server-pub "$OP_PUB" --tun gatun-a --log-level info \
  >> "$LOG" 2>&1 &
log "5. 起 client B（gaso-b，真 TUN）"
sudo ip netns exec $NS_B "$CL" \
  --endpoint 10.99.0.1:18000 --transport udp --vni 200 \
  --key "$B_PRIV" --server-pub "$OP_PUB" --tun gatun-b --log-level info \
  >> "$LOG" 2>&1 &
echo "   等待握手 + TUN 起来 (5s)"; sleep 5

log "6. 读取 A/B 分配到的 overlay IP"
A_IP=$(sudo ip netns exec $NS_A ip -4 addr show gatun-a 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
B_IP=$(sudo ip netns exec $NS_B ip -4 addr show gatun-b 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
echo "   A overlay=$A_IP   B overlay=$B_IP"
if [ -z "$A_IP" ] || [ -z "$B_IP" ]; then
  echo "   !! TUN 未拿到 IP，日志尾部："; sudo tail -30 "$LOG"; teardown; exit 1
fi

log "7. 真实 ping：A → B（加密数据面 + operator 转发）"
sudo ip netns exec $NS_A ping -c4 -W2 "$B_IP"
RC=$?

log "8. operator/client 日志尾部"
sudo tail -25 "$LOG"

echo ""
if [ $RC -eq 0 ]; then echo "===== 结果：真实端到端 ping 通 ✅ ====="; else echo "===== 结果：ping 不通 (rc=$RC)，见上方日志 ====="; fi

log "9. 清理（保留日志 $LOG）"
teardown

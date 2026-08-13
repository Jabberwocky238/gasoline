#!/usr/bin/env bash
# 真实端到端：3 operator (Raft 集群) + 3 client (真 TUN)，3c 互 ping；
# 然后 kill 一个 operator，验证连它的 client 跳到别的 operator 继续 ping 通 (G4)。
# 需要 sudo。可重复运行（先 teardown）。
#
#   underlay 10.99.0.0/24（bridge gaso-br）：
#     op0 .1  op1 .2  op2 .3      A .11   B .12   C .13
#   Raft: op0 bootstrap，3 节点集群（端口 17000，转发口 17001）
#   client 监听: udp://10.99.0.{1,2,3}:18000
#   A→op0  B→op1  C→op2（各连一个 operator，follower 转发握手给 leader）
#   hop-endpoints: 每个 operator 广播全部 3 个（client 据此跳跃）
#   overlay TUN: A/B/C 从 vnet pool 10.0.200.16/28 各拿一个 IP
set -u

S=/tmp/claude-1000/-home-zq-gasoline/3be1ba3f-3c46-4277-9d80-2cc77c6def23/scratchpad
WORK=${GASO_WORK:-$S}
OP=$WORK/gaso-operator
CL=$WORK/gaso-client
ROOT=$WORK/vnets3
LOG=$WORK/e2e3.log
: > "$LOG"

# 固定 UUID（--uuid / --raft-peers / --hop-endpoint 一致引用）
U0=a0000000000000000000000000000000
U1=b0000000000000000000000000000000
U2=c0000000000000000000000000000000
BR=gaso-br

log(){ echo "==> $*"; }
opns(){ echo "gaso-op$1"; }
clns(){ echo "gaso-c$1"; }

teardown(){
  log "teardown"
  sudo pkill -f gaso-operator 2>/dev/null
  for ns in gaso-op0 gaso-op1 gaso-op2 gaso-ca gaso-cb gaso-cc; do
    sudo ip netns pids $ns 2>/dev/null | xargs -r sudo kill 2>/dev/null
    sudo ip netns del $ns 2>/dev/null
  done
  sudo ip link del $BR 2>/dev/null
  for v in v-op0 v-op1 v-op2 v-ca v-cb v-cc; do sudo ip link del $v 2>/dev/null; done
}
[ "${1:-}" = "down" ] && { teardown; exit 0; }
teardown

# ns <name> <underlay-ip-last-octet> <veth>
mkns(){
  local ns=$1 ip=$2 veth=$3
  sudo ip netns add $ns
  sudo ip link add $veth type veth peer name in-$veth
  sudo ip link set $veth master $BR; sudo ip link set $veth up
  sudo ip link set in-$veth netns $ns
  sudo ip netns exec $ns ip link set in-$veth name eth0
  sudo ip netns exec $ns ip addr add 10.99.0.$ip/24 dev eth0
  sudo ip netns exec $ns ip link set eth0 up
  sudo ip netns exec $ns ip link set lo up
}

log "1. 密钥 + vnet YAML（3 operator 共享静态密钥，A/B/C 授权）"
OP_KEYS=$($CL genkey); OP_PRIV=$(echo "$OP_KEYS"|awk '/private/{print $2}'); OP_PUB=$(echo "$OP_KEYS"|awk '/public/{print $2}')
A_KEYS=$($CL genkey); A_PRIV=$(echo "$A_KEYS"|awk '/private/{print $2}'); A_PUB=$(echo "$A_KEYS"|awk '/public/{print $2}')
B_KEYS=$($CL genkey); B_PRIV=$(echo "$B_KEYS"|awk '/private/{print $2}'); B_PUB=$(echo "$B_KEYS"|awk '/public/{print $2}')
C_KEYS=$($CL genkey); C_PRIV=$(echo "$C_KEYS"|awk '/private/{print $2}'); C_PUB=$(echo "$C_KEYS"|awk '/public/{print $2}')
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
  - pubkey: "$C_PUB"
YAML

log "2. bridge + 6 netns（3 op + 3 client）"
sudo ip link add $BR type bridge; sudo ip link set $BR up
mkns gaso-op0 1 v-op0; mkns gaso-op1 2 v-op1; mkns gaso-op2 3 v-op2
mkns gaso-ca 11 v-ca;   mkns gaso-cb 12 v-cb;  mkns gaso-cc 13 v-cc
sudo ip netns exec gaso-ca ping -c1 -W1 10.99.0.1 >/dev/null 2>&1 && echo "   underlay 通" || { echo "   !! underlay 不通"; teardown; exit 1; }

# 全部 operator 广播的 hop 列表（3 个 operator，单端口 18000）
HOPS="--hop-endpoint $U0@10.99.0.1:18000-18000 --hop-endpoint $U1@10.99.0.2:18000-18000 --hop-endpoint $U2@10.99.0.3:18000-18000"
PEERS="$U0@10.99.0.1:17000;$U1@10.99.0.2:17000;$U2@10.99.0.3:17000"

start_op(){  # <idx> <uuid> <ip> <bootstrap>
  local idx=$1 uuid=$2 ip=$3 boot=$4
  sudo ip netns exec gaso-op$idx "$OP" \
    --uuid $uuid --key "$OP_PRIV" \
    --listen udp://10.99.0.$ip:18000 \
    --op-listen 10.99.0.$ip:16677 \
    --root "$ROOT" \
    $HOPS \
    --raft-bind 10.99.0.$ip:17000 --raft-peers "$PEERS" --raft-bootstrap $boot \
    --log-level info --ipc "$WORK/op$idx.sock" \
    >> "$LOG" 2>&1 &
}

log "3. 起 3 个 operator（op0 bootstrap）"
start_op 0 $U0 1 true
start_op 1 $U1 2 false
start_op 2 $U2 3 false
echo "   轮询等待选主 + vnet 进 Raft（最多 20s）"
for i in $(seq 1 40); do
  sudo grep -q "upserted from" "$LOG" && break
  sleep 0.5
done
if sudo grep -q "upserted from" "$LOG"; then echo "   vnet 已进 Raft"; else echo "   !! vnet 未加载"; sudo tail -20 "$LOG"; teardown; exit 1; fi
sleep 1   # 让全集群复制 vnet + 授权稳定

start_cl(){  # <ns> <priv> <endpoint-ip> <tun>
  sudo ip netns exec $1 "$CL" \
    --endpoint 10.99.0.$3:18000 --transport udp --vni 200 \
    --key "$2" --server-pub "$OP_PUB" --tun $4 --log-level info \
    >> "$LOG" 2>&1 &
}

get_ip(){ sudo ip netns exec $1 ip -4 addr show $2 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1; }

log "4. 起 3 个 client（A→op0, B→op1, C→op2，各建真 TUN）；失败自动重启（等授权全集群复制）"
# 每个 client 独立重试：若 6s 内没拿到 TUN IP，杀掉重起，最多 4 轮。
start_client_until_ip(){  # <ns> <priv> <endpoint-ip> <tun>
  local ns=$1 priv=$2 ip=$3 tun=$4
  for round in 1 2 3 4; do
    sudo ip netns exec $ns "$CL" \
      --endpoint 10.99.0.$ip:18000 --transport udp --vni 200 \
      --key "$priv" --server-pub "$OP_PUB" --tun $tun --log-level info \
      >> "$LOG" 2>&1 &
    for w in 1 2 3 4 5 6; do
      sleep 1
      [ -n "$(get_ip $ns $tun)" ] && return 0
    done
    # this round failed; kill the client in that ns and retry
    sudo ip netns pids $ns 2>/dev/null | xargs -r sudo kill 2>/dev/null
    sleep 1
  done
  return 1
}
start_client_until_ip gaso-ca "$A_PRIV" 1 gatun-a &
start_client_until_ip gaso-cb "$B_PRIV" 2 gatun-b &
start_client_until_ip gaso-cc "$C_PRIV" 3 gatun-c &
wait

A_IP=$(get_ip gaso-ca gatun-a); B_IP=$(get_ip gaso-cb gatun-b); C_IP=$(get_ip gaso-cc gatun-c)
echo "   A=$A_IP  B=$B_IP  C=$C_IP"
if [ -z "$A_IP" ] || [ -z "$B_IP" ] || [ -z "$C_IP" ]; then
  echo "   !! 有 client 没拿到 IP"; sudo tail -40 "$LOG"; teardown; exit 1
fi

pingcheck(){ # <ns> <dst> <label>
  if sudo ip netns exec $1 ping -c3 -W2 "$2" >/dev/null 2>&1; then echo "   ✅ $3"; return 0
  else echo "   ❌ $3"; return 1; fi
}

log "5. 3c 互 ping（全通证明 3 operator 集群 + follower 转发 + 跨 op 转发都work）"
OK=0
pingcheck gaso-ca "$B_IP" "A→B" || OK=1
pingcheck gaso-ca "$C_IP" "A→C" || OK=1
pingcheck gaso-cb "$C_IP" "B→C" || OK=1
[ $OK -eq 0 ] && echo "   互 ping 全通" || echo "   !! 互 ping 有失败"

log "6. kill op2（C 的接入 operator）"
sudo ip netns pids gaso-op2 2>/dev/null | xargs -r sudo kill
echo "   op2 已 kill；等待 C 跳到别的 operator (hopper 周期 3s，等 8s)"; sleep 8

log "7. kill 后再 ping：C↔A（C 应已跳到 op0/op1 继续通）"
# 注意：C 的 endpoint 是 op2，op2 死后新握手会失败；但 C 已有会话，靠 hopper
# 跳到 op0/op1 的数据面 demux 继续，无需重新握手（G4 核心）。
if pingcheck gaso-ca "$C_IP" "A→C（op2 死后）"; then
  echo "   ✅✅ C 在其接入 operator 被 kill 后仍可达——跳跃生效，会话未断"
else
  echo "   ❌ C 不可达；日志尾部："; sudo tail -30 "$LOG"
fi

log "8. operator/client 日志尾部"
sudo tail -25 "$LOG"
log "9. 清理（日志 $LOG）"
teardown

# PRD：共识 / 身份 / 动态 IP / 端口跳跃 / 多 server 跳跃 / 数据面加密

分支：`pure-mesh`　状态：待评审　目标版本：握手协议 v2 + operator 共识层 v1 + 数据面 v1

---

## 0. 背景与问题定位

当前握手（`protocol/handshake/handshake.go`）是四段式：

```
ClientHello(vni, cid) → ServerHello(challenge) → ClientAnswer(response) → ServerAssign(ip, cidr)
```

四个结构性缺陷，正是本次要修的：

**其一，身份可伪造。** CID 由客户端在 `ClientHello` 里自报，服务端拿它查 `PresetCIDmap` 决定 IP。HMAC 认证（`type-hmac.go:59`）的 `VerifyResponse` 第一个参数是 `_ protocol.CID_Ty`——**CID 被显式丢弃**。任何持有任一有效 `<id, secret>` 的客户端都能声称自己是任意 CID，从而取得别人的 IP。`CryptoSuite_Wireguard` 常量已定义但无任何实现。

**其二，IP 是静态表，不是分配器。** `vniResolver.IP()`（`operator.go:53`）只做 `routingMap.LookupByCID(cid)` 查表；表来自 `--preset` 命令行。没有池、没有租约、没有回收——新客户端接入必须先改命令行重启 operator。

**其三，端口与服务端均固定。** listener 绑定单一 `addr` 后终身不变（`udp/listener.go:48`、`quic/listener.go:20`）。更进一步，会话与"某个 operator 进程"死绑：`virtualPeer` 以 `netip.AddrPort` 为键（`udp/listener.go:86`），源地址一变即被当作新 peer 重新握手——这既挡死了端口跳跃，也挡死了多 server 跳跃，还顺带使 NAT 重绑定必然断线。

**其四，operator 之间没有一致的世界观。** 现有 operator↔operator 链路是裸 UDP 单播（`peer_operator.go:32` `WritePacket`：一次 `WriteToUDP`，**无重传、无排序、无确认**），只用来转发数据帧。路由表靠外部（已删除的 cordinator）推送，session、密钥、地址池各自为政。这使得"客户端在任意 operator 上都能被正确服务"无从谈起。

另有一处：`SessionContext.SessionID [16]byte` 字段已存在并已在 `ServerAssign` 线格式中占位传输（`messages.go:148`），但**从未被赋值**，始终是全零。本次将它启用为会话标识。

---

## 1. 目标与非目标

### 目标

| # | 能力 | 参照 | 验收口径 |
|---|---|---|---|
| G0 | operator 强一致共识 | Raft | 全 mesh 对 session / vnet / 子网 / 密钥表 / 接入点位置有单一一致视图；leader 故障自动选举 |
| G1 | 身份绑定密钥 | WireGuard | 客户端身份 = 其静态公钥。CID 由公钥推导，不可自选；冒用他人 CID 必然握手失败 |
| G2 | 动态 IP 下发 | OpenVPN | 地址池按需分配、带租约、断线回收；**IP 与 session 号在一次握手内完成分配**，零额外往返 |
| G3 | 端口跳跃 | Hysteria2 | 服务端监听端口区间，客户端按共享密钥推导的时间序列跳跃；跳跃对上层数据面透明 |
| G4 | 多 server 跳跃 | — | 握手绑定单一 host:port；握手成功后可在**任意 server 的任意区间**发送，全部可行 |
| G5 | 数据面加密 | WireGuard | Noise_IK 握手协商密钥，ChaCha20-Poly1305 加密每个 IP 包；含重放窗口与 rekey |

### 非目标（本次明确不做）

- 不做 PKI / CA / 证书链。公钥即身份，信任来自授权列表，同 WireGuard。
- 不做 IPv6 地址池（协议字段预留，不实现）。
- 不改 gasoctl IPC 的既有命令语义（只做加法）。
- 不做跨 Raft 集群的联邦（一个 mesh = 一个 Raft 集群）。

---

## 2. G0：operator 强一致共识层

**这是本次的地基，G2 与 G4 都建立在它之上，必须最先落地。**

### 2.1 一个必要的澄清

"QUIC 分布式强一致共识"里的两个词是正交的：**QUIC 是传输**（可靠、有序、加密的连接），**共识是算法**（选主、日志复制、多数派提交）。QUIC 不提供共识，但可以作为共识算法的传输层。

因此本方案 = **hashicorp/raft（共识算法）跑在 QUIC 之上（传输）**。选 hashicorp/raft 而非自研，是因为共识算法自实现极易出现只在特定分区/时序下暴露的微妙 bug；该库是 Consul / Nomad 的生产实现，我们只需提供两样东西：`FSM`（状态机）与 `Transport`（接到 QUIC）。

### 2.2 复制的状态（FSM）

Raft 日志复制以下全部状态，每个 operator 持有完整副本：

```go
type meshState struct {
    // 虚拟网络组：类 VXLAN，一个 VNI 可含多个网段
    VNets    map[protocol.VNI_Ty]*vnetDef

    // 会话：握手即 session
    Sessions map[protocol.SessionID_Ty]*sessionEntry
}

type vnetDef struct {
    VNI      protocol.VNI_Ty
    Segments []segment          // 一个 vnet 多个网段
    AuthKeys map[[32]byte]*keyGrant  // 子网对应的密钥表
}

type segment struct {
    CIDR     netip.Prefix       // 网段，如 10.0.1.0/24
    Pool     netip.Prefix       // IP 池，必须是 CIDR 的子集
    Reserved []netip.Addr       // 网关等保留地址
}

type keyGrant struct {
    PubKey     [32]byte
    VNI        protocol.VNI_Ty
    AllowedSeg []netip.Prefix   // 该密钥可在哪些网段取地址
    StaticIP   netip.Addr       // 可选：固定分配
}

type sessionEntry struct {
    SessionID   protocol.SessionID_Ty
    CID         protocol.CID_Ty
    PubKey      [32]byte
    VNI         protocol.VNI_Ty
    IP          netip.Addr
    HopSecret   [32]byte        // 端口跳跃推导用（可被任意 operator 读取）
    LastTimestamp [12]byte      // Noise 防重放：该公钥见过的最大 TAI64N

    // 注意：数据面传输密钥（send_key/recv_key）**不在此处**——
    // 它由 Noise 握手在两端本地派生，不进 Raft，operator 无法解密（§7.2）

    // 哪个密钥在哪个接入点最近接入
    LastOperator [16]byte       // 最近服务它的 operator UUID
    LastSeen     time.Time
    Expires      time.Time      // 租约
}
```

**`Pool ⊆ CIDR` 是硬约束**，在 `ApplyVNetUpsert` 时校验，违反则拒绝该日志条目。

### 2.3 握手在一次往返内完成分配

你的要求：**分配 IP 和 session 号必须在一次握手内完成**。这与 Raft 的"写入需过 leader + 等多数派"存在张力，解法是把三件事合成**一条 Raft 日志**：

```
ClientHello(Noise msg1)
  ↓  ← 服务端解密 msg1 得客户端静态公钥，校验 CID 与授权
ServerHello(Noise msg2)
  ↓  ← 至此双方已各自派生 send_key / recv_key（不进 Raft）
ClientAnswer(空载荷)
  ↓  ← 服务端在此处做唯一一次 Raft 写入：
     Apply(SessionCreate{
        pubkey, cid, vni,
        ip:        <本地预选，见下>,
        sessionID: <本地生成>,
        hopSecret,
        operator:  self.UUID,
     })
     等待多数派提交 → 提交成功即分配生效
  ↓
ServerAssign(ip, sessionID, hopSecret, serverList)   ← 此报文起已被 AEAD 加密
```

握手报文数**不变**（仍是 4 条），额外成本是 `ClientAnswer` 到 `ServerAssign` 之间的一次 Raft 提交（本地 leader 约 1ms；跨地域跟随者转发至 leader 约 1 RTT）。这是强一致的固有代价，你已确认接受。

**IP 预选**：接入的 operator 从 FSM 的当前快照里挑一个空闲地址填进日志条目。若在提交前被别人抢占，leader 侧 `Apply` 时检测冲突并拒绝，接入方**重选后重试**（最多 3 次，仍失败则 `HandshakeNoRoute`）。这是乐观并发，比"先申请再确认"少一个往返。

### 2.4 Leader 不可达

选举是 operator 集群内部的事，客户端无感：

- Raft 默认选举超时 1~2s，期间**新握手阻塞**（返回超时，客户端重试即可），**既有 session 的数据转发完全不受影响**（转发只读本地 FSM 副本，不需要 leader）。
- 跟随者收到握手时把 Raft 写入转发给 leader（hashicorp/raft 的标准做法）；leader 未知时短暂等待选举完成。
- **需要完善测试**（你的明确要求），见 §11 的 P1 验收项：包含 leader 主动下线、网络分区、少数派隔离三类场景。

### 2.5 集群成员与传输

- `--raft-peers "uuid@host:port;..."` 声明初始成员；`--raft-bind` 本节点 Raft 监听地址。
- **集群规模任意**：3/4/5/7 皆可，不强制奇数。偶数节点只是略微浪费（4 节点的 quorum 是 3，容错能力与 3 节点相同），不影响正确性。选举完全交给 hashicorp/raft，配置上零额外心智负担。
- Transport 实现 `raft.Transport` 接口，底层用 `quic-go`（已在 `go.mod`，QUIC 自带 TLS 加密与多路复用，正适合日志复制 + 快照传输并行）。
- 快照：FSM 定期 snapshot，新节点加入时传快照而非全量日志重放。
- **数据面不走 Raft**：IP 包转发仍走既有的 `PeerOperator` UDP 直连路径。Raft 只承载控制状态。这个边界必须清晰，否则吞吐会被共识拖垮。

**为什么保留 Raft 选举而非"按初始化时间戳定老大"**：多数派（quorum）是"绝不出现双 leader、绝不重复分配 IP"的根源。若改用时间戳定序，网络分区时两侧会各自认定一个存活的"最老"节点为 leader，双方继续分配 IP，**分区恢复后必然冲突且无法自动裁决**——恰好摧毁强一致这一核心目标。时间戳仅在选举平票时作为 tie-break 提示，不替代 quorum。

### 2.6 写入批处理（Batch）

Raft 的每条日志都要过一轮多数派确认，逐条提交高频事件会压垮集群。因此**所有高频写入统一走批处理**：

```
事件产生 → 本地批队列 → 满足任一条件即打包成一条 Raft 日志提交：
   · 累积条目数 ≥ 64
   · 距上次提交 ≥ 500ms
```

一条 Raft 日志内含多个事件（`BatchOp{ops: []Op}`），FSM 顺序 Apply。这样 keepalive **每次都写 Raft**（语义上不丢事件、状态始终精确），但**不是每次都发起共识**——批处理把 N 次共识压成 1 次。

适用于：`SessionRenew`（keepalive 续期）、`SessionMigrate`（接入点变更）、`SessionDrop`（掉线）。

**不批处理**（要求立即生效、且低频）：`SessionCreate`（握手，客户端在等）、`KeyGrant`/`KeyRevoke`、`VNetUpsert`、gasoctl 的踢人操作。

### 2.7 落点

- 新增 `cmd/operator/device/consensus/`：`fsm.go`（状态机 + Apply）、`transport_quic.go`（raft.Transport over QUIC）、`commands.go`（日志条目类型）。
- `go.mod` 增 `github.com/hashicorp/raft`。
- `operatorState` 增 `raft *raft.Raft` 与 `fsm *meshState`；`vnets` 字段的权威来源从静态配置改为 FSM。
- `--network` 静态配置降级为"集群初始化时的种子数据"（仅 bootstrap 节点生效）。

---

## 3. G1：身份绑定密钥

### 3.1 设计

采用 WireGuard 的核心不变式：**身份即密钥，CID 是公钥的函数而非独立输入**。

- 密钥体制：**X25519**（32B 公钥）。

  上一版本 PRD 选的是 Ed25519（签名），因为当时数据面加密是非目标。**加入 G5 后改为 X25519**：Noise_IK 用 DH 而非签名做认证——能算出正确共享密钥本身就证明持有私钥，无需额外签名。同 WireGuard，一把密钥既是身份也是密钥协商材料，不引入第二套密钥体系。

- 推导规则：

  ```
  CID = BLAKE2s-256("gaso" || pubkey)[0:8]
  ```

  截断到 8 字节以适配现有 `CID_Ty [8]byte`，路由表、日志、gasoctl 全链路无需改动。

- 碰撞：64 位空间。密钥授权写入 Raft 时检测 CID 碰撞并拒绝该条目——把风险从"运行时静默串号"降为"授权时显式报错"。

### 3.2 握手改造：Noise_IK

身份认证与密钥协商合一，握手即 Noise_IK 的两条消息，映射到现有四段式结构：

```
ClientHello:  version(1) cryptoSuite(2) vni(4) cid(8) labels
              + Label[LabelKey_NoiseInitiation] = Noise msg1     ← 新增
                  msg1 = e_pub(32) || encrypted_static(32+16)
                                   || encrypted_timestamp(12+16)

ServerHello:  version(1) cryptoSuite(2) labels
              + Label[LabelKey_NoiseResponse]   = Noise msg2     ← 新增
                  msg2 = e_pub(32) || encrypted_empty(16)

ClientAnswer: 保留报文但载荷为空（Noise 在两条消息内已完成认证）
ServerAssign: ip / sessionID / hopSecret / serverList
```

**"IK" 的含义**：Initiator 在第一条消息里就把自己的静态公钥（加密后）发出去，且**预先知道** Responder 的静态公钥。后者要求客户端配置里写明目标 server 的公钥——同 WireGuard 的 `PublicKey =` 配置项。

**认证如何达成（无需签名）**：msg1 中客户端的静态公钥用 `DH(e_client, s_server)` 派生的密钥加密；服务端只有持有 `s_server` 私钥才能解开。反过来，客户端只有持有 `s_client` 私钥才能算出后续 `DH(s_client, e_server)`，得到正确的传输密钥。**能通信本身即完成双向认证**。

服务端验证三步（顺序不可换）：

1. Noise 解密 msg1 成功 → 得到客户端静态公钥（失败则丢弃，不回包）
2. `CID == derive(pubkey)`　→ 否则拒绝（**这一步堵死冒用**）
3. `pubkey ∈ FSM 的 VNI 密钥表`　→ 否则拒绝（读本地 Raft 副本，无需网络往返）

失败一律**静默丢弃或返回同一错误码同一延迟**，不泄露"该公钥是否已授权"。

**防重放**：msg1 内含加密的 TAI64N 时间戳，服务端记录每个静态公钥见过的最大时间戳，拒绝更旧的 msg1（同 WireGuard）。该状态随 `keyGrant` 存入 Raft，使**任意 operator 都能拒绝重放**——单机方案在多 server 跳跃下会被绕过，这是 G0 的又一处收益。

### 3.3 落点

- 新增 `protocol/noise/`：`handshake.go`（IK 模式状态机）、`kdf.go`（HKDF-BLAKE2s）、`cipher.go`（ChaCha20-Poly1305 封装）。依赖 `golang.org/x/crypto`（当前是 indirect，提升为直接依赖）。
- 新增 `protocol/auth/type-noise.go`：`Type = TypeNoise (0x03)`，把 Noise 状态机接进既有 authenticator 接口。
- **接口需扩容**：现有 `Respond(challenge []byte)` 无法承载 Noise 的双向状态机，改为传 `AuthContext`（含 vni/cid/静态密钥对/对端公钥）。这是唯一的破坏性接口变更，影响三个既有 authenticator（noauth/hmac/userpass 忽略新字段即可）。
- `VerifyResponse` 的 `cid` 参数**恢复使用**（当前被丢弃）。
- 密钥授权经 Raft 写入：gasoctl `key grant <vni> <pubkey> [seg...]` / `key revoke <vni> <pubkey>`。
- 客户端 `--key <path>`（缺失则生成并落盘 0600）+ 配置文件中每个 server 的 `pubkey`；新增 `client genkey`。
- **operator 也需要静态密钥对**：`--key <path>`，公钥经 `ServerAssign` 的 server 列表下发（客户端首次仍需带外获知，同 WireGuard）。

### 3.4 兼容性

`HandshakeVersion` 由 `0x01` 升至 `0x02`，服务端**不接受** v1（v1 身份模型不可信，保留即保留漏洞）。legacy 的 `hmac:`/`userpass:` 保留但不与 `pubkey:` 在同一 VNI 混用。

---

## 4. G2：动态 IP 下发

### 4.1 vnet / 网段 / 池的关系

按你的设定，类 VXLAN：

```
VNI 200  (一个虚拟网络组)
 ├─ segment 10.0.1.0/24   pool 10.0.1.16/28   reserved [10.0.1.1]
 └─ segment 10.0.2.0/24   pool 10.0.2.0/25    reserved [10.0.2.1]
```

- 一个 vnet 含**多个网段**；
- **池必须是网段的子集**（`Pool ⊆ CIDR`，Raft Apply 时强校验）；
- 池外、网段内的地址可用于静态绑定与网关，不会被动态分配占用。

### 4.2 分配优先级

1. **静态绑定**（`keyGrant.StaticIP`）—— 恒定生效，不进池。
2. **续租** —— 该 PubKey 的既有租约未过期 → 返回原 IP。**这是 IP 稳定性的关键**：重连（换端口、抖动、进程重启、甚至换 operator）都应拿回同一 IP，否则上层 TCP 全断。因状态在 Raft 中全局一致，**跨 operator 重连同样能续租**——这是 G0 带来的直接收益。
3. **新分配** —— 从该密钥 `AllowedSeg` 允许的网段池中取空闲地址。
4. **池满** —— `HandshakeNoRoute`。

### 4.3 生命周期

- 租约 TTL 默认 3600s（`--lease-ttl`）。
- **续期每次都写 Raft，但走批处理**（§2.6）：既有 keepalive 每 10~15s 一次（`keepalive.go:39`），产生一条 `SessionRenew` 进批队列；批队列按"64 条或 500ms"打包成单条 Raft 日志。语义上不丢任何一次续期，集群状态始终精确，同时把 N 次共识压成 1 次。
- 过期回收由 leader 侧定时任务批量提交 `SessionExpire`，复用既有 `routineReaper` 节奏（30s）。
- `DataCtrlPrefixChanged`（`message-datactrl.go:53`，已实现编解码但从未有人发送）本次启用：IP 变更时主动下发，客户端重配 TUN。

### 4.4 配置形态：一个 vnet 一个文件

vnet 定义以文件为单位，作为**集群的种子数据**：

```yaml
# vnet-200.yaml
vni: 200

segments:
  - cidr: 10.0.1.0/24
    pool: 10.0.1.16/28        # 池必须 ⊆ cidr
    reserved: [10.0.1.1]      # 网关
  - cidr: 10.0.2.0/24
    pool: 10.0.2.0/25

keys:
  - pubkey: "base64...."
    allowed_segments: [10.0.1.0/24]
  - pubkey: "base64...."
    allowed_segments: [10.0.1.0/24, 10.0.2.0/24]
```

**加载语义**：`operator --vnet ./vnet-200.yaml`。仅 bootstrap 节点在集群初始化时读取并写入 Raft；此后一切变更走 gasoctl（文件不再是权威）。重复加载已存在的 vni 会被拒绝，除非显式 `--vnet-force`。

### 4.5 固定 IP 与 lock 文件

**默认每个密钥固定 IP**：密钥首次接入时分配的地址即成为其固定绑定，后续永远拿这个 IP（不因租约过期而释放）。

分配结果写入**同名 lock 文件**并经 Raft 同步：

```yaml
# vnet-200-lock.yaml   ← 由 operator 生成，勿手工编辑
vni: 200
bindings:
  - pubkey: "base64...."
    ip: 10.0.1.17
    bound_at: 2026-08-11T13:00:00Z
  - pubkey: "base64...."
    ip: 10.0.1.18
    bound_at: 2026-08-11T13:04:12Z
```

- lock 文件的**权威副本在 Raft 中**（`vnetDef.Bindings`）；磁盘文件是可读的镜像，由 leader 在绑定变更时落盘，便于运维查看与备份。
- 集群重启后从 Raft 快照恢复，不依赖磁盘 lock 文件；lock 文件仅在**全新集群 bootstrap** 时可作为种子导入。
- **解除固定**：`gasoctl ip unlock <vni> <pubkey>`——提交 Raft，删除绑定，该 IP 回池。下次接入重新分配。
- `gasoctl ip lock <vni> <pubkey> <ip>` 手动指定固定 IP（须在池内且空闲）。

这与 §4.2 的分配优先级一致：固定绑定命中即返回，等价于"续租永不过期"。

### 4.6 落点

- 地址池逻辑进 `consensus/fsm.go`（分配是状态机转移，不能是本地独立行为）。
- `vniResolver.IP()` 改为走 §2.3 的 Raft 提交路径。
- 分配结果仍写入既有 `routingMap.SetClient`，路由链路完全复用。
- 新增 `cmd/operator/device/vnetfile.go`：YAML 解析 + `Pool ⊆ CIDR` 校验 + lock 文件读写。
- gasoctl 增 `vnet load <file>` / `vnet add-segment` / `ip lock` / `ip unlock` / `lease list`。

---

## 5. G3：端口跳跃

### 5.1 设计

服务端在**端口区间**上同时监听，客户端按时间片轮换目标端口。

**关键决策：服务端全区间同时监听，而非跟着时钟切换。**

- 无时钟同步问题——客户端偏移 ±1 个时间片也能连上；
- 无切换窗口丢包；
- 代价是占用 N 个 UDP 套接字（N ≤ 64，可接受）。

**端口序列推导**（两端各自独立计算，无需协商）：

```
epoch = floor(unix_time / hop_interval)
idx   = HMAC-SHA256(hop_secret, "gasoline-hop" || vni(4) || epoch(8))[0:2] mod range_size
port  = range_start + idx
```

`hop_secret` 在握手时随 `ServerAssign` 下发（见 §5.3），并已存入 Raft，故**任意 operator 都能推导同一客户端的端口序列**——这是 G4 的前提。

### 5.2 会话延续性

UDP listener 现以 `netip.AddrPort` 为键索引 `virtualPeer`（`udp/listener.go:86`），客户端一换端口即被当作新 peer 重新握手。

**解决方案：以 SessionID 而非四元组标识会话。**

- 启用当前恒为零的 `SessionContext.SessionID`：握手时生成并经 `ServerAssign` 下发（**线格式已有该字段，无需改 messages.go**）。
- 数据面每帧前置 6 字节会话标签（见 §6.4）。
- peers 索引主键由 `AddrPort` 改为 SessionID，`AddrPort` 降为辅助索引。已知 SessionID + 新源地址 → 原地更新 `remoteAddr`，**不重新握手**。

顺带修复了 NAT 重绑定断连——一个既有但未记录的缺陷。

### 5.3 握手期的鸡生蛋问题

- 客户端首包发往 `range_start`（引导端口，恒定开放）。
- `ServerAssign` 通过 **label** 下发 `hop_secret(32B)` + 区间参数 + **全量 server 列表**。`ServerAssign` 目前**没有** labels 字段，需补上 label 段（照抄 `ClientHello`）——这是本项唯一的线格式变更。
- 此后客户端从当前 epoch 起跳，不再走引导端口。

### 5.4 QUIC 的限制

QUIC 有自身的连接迁移与路径验证，叠加我们的跳跃会冲突。**G3/G4 仅在 UDP 传输实现**；QUIC 保持单端口，依赖其原生迁移。CLI 在 `--transport quic` + 跳跃参数时**报错而非静默忽略**。

---

## 6. G4：多 server 跳跃

### 6.1 G0 让这件事变得简单

在没有共识层的方案里，G4 是最难的一项（收包的 operator 对会话一无所知，需要转发到宿主）。**有了 G0，它几乎是免费的**：

每个 operator 都持有全部 session 的完整副本（SessionID、PubKey、IP、HopSecret、租约）。任意 operator 收到任意会话的包，都能：

1. 用 `SessionTag` 查本地 FSM → 命中，得知这是哪个会话、对应哪个 overlay IP；
2. 用本地 `routingMap` 按目的 IP 转发 → 与宿主 operator 的行为完全一致。

**不需要转发到宿主，不需要 SessionBind 广播，不存在"宿主故障"这一概念。** 这正是你选择强一致的核心收益。

### 6.1bis G5 带来的约束：operator 不能解密

引入端到端加密后，上面第 2 步有一个前提问题：**operator 拿不到传输密钥，它看不见密文里的目的 IP，怎么按 IP 转发？**

这是 G4 与 G5 的真实冲突，必须明确解决。方案：**把路由所需的最小信息放在密文之外**。

```
frame = SessionTag(6) || Counter(8) || AEAD密文(加密的完整 IP 包)
         └─ 明文，用于查会话 → 得知源会话
```

- **上行**（客户端 → operator）：operator 由 `SessionTag` 确定**源**会话；目的地则由密文内的 IP 决定，operator 看不到。
- 因此 operator 必须能在不解密的前提下知道往哪送。解法是 `SessionTag` 之后**再附一个明文的目的标识**：

```
frame = SessionTag(6) || DstTag(6) || Counter(8) || AEAD密文
                        └─ 目的会话的 SessionTag，由客户端填写
```

客户端在发包前用本地 ARP/路由表把目的 overlay IP 解析为对端的 `SessionTag`（该映射由 operator 经 `DataCtrlPeerAdvertise` 下发——**这条消息已实现编解码但目前无人发送**，§4.3 同款情况）。operator 只需 `DstTag → 会话 → 当前接入 operator`，纯查表转发，全程不解密。

**代价与收益**：每包多 6 字节（总开销见 §7.6 更新）。收益是 operator 彻底退化为"加密信封的邮差"——它知道谁发给谁，但读不到内容。这正是 `ARCHETECT.md` 里"operator 和链路层永远无法知道内部信息"那条零信任目标的落地。

**副作用**：广播/组播（如 ARP 广播）无法用单一 `DstTag` 表达。本期做法是保留一个全零 `DstTag` 表示"广播给同 VNI 所有会话"，由 operator 复制分发；密文仍只有目标能解开（需为广播额外协商组密钥，**本期不做，广播帧走明文**，仅限 ARP 这类不含用户数据的控制流量）。

### 6.2 配置与下发

```yaml
servers:
  - host: 1.2.3.4
    ports: [20000-20063, 30000-30015]
  - host: 5.6.7.8
    ports: [20000-20063]
```

- 握手绑定其中某一个 `host:port`（首个可达 server 的引导端口）；
- `ServerAssign` 下发**服务端权威的** server 列表（各 host + 区间 + UUID），覆盖客户端本地配置（本地配置可能过期）；
- 此后客户端可向列表中**任意 (server, 区间)** 组合发包，全部可行。

### 6.3 接入点位置追踪

你要求记录"哪个密钥在哪个接入点最近接入"。实现为 `sessionEntry.LastOperator` + `LastSeen`：

- 客户端跳到新 operator 时，该 operator 更新本地 `LastSeen`；
- **不是每包都写 Raft**（会压垮集群），而是在 `LastOperator` 发生**变化**时提交一次 `SessionMigrate`；
- gasoctl `session list` 可查每个密钥当前的接入点，满足运维观测需求。

### 6.4 数据面来包校验

任意 operator 都会转发任意会话的包，因此必须能识别会话归属并拒绝伪造包。

**加入 G5 后，这里被简化了**：不再需要独立的转发准入 MAC。

```
frame = SessionTag(6) || DstTag(6) || Counter(8) || AEAD密文   ← 见 §7.3
```

- operator 用 `SessionTag`（6 字节）查本地 Raft 副本定位会话 → O(1) 转发；
- 包的真伪由端到端的 **Poly1305 tag** 保证，比原先 4 字节截断 MAC 强得多；
- operator **不解密**——它没有传输密钥（密钥不进 Raft），只做转发。这正是端到端加密应有的形态。

**SessionTag 取 6 字节**（SessionID 前 6 字节，48 bit）：按生日界，百万级并发会话下碰撞概率约 10⁻³，且碰撞只导致一次查表失败后丢包（AEAD 校验必然失败），不构成安全问题。你要求尽可能短，6 字节是可用性与开销的平衡点。

### 6.5 落点

- `transport/udp/listener.go`：多端口监听 + SessionID 索引 + MAC 校验。
- `transport/udp/dialer.go`：跳跃 ticker（端口 + server 双维度）。
- 客户端配置从 flag 迁到**配置文件**（多 server 多区间无法用扁平 flag 表达）：新增 `--config <path>`。

---

## 7. G5：数据面加密（WireGuard AEAD）

### 7.1 现状澄清

`3rdparty/` 下 11 个目录**全部为空**（无 `.gitmodules`，无任何文件），第一方代码中 `aead` / `chacha` / `poly1305` / `noise` 搜索结果为零，`golang.org/x/crypto` 目前只是 sing-tun 拉进来的 **indirect** 依赖。因此本项**需从头实现**，可对照 wireguard-go 的公开实现。

### 7.2 密钥协商

由 §3.2 的 Noise_IK 握手直接产出两把方向密钥：

```
握手完成 → HKDF 派生 → (send_key, recv_key)   各 32 字节
                        客户端的 send = 服务端的 recv，反之亦然
```

密钥**不进 Raft**——它是每会话、每次握手独立的临时密钥，且具备前向保密（依赖 ephemeral 密钥对）。Raft 中只存静态公钥（身份）与 `SessionKey`（§6.4 的转发准入 MAC，与加密密钥是两回事）。

**这带来一个必须解决的设计冲突，见 §7.5。**

### 7.3 数据面帧格式

```
frame = SessionTag(6) || DstTag(6) || Counter(8)
        || ChaCha20-Poly1305(send_key, Counter, ip_pkt)
           └── 密文 = 明文长度 + 16 字节 Poly1305 tag
```

`SessionTag` / `DstTag` 均为明文（operator 靠它们纯查表转发，见 §6.1bis）；`Counter` 明文（AEAD nonce 本就无需保密）。

- `Counter`：单调递增的 nonce，每包 +1。ChaCha20-Poly1305 的 96-bit nonce 由 `Counter` 零扩展而来（同 WireGuard）。
- **同一密钥下 Counter 绝不重复**——这是 AEAD 安全性的绝对前提，达到上限必须 rekey。
- §6.4 的 4 字节转发准入 MAC **被 AEAD tag 取代**：既然任意 operator 都持有 `SessionKey`（Raft 同步），转发准入改用 `SessionTag` 查表即可；真伪由端到端的 Poly1305 tag 保证。**省下 4 字节，且安全性更强**。

### 7.4 重放窗口与 rekey

- **重放窗口**：滑动 bitmap，窗口大小 2048（同 WireGuard）。收到的 Counter 若落在窗口外（过旧）或已被标记，丢弃。
- **rekey 触发**（任一满足）：
  - 距上次握手 ≥ 120s（`REKEY_AFTER_TIME`）
  - 发送包数 ≥ 2^60（`REKEY_AFTER_MESSAGES`）
  - 收到对端 rekey 请求
- rekey 即重跑一次 Noise_IK 握手，**但不重新分配 IP / SessionID**——租约与会话延续，只换传输密钥。这一点必须在实现时明确，否则每 2 分钟客户端就换一次 IP。

### 7.5 与 QUIC / UDP 两种传输的关系

这是本项**最需要想清楚的部分**（你的明确要求）。两种传输的安全属性本就不同：

| | UDP 传输 | QUIC 传输 |
|---|---|---|
| 现状 | 完全明文 | 已有 TLS 1.3 加密（`transport/quic/tls.go`） |
| 加 G5 后 | Noise AEAD 加密 | Noise AEAD **再套一层** TLS |

**决策：两种传输都启用 G5，不做例外。** 理由：

1. **端到端 vs 逐跳**：QUIC 的 TLS 只加密"客户端 ↔ 当前 operator"这一跳。而在 G4 多 server 跳跃下，客户端会连到不同 operator；更重要的是 operator 之间转发走的是**裸 UDP underlay**（`peer_operator.go`），那一段今天完全明文。G5 的密钥是端到端的（客户端 ↔ 会话，跨 operator 不变），**这是 TLS 给不了的**。
2. **一致的安全模型**：若 UDP 加密而 QUIC 不加密，则"用哪个传输"变成安全等级的隐式开关，是设计缺陷。
3. **代价可接受**：QUIC 上多一层 AEAD，CPU 开销约 +3~5%（ChaCha20 在无 AES-NI 的平台上尤其快），换取端到端保密。

**QUIC 上的具体简化**：QUIC 已保证可靠有序，故 QUIC 传输上的 G5 **不需要重放窗口**（不会乱序不会重复），仅需 AEAD 加解密；`Counter` 仍必须严格递增以满足 nonce 唯一性。UDP 传输则必须完整实现滑动窗口。

```
UDP  : Noise AEAD + Counter + 重放窗口(2048 bitmap)   ← 完整实现
QUIC : Noise AEAD + Counter，无重放窗口                ← QUIC 已保序去重
```

两者共用同一套 `protocol/noise` 密码学代码与同一份帧格式，差异仅在**是否启用窗口检查**，由 `transport.Conn` 的实现决定。

### 7.6 MTU 影响（累计）

```
原始 IP 包                                    1400
+ SessionTag(6)                                  6
+ DstTag(6)                                      6
+ Counter(8)                                     8
+ Poly1305 tag                                  16
────────────────────────────────────────────────
每包净增                                        36 字节
```

`DEFAULT_MTU` 需由 1400 下调至 **1364**（`tun.go:14`）。若同时跑在已有隧道内需再留余量。

### 7.7 落点

- 新增 `protocol/noise/`（见 §3.3）。
- `transport/udp/conn.go`、`transport/quic/conn.go`：收发路径加解密；UDP 侧额外挂重放窗口。
- `protocol/message/`：帧格式增加加密封装层。
- `go.mod`：`golang.org/x/crypto` 提升为直接依赖。

---

## 8. 下线与踢人

四条路径，全部经 Raft 全集群生效——这是必须的：多 server 跳跃下客户端可能在任意 operator 上，只在本地踢等于没踢。

### 8.1 手动踢断，允许重连（`gasoctl session kick <vni> <cid>`）

- 提交 `SessionDrop{reason: kicked}` → 全集群移除 session，IP 回池（若非固定绑定）。
- 当前接入的 operator 向客户端下发 `DataCtrlShutdown{reason: ShutdownGoingAway}`（**该消息已实现编解码，`message-datactrl.go:57`，目前无人发送**）。
- 客户端收到后关闭连接；因密钥仍有效，可立即重新握手。**固定 IP 绑定保留，重连拿回同一 IP。**
- 用途：强制刷新会话状态、迁移接入点。

### 8.2 删除密钥强制踢（`gasoctl key revoke <vni> <pubkey>`）

- 提交 `KeyRevoke` → 从密钥表移除 → **级联** `SessionDrop{reason: revoked}` 移除该密钥的所有 session。
- 同时清除固定 IP 绑定（lock 文件同步更新），IP 回池。
- 下发 `DataCtrlShutdown{reason: ShutdownPolicy}`。
- 客户端重连时在 §3.2 验证第 2 步（`pubkey ∈ 密钥表`）失败 → `HandshakeAuthFail`。**永久踢出。**

### 8.3 自动掉线检测

- 判定方：**当前服务该 session 的 operator**（`sessionEntry.LastOperator`）。
- 判据：`--session-timeout` 秒内（默认 60s，即 4~6 个 keepalive 周期）未收到该 session 的任何帧。
- 动作：提交 `SessionDrop{reason: timeout}`，走**批处理**（§2.6）——掉线不是紧急事件，批量提交即可。
- 全集群移除 session、IP 回池（固定绑定保留）。

**误判防护**：多 server 跳跃下，客户端可能已跳到别的 operator。因此判定前必须先检查本地 FSM 的 `LastOperator` 是否仍是自己——若已被别的 operator 更新（对方收到帧时提交了 `SessionMigrate`），则放弃判定。这条检查不能省，否则跳跃会被误判为掉线。

### 8.4 operator 自身下线

- 优雅退出：提交 `SessionDrop` 批量清理自己持有的 session，然后离开 Raft 集群。
- 崩溃：其持有的 session 由其余节点在 `--session-timeout` 后按 §8.3 清理（任一 operator 发现 `LastOperator` 指向的节点已不在 Raft 集群成员列表中，即可代为判定）。
- **客户端侧无感**：因为全部 session 状态在 Raft 中，客户端跳到任何存活 operator 都能继续通信——这正是 G0+G4 的收益。

### 8.5 gasoctl 命令汇总

```
session list [vni]                    # 含 LastOperator / LastSeen
session kick   <vni> <cid>            # 7.1 可重连
key    grant   <vni> <pubkey> [seg…]
key    revoke  <vni> <pubkey>         # 7.2 永久踢出
ip     lock    <vni> <pubkey> <ip>
ip     unlock  <vni> <pubkey>         # 解除固定 IP
vnet   load    <file>
vnet   add-segment <vni> <cidr> <pool>
lease  list    <vni>
```

---

## 9. 传输层兼容矩阵（QUIC / UDP）

本次全部特性都必须在两种传输上有明确行为，不允许"某个传输上悄悄不生效"。

| 特性 | UDP | QUIC | 说明 |
|---|---|---|---|
| G0 共识 | — | — | operator 之间的事，与客户端传输无关；Raft 自身固定用 QUIC |
| G1 Noise 身份 | ✅ | ✅ | 握手在 `transport.Conn` 之上，与传输无关 |
| G2 动态 IP | ✅ | ✅ | 同上 |
| G3 端口跳跃 | ✅ | ❌ **报错** | QUIC 有自身连接迁移与路径验证，叠加会冲突 |
| G4 多 server | ✅ | ⚠️ **重握手** | QUIC 换 server 需新建连接；会话状态在 Raft 中，故能续租同一 IP，但 TCP 长连接会断 |
| G5 加密 | ✅ 含重放窗口 | ✅ 无重放窗口 | QUIC 已保序去重，仅需 AEAD |

**设计原则**：能力差异必须**显式报错或显式降级**，绝不静默忽略。

- `--transport quic` + 跳跃参数 → 启动即报错，提示改用 udp。
- QUIC 下的多 server：客户端仍可切换 server，但走完整重握手路径（新 QUIC 连接 + 新 Noise 握手），**IP 与租约不变**（Raft 保证），仅传输密钥更新。这是"可用"而非"透明"，文档需明示。

**为什么不给 QUIC 也做透明跳跃**：QUIC 的连接由其自身的 Connection ID 标识并有路径验证机制，若我们在外层再套一个会话标签并任意更换四元组，会与 QUIC 的迁移逻辑打架（它会认为路径变更需要重新验证，或直接丢弃）。强行绕开等于重写 QUIC 的连接管理。**UDP 传输就是为这个场景准备的**——需要跳跃就用 UDP，需要 QUIC 的可靠有序就接受单端口。

---

## 10. 架构总览

```
                    ┌──────── Raft (over QUIC) ────────┐
                    │  强一致复制：                     │
   operator A ◄─────┤   vnet / segment / pool          ├─────► operator C
       ▲            │   密钥授权表                      │            ▲
       │            │   session (含 IP / key / hop)     │            │
       │            │   接入点位置                      │            │
       │            └──────────────┬───────────────────┘            │
       │                     operator B                             │
       │                                                            │
       │  ┌─────────────── 数据面：不走 Raft ──────────────┐        │
       └──┤  client 帧 (SessionTag+MAC) 可发往任意 operator ├────────┘
          │  operator 间 IP 包转发仍走 PeerOperator UDP 直连 │
          └────────────────────────────────────────────────┘
```

**关键分层：控制状态走 Raft（强一致，低频），数据帧走 UDP 直连（高吞吐，不阻塞）。**

---

## 11. 交付顺序

```
G0 共识层 ──┬──► G1 身份绑定 ──► G2 动态 IP（分配是 FSM 转移）
            │
            └──► G3 端口跳跃 ──► G4 多 server（G0 让它近乎免费）
```

| 阶段 | 内容 | 验收 |
|---|---|---|
| P0 | Raft 骨架：FSM + QUIC Transport + 集群 bootstrap | 3 节点集群启动、选主成功、日志复制一致 |
| P1 | **Raft 容错测试**（你的明确要求） | leader 主动下线后 < 5s 选出新 leader；网络分区下少数派拒绝写入；分区恢复后状态收敛；滚动重启不丢数据 |
| P2 | 握手 v2 骨架：`ServerAssign` 补 label 段、`AuthContext` 改造 | 既有测试全绿（noauth 不回归） |
| P3 | G1 Ed25519 + CID 推导 + 密钥表进 Raft | 冒用 CID 必失败；未授权公钥必失败；错误码一致 |
| P4 | G2 vnet/网段/池 + 一次握手内分配 | `Pool ⊆ CIDR` 校验生效；并发 100 握手无重复 IP；**跨 operator 重连拿回同一 IP**；池满返回 NoRoute |
| P5 | G3 SessionID 会话标识（不含跳跃） | 客户端源端口人为变更后会话不中断（同时验证 NAT 重绑定修复） |
| P6 | G3 端口跳跃（单 server） | 端口按 interval 轮换；跨跳跃点 TCP 长连接不断；时钟偏移 ±1 片仍可连 |
| P7 | G4 多 server + 配置文件 | 握手于 A，改向 B/C 发包会话不中断；伪造 MAC 的包被丢弃 |
| P8 | 下线与踢人（§8） | 四条路径各自生效且全集群同步：kick 后可重连且保住固定 IP；revoke 后重连必失败；60s 无帧自动下线；**跳到别的 operator 不被误判为掉线** |
| P9 | G5 数据面加密 | 抓包确认 payload 不可读；篡改一字节必被 AEAD 拒绝；重放旧包被窗口丢弃；rekey 后会话与 IP 不变；**UDP 与 QUIC 两条路径都验证** |

P1 单独成阶段，因为共识层的正确性无法靠"跑通一次"证明——必须主动注入故障。P8 置于最后，因为它依赖 G4 才能验证"跳跃 vs 掉线"的区分。

---

## 12. 风险

| 风险 | 影响 | 应对 |
|---|---|---|
| **握手引入 Raft 写入延迟** | 跨地域握手 +1 RTT | 已确认接受；乐观预选 IP 避免二次往返 |
| **Leader 不可达期间无法新握手** | 1~2s 窗口内新客户端连不上 | 既有 session 转发不受影响；客户端重试；P1 专项测试 |
| keepalive 高频写 Raft | 逐条提交会压垮集群 | 每次都写，但走批处理（§2.6）：64 条或 500ms 打包成一条日志，N 次共识压成 1 次 |
| 数据面若走 Raft | 吞吐崩塌 | 明确分层：Raft 只承载控制状态（§10） |
| 跳跃被误判为掉线 | 活跃客户端被踢 | 判定前校验 `LastOperator` 是否仍是自己（§8.3），已迁移则放弃判定 |
| lock 文件与 Raft 不一致 | 运维误读 | 权威副本在 Raft，磁盘文件仅为镜像；重启从快照恢复而非读文件（§4.5） |
| 加密与标签增加每包开销 | 有效 MTU 下降 36 字节 | SessionTag 6B + DstTag 6B + Counter 8B + tag 16B；`DEFAULT_MTU` 1400→1364（§7.6） |
| 全区间监听占用 fd | 区间过大时耗尽 | 区间上限硬编码 64 |
| `AuthContext` 破坏既有接口 | 三个 authenticator 需改签名 | 改动机械，noauth 路径有测试覆盖 |
| 引入 hashicorp/raft 依赖 | 依赖体积增加 | 成熟度换正确性，已确认接受 |

---

## 13. 待定问题（请评审确认）

1. **批处理窗口 500ms / 64 条是否合适？** 影响的是"客户端掉线后多久被集群感知"，与 60s 的掉线判定相比可忽略，但若你要更实时可调小。
2. **rekey 周期 120s 是否合适？** 沿用 WireGuard 默认值。周期越短前向保密粒度越细，但握手开销越高（每次 rekey 是一次 Noise 往返，不走 Raft、不重分配 IP）。

### 已确认的决策（本轮）

- ✅ 集群规模任意，不强制奇数；保留 Raft 标准选举与多数派，**不**改为时间戳定序（§2.5）
- ✅ keepalive 每次都写 Raft，靠批处理聚合（§2.6）
- ✅ `--network` 降级为 bootstrap 种子，改为一 vnet 一文件（§4.4）
- ✅ 默认密钥固定 IP + lock 文件 + Raft 同步 + gasoctl 可解除（§4.5）
- ✅ 掉线自动检测由接入 operator 判定后经 Raft 广播（§8.3）

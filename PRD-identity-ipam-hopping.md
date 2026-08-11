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

**其三，会话被绑死在连接层。** 这是最根本的一条。listener 绑定单一 `addr` 后终身不变（`udp/listener.go:48`、`quic/listener.go:20`）；更要害的是 `virtualPeer` 以 `netip.AddrPort` 为键（`udp/listener.go:86`），**等于用四元组定义"你是谁"**——源地址一变即被当作新 peer 重新握手。

正确的抽象是：**会话应由报文自身保证，而非由连接层保证**。每个包自带会话标识与认证信息，则任何 operator、任何端口、任何来源地址收到它都能独立处理。当前设计与此背道而驰，因而同时挡死了端口跳跃、多 IP 跳跃，还顺带使 NAT 重绑定必然断线。详见 §5.4。

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
| G3 | 端口跳跃 | Hysteria2 | 服务端监听端口区间，客户端按共享密钥推导的时间序列跳跃；**UDP 与 QUIC 均支持**，对上层数据面透明 |
| G4 | 多 IP 跳跃 | — | 握手绑定单一 host:port；握手成功后可在**任意 server IP 的任意端口区间**发送；**UDP 与 QUIC 行为完全一致，均零额外跳数** |
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

    // 数据面传输密钥：Noise 握手派生后随 SessionCreate 写入 Raft（§7.2）。
    // 任意 operator 凭它加解密该会话的帧——这是多 server 跳跃的前提（逐跳模型，§5.4.1）
    C2SKey [32]byte         // 客户端→operator 方向
    S2CKey [32]byte         // operator→客户端 方向

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
  ↓  ← 至此双方已各自派生 send_key / recv_key
ClientAnswer(空载荷)
  ↓  ← 服务端在此处做唯一一次 Raft 写入：
     Apply(SessionCreate{
        pubkey, cid, vni,
        ip:        <本地预选，见下>,
        sessionID: <本地生成>,
        hopSecret,
        c2sKey, s2cKey,      // Noise 派生的传输密钥，进 Raft（§7.2）
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
- **需要完善测试**（你的明确要求），见 §12 的 P1 验收项：包含 leader 主动下线、网络分区、少数派隔离三类场景。

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

**不批处理**（要求立即生效、且低频）：`SessionCreate`（握手，客户端在等）、`SessionRekey`（提交前其他 PE 无法解密新密钥帧，§7.4）、`KeyGrant`/`KeyRevoke`、`VNetUpsert`、gasoctl 的踢人操作。

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

### 5.4 核心原则：会话由报文保证，不由连接层保证

**这一节是全篇的地基，前两版 PRD 在此处的设计是错的，现予推翻并说明原因。**

#### 5.4.1 两条正交的原则

**订正（第三轮）**：本节前一版把两件正交的事糊成了一件，并错误地拔高成 zerotrust。现拆开：

**原则一：会话 ≠ 连接。** 会话是逻辑概念（一个 CE 的身份 + 租约 + 密钥），不绑定任何一条具体的传输连接。一个 CE 在其会话生命周期内可以换端口、换 server、换 QUIC 连接，会话不变。这一条**正确，保留**——它是端口跳跃 / 多 IP 跳跃的地基。

**原则二：加密是逐跳的（WireGuard 模型），PE 解密。** 用 PE/CE 术语（同 MPLS-VPN）：

- **CE = client，PE = operator。**
- 加密隧道只建立在 **CE↔PE**（一对 Noise 密钥）——**不是** CE↔CE 端到端穿透 PE。**PE↔PE underlay 不加密**：operator 间链路默认可信（内网/专线），本次不做（§7.5）。
- **PE 是隧道端点，它解密**：收到 CE 的帧 → 解密得到明文 IP 包 → 按明文 dst IP 查 `routingMap`（Raft 全局表：IP → CE → 当前接入 PE）→ 命中本地 CE 直接发，命中远端 PE 就封 `MessageTransport` 转发过去 → 目标 PE 重新加密发给目标 CE。

这与 WireGuard 的接收路径完全一致（解密 → 按 AllowedIPs 路由 → 写 TUN），也与现有 `forwardFrame` 的 `RouteTargetClient` / `RouteTargetOperator` 两分支完全吻合。

**为什么不做 zerotrust（PE 不解密）**：

1. **路由不需要它**。PE 解密后就能看到明文 dst IP，`routingMap` 用 IP 做键即可定位目标 CE 挂在哪个 PE——不需要 `DstTag` 这类明文路由标签。IP 本身就是路由键。（`SessionTag` 保留，但职责不同：它只用于**解密前定位会话密钥**，不参与路由，见 §6.4。）
2. **握手 RTT 会飞起来**。zerotrust 要 CE↔CE 端到端加密，CE-A 发给 CE-B 前得先跨 PE 做一次 CE↔CE 密钥协商（拿对端公钥、跑 Noise），这是**额外的跨 PE 往返**。逐跳模型里每个 CE 只跟自己的 PE 握一次手，PE 间走已建好的 underlay，**零额外 RTT**。
3. **管理困难**。PE 看不到内容就无法做集中的路由 / 策略 / 观测。

**因此：`DstTag` / 明文标签路由 / "PE 不解密" 全部作废。** 数据面加密（§7）是逐跳 AEAD，PE 解密后按 IP 路由；`SessionTag` 仅作解密密钥索引保留。

#### 5.4.2 前两版错在哪里

上一版设计把 QUIC 的 **Connection ID（DCID）当作会话标识**，于是推导出一堆特例：

- 因为 DCID 绑定某个 `quic.Transport` 实例 → 需要"DCID 路由层"分发；
- 因为 TLS 状态在原机器上 → 需要 `ownerTag` 内嵌 DCID + **跨机转发 +1 跳**；
- 因为 owner 崩溃则连接失效 → 需要"非对称、可用但不对等"的免责声明。

**这一整条推理链的前提就是错的。** 它在努力保护一个本不该存在的绑定：QUIC 连接与会话身份的绑定。一旦解除这个绑定，上述三个问题**全部自动消失**——不是被解决，是根本不产生。

#### 5.4.3 跳跃的正确实现：跳跃后由新接入 PE 更新 Raft 路由表

会话跟着 CE 走，靠的**不是**明文标签让 PE 无脑转发，而是：**CE 跳到新 PE 后，新 PE 把"这个 CE 的 IP 现在挂我这"提交进 Raft 路由表,全集群立即知道。**

```
CE-B 原挂 PE-C     routingMap: 10.0.0.5 → CE-B @ PE-C
   ↓ CE-B 跳到 PE-D
PE-D 收到 CE-B 帧 → 解密 → 提交 Raft SessionMigrate: 10.0.0.5 → CE-B @ PE-D
   ↓ Raft 全集群同步
此后任一 PE 查 routingMap[10.0.0.5] 都指向 PE-D → 转发正确
```

- **IP 始终是路由键**，变的只是"该 IP 对应的 CE 当前接入哪个 PE"（`sessionEntry.LastOperator`）。
- 跳跃 = 提交一条 `SessionMigrate`（§2.6 批处理：不必每包提交，接入点**变化**时提交一次）。
- `LastOperator` 因此**不是纯观测字段,而是路由决策的一部分**：`routingMap` 的 `RouteTargetOperator` 分支指向 `LastOperator`（订正前一版把它标为"纯观测"的说法）。
- QUIC 侧：跳到新 `(IP,端口)` 就地建/复用一条 QUIC 连接把帧发出去，PE-D 解密后照上面流程更新路由。QUIC 连接是可丢弃的字节管道，不做连接迁移。握手开销由客户端对每个 server 预热一条连接消化。

#### 5.4.4 由此得到的对称性

| | UDP | QUIC |
|---|---|---|
| 会话标识 | overlay IP（路由键） | overlay IP（路由键）**完全相同** |
| 跳端口 | 换目的端口发包 | 切到该端口的连接 |
| 跳 IP | 换目的 IP 发包 | 切到该 IP 的连接 |
| 跳跃后定位 | 新 PE 提交 `SessionMigrate` 更新 Raft 路由 | **完全相同** |
| operator 崩溃 | 会话不受影响（CE 重连别的 PE，新 PE 更新路由） | **完全相同** |
| 序列推导 | §5.1 算法 | §5.1 算法，**同一份代码** |

**两种传输在会话语义上完全对等。** 差异只剩传输本身的固有属性：QUIC 提供可靠有序与拥塞控制（每条连接有建立开销），UDP 无连接开销但需自行处理丢包。

#### 5.4.5 代价与取舍

- **QUIC 侧代价**：客户端需为每个 server 维持一条预热连接（N 个 server = N 条，通常 ≤ 5，可接受）。服务端仍是 N 个端口 = N 个 `quic.Transport`，但**它们之间无需协调**——因为不再有跨 Transport 的连接归并需求，每个 Transport 独立接受连接、独立交出帧即可。
- **双层 AEAD**：QUIC 传输上，帧先被 Noise AEAD 加密（§7），再被 QUIC 的 TLS 加密一次。CPU 约 +3~5%。这是分层的必然结果：QUIC 的 TLS 绑定在单条连接上、随连接销毁；Noise 密钥属于会话，跳到任意 PE 依然有效（§7.5）。
- **不做 QUIC 连接迁移**：明确放弃使用 QUIC 原生迁移能力。它解决的是"保住同一条连接"，而我们的设计根本不需要保住连接。

---

## 6. G4：多 server 跳跃

### 6.1 G0 让这件事简单：PE 解密后按 IP 路由 + 跳跃更新 Raft

WireGuard 逐跳模型（§5.4.1 原则二）下，多 server 跳跃是这样的：

1. CE 跳到某个 PE，把帧发过去。
2. 该 PE **解密**得到明文 IP 包，按明文 dst IP 查本地 `routingMap`（Raft 全局表）：
   - 目标 CE 挂在**本 PE** → 直接重新加密发给它；
   - 目标 CE 挂在**远端 PE** → 封 `MessageTransport` 走 underlay 转发过去，目标 PE 再加密发给目标 CE。
3. 若这次跳跃改变了**源 CE** 的接入点，收包 PE 提交一条 `SessionMigrate` 更新 `routingMap[srcIP] → 源CE @ 本PE`（§5.4.3），全集群同步。

**不需要转发到宿主、不需要 SessionBind 广播、不存在"宿主故障"** —— 任一 PE 都能独立解密并路由，跳跃只是让路由表指向新接入点。这正是强一致 + 逐跳解密的核心收益。

（前一版 §6.1bis 设计的 `DstTag`/"PE 不解密" zerotrust 机制**已作废**，见 §5.4.1 订正；`SessionTag` 保留为解密密钥索引。）

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

### 6.2bis 两种传输的一致行为

**上一版此处设计了 QUIC 专用的 ownerTag 路由与跨机转发机制，现已全部删除。** 依据 §5.4 的原则——会话由报文保证，不由连接层保证——QUIC 与 UDP 在跳 IP 这件事上行为完全一致：

- 客户端跳到新的 server IP 时，UDP 直接换目的地址发包；QUIC 切到该 IP 的预热连接发包。
- 服务端任意 operator 收到帧后，剥掉传输层，按 `SessionTag` 查本地 Raft 副本取会话密钥 → 解密 → 按 dst IP 路由（§6.1）。
- **两者都是零额外跳数，都不存在 owner 概念，都不受任何单台 operator 故障影响。**

唯一残留的差异是传输本身的固有属性（QUIC 有连接建立开销、提供可靠有序），与会话语义无关。

### 6.3 接入点位置追踪

你要求记录"哪个密钥在哪个接入点最近接入"。实现为 `sessionEntry.LastOperator` + `LastSeen`：

- 客户端跳到新 operator 时，该 operator 更新本地 `LastSeen`；
- **不是每包都写 Raft**（会压垮集群），走 §2.6 批处理提交 `SessionMigrate`；
- gasoctl `session list` 可查每个密钥当前的接入点，满足运维观测需求。

**注意其性质**：`LastOperator` 是**路由决策的一部分**（§5.4.3）——它定义 session 的当前接入点，`routingMap` 的 `RouteTargetOperator` 分支据此把发往该 CE 的包转到正确的 PE。它同时服务于 §9.3 的掉线误判防护（判定前确认"客户端是不是跳去别处了"）。它经 `SessionMigrate` 随跳跃更新，因此不会把会话绑死在某台机器上——绑定的是"当前位置"，不是"归属"。

### 6.4 数据面来包校验

任意 operator 都可能收到任意会话的帧，因此必须能定位会话密钥并拒绝伪造包。

**加入 G5 后，这里被简化了**：不再需要独立的转发准入 MAC。

```
frame = SessionTag(6) || Counter(8) || AEAD密文   ← 见 §7.3
```

- operator 用 `SessionTag`（6 字节）查本地 Raft 副本取出该会话的传输密钥（§7.2）→ 解密；
- 包的真伪由 **Poly1305 tag** 保证：伪造者无密钥，解密必失败即丢弃，比原先 4 字节截断 MAC 强得多；
- 解密得到明文 IP 包后按 dst IP 查 `routingMap` 路由（§6.1）——**不需要 DstTag，IP 本身就是路由键**。

**SessionTag 取 6 字节**（SessionID 前 6 字节，48 bit）：按生日界，百万级并发会话下碰撞概率约 10⁻³，且碰撞只导致一次查表失败后丢包（AEAD 校验必然失败），不构成安全问题。你要求尽可能短，6 字节是可用性与开销的平衡点。

### 6.5 落点

- `transport/udp/listener.go`：多端口监听 + SessionTag 索引。
- `transport/udp/dialer.go`：跳跃 ticker（IP + 端口双维度）。
- `transport/quic/listener.go`：N 个端口各起一个 `quic.Transport`，彼此独立、无需协调；收到帧后直接交给上层，不做连接归并。
- `transport/quic/dialer.go`：为每个 server 维持一条预热 QUIC 连接；跳跃时切换连接而非迁移连接。
- **跳跃逻辑（序列推导、切换时机）在 UDP 与 QUIC 间共用同一份代码**，仅"如何把帧送出去"不同。
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

密钥**随 `SessionCreate` 写入 Raft**（§2.3、`sessionEntry.C2SKey/S2CKey`）。逐跳模型下这是必需的：客户端跳到任意 PE，该 PE 都必须能立即解密其帧——若密钥只在原握手 PE 手里，跳跃就得重新握手，G4 的"零额外开销"不成立。

**代价（明确接受）**：

- 任一 operator 被攻破即可解密全部会话流量——这是逐跳模型的固有信任假设（同 MPLS-VPN 对 PE 的信任），不是缺陷；
- Raft 日志与快照含密钥材料：Raft 传输本身走 QUIC TLS 加密，快照落盘权限 0600；
- 前向保密以 rekey 为粒度（§7.4）：rekey 用新的 ephemeral 密钥对派生新密钥并覆盖 Raft 中旧值，旧密钥随日志压缩消失。

### 7.3 数据面帧格式

```
frame = SessionTag(6) || Counter(8)
        || ChaCha20-Poly1305(send_key, Counter, ip_pkt)
           └── 密文 = 明文长度 + 16 字节 Poly1305 tag
```

`SessionTag` 明文（operator 靠它查会话密钥，见 §6.4）；`Counter` 明文（AEAD nonce 本就无需保密）。**没有 DstTag**——PE 解密后按明文 dst IP 路由（§5.4.1）。

- `Counter`：单调递增的 nonce，每包 +1。ChaCha20-Poly1305 的 96-bit nonce 由 `Counter` 零扩展而来（同 WireGuard）。
- **同一密钥下 Counter 绝不重复**——这是 AEAD 安全性的绝对前提，达到上限必须 rekey。
- 独立的转发准入 MAC **被 AEAD tag 取代**：任意 operator 都持有传输密钥（Raft 同步，§7.2），直接解密验证 Poly1305 tag 即完成准入。**省下 4 字节，且安全性更强**。

### 7.4 重放窗口与 rekey

- **重放窗口**：滑动 bitmap，窗口大小 2048（同 WireGuard）。收到的 Counter 若落在窗口外（过旧）或已被标记，丢弃。
- **rekey 触发**（任一满足）：
  - 距上次握手 ≥ 120s（`REKEY_AFTER_TIME`）
  - 发送包数 ≥ 2^60（`REKEY_AFTER_MESSAGES`）
  - 收到对端 rekey 请求
- rekey 即重跑一次 Noise_IK 握手，**但不重新分配 IP / SessionID**——租约与会话延续，只换传输密钥。这一点必须在实现时明确，否则每 2 分钟客户端就换一次 IP。
- 新密钥经一条 `SessionRekey` Raft 日志覆盖旧值——**不批处理，立即提交**：提交生效前其他 PE 仍持旧密钥，会把新密钥加密的帧当伪造包丢弃，所以客户端应在收到 rekey 完成确认后再切换新密钥发包（旧密钥保留一个短暂的重叠期用于收包）。

### 7.5 与 QUIC / UDP 两种传输的关系

这是本项**最需要想清楚的部分**（你的明确要求）。两种传输的安全属性本就不同：

| | UDP 传输 | QUIC 传输 |
|---|---|---|
| 现状 | 完全明文 | 已有 TLS 1.3 加密（`transport/quic/tls.go`） |
| 加 G5 后 | Noise AEAD 加密 | Noise AEAD **再套一层** TLS |

**决策：两种传输都启用 G5，不做例外。G5 是逐跳加密（CE↔PE 段）；PE↔PE underlay 不加密，链路默认可信（内网/专线）。** 理由：

1. **会话密钥 vs 连接密钥**：QUIC 的 TLS 密钥绑定在单条连接上，连接销毁即失效；G4 多 server 跳跃下客户端不断切换 PE 和连接。G5 的密钥属于**会话**（存 Raft，跨 operator、跨连接不变），跳到任意 PE 都直接可用，**这是 TLS 给不了的**。
2. **一致的安全模型**：若 UDP 加密而 QUIC 不加密，则"用哪个传输"变成安全等级的隐式开关，是设计缺陷。
3. **代价可接受**：QUIC 上多一层 AEAD，CPU 开销约 +3~5%（ChaCha20 在无 AES-NI 的平台上尤其快）。

**PE↔PE 不加密的边界要说清楚**：operator 间转发（`peer_operator.go` UDP underlay）传的是**解密后的明文 IP 包**。这建立在"operator 间链路可信"的运维前提上；若未来要跑公网 underlay，需另起一项给 PE↔PE 加 WireGuard 级隧道，不影响本次设计。

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
+ Counter(8)                                     8
+ Poly1305 tag                                  16
────────────────────────────────────────────────
每包净增                                        30 字节
```

`DEFAULT_MTU` 需由 1400 下调至 **1370**（`tun.go:14`）。若同时跑在已有隧道内需再留余量。

### 7.7 落点

- 新增 `protocol/noise/`（见 §3.3）。
- `consensus/commands.go` 增 `SessionRekey` 日志类型（覆盖 `sessionEntry` 的传输密钥）。
- `transport/udp/conn.go`、`transport/quic/conn.go`：收发路径加解密；UDP 侧额外挂重放窗口。
- `protocol/message/`：帧格式增加加密封装层。
- `go.mod`：`golang.org/x/crypto` 提升为直接依赖。

---

## 8. 会话唯一性与下线

### 8.0 同一密钥同一时刻只允许一个接入点

**约束**：一个密钥在任一时刻只能有一个活跃会话。出现第二个握手请求时，视为**潜在冲突**，须先判定原会话是否还活着。

#### 8.0.1 必须先区分"跳跃"与"新握手"

这一点是前提，搞混会直接摧毁 G3/G4：

| 情形 | 表现 | 处理 |
|---|---|---|
| **跳跃**（合法，常态） | 已有会话的**数据帧**从新地址/新 operator 到来，携带有效 `SessionTag` + AEAD tag | 直接处理，更新 `LastOperator`。**绝不触发任何冲突判定** |
| **新握手**（可能冲突） | 收到 `ClientHello`，其公钥在 FSM 中**已存在活跃会话** | 进入下面的冲突裁决流程 |

跳跃走的是数据面（已有密钥、已有会话），新握手走的是控制面（Noise msg1）。**两者在协议上截然可分**，不存在误判风险——这也是 §5.4"会话由报文保证"带来的好处：合法跳跃根本不需要重新握手，因此任何握手请求都是真正的新会话意图。

#### 8.0.2 裁决：按新接入点是否等于上次失连点分流

收到与既有会话冲突的握手请求时，比较**发起握手的 operator** 与 `sessionEntry.LastOperator`：

**情形 A — 同一接入点（`新 operator == LastOperator`）**

> 语义：同一个点位重连。上一条连接就在我这儿，我最清楚它的状态。

- **不做活性探测**（探测自己已知的东西是浪费一个 RTT）。
- 直接关闭本地那条旧 `transport.Conn`，提交 `SessionReplace`，接受新握手。
- 典型场景：客户端进程重启、网络抖动后重连、NAT 重绑定后重新握手。
- **固定 IP 绑定保留**，新会话拿回同一 IP（§4.5）。

**情形 B — 异地接入（`新 operator != LastOperator`）**

> 语义：可能是真的换了地方，也可能是密钥被盗用、两个客户端同时在跑。

- **必须先探测原接入点的活性**，活性确认死亡后才允许接入：

```
operator B 收到冲突握手（LastOperator = A）
  ↓
B 向 A 发起活性探测（走 operator↔operator underlay，非 Raft——要快）
  ↓
A 检查该会话最后一次收到帧的时间 + 主动下发一个探测帧等回应
  ↓
┌─ A 回复"活着"  → B 拒绝握手，返回 HandshakeConflict（新增错误码）
├─ A 回复"已死"  → B 接受握手，提交 SessionReplace
└─ A 超时未回复（--probe-timeout 默认 2s）
       ↓
   查 Raft 成员列表：A 是否还在集群？
     ├─ 不在（A 已崩溃/离群） → 接受握手
     └─ 还在但不应答        → 拒绝，让客户端重试（避免脑裂期误判）
```

- 探测**不走 Raft**：它是一次点对点问询，要求低延迟；Raft 只用于最终的 `SessionReplace` 提交（需要全集群一致）。
- 新增握手错误码 `HandshakeConflict`，客户端收到后应**停止重试并明确报错**（"该密钥已在别处使用"），而不是无限重连——否则两个客户端会互相踢来踢去。

**"活性"的判据**（A 侧如何回答）：不能只看 `LastSeen`——那只能证明"曾经活着"。A 必须**主动验证**：

1. 若 `now - LastSeen > session-timeout`（60s）→ 直接回"已死"，无需发包；
2. 否则向该会话下发一个 `DataCtrlPing`（**已实现，`message-datactrl.go:51`**）并等待 `DataCtrlPong`，超时 `--probe-timeout`（默认 2s）；
3. 收到 Pong → 回"活着"；超时 → 回"已死"，并顺手提交 `SessionDrop{reason: timeout}`。

这样探测同时起到了**加速掉线检测**的作用：原本要等 60s 才发现的死会话，被一次冲突握手立刻确认。

#### 8.0.3 为什么必须这样分流

若情形 A 也走探测，则每次进程重启都要等一个探测 RTT，且探测对象是自己——纯浪费。若情形 B 不探测就放行，则密钥被盗用时攻击者可以随时把合法用户挤下线（**会话劫持**）。分流让常见路径快、危险路径严。

#### 8.0.4 落点

- FSM 增 `Sessions` 的公钥反查索引：`PubKey → SessionID`（O(1) 判断"该密钥是否已有活跃会话"）。
- 新增 `control` 层的点对点探测消息（不入 Raft）：`ProbeLiveness{SessionID}` / `ProbeReply{alive bool}`。
- 新增 Raft 日志类型 `SessionReplace`（原子完成"删旧会话 + 建新会话"，保留固定 IP 绑定）。
- 新增 `HandshakeConflict` 错误码（`protocol/handshake/types.go`，当前有 5 个码，加第 6 个）。
- 客户端：收到 `HandshakeConflict` 时终止重试并报错。

---

## 9. 下线与踢人

四条路径，全部经 Raft 全集群生效——这是必须的：多 server 跳跃下客户端可能在任意 operator 上，只在本地踢等于没踢。

### 9.1 手动踢断，允许重连（`gasoctl session kick <vni> <cid>`）

- 提交 `SessionDrop{reason: kicked}` → 全集群移除 session，IP 回池（若非固定绑定）。
- 当前接入的 operator 向客户端下发 `DataCtrlShutdown{reason: ShutdownGoingAway}`（**该消息已实现编解码，`message-datactrl.go:57`，目前无人发送**）。
- 客户端收到后关闭连接；因密钥仍有效，可立即重新握手。**固定 IP 绑定保留，重连拿回同一 IP。**
- 用途：强制刷新会话状态、迁移接入点。

### 9.2 删除密钥强制踢（`gasoctl key revoke <vni> <pubkey>`）

- 提交 `KeyRevoke` → 从密钥表移除 → **级联** `SessionDrop{reason: revoked}` 移除该密钥的所有 session。
- 同时清除固定 IP 绑定（lock 文件同步更新），IP 回池。
- 下发 `DataCtrlShutdown{reason: ShutdownPolicy}`。
- 客户端重连时在 §3.2 验证第 2 步（`pubkey ∈ 密钥表`）失败 → `HandshakeAuthFail`。**永久踢出。**

### 9.3 自动掉线检测

- 判定方：**当前服务该 session 的 operator**（`sessionEntry.LastOperator`）。
- 判据：`--session-timeout` 秒内（默认 60s，即 4~6 个 keepalive 周期）未收到该 session 的任何帧。
- 动作：提交 `SessionDrop{reason: timeout}`，走**批处理**（§2.6）——掉线不是紧急事件，批量提交即可。
- 全集群移除 session、IP 回池（固定绑定保留）。

**误判防护**：多 server 跳跃下，客户端可能已跳到别的 operator。因此判定前必须先检查本地 FSM 的 `LastOperator` 是否仍是自己——若已被别的 operator 更新（对方收到帧时提交了 `SessionMigrate`），则放弃判定。这条检查不能省，否则跳跃会被误判为掉线。

### 9.4 operator 自身下线

- 优雅退出：提交 `SessionDrop` 批量清理自己持有的 session，然后离开 Raft 集群。
- 崩溃：其持有的 session 由其余节点在 `--session-timeout` 后按 §9.3 清理（任一 operator 发现 `LastOperator` 指向的节点已不在 Raft 集群成员列表中，即可代为判定）。
- **客户端侧无感**：因为全部 session 状态在 Raft 中，客户端跳到任何存活 operator 都能继续通信——这正是 G0+G4 的收益。

### 9.5 gasoctl 命令汇总

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

## 10. 传输层兼容矩阵（QUIC / UDP）

本次全部特性都必须在两种传输上有明确行为，不允许"某个传输上悄悄不生效"。

| 特性 | UDP | QUIC | 说明 |
|---|---|---|---|
| G0 共识 | — | — | operator 之间的事，与客户端传输无关；Raft 自身固定用 QUIC |
| G1 Noise 身份 | ✅ | ✅ | 握手在 `transport.Conn` 之上，与传输无关 |
| G2 动态 IP | ✅ | ✅ | 同上 |
| G3 端口跳跃 | ✅ 查 SessionTag | ✅ 查 SessionTag | **完全一致**，同一份代码 |
| G4 多 IP 跳跃 | ✅ 任意 operator 本地处理 | ✅ 任意 operator 本地处理 | **完全一致**，均零额外跳数 |
| G5 加密 | ✅ 含重放窗口 | ✅ 无重放窗口 | QUIC 已保序去重，仅需 AEAD |

**设计原则**：**会话由报文保证，不由连接层保证**（§5.4）。因此两种传输在会话语义上完全对等，没有任何特例——UDP 具备的一切特性 QUIC 同样具备，且共用同一份跳跃代码。

差异仅剩传输本身的固有属性，与会话无关：

| | UDP | QUIC |
|---|---|---|
| 连接建立开销 | 无 | 有（TLS 握手，由预热连接消化） |
| 丢包处理 | 交给上层 TCP | QUIC 自身重传 |
| 加密层数 | 一层（Noise） | 两层（Noise + QUIC TLS），CPU +3~5% |

**选型建议**：要极致轻量与抗封锁用 UDP；要可靠有序与拥塞控制用 QUIC。**两者的抗封锁能力（跳 IP、跳端口）相同。**

**"谁都可以接入"的正确含义**（贯穿两种传输）：**传输层完全放开**（任意 IP、任意端口都收包，不校验来源四元组），**密码学层绝不放开**（UDP 侧靠 Noise AEAD，QUIC 侧靠 TLS 1.3 AEAD，伪造者无密钥则解密失败即丢弃）。正因为有 AEAD 兜底，传输层才敢放开——认证职责放在它该在的层，而不是靠"记住对方的 IP 和端口"。

---

## 11. 架构总览

```
                    ┌──────── Raft (over QUIC) ────────┐
                    │  强一致复制：                     │
   operator A ◄─────┤   vnet / segment / pool          ├─────► operator C
       ▲            │   密钥授权表                      │            ▲
       │            │   session (IP / 传输密钥 / hop)   │            │
       │            │   接入点位置                      │            │
       │            └──────────────┬───────────────────┘            │
       │                     operator B                             │
       │                                                            │
       │  ┌─────────────── 数据面：不走 Raft ──────────────┐        │
       └──┤  client 帧 (SessionTag+AEAD) 可发往任意 operator├────────┘
          │  operator 间明文 IP 包仍走 PeerOperator UDP 直连 │
          └────────────────────────────────────────────────┘
```

**关键分层：控制状态走 Raft（强一致，低频），数据帧走 UDP 直连（高吞吐，不阻塞）。**

---

## 12. 交付顺序

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
| P3 | G1 Noise_IK + X25519 + CID 推导 + 密钥表进 Raft | 冒用 CID 必失败；未授权公钥必失败；错误码一致；重放的 msg1 被时间戳拒绝 |
| P4 | G2 vnet/网段/池 + 一次握手内分配 | `Pool ⊆ CIDR` 校验生效；并发 100 握手无重复 IP；**跨 operator 重连拿回同一 IP**；池满返回 NoRoute |
| P5 | G3 SessionID 会话标识（不含跳跃） | 客户端源端口人为变更后会话不中断（同时验证 NAT 重绑定修复） |
| P6 | G3 端口跳跃（UDP + QUIC，单 IP） | 两种传输均：端口按 interval 轮换、跨跳跃点 TCP 长连接不断、时钟偏移 ±1 片仍可连 |
| P7 | G4 多 IP 跳跃 + 配置文件 | 握手于 A，改向 B/C 发包会话不中断（两种传输均本地处理，零额外跳）；伪造包被 AEAD 丢弃；**杀掉握手所在的 operator，会话仍可继续** |
| P8 | 会话唯一性（§8）+ 下线与踢人（§9） | 四条踢人路径各自生效且全集群同步：kick 后可重连且保住固定 IP；revoke 后重连必失败；60s 无帧自动下线；**跳跃不被误判为掉线**。唯一性：同点位重连直接替换旧 conn 且不探测；异地接入在原会话活着时返回 HandshakeConflict、原会话已死时放行；杀掉原 operator 后异地接入立即成功 |
| P9 | G5 数据面加密 | 抓包确认 payload 不可读；篡改一字节必被 AEAD 拒绝；重放旧包被窗口丢弃；rekey 后会话与 IP 不变；**UDP 与 QUIC 两条路径都验证** |

P1 单独成阶段，因为共识层的正确性无法靠"跑通一次"证明——必须主动注入故障。P8 置于最后，因为它依赖 G4 才能验证"跳跃 vs 掉线"的区分。

---

## 13. 风险

| 风险 | 影响 | 应对 |
|---|---|---|
| **握手引入 Raft 写入延迟** | 跨地域握手 +1 RTT | 已确认接受；乐观预选 IP 避免二次往返 |
| **Leader 不可达期间无法新握手** | 1~2s 窗口内新客户端连不上 | 既有 session 转发不受影响；客户端重试；P1 专项测试 |
| keepalive 高频写 Raft | 逐条提交会压垮集群 | 每次都写，但走批处理（§2.6）：64 条或 500ms 打包成一条日志，N 次共识压成 1 次 |
| 数据面若走 Raft | 吞吐崩塌 | 明确分层：Raft 只承载控制状态（§11） |
| 跳跃被误判为掉线 | 活跃客户端被踢 | 判定前校验 `LastOperator` 是否仍是自己（§9.3），已迁移则放弃判定 |
| 跳跃被误判为冲突接入 | 合法跳跃被拒 | 跳跃走数据面（有 SessionTag+AEAD），冲突判定只针对控制面握手，协议上截然可分（§8.0.1） |
| 异地接入探测引入握手延迟 | 冲突场景下 +1 RTT（≤2s） | 仅在"该密钥已有活跃会话"时触发，正常首次握手零开销；同点位重连不探测 |
| 密钥被盗用后劫持会话 | 合法用户被挤下线 | 异地接入必须先确认原会话死亡；活着则拒绝（§8.0.2 情形 B） |
| lock 文件与 Raft 不一致 | 运维误读 | 权威副本在 Raft，磁盘文件仅为镜像；重启从快照恢复而非读文件（§4.5） |
| 加密与标签增加每包开销 | 有效 MTU 下降 30 字节 | SessionTag 6B + Counter 8B + tag 16B；`DEFAULT_MTU` 1400→1370（§7.6） |
| 传输密钥进 Raft | 任一 operator 沦陷可解密全部流量 | 逐跳模型的固有信任假设（§7.2）；rekey 限损；Raft 传输 QUIC TLS、快照 0600 |
| PE↔PE underlay 明文 | operator 间链路被窃听则泄露明文 IP 包 | 运维前提：operator 间走内网/专线；公网 underlay 属未来工作（§7.5） |
| 全区间监听占用 fd | 区间过大时耗尽 | 区间上限硬编码 64 |
| QUIC 需 N 个 Transport 实例 | 内存开销高于 UDP | 各 Transport 完全独立、无需协调；同受 64 上限约束 |
| QUIC 预热连接占用资源 | 每个 server 一条常驻连接 | server 数通常 ≤ 5；连接空闲成本低（keepalive 已有） |
| QUIC 双层 AEAD | CPU +3~5% | 分层的必然代价；ChaCha20 在无 AES-NI 平台上很快 |
| `AuthContext` 破坏既有接口 | 三个 authenticator 需改签名 | 改动机械，noauth 路径有测试覆盖 |
| 引入 hashicorp/raft 依赖 | 依赖体积增加 | 成熟度换正确性，已确认接受 |

---

## 14. 待定问题（请评审确认）

1. **批处理窗口 500ms / 64 条是否合适？** 影响的是"客户端掉线后多久被集群感知"，与 60s 的掉线判定相比可忽略，但若你要更实时可调小。
2. **rekey 周期 120s 是否合适？** 沿用 WireGuard 默认值。周期越短前向保密粒度越细，但握手开销越高（每次 rekey 是一次 Noise 往返，不走 Raft、不重分配 IP）。

### 已确认的决策（本轮）

- ✅ 集群规模任意，不强制奇数；保留 Raft 标准选举与多数派，**不**改为时间戳定序（§2.5）
- ✅ keepalive 每次都写 Raft，靠批处理聚合（§2.6）
- ✅ `--network` 降级为 bootstrap 种子，改为一 vnet 一文件（§4.4）
- ✅ 默认密钥固定 IP + lock 文件 + Raft 同步 + gasoctl 可解除（§4.5）
- ✅ 掉线自动检测由接入 operator 判定后经 Raft 广播（§9.3）

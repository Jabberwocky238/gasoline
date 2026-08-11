# PRD：身份绑定密钥 / 动态 IP 下发 / 端口跳跃 / 多 server 跳跃

分支：`pure-mesh`　状态：待评审　目标版本：握手协议 v2 + operator 共识层 v1

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

### 非目标（本次明确不做）

- **不做数据面加密。** G1 只解决"你是谁"，不解决"链路上谁能看见"。`ARCHETECT.md` 里的零信任端到端加密是独立的后续工作。本 PRD 交付后 payload 仍是明文——QUIC 传输自带 TLS，UDP 传输不带。**验收时须明示，避免误以为已经加密。**
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
    SessionKey  [32]byte        // 数据面转发准入 MAC 用
    HopSecret   [32]byte        // 端口跳跃推导用

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
ClientHello
  ↓
ServerHello(nonce)
  ↓
ClientAnswer(sig)
  ↓  ← 服务端在此处做唯一一次 Raft 写入：
     Apply(SessionCreate{
        pubkey, cid, vni,
        ip:        <本地预选，见下>,
        sessionID: <本地生成>,
        sessionKey, hopSecret,
        operator:  self.UUID,
     })
     等待多数派提交 → 提交成功即分配生效
  ↓
ServerAssign(ip, sessionID, hopSecret, serverList)
```

握手报文数**不变**（仍是 4 条），额外成本是 `ClientAnswer` 到 `ServerAssign` 之间的一次 Raft 提交（本地 leader 约 1ms；跨地域跟随者转发至 leader 约 1 RTT）。这是强一致的固有代价，你已确认接受。

**IP 预选**：接入的 operator 从 FSM 的当前快照里挑一个空闲地址填进日志条目。若在提交前被别人抢占，leader 侧 `Apply` 时检测冲突并拒绝，接入方**重选后重试**（最多 3 次，仍失败则 `HandshakeNoRoute`）。这是乐观并发，比"先申请再确认"少一个往返。

### 2.4 Leader 不可达

选举是 operator 集群内部的事，客户端无感：

- Raft 默认选举超时 1~2s，期间**新握手阻塞**（返回超时，客户端重试即可），**既有 session 的数据转发完全不受影响**（转发只读本地 FSM 副本，不需要 leader）。
- 跟随者收到握手时把 Raft 写入转发给 leader（hashicorp/raft 的标准做法）；leader 未知时短暂等待选举完成。
- **需要完善测试**（你的明确要求），见 §8 的 P1 验收项：包含 leader 主动下线、网络分区、少数派隔离三类场景。

### 2.5 集群成员与传输

- `--raft-peers "uuid@host:port;..."` 声明初始成员；`--raft-bind` 本节点 Raft 监听地址。
- Transport 实现 `raft.Transport` 接口，底层用 `quic-go`（已在 `go.mod`，QUIC 自带 TLS 加密与多路复用，正适合日志复制 + 快照传输并行）。
- 快照：FSM 定期 snapshot，新节点加入时传快照而非全量日志重放。
- **数据面不走 Raft**：IP 包转发仍走既有的 `PeerOperator` UDP 直连路径。Raft 只承载控制状态。这个边界必须清晰，否则吞吐会被共识拖垮。

### 2.6 落点

- 新增 `cmd/operator/device/consensus/`：`fsm.go`（状态机 + Apply）、`transport_quic.go`（raft.Transport over QUIC）、`commands.go`（日志条目类型）。
- `go.mod` 增 `github.com/hashicorp/raft`。
- `operatorState` 增 `raft *raft.Raft` 与 `fsm *meshState`；`vnets` 字段的权威来源从静态配置改为 FSM。
- `--network` 静态配置降级为"集群初始化时的种子数据"（仅 bootstrap 节点生效）。

---

## 3. G1：身份绑定密钥

### 3.1 设计

采用 WireGuard 的核心不变式：**身份即密钥，CID 是公钥的函数而非独立输入**。

- 密钥体制：**Ed25519**（32B 公钥 / 64B 签名）。本阶段只需证明持有私钥（认证），不需协商共享密钥；后续做数据面加密时再引入 X25519，两者可共存。
- 推导规则：

  ```
  CID = BLAKE2s-256("gaso" || pubkey)[0:8]
  ```

  截断到 8 字节以适配现有 `CID_Ty [8]byte`，路由表、日志、gasoctl 全链路无需改动。

- 碰撞：64 位空间。密钥授权写入 Raft 时检测 CID 碰撞并拒绝该条目——把风险从"运行时静默串号"降为"授权时显式报错"。

### 3.2 握手改造

```
ClientHello:  version(1) cryptoSuite(2) vni(4) cid(8) labels
              + Label[LabelKey_ClientPubKey] = [32]byte          ← 新增

ServerHello:  version(1) cryptoSuite(2) labels
              + Label[LabelKey_Challenge]    = [32]byte nonce    ← 已有

ClientAnswer: answerLen(2) + answer
              answer = Ed25519.Sign(privkey, transcript)         ← 语义改变
```

**签名覆盖范围（transcript binding）**，防重放与降级：

```
transcript = "gasoline-v2-auth"
           || version(1) || cryptoSuite(2)
           || vni(4) || cid(8)
           || client_pubkey(32) || server_nonce(32)
```

服务端验证三步：

1. `CID == derive(pubkey)`　→ 否则拒绝（**这一步堵死冒用**）
2. `pubkey ∈ FSM 的 VNI 密钥表`　→ 否则拒绝（读本地 Raft 副本，无需网络往返）
3. `Ed25519.Verify(pubkey, transcript, sig)`　→ 否则拒绝

三种失败返回**同一错误码、同一延迟**，不泄露"该公钥是否已授权"。

### 3.3 落点

- 新增 `protocol/auth/type-pubkey.go`：`Type = TypePubKey (0x03)`。
- **接口需扩容**：现有 `Respond(challenge []byte)` 拿不到 transcript 所需字段，改为传 `AuthContext` 结构体。这是唯一的破坏性接口变更，影响三个既有 authenticator（noauth/hmac/userpass 忽略新字段即可）。
- `VerifyResponse` 的 `cid` 参数**恢复使用**（当前被丢弃）。
- 密钥授权改为经 Raft 写入：gasoctl 新增 `key grant <vni> <pubkey> [seg...]` / `key revoke <vni> <pubkey>`。
- 客户端 `--key <path>`，缺失时生成并落盘（0600）；新增 `client genkey` 输出公钥。

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
- **续期不走 Raft**：既有 keepalive（10s 周期）只更新本地 `LastSeen`；仅当租约过半时才提交一次 Raft `SessionRenew`。否则 10s 一次的全局共识写入会压垮集群——**这是本设计里最重要的性能取舍**。
- 过期回收由 leader 侧定时任务批量提交 `SessionExpire`，复用既有 `routineReaper` 节奏（30s）。
- `DataCtrlPrefixChanged`（`message-datactrl.go:53`，已实现编解码但从未有人发送）本次启用：IP 变更时主动下发，客户端重配 TUN。

### 4.4 落点

- 地址池逻辑进 `consensus/fsm.go`（分配是状态机转移，不能是本地独立行为）。
- `vniResolver.IP()` 改为走 §2.3 的 Raft 提交路径。
- 分配结果仍写入既有 `routingMap.SetClient`，路由链路完全复用。
- gasoctl 增 `lease list <vni>` / `lease release <vni> <cid>` / `vnet add-segment <vni> <cidr> <pool>`。

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
- 数据面每帧前置会话标签（长度见 §9 Q1）。
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

每个 operator 都持有全部 session 的完整副本（SessionID、PubKey、IP、SessionKey、HopSecret）。任意 operator 收到任意会话的包，都能：

1. 用 SessionID 查本地 FSM → 命中；
2. 用 `SessionKey` 校验帧 MAC → 确认来包真伪；
3. 用本地 `routingMap` 转发 → 与宿主 operator 的行为完全一致。

**不需要转发到宿主，不需要 SessionBind 广播，不存在"宿主故障"这一概念。** 这正是你选择强一致的核心收益。

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

任意 operator 都会转发任意会话的包，因此**必须**校验，否则可被用作放大攻击：

```
frame = SessionTag(8) || MAC(4) || payload
MAC   = HMAC-SHA256(session_key, SessionTag || epoch)[0:4]
```

4 字节 MAC 挡不住定向攻击，但足以挡住无差别扫描。注意这**不是**数据面加密（§1 非目标仍成立），只是转发准入。

### 6.5 落点

- `transport/udp/listener.go`：多端口监听 + SessionID 索引 + MAC 校验。
- `transport/udp/dialer.go`：跳跃 ticker（端口 + server 双维度）。
- 客户端配置从 flag 迁到**配置文件**（多 server 多区间无法用扁平 flag 表达）：新增 `--config <path>`。

---

## 7. 架构总览

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

## 8. 交付顺序

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

P1 单独成阶段，因为共识层的正确性无法靠"跑通一次"证明——必须主动注入故障。

---

## 9. 风险

| 风险 | 影响 | 应对 |
|---|---|---|
| **握手引入 Raft 写入延迟** | 跨地域握手 +1 RTT | 已确认接受；乐观预选 IP 避免二次往返 |
| **Leader 不可达期间无法新握手** | 1~2s 窗口内新客户端连不上 | 既有 session 转发不受影响；客户端重试；P1 专项测试 |
| keepalive 若每次写 Raft | 集群被高频写入压垮 | 续期只在租约过半时提交（§4.3），10s 心跳仅更新本地 |
| 数据面若走 Raft | 吞吐崩塌 | 明确分层：Raft 只承载控制状态（§7） |
| 会话标签增加每包开销 | 有效 MTU 下降 | 8B 标签 + 4B MAC = 12B；相应下调 `DEFAULT_MTU` |
| 全区间监听占用 fd | 区间过大时耗尽 | 区间上限硬编码 64 |
| `AuthContext` 破坏既有接口 | 三个 authenticator 需改签名 | 改动机械，noauth 路径有测试覆盖 |
| 引入 hashicorp/raft 依赖 | 依赖体积增加 | 成熟度换正确性，已确认接受 |

---

## 10. 待定问题（请评审确认）

1. **会话标签 8B 还是 16B？** 我倾向 8B（SessionID 前 8 字节）+ 4B MAC，共 12B/包。万级会话下碰撞可忽略。
2. **Raft 集群规模？** 3 或 5 节点（需奇数）。operator 数量若超过集群规模，多出的应作为 **non-voting learner** 加入（只读副本，不参与选举），否则选举延迟随规模劣化。这个分层需要你确认。
3. **`--network` 静态配置的去留？** 有了 Raft，vnet 定义应由 gasoctl 写入集群。我建议保留它仅作 bootstrap 种子，其后一律走 gasoctl。
4. **本 PRD 不含数据面加密**，交付后 UDP payload 仍是明文。请确认符合预期。

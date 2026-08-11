# PRD：身份绑定密钥 / 动态 IP 下发 / 端口跳跃 / 多 server 跳跃

分支：`pure-mesh`　状态：待评审　目标版本：握手协议 v2

---

## 0. 背景与问题定位

当前握手（`protocol/handshake/handshake.go`）是四段式：

```
ClientHello(vni, cid) → ServerHello(challenge) → ClientAnswer(response) → ServerAssign(ip, cidr)
```

三个结构性缺陷，正是本次要修的：

**其一，身份可伪造。** CID 由客户端在 `ClientHello` 里自报，服务端拿它查 `PresetCIDmap` 决定 IP。HMAC 认证（`type-hmac.go:59`）的 `VerifyResponse` 第一个参数是 `_ protocol.CID_Ty`——**CID 被显式丢弃**。任何持有任一有效 `<id, secret>` 的客户端都能声称自己是任意 CID，从而取得别人的 IP。`CryptoSuite_Wireguard` 常量已定义但无任何实现。

**其二，IP 是静态表，不是分配器。** `vniResolver.IP()`（`operator.go:53`）只做 `routingMap.LookupByCID(cid)` 查表；表来自 `--preset` 命令行。没有池、没有租约、没有回收——新客户端接入必须先改命令行重启 operator。

**其三，端口与服务端均固定。** listener 绑定单一 `addr` 后终身不变（`udp/listener.go:48`、`quic/listener.go:20`），四元组长期暴露，易被针对性阻断。更进一步，会话与"某个 operator 进程"死绑：`virtualPeer` 以 `netip.AddrPort` 为键（`udp/listener.go:86`），源地址一变即被当作新 peer 重新握手——这既挡死了端口跳跃，也挡死了多 server 跳跃，还顺带使 NAT 重绑定必然断线。

另有一处与三者都相关：`SessionContext.SessionID [16]byte` 字段已存在并已在 `ServerAssign` 线格式中占位传输（`messages.go:148`），但**从未被赋值**，始终是全零。本次将它启用为会话标识。

---

## 1. 目标与非目标

### 目标

| # | 能力 | 参照 | 验收口径 |
|---|---|---|---|
| G1 | 身份绑定密钥 | WireGuard | 客户端身份 = 其静态公钥。CID 由公钥推导，不可自选；冒用他人 CID 必然握手失败 |
| G2 | 动态 IP 下发 | OpenVPN | operator 侧地址池按需分配、带租约、断线回收；新客户端零配置接入，无需重启 |
| G3 | 端口跳跃 | Hysteria2 | 服务端监听端口区间，客户端按共享密钥推导的时间序列跳跃；跳跃对上层数据面透明 |
| G4 | 多 server 跳跃 | — | 客户端配置多个 server，每个 server 带多个端口区间。握手绑定单一 host:port，握手成功后可在**任意 server 的任意区间**发送，全部可行 |

### 非目标（本次明确不做）

- **不做数据面加密。** G1 只解决"你是谁"，不解决"链路上谁能看见"。`ARCHETECT.md` 里的零信任端到端加密（特殊化 ARP 携带对端公钥）是独立的后续工作。本 PRD 交付后，payload 仍是明文——QUIC 传输自带 TLS，UDP 传输不带。这一点必须在验收时明示，避免误以为已经"加密了"。
- 不做 PKI / CA / 证书链。公钥即身份，信任来自 operator 侧的授权列表，同 WireGuard。
- 不做 IPv6 地址池（G2 仅 IPv4；协议字段为 v6 预留但不实现）。
- 不改 operator↔operator underlay（`--op-listen`）与 gasoctl IPC。
- 不做端口跳跃的 UDP 之外形态（QUIC 见 §4.4 的限制说明）。

---

## 2. G1：身份绑定密钥

### 2.1 设计

采用 WireGuard 的核心不变式：**身份即密钥，CID 是公钥的函数而非独立输入**。

- 密钥体制：**Ed25519**（签名，32B 公钥 / 64B 签名）。选它而非 X25519，是因为本阶段只需证明持有私钥（认证），不需协商共享密钥（加密留待后续）。后续做数据面加密时再引入 X25519，两者可共存。
- 推导规则：

  ```
  CID = BLAKE2s-256(0x67 0x61 0x73 0x6F || pubkey)[0:8]     // "gaso" 域分隔
  ```

  截断到 8 字节以适配现有 `CID_Ty [8]byte`，全链路（路由表、日志、gasoctl）无需改动。

- 碰撞：64 位空间，生日界约 2^32 个身份时碰撞概率显著。operator 在授权列表载入时检测 CID 碰撞并拒绝启动，将风险从"运行时静默串号"降为"启动期显式报错"。

### 2.2 握手改造

`ClientHello` 增加公钥，`ClientAnswer` 从 HMAC 改为签名：

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
transcript = "gasoline-v2-auth"           // 域分隔，防跨协议重放
           || version(1) || cryptoSuite(2)
           || vni(4) || cid(8)
           || client_pubkey(32)
           || server_nonce(32)
```

服务端验证三步，缺一不可：

1. `CID == derive(pubkey)`　→ 否则 `HandshakeAuthFail`（**这一步堵死冒用**）
2. `pubkey ∈ VNI 授权列表`　→ 否则 `HandshakeAuthFail`
3. `Ed25519.Verify(pubkey, transcript, sig)`　→ 否则 `HandshakeAuthFail`

三种失败返回**同一错误码、同一延迟**，不泄露"该公钥是否已授权"。

### 2.3 落点

- 新增 `protocol/auth/type-pubkey.go`：实现 `ClientAuthenticator` / `ServerAuthenticator`，`Type = TypePubKey (0x03)`。
- **接口需扩容**：现有 `Respond(challenge []byte)` 拿不到 transcript 所需的 vni/cid/pubkey。改为传入一个 `AuthContext` 结构体（含上述字段），这是本次唯一的破坏性接口变更，影响三个既有 authenticator 的签名（noauth/hmac/userpass 忽略新字段即可）。
- `VerifyResponse` 的 `cid` 参数**恢复使用**（当前被丢弃）。
- 配置：`--network` 的 auth 段扩展为 `pubkey:<base64key>[,<base64key>...]`，或 `pubkey:@/path/to/authorized_keys` 走文件（推荐，便于热加载与规模化）。
- 客户端：`--key <path>` 指定私钥文件；缺失时生成并落盘（0600），同 `wg genkey` 习惯。CLI 新增 `client genkey` 子命令输出公钥供管理员登记。

### 2.4 兼容性

`HandshakeVersion` 由 `0x01` 升至 `0x02`。服务端**不接受** v1（v1 的身份模型不可信，保留即等于保留漏洞）。`--network` 中旧的 `hmac:` / `userpass:` 仍可用于非零信任 VNet，但文档标注为 legacy，且不与 `pubkey:` 在同一 VNI 混用。

---

## 3. G2：动态 IP 下发

### 3.1 设计

在 `vniEntry` 上挂一个地址池，取代"查 preset 表"。

**分配优先级**（先命中先返回）：

1. **静态绑定** —— `--preset` 声明的 `cid → prefix` 恒定生效，优先级最高。保留它对运维定位关键节点很重要。
2. **续租** —— 该 CID 的既有租约仍在有效期内 → 返回原 IP。**这是 IP 稳定性的关键**：客户端重连（换端口、网络抖动、进程重启）应拿回同一个 IP，否则上层 TCP 全断。
3. **新分配** —— 从池中取空闲地址，建立租约。
4. **池满** —— 返回 `HandshakeNoRoute`（现有错误码，语义吻合）。

**池的边界**：来自 `--network` 的 CIDR，扣除网络地址、广播地址、网关地址（`.1` 保留给 operator 侧）。

**租约**：

```go
type lease struct {
    CID      protocol.CID_Ty
    PubKey   [32]byte      // 绑定到身份，非仅 CID
    Prefix   netip.Prefix
    Expires  time.Time
}
```

租约同时绑 PubKey：CID 已由公钥推导，此处冗余存储是为了让"同一 CID 不同公钥"这种理论上的碰撞场景能被检测并拒绝，而不是静默夺取他人租约。

**生命周期**：

- TTL 默认 3600s，可配 `--lease-ttl`。
- 客户端在线期间由既有 keepalive（`device/client/keepalive.go`，10s 周期）隐式续期——**无需新增协议消息**，operator 侧在 `routineReadFromClient` 收到任何帧时刷新租约 `Expires`。
- 断线后租约保留至过期，期间该 IP 不再分配给他人（这就是重连拿回原 IP 的机制）。
- 过期回收由既有 `routineReaper`（`operator.go:293`，30s 周期）顺带执行，不新起 goroutine。

**IP 变更通知**：`DataCtrlPrefixChanged`（`message-datactrl.go:53`）已定义且已实现编解码，但目前无人发送。本次启用：当运维通过 gasoctl 改动路由导致客户端 IP 变化时，operator 主动下发该帧，客户端重配 TUN 地址。这补上了一条既有但闲置的能力。

### 3.2 落点

- 新增 `cmd/operator/device/ipam.go`：池 + 租约表，接口约 5 个方法（`Acquire/Renew/Release/Lookup/Reap`）。
- `vniResolver.IP()`（`operator.go:53`）改为调 `ipam.Acquire(cid, pubkey)`。
- `vniEntry` 增加 `ipam *ipamPool` 字段，`newVniEntry` 时按 VNI CIDR 构造。
- 分配成功后写入既有 `routingMap.SetClient(cid, prefix)`，路由链路完全复用，无改动。
- gasoctl 增加 `lease list <vni>` / `lease release <vni> <cid>` 两个只读+运维命令。

### 3.3 并发

`Acquire` 必须在 `vniEntry.mu` 写锁内完成"查空闲→标记占用→写路由表"，否则两个并发握手可能拿到同一 IP。这是本项唯一的并发风险点，需在实现时以测试覆盖（并发 100 个握手，断言分配出的 IP 两两不同）。

---

## 4. G3：端口跳跃

### 4.1 设计

服务端在**端口区间**上同时监听，客户端按时间片轮换目标端口；跳跃对数据面完全透明。

**关键决策：服务端全区间同时监听，而非跟着时钟切换。** Hysteria2 的做法依赖外部 NAT 重定向；我们自己实现，选择"全开"是因为：

- 无时钟同步问题——客户端时钟偏移 ±1 个时间片也能连上；
- 无切换窗口丢包——不存在"旧端口已关、新端口未开"的空隙；
- 代价是占用 N 个 UDP 套接字（N 通常 ≤ 64，可接受）。

**端口序列推导**（客户端与服务端各自独立计算，无需协商）：

```
epoch = floor(unix_time / hop_interval)
idx   = HMAC-SHA256(hop_secret, "gasoline-hop" || vni(4) || epoch(8))[0:2] mod range_size
port  = range_start + idx
```

- `hop_secret`：**握手期间由服务端下发**（见 §4.3），而非命令行预共享——避免又多一个需要带外分发的密钥。
- `hop_interval`：默认 30s，可配。
- 相邻 epoch 可能推导出同一端口，属正常，不做去重。

### 4.2 会话延续性

这是本项的**核心难点**。UDP listener 现以 `netip.AddrPort` 为键索引 `virtualPeer`（`udp/listener.go:86`）——客户端一换端口，源地址变了，服务端会把它当作全新 peer 并触发一次新握手。

**解决方案：以 SessionID 而非四元组标识会话。**

- 启用当前恒为零的 `SessionContext.SessionID [16]byte`：`ServerHandshake` 时随机生成并经 `ServerAssign` 下发（线格式已有该字段，**无需改动 messages.go**）。
- 数据面每个帧前置 16 字节 SessionID 前缀（仅 UDP 传输，QUIC 见 §4.4）。
- listener 的 peers 索引主键由 `AddrPort` 改为 `SessionID`；`AddrPort` 降为辅助索引。收到已知 SessionID 但源地址不同的帧 → 判定为跳跃，原地更新该 peer 的 `remoteAddr`，**不重新握手**。

这同时顺带解决了 NAT 重绑定导致的断连——一个既有的、未被记录的缺陷。

**开销**：每包 +16 字节。当前 MTU 1400（`tun.go:14` `DEFAULT_MTU`），需相应下调有效载荷预算。若认为开销偏大，备选是 8 字节短会话标签（SessionID 的前 8 字节），碰撞概率在万级会话下可忽略——**建议评审时定夺**。

### 4.3 握手期的鸡生蛋问题

首次握手时客户端还没有 `hop_secret`，无从跳跃。

- 客户端首包发往 `range_start`（区间首端口），该端口恒定开放，作为"引导端口"。
- 握手成功后，`ServerAssign` 通过 **label** 下发 `hop_secret(32B)` + `range_start(2B)` + `range_size(2B)` + `hop_interval(2B)`。用 label 而非改结构体，因为 `ServerAssign` 目前**没有** labels 字段——需要为它补上 label 段（`ClientHello`/`ServerHello` 已有，照抄即可），这是 G3 唯一的线格式变更。
- 客户端收到后开始跳跃；下次重连直接从当前 epoch 对应端口起跳，不再走引导端口。

### 4.4 QUIC 的限制（须明示）

QUIC 有自己的连接迁移机制，且 `quic.ListenAddr` 绑单地址。在 QUIC 上叠加我们的端口跳跃会与 QUIC 自身的路径验证冲突。

**结论：G3 仅在 UDP 传输上实现。** QUIC 传输保持单端口，依赖其原生连接迁移。CLI 在 `--transport quic --hop ...` 组合下直接报错而非静默忽略。这是一个功能边界，不是缺陷。

### 4.5 落点

- 新增 `transport/udp/hop.go`：端口序列推导（纯函数，易测）。
- `transport/udp/listener.go`：改为持有 `[]*net.UDPConn`，共享一个 peers 表；索引主键改 SessionID。
- `transport/udp/dialer.go`：起一个 ticker，到点切换目标端口。
- `transport/udp/conn.go`：帧前置/剥离 SessionID。
- CLI：operator `--listen "udp://0.0.0.0:20000-20063"` 区间语法；`--hop-interval`。

---

## 5. G4：多 server 跳跃

### 5.1 需求与真正的难点

配置形如：

```yaml
servers:
  - host: 1.2.3.4
    ports: [20000-20063, 30000-30015]
  - host: 5.6.7.8
    ports: [20000-20063]
```

要求：握手绑定某一个 `host:port`；握手成功后，**在任意 server 的任意区间跳跃发送都必须可行**。

难点不在客户端——客户端换目标地址是平凡的。难点在**服务端**：G3 的跳跃只换端口，包始终落在同一个 operator 进程，那个进程持有会话的全部状态（`virtualPeer`、`SessionContext`、租约、`routingMap` 里的 `cid → prefix` 绑定）。而 G4 的包会落到**另一台机器上的另一个 operator 进程**，它对这个会话一无所知：

- 它的 `peers` 表里没有这个 SessionID；
- 它的 `routingMap` 里没有这个 CID 的路由（那条路由指向的是原 operator 的本地 client）；
- 它没有这个客户端的公钥，无法验证来包真伪。

因此 **G4 不是 G3 的参数化扩展，而是一次会话状态的分布式化改造**。必须诚实说明这一点：它的工作量大于 G1+G2+G3 之和。

### 5.2 两种实现路径

**路径 A：无状态转发（推荐）**

收包的 operator 不需理解会话，只需知道"这个 SessionID 归谁"，然后把整包转发给宿主 operator。

- 复用**既有的** operator↔operator underlay（`--op-listen` UDP + `PeerTable` + `MessageTransport`），这条链路已经在跑，`vnet_entry.go:131` 的 `RouteTargetOperator` 分支就是它。
- 新增一张全局 `SessionID → ownerUUID` 映射，随会话建立/销毁在 operator 之间广播。
- 收到不认识的 SessionID → 查表 → 用 `MessageTransport` 包一层发给 owner → owner 按既有逻辑处理，回包沿原路返回。

代价：非宿主 server 上的流量多一跳（客户端→A→B→目的）。收益：改动集中，会话状态仍单点持有，无一致性问题。

**路径 B：会话状态全同步**

每个 operator 都持有全部会话的完整状态，任何一台都能独立处理任何包。

代价：租约、路由、公钥全部需要强一致复制；`ipam.Acquire` 变成分布式锁；脑裂时会分配出重复 IP。**在没有共识层（raft/etcd）的前提下不建议**——而我们刚刚删掉了 cordinator，正是把中心化控制面移除了。

**建议采用路径 A。** 下文按 A 展开。

### 5.3 SessionID → owner 的分发

这是路径 A 唯一的新增分布式状态。三种选择：

1. **广播**（推荐起步）：会话建立时，宿主 operator 向 `PeerTable` 中所有 peer 广播 `SessionBind{SessionID, ownerUUID, vni}`；销毁时广播 `SessionUnbind`。peer 数量在 mesh 场景下通常 < 100，广播成本可忽略。
2. **按需查询**：收到未知 SessionID → 向所有 peer 询问"谁认识它"。省内存，但首包引入一个 RTT 的延迟，且未知 SessionID 可被用来放大询问流量。
3. **可推导**：让 SessionID 自带 owner 信息（如高 16 字节嵌 operator UUID 的哈希）。零状态，但泄露拓扑，且 owner 变更（故障转移）时失效。

选 1。新增两个 `control.Op`（`SessionBind` / `SessionUnbind`）——注意本分支刚删掉 cordinator 的 websocket 广播通道，所以这个广播需走 operator↔operator 的 UDP underlay，而非重建控制面。

### 5.4 安全：跨 server 的来包验证

非宿主 operator 收到一个陌生 SessionID 的包，**不能**无条件转发——否则任何人都能凭猜测的 SessionID 让整个 mesh 替他转发流量（放大攻击 + 资源耗尽）。

对策：数据面帧的 SessionID 前缀附带一个轻量 MAC：

```
frame = SessionID(8) || MAC(4) || payload
MAC   = HMAC-SHA256(session_key, SessionID || epoch)[0:4]
```

`session_key` 在握手时由宿主下发（与 `hop_secret` 同批），并随 `SessionBind` 一同分发给各 peer，使任意 operator 都能在**转发前**做 O(1) 校验。4 字节 MAC 挡不住定向攻击，但足以挡住无差别扫描——这是与开销的折中，评审可上调至 8 字节。

注意这**不是**数据面加密（§1 非目标仍然成立），只是转发准入。

### 5.5 握手的绑定语义

用户要求"握手必须绑定 host:port"。落实为：

- 握手只在客户端配置的某一个 `host:port` 上完成（首个可达的 server 的区间首端口，同 §4.3 引导端口）。
- 该 server 成为本会话的**宿主**（owner），持有租约与路由。
- `ServerAssign` 除下发 `hop_secret` 外，追加下发**全量 server 列表**（各 host + 各区间 + 各自的 UUID）——客户端配置里的列表可能过期，以服务端下发的为准。
- 此后客户端可向列表中任意 `(server, 区间)` 组合发包。

### 5.6 宿主故障

宿主挂掉时，会话的租约与路由随之消失，其余 operator 上的 `SessionBind` 条目变成悬空指针。

**本期不做故障转移**：peer 检测到 owner 不可达后删除该 SessionID 映射，客户端收不到回包，超时后重新握手（可能落到另一台 server，成为新宿主，并按 §3.1 的续租规则**拿回同一个 IP**——前提是租约信息可跨 operator 查询，这需要租约表也随 `SessionBind` 分发，或接受重连后换 IP）。

**这是一个明确的功能边界，需要你确认取舍**：要么接受宿主故障后 IP 变化，要么额外做租约的跨 operator 复制（工作量再上一个台阶）。

### 5.7 落点

- `transport/udp/listener.go`：未知 SessionID 的转发分支。
- `cmd/operator/device/session_registry.go`（新增）：`SessionID → ownerUUID + session_key` 表。
- `protocol/control/session_bind.go` / `session_unbind.go`（新增两个 Op）。
- `cmd/operator/device/peer_operator.go`：承载 SessionBind 广播。
- `vnet_entry.go`：转发路径增加"目标是远端 operator 持有的 client 会话"这一情形。
- 客户端配置从命令行升级为**配置文件**（多 server + 多区间已无法用扁平 flag 表达）——新增 `--config <path>`，YAML 或 JSON。

---

## 6. 交付顺序

四项之间有真实依赖，不可并行：

```
G1 身份绑定  ──→  G2 动态 IP   （租约需绑 PubKey，故 G1 先行）
     │
     └────────→  G3 端口跳跃  ──→  G4 多 server 跳跃
                （握手下发密钥）    （G4 是 G3 在跨进程维度的推广，
                                     必须先有 SessionID 会话标识）
```

| 阶段 | 内容 | 验收 |
|---|---|---|
| P0 | 握手 v2 骨架：`ServerAssign` 补 label 段、`AuthContext` 接口改造 | 既有测试全绿（noauth 路径不回归） |
| P1 | G1 Ed25519 认证 + CID 推导 | 冒用他人 CID 必失败；未授权公钥必失败；两者错误码一致 |
| P2 | G2 地址池 + 租约 | 零 preset 配置下 N 个客户端各得唯一 IP；断线重连拿回原 IP；池满返回 NoRoute；并发 100 握手无重复 IP |
| P3 | G3 SessionID 会话标识（不含跳跃） | 客户端源端口人为变更后会话不中断 |
| P4 | G3 端口跳跃（单 server） | 抓包可见端口按 interval 轮换；跨跳跃点 TCP 长连接不断；时钟偏移 ±1 片仍可连 |
| P5 | G4-a 客户端配置文件 + 多 server 列表下发 | 客户端可解析多 server 多区间；`ServerAssign` 下发的列表覆盖本地配置 |
| P6 | G4-b SessionBind 广播 + 跨 operator 转发 | 客户端握手于 A，改向 B 发包，会话不中断、回包正常；B 对未知 SessionID 的包拒绝转发 |

P3 独立于 P4 先行落地，是为了让"会话延续"这个高风险改动能单独验证——它同时是 NAT 重绑定的修复，即使 P4 延后也有独立价值。P5/P6 拆分同理：P5 无协议风险，P6 才引入分布式状态。

---

## 7. 风险

| 风险 | 影响 | 应对 |
|---|---|---|
| SessionID 前缀增加 16B 开销 | 有效 MTU 下降 | 评审定夺 16B/8B；相应下调 `DEFAULT_MTU` |
| 全区间监听占用套接字 | 区间过大时 fd 耗尽 | 区间上限硬编码 64，超出报错 |
| 租约与 `--preset` 语义重叠 | 运维困惑 | preset 优先级最高且不进池；文档明示 |
| `AuthContext` 破坏既有接口 | 三个 authenticator 需改签名 | 改动机械，一次性完成；noauth 路径有测试覆盖 |
| 时钟漂移致跳跃失步 | 客户端连不上 | 服务端全区间监听，本就不依赖服务端时钟；客户端偏移 ±1 片仍落在开放端口内 |
| **G4 使会话状态分布式化** | 工作量大于 G1+G2+G3 之和 | 采用路径 A（无状态转发），会话状态仍单点持有；拆成 P5/P6 两阶段 |
| G4 转发被滥用为放大攻击 | mesh 替攻击者转发流量 | 转发前校验 4B MAC（§5.4）；未知 SessionID 直接丢弃并限速 |
| G4 宿主故障 | 会话中断、IP 可能变化 | 本期不做故障转移，超时重握手；是否复制租约表需评审定夺（§5.6） |
| 非宿主路径多一跳 | 时延与带宽放大 | 客户端优先选宿主 server；跳跃到非宿主是可用性手段而非常态 |

---

## 8. 待定问题（请评审确认）

1. **SessionID 前缀 16B 还是 8B？** 我倾向 8B——万级会话碰撞概率可忽略，省一半开销。
2. **`hop_secret` 下发 vs 预共享？** 我倾向握手下发（少一个带外分发的密钥），但它意味着首包引导端口固定，是一个可被识别的特征。若你更看重抗识别，则应改为预共享。
3. **legacy 的 hmac/userpass 是否保留？** 我倾向保留但标注 legacy，因为 `--network` 的既有部署会依赖它。若你要求纯粹，可一并删除。
4. **本 PRD 明确不含数据面加密**，请确认这符合你的预期——G1 完成后 UDP 传输的 payload 仍是明文。
5. **G4 采用路径 A（无状态转发）还是路径 B（状态全同步）？** 我强烈建议 A。B 需要共识层，而本分支刚刚删掉了 cordinator（中心化控制面），再引入 raft 与 pure-mesh 方向相悖。
6. **G4 宿主故障后，是否要求客户端保住原 IP？** 保住 ⇒ 租约表须跨 operator 复制，工作量显著上升；不保 ⇒ 重握手换 IP，上层连接断。倾向后者（本期不做）。
7. **客户端配置从 flag 迁到配置文件**，多 server 多区间已无法用扁平 flag 表达。确认接受 `--config <path>`（YAML）。

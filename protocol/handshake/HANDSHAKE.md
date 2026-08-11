# Gasoline 握手协议 (v2, Noise_IK)

握手版本 `0x02`。**没有 v1 兼容**——旧的 HMAC / challenge / userpass / noauth 模型已整体删除。唯一的接入方案是**密钥身份**：客户端就是它的静态公钥。

- 密码学：`Noise_IK` over Curve25519 / ChaCha20-Poly1305 / BLAKE2s（同 WireGuard 构造）
- 身份绑定：`CID = BLAKE2s-256("gaso" || client_static_pub)[0:8]`，CID 是公钥的函数，不可自选
- 握手同时完成**双向认证**与**传输密钥协商**——能通信本身即证明持有私钥，无需签名

---

## 1. 前置条件

| 一方 | 持有 |
|---|---|
| **客户端** | 自己的静态密钥对 `(c_priv, c_pub)`；**目标 operator 的静态公钥** `s_pub`（带外获知，同 WireGuard 的 `PublicKey=`）|
| **operator** | 自己的静态密钥对 `(s_priv, s_pub)`；该 VNI 的**授权公钥表**（`c_pub` 必须在其中，否则拒绝——无 "open" 模式）|

"IK" 中的 **K** 即指客户端**预先知道** operator 的静态公钥；**I** 指客户端在第一条消息里就（加密）发出自己的静态公钥。

---

## 2. 时序总览

四条帧，沿用既有的四段式框架。真正的认证在前两条（Noise msg1 / msg2）内完成；第三条空载荷，第四条下发分配结果。

```
客户端 (Initiator)                              operator (Responder)
     │                                                    │
     │  ── ClientHello { vni, cid, msg1 } ─────────────►  │
     │       msg1 = Noise_IK initiation                   │
     │                                            (1) 解密 msg1 → 得 c_pub
     │                                            (2) 校验 CID == derive(c_pub)
     │                                            (3) 校验 c_pub ∈ 授权表
     │                                                    │
     │  ◄──────────── ServerHello { msg2 } ─────────────  │
     │       msg2 = Noise_IK response                     │
     │   此刻两端各自导出 send_key / recv_key             │
     │                                                    │
     │  ── ClientAnswer { 空 } ─────────────────────────► │
     │       （Noise 已认证，无载荷；仅保持四段框架）      │
     │                                            (4) IP(cid) 解析分配地址
     │                                                    │
     │  ◄────── ServerAssign { code, session } ─────────  │
     │       code=OK, ip / sessionID / ipRanges           │
     │                                                    │
   握手完成，进入数据面（用 send_key/recv_key 加密）
```

---

## 3. 逐帧线格式

所有整数大端。`labels` 是一个键值表，线格式为
`count:u16 · [ valLen:u16 · key:u64 · val:valLen ]*`。

### 3.1 ClientHello （客户端 → operator）

```
version      : u8   = 0x02
cryptoSuite  : u16  = 0x0001 (Noise_IK)
vni          : u32  （低 24 位有效）
cid          : [8]byte  = BLAKE2s("gaso" || c_pub)[0:8]
labels       : Label[NoiseInitiation=0] = msg1
```

**msg1（Noise_IK initiation，共 108 字节）**：

```
e_pub            : 32   客户端临时公钥
enc_static       : 48   AEAD(k1, c_pub)      —— 32 明文 + 16 tag
enc_timestamp    : 28   AEAD(k2, TAI64N)     —— 12 明文 + 16 tag
```

- `k1` 由 `DH(e_priv, s_pub)` 经哈希链导出；`k2` 由再混入 `DH(c_priv, s_pub)` 导出。
- `enc_static` 只有持 `s_priv` 的 operator 能解开 → 得到客户端静态公钥。
- `enc_timestamp` 是 12 字节 TAI64N，用于**防重放**：operator 记录每个静态公钥见过的最大时间戳，拒绝更旧的 msg1。

### 3.2 ServerHello （operator → 客户端）

```
version      : u8   = 0x02
cryptoSuite  : u16  = 0x0001
labels       : Label[NoiseResponse=1] = msg2
```

**msg2（Noise_IK response，共 48 字节）**：

```
e_pub        : 32   operator 临时公钥
enc_empty    : 16   AEAD(k, ∅)   —— 空载荷 + 16 tag，用于认证 transcript
```

收发双方在此步各自完成密钥链，**导出方向密钥**：

```
initiator.send == responder.recv
initiator.recv == responder.send
```

**拒绝路径**：若前三步校验（解密 / CID / 授权）任一失败，operator 发送一条**不带 NoiseResponse 标签**的 ServerHello。客户端解码正常，但取不到 msg2 标签，于是干净地报错退出——不会阻塞。所有 pre-auth 失败走同一路径、同一延迟，不泄露"是密钥错还是未授权"。

### 3.3 ClientAnswer （客户端 → operator）

```
answerLen : u16 = 0
answer    : （空）
```

Noise 在前两条消息内已完成双向认证，此帧无载荷，仅为保持四段式框架而保留。

### 3.4 ServerAssign （operator → 客户端）

```
code         : u32   0x00=OK, 0x02=AuthFail, 0x04=NoRoute, 0x05=Conflict, ...
cid          : [8]byte
vni          : u32
sessionID    : [16]byte
sessionIndex : u32
ipLen        : u8            （0 / 4 / 16）
ip           : ipLen 字节     分配的 overlay 地址
rangeLen     : u8
rangeAddr    : rangeLen 字节   VNI 的网段
rangeBits    : u8             网段前缀长度
```

`code != OK` 时 SessionContext 块仍以零值发出，保持定长便于解码。

---

## 4. operator 侧校验顺序（不可换）

```
1. 解密 msg1 成功           否则 → reject（AuthFail）  ← 堵住无效密文
2. CID == derive(c_pub)     否则 → reject（AuthFail）  ← 堵住冒用他人 CID
3. c_pub ∈ VNI 授权表        否则 → reject（AuthFail）  ← 堵住未授权密钥
   ── 以上任一失败：发无标签 ServerHello，同一码同一延迟 ──
4. IP(cid) 解析成功          否则 → sendFail（NoRoute）
```

第 2 步是身份绑定的关键：CID 由公钥推导，客户端无法声称一个与自己密钥不符的 CID。

---

## 5. 握手产物

| 产物 | 用途 | 是否进 Raft |
|---|---|---|
| `SessionContext`（ip / sessionID / ipRanges / cid / vni） | 数据面路由与会话标识 | 是（session 元数据） |
| `TransportKeys{ send, recv }` | 数据面 AEAD 加密（P9） | **否**——每会话临时密钥，两端本地导出，operator 无法解密 |
| `c_pub`（operator 侧恢复得到） | 记入 session、驱动唯一性判定（§8） | 是（作为身份） |

---

## 6. 与 PRD 的对应

- 身份绑定密钥 → 本文件（PRD §3，G1）
- 一次握手内完成 IP + session 分配 → `ServerAssign`（PRD §2.3，G2）；分配走一条 Raft 日志
- Noise_IK 密码学核心 → `protocol/noise/`（PRD §7，G5 的密钥来源）
- 会话唯一性 / HandshakeConflict → PRD §8（后续阶段接入）

---

## 7. 代码位置

| 文件 | 职责 |
|---|---|
| `handshake.go` | `ClientHandshake` / `ServerHandshake` 流程 + 校验 |
| `messages.go` | 四条帧的 Encode/Decode |
| `labels.go` | 标签表编解码；`LabelKey_NoiseInitiation` / `LabelKey_NoiseResponse` |
| `types.go` | 版本、错误码、CryptoSuite |
| `tai64n.go` | 防重放时间戳 |
| `../noise/` | Noise_IK 状态机、KDF、X25519、AEAD |
| `../cid.go` | `DeriveCID(pub)` |

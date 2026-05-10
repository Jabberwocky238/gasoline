<!-- ANY AI AGENT SHOULD NOT MODIFY THIS FILE -->

# gasoline

## on the fly
ClientRequest除了长度，还要发一个encryption.PublicKey，也就是长度，encryption.PublicKey，payload，这个公钥在握手时生成，client在握手时产 
生密钥对，operator不产生密钥对，删除operator的密钥对。client连接时发送自己的vmac和公钥，需要一同保存到mac表里，当arp请求发送来的时候，需 
要检测是标准arp还是gasoline特殊的arp，如果是标准arp，返回标准arp报文，否则返回特殊化arp报文，特殊化报文附带对应ip所在client的公钥。每次  
传输之前，使用对方ip对应的公钥进行加密，这样operator和链路层永远无法知道内部信息。同时你要在vnet定义的时候，定义这是一个zerotrust网络还  
是普通网络，如果是普通网络，所有的握手过程和传输过程都不加密，arp也响应正常arp，否则就都加密，但是因为路由是基于mac的所以都不影响 

## debug

go run main.go operator --listen "quic://0.0.0.0:8443" --network "200:10.0.0.0/24;1000:192.168.200.0/24"
./gasoline operator --listen "quic://0.0.0.0:20000" --network "200:10.0.0.0/24;1000:192.168.200.0/24" --op-listen "0.0.0.0:6678;69.164.244.173:6678"
./gasoline operator --listen "quic://0.0.0.0:20000;tls://0.0.0.0:20001" --network "200:10.0.0.0/24;1000:192.168.200.0/24" --op-listen "0.0.0.0:6678;69.164.253.11:6678" --discover "69.164.244.173:6678"

sudo go run main.go client --endpoint 69.164.244.173:20000 --vni 200
sudo go run main.go client --endpoint 69.164.253.11:20000 --vni 200

● Linux —— client A：
./bin/client -endpoint :8443 -transport quic -auth noauth -vni 0 -cid 100 -tun gasoctlA -log-level debug
go run ./cmd/client -endpoint 163.245.211.144:8443 -transport quic -auth noauth -vni 0 -cid 101 -tun gasoctlA -log-level debug

Linux client B：
./bin/client -endpoint :8443 -transport quic -auth noauth -vni 0 -cid 101 -tun gasoctlB -log-level debug

Windows（PowerShell 或 cmd 都行）—— client A：
.\bin\client.exe -endpoint 163.245.211.144:8443 -transport quic -auth noauth -vni 0 -cid 100 -tun gasoctlA -log-level debug
go run ./cmd/client -endpoint 163.245.211.144:8443 -transport quic -auth noauth -vni 0 -cid 100 -tun gasoctlA -log-level debug

Windows client B：
.\bin\client.exe -endpoint :8443 -transport quic -auth noauth -vni 0 -cid 101 -tun gasoctlB -log-level debug

go run main.go client --endpoint 76.13.182.201:20000 --vni 300
go run main.go client --endpoint 172.29.64.1:8443 --vni 200

sudo go run main.go client --endpoint 69.164.244.173:20000 --vni 1000
sudo go run main.go client --endpoint localhost:8443 --vni 1000
go run main.go client --endpoint 172.29.64.1:8443 --vni 1000

kubectl label node vps3359430.trouble-free.net externalip=163.245.211.144
kubectl get nodes -L externalip    
kubectl get nodes --show-labels   
比如有三个节点：    
  
kubectl label node node-1 externalip=10.0.0.1       
kubectl label node node-2 externalip=10.0.0.2
kubectl label node node-3 externalip=10.0.0.3



gasolines启动时自动连接 <serverip>:6677，server自己维护一个map，包括了所有server和自己到目标server的延迟时间。

gasolinec只链接一个server，连接上之后开始握手，握手成功后链接成功
所有gasolinec默认自带一个clientid和一个clientsecret

握手开始的时候，服务器给出一个一次性nonce，客户端返回hmac加密结果和自己的clientid，服务器校验通过，下发服务器的wg公钥和client的wg私钥，还有客户端所属ip

客户端发送aead加密后的信息给服务器，服务器解密，获取明文，加上客户端所属的vni group前缀，找到其目的地对应的server是哪个，然后转发给哪个server。对应的server接到后，根据vni group前缀，找到链接的client组，然后根据对应client的allowedips，确定是否发送给他这个包。

gasolines和gasolinec之间的连接使用quic/udp/tcp三种模式

## handshake

1. clienthello, with client_id
2. serverhello, with type, payload(nonce for hmac, salt for user/pswd)
3. clientrequest, with payload
4. serverrespond, with config
5. startsession

  六、"套接字劫持" 是怎么做到的

  严格说 mihomo 并没有劫持 socket，而是整条路由走 TUN：
  - auto-route（Linux/Mac/Win）把默认路由改到 TUN 设备，或加高优先级路由表 + 规则；
  - auto-redirect（Linux）配合 nftables / iptables，处理需要旁路的本机流量；
  - 出站 proxy 自己发起的连接需要避免回环进 TUN，由 EnforceBindInterface（server.go:472）强制出站绑定到物理网卡；旧版 Windows（<
  Win10）强制开启。

  这样应用层完全无感，只需要把默认下一跳路由引到 TUN，剩下的协议栈工作全部由 sing-tun 的用户态栈完成。

  七、平台细节

  - Windows：基于 Wintun；tun_name_other.go 分支；server_windows.go 有重试与旧系统 EnforceBindInterface 的补丁。
  - Linux：tun_name_linux.go:12 用 TUNGETIFF ioctl 拿设备名；支持 auto-redirect + redirect_linux.go 生成 nft/iptables 规则；支持双路由表。
  - macOS：tun_name_darwin.go:5 通过 SYSPROTO_CONTROL 拿 utunN 名；设备走 utun。

  八、一句话总结

  mihomo 的"用户态 TUN 栈"= sing-tun 打开虚拟网卡 + gVisor/system/mixed 协议栈 + ListenerHandler 适配器 + Tunnel 
  路由。自己不写协议栈，只写回调：IP 包进来被栈变成 net.Conn，ListenerHandler 打包成 Metadata 塞给 tunnel，tunnel
  选出站、拨号、双向中继；DNS 在最外层被提前短路。

✻ Sautéed for 3m 7s

❯ 我现在需要实现一个全劫持栈，劫持全部流量，然后用户态重组，当目的ip为公网ip时，走socks5通道，如果socks5没有开启，走物理网卡通道。目的ip是 
  内网ip时，检测其是否落在overlay内，如果不是，走物理网卡，如果是，走overlay。此时为了避免socks5通道的包需要两次进入tun（一次主机进tun，一 
  次tun进隧道），我需要你在用户侧模拟栈劫持的时候，直接封装为隧道包发送到隧道里。给一个计划                                                

  Read 8 files, listed 4 directories (ctrl+o to expand)     
           
● 下面是落地这个"全劫持 + 分流 + 免二次入 TUN"栈的计划。分阶段，逐步可验证，先不动协议。
                                      
  一、关键设计决断（先锚住，再开工）                                                                                                   

  1. 栈选型：gVisor netstack（sagernet/gvisor，已在 go.mod 间接依赖）。理由：纯用户态、跨平台、允许自己掌控路由表与 Endpoint，不像 system  
  stack 会把 socket 下发给内核导致你无法拦截 SOCKS5 上行流量。放弃 sing-tun 的 tun.NewStack 壳子，直接用 gVisor 的 stack.Stack ——
  因为我们需要在同一个栈里挂两块 NIC（tun 侧 + overlay 侧），sing-tun 的 StackOptions 只认一块。                                           
  2. 分流点放在"栈之前"还是"栈之后"：两个都要。    
    - 栈前按 IP 分类（TUN 读到原始包时）：overlay 内网包 → 直接透传 tap，不进栈；其它（公网 + 非 overlay 内网）→ 喂进 gVisor。理由：overlay
   peer 到 peer 要端到端 TCP 透明，不应被你重组；重组后会破坏对端的 MSS/SACK/时序。
    - 栈后按目的分类（handler NewConnection 拿到 net.Conn 时）：公网 + SOCKS5 开 → 走 SOCKS5-over-overlay；公网 + SOCKS5 关 或 非 overlay
  内网 → physical NIC bypass dial。
  3. SOCKS5 走隧道的姿态：不要在用户侧起一个真 TCP socket 连对端 SOCKS5 监听端口，那就是你担心的二次入 TUN。两种做法，二选一：
    - A. Mux 通道（推荐）：在现有 transport.Conn 上新开一种帧类型 EtherTypeSocks5Stream（或独立子协议），每个 socks5 流分配一个
  stream-id，client 端用户态把 SOCKS5 报文直接当 payload 塞进帧里；peer 端收到后，在本机 loopback 连到本地 SOCKS5 server
  转发字节。协议面多一点工作，但完全绕过任何 TCP 协议栈。
    - B. gVisor 两块 NIC 合成真 SYN：在用户态 gVisor 里 Dial SOCKS5 server 的 overlay IP，出口 NIC 是 overlay NIC（write 回调直接写
  transport.Conn 的 ethernet 帧），对端 TUN 自然地把它变成真 TCP 连接到自家 SOCKS5。协议不用改，但 client 端要跑完整 TCP
  栈、重传、拥塞控制，overlay 一跳还得再在对端内核跑一遍 TCP，性能不如 A。

  建议选 A。既然已经在改全栈劫持，不差多加一个帧类型；省一层 TCP 重组是真金白银。
  4. physical NIC bypass：被判为"走物理网卡"的流，从 gVisor 中 Dial 出去时，必须绕开 TUN。手段：
    - Linux：SO_BINDTODEVICE 到物理默认接口 + 在 TUN 上把物理默认网关 IP 或该目的 IP 排除（sing-tun 的
  Inet4RouteExcludeAddress），或者直接用 socket mark + ip rule。
    - macOS：IP_BOUND_IF + utun 路由排除。
    - Windows：SIO_INDEX_BIND / setIpUnicastIpAddressEntry skip + Wintun 路由表 metric。
    - 统一做法：维护一个 "bypass dialer"，net.Dialer.Control 里绑到 defaultInterfaceMonitor 给的物理接口 index。gVisor 在 handler 里拿到
  net.Conn 目标 IP，就用 bypass dialer 出站，双向 splice。

  二、现有代码改点盘点

  - tun/tun.go:133-134：Inet4RouteAddress 当前只路由自己 IP，这是"窄路由"。全劫持要改成 0.0.0.0/0 + 维护 exclude 列表（本机 physical
  gateway、overlay operator endpoint、SOCKS5-over-overlay 用不到 exclude）。
  - client/vtap/device.go：ingressLoop/egressLoop 现在是 TUN 和 overlay conn 的直通（只剥/加 ethernet 头）。这套保留，但 egressLoop
  前面要加一个 classifier：overlay-prefix 命中 → 走现在的 shipIP；否则丢给 gVisor 栈。
  - client/client.go：构造 vtap 之后，再起一个 gVisor 栈，两块 NIC：
    - NIC-1 "tun"：LinkEndpoint 的 write 回调是 tun.Write，read 是 classifier 里未命中 overlay 的旁路 chan。
    - NIC-2 "overlay"：write 回调是 vtap.shipIP(ipPkt, arpLookup(dst))，read 是 overlay conn 收到但目的是 gVisor synthesized src IP
  的帧（即对端给我们的 SOCKS5 mux 或 bypass-dial 回包 —— 若走方案 A，这块不需要）。
  - client/quicksocks5/：保持 server 端不变（对端提供）；client 端新增 quicksocks5/mux.go，在 overlay 帧上跑 stream-id + socks5 payload。
  - 需要一个新包 client/netstack/：gVisor stack 构造 + handler。

  三、阶段化实施

  Phase 0 — 路由与旁路基线（不动栈）

  - 把 TUN 改为全劫持 + exclude：overlay operator server IP、物理默认 gateway、可选 loopback 段。
  - 写一个 physdialer 包：按平台 bind 物理接口的 Dialer，跑单元测试（能 dial 8.8.8.8:443 不经 TUN）。
  - 验收：改成 0.0.0.0/0 路由后，系统里 curl 8.8.8.8 应该断（因为 vtap 没有 overlay 出口给公网）；physdialer.Dial("8.8.8.8:443") 仍能通。

  Phase 1 — 栈前分类（overlay 内网透传 vs 其它进栈）

  - 在 vtap.egressLoop 里引入 classify(dstIP)：
    - 若 dstIP ∈ allowedRanges（overlay）→ 原路径 shipIP。
    - 否则投到 toStackCh。
  - 起一个 stub "stack"：先不用 gVisor，就 drop toStackCh，验证 overlay 对端可达性不变。
  - 同时从 overlay 侧分类：vtap ingress 收到目的是自己的 IP 且不是 overlay 源 → 投给 stack（日后给栈上行）。

  Phase 2 — 接入 gVisor，跑通 physical-NIC bypass 路径

  - 构造 stack.Stack（一块 NIC attach 到 toStackCh / 出向回写 TUN 的 LinkEndpoint）。
  - 开 IP forwarding + TCP/UDP forwarder。TCP handler：拿到 gonet.Conn + 目标 addr → physdialer.Dial(target) → io.Copy 双向。UDP 同理（用
  gVisor 的 UDPForwarder）。
  - 此时暂不接 SOCKS5，公网流全部物理网卡 bypass。
  - 验收：主机 curl ipinfo.io 能通，抓包看从物理网卡出，TUN 上没有 SOCKS5-server 的包。

  Phase 3 — SOCKS5-over-overlay mux（避免二次入 TUN）

  - 定义帧格式：EtherTypeGaMux（新 EtherType）+ 头 {streamID uint32, flags uint8 (SYN/DATA/FIN/RST), len uint16} + payload。把现有 ethernet
   帧字节流复用即可，走 transport.Conn.WritePacket。
  - client 端：muxDialer.Dial(target) → 分配 streamID → 发 SYN 帧，payload 是 SOCKS5 greeting + CONNECT 请求的字节流；读回复组装 net.Conn。
  - server 端 peer：muxListener 收到 SYN → 本地 net.Dial("tcp", "127.0.0.1:socks5port") → 把 stream 字节双向 pipe 到本地 SOCKS5
  server；FIN/RST 转 close。
  - gVisor handler 分支：isPublic(dst) && socks5Available → muxDialer.Dial(dst) 代替 physdialer.Dial(dst)。

  Phase 4 — SOCKS5 可用性探测与回退

  - client 在 handshake / keepalive 里加一个字段或探测帧，询问 overlay 是否有 peer 启用 --quick-socks5。维护 socks5Available atomic.Bool。
  - gVisor handler 查 bool：false → 回 Phase 2 的 physdialer 路径。

  Phase 5 — UDP、DNS、ICMP 扫尾

  - UDP 公网走 SOCKS5 ASSOCIATE（mux 的 DATAGRAM 帧）；非 overlay 内网 UDP 走 physdialer。
  - DNS 劫持：参考 mihomo sing_tun/dns.go，命中 TUN 网关 IP:53 → 直接用 mux-socks5 或 physdialer 解析。
  - ICMP：默认 drop（或在栈里回 echo reply 给 ping）。

  四、要提前想清楚的坑

  - MTU 串联：TUN MTU = 1500（或当前 common.TunMTU），overlay transport 每跳再包一层 ethernet + quic/tcp/udp。mux 帧 payload 最大 = overlay
   MTU - 头部。gVisor 出 TUN 的 MSS 要按 overlay 实际可承载算一次 PMTU，否则在 SOCKS5 路径会碎片。
  - ARP 与 SOCKS5-server MAC 发现：mux 帧要填 dst VMAC，但 SOCKS5 peer 的 VMAC 可能不在 ARP 表。需要一次 ARP 或由 operator 下发 peer 清单。
  - 连接数：toStackCh 会成为瓶颈，gVisor 的 LinkEndpoint 是 per-packet，要用有 buffer 的 channel + 多 worker，不然高并发会丢包。
  - route exclude 动态化：overlay operator 的 endpoint 可能多个、可能漂移；Phase 0 的 exclude 列表得接 defaultInterfaceMonitor 的回调，重建
   TUN 路由。
  - StrictRoute: true 当前开着，改全劫持后和 exclude 规则有冲突，需要测一遍特别是 Windows Wintun。
  - 回环保护：gVisor synthesized 的 SYN 如果目的 IP = 本机 overlay IP，别绕回自己。classifier 要排除 self-IP。

  五、里程碑验收（粗口径）

  ┌───────┬────────────────────────────────────────────────────────────────────────────────────┐
  │ Phase │                                        验收                                        │
  ├───────┼────────────────────────────────────────────────────────────────────────────────────┤
  │ 0     │ TUN 全劫持路由生效 + physdialer 单测过                                             │
  ├───────┼────────────────────────────────────────────────────────────────────────────────────┤
  │ 1     │ overlay 内网 ping/TCP 不回归，公网不通                                             │
  ├───────┼────────────────────────────────────────────────────────────────────────────────────┤
  │ 2     │ 公网 TCP/UDP 走物理网卡（tcpdump 物理接口）                                        │
  ├───────┼────────────────────────────────────────────────────────────────────────────────────┤
  │ 3     │ 关掉物理 bypass，公网 TCP 能走 overlay SOCKS5，抓 TUN 看不到 SOCKS5 server IP 的包 │
  ├───────┼────────────────────────────────────────────────────────────────────────────────────┤
  │ 4     │ 拔掉 peer 的 --quick-socks5，公网流自动降级到物理                                  │
  ├───────┼────────────────────────────────────────────────────────────────────────────────────┤
  │ 5     │ UDP/DNS/ICMP 齐活                                                                  │
  └───────┴────────────────────────────────────────────────────────────────────────────────────┘

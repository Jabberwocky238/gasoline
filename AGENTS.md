# AGENTS.md

## 参考 (3rdparty)

`3rdparty/` 目录下克隆了以下第三方仓库，仅作设计/实现参考，不参与构建：

| 目录 | 上游仓库 | 简介 |
| --- | --- | --- |
| `3rdparty/calico` | https://github.com/projectcalico/calico | Kubernetes / 裸金属网络与网络策略方案（BGP、eBPF、VPP 数据面）。 |
| `3rdparty/cilium` | https://github.com/cilium/cilium | 基于 eBPF 的 Kubernetes CNI、服务网格与可观测性平台。 |
| `3rdparty/cloudflared` | https://github.com/cloudflare/cloudflared | Cloudflare Tunnel 客户端，反向连接 + QUIC 隧道。 |
| `3rdparty/flannel` | https://github.com/flannel-io/flannel | 简易 Kubernetes overlay 网络（VXLAN / host-gw 等）。 |
| `3rdparty/gobgp` | https://github.com/osrg/gobgp | 纯 Go 实现的 BGP 协议栈，支持 BGP-LU、L3VPN/EVPN、MPLS 标签分发。 |
| `3rdparty/mihomo` | https://github.com/MetaCubeX/mihomo | 多协议代理内核（Clash.Meta 衍生），规则引擎与多入站/出站。 |
| `3rdparty/ovs` | https://github.com/openvswitch/ovs | Open vSwitch，多层虚拟交换机，支持 OpenFlow / OVSDB。 |
| `3rdparty/pangolin` | https://github.com/fosrl/pangolin | 自托管隧道反代，基于 WireGuard 暴露内网服务。 |
| `3rdparty/pola` | https://github.com/nttcom/pola | 纯 Go 实现的 Stateful PCE / PCEP，支持 SR-MPLS、Segment Routing。 |
| `3rdparty/sing-box` | https://github.com/SagerNet/sing-box | 通用代理平台，多协议入/出站、路由与 DNS。 |
| `3rdparty/sing-tun` | https://github.com/SagerNet/sing-tun | TUN 设备封装库，gVisor / system stack，跨平台。 |
| `3rdparty/wireguard-go` | https://github.com/WireGuard/wireguard-go | WireGuard 的官方 Go 用户态实现。 |

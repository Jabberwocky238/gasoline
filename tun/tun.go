package tun

import (
	"fmt"
	"net/netip"

	"wwww/config"
	"wwww/tun/common/log"

	singTun "github.com/jabberwocky238/sing-tun"
	// "github.com/metacubex/sing/common/ranges"
)

const DefaultMTU = 1500

// Start-Process cmd -Verb RunAs
func NewTun(tunName string, config *config.Config) (singTun.Tun, error) {
	InetAddress := netip.MustParsePrefix(config.Interface.Address)
	var allowedIPs []netip.Prefix
	for _, peer := range config.Peers {
		allowedIP, err := netip.ParsePrefix(peer.AllowedIPs)
		if err != nil {
			return nil, err
		}
		allowedIPs = append(allowedIPs, allowedIP)
	}

	InetAddress, err := calcAddressAndMask(InetAddress, allowedIPs)
	if err != nil {
		return nil, err
	}
	fmt.Printf("InetAddress: %v\n", InetAddress)

	var Inet4Address []netip.Prefix
	var Inet6Address []netip.Prefix
	// var Inet4Gateway netip.Addr
	// var Inet6Gateway netip.Addr
	if InetAddress.Addr().Is4() {
		Inet4Address = []netip.Prefix{InetAddress}
	} else if InetAddress.Addr().Is6() {
		Inet6Address = []netip.Prefix{InetAddress}
	} else {
		return nil, fmt.Errorf("unknown address type")
	}
	// Gateway就是InetAddress
	// if InetAddress.Addr().Is4() {
	// 	Inet4Gateway = netip.AddrFrom4(InetAddress.Addr().As4())
	// } else {
	// 	Inet6Gateway = netip.AddrFrom16(InetAddress.Addr().As16())
	// }

	// SING-TUN
	networkUpdateMonitor, err := singTun.NewNetworkUpdateMonitor(log.SingLogger)
	if err != nil {
		return nil, err
	}
	interfaceMonitorOptions := singTun.DefaultInterfaceMonitorOptions{
		OverrideAndroidVPN: false,
	}
	interfaceMonitor, err := singTun.NewDefaultInterfaceMonitor(networkUpdateMonitor, log.SingLogger, interfaceMonitorOptions)
	if err != nil {
		return nil, fmt.Errorf("create DefaultInterfaceMonitor: %v", err)
	}

	tunOptions := singTun.Options{
		Name:         tunName,
		Inet4Address: Inet4Address,
		Inet6Address: Inet6Address,
		MTU:          DefaultMTU, // 使用标准MTU大小
		GSO:          false,      // 在Linux下禁用GSO以避免兼容性问题
		AutoRoute:    false,      // 禁用自动路由配置，使用手动路由
		// Inet4Gateway: Inet4Gateway,  // 模仿wireguard行为
		// Inet6Gateway: Inet6Gateway,  // 模仿wireguard行为
		// DNSServers: []netip.Addr{},
		IPRoute2TableIndex:     singTun.DefaultIPRoute2TableIndex,
		IPRoute2RuleIndex:      singTun.DefaultIPRoute2RuleIndex,
		AutoRedirectMarkMode:   false,
		AutoRedirectInputMark:  singTun.DefaultAutoRedirectInputMark,
		AutoRedirectOutputMark: singTun.DefaultAutoRedirectOutputMark,
		Inet4LoopbackAddress: []netip.Addr{
			netip.MustParseAddr("127.0.0.1"),
		},
		Inet6LoopbackAddress: []netip.Addr{
			netip.MustParseAddr("::1"),
		},
		StrictRoute:       false,
		Inet4RouteAddress: Inet4Address, // 只路由VPN网段的流量，不劫持所有流量
		Inet6RouteAddress: Inet6Address, // 只路由VPN网段的流量，不劫持所有流量
		// Inet4RouteExcludeAddress: []netip.Prefix{},
		// Inet6RouteExcludeAddress: []netip.Prefix{},
		// IncludeInterface:         []string{},
		// ExcludeInterface:         []string{},
		// IncludeUID:               []ranges.Range[uint32]{},
		// ExcludeUID:               []ranges.Range[uint32]{},
		// ExcludeSrcPort:           []ranges.Range[uint16]{},
		// ExcludeDstPort:           []ranges.Range[uint16]{},
		// IncludeAndroidUser:       []int{},
		// IncludePackage:           []string{},
		// ExcludePackage:           []string{},
		InterfaceMonitor: interfaceMonitor,
		// EXP_RecvMsgX:             false,
		// EXP_SendMsgX:             false,
		Logger: log.SingLogger,
	}

	tunIf, err := tunNew(tunOptions)
	if err != nil {
		log.Errorln("Error creating tun: %v", err)
		return nil, err
	}
	return tunIf, nil
}

func calcAddressAndMask(interfaceAddress netip.Prefix, allowedIPs []netip.Prefix) (netip.Prefix, error) {
	// 获取接口IP地址
	addr := interfaceAddress.Addr()

	// 过滤出与interfaceAddress在同一网段的allowedIPs
	var sameNetworkIPs []netip.Prefix
	for _, allowedIP := range allowedIPs {
		// 检查两个IP是否在同一网段（使用较短的掩码）
		minBits := interfaceAddress.Bits()
		if allowedIP.Bits() < minBits {
			minBits = allowedIP.Bits()
		}
		network1 := netip.PrefixFrom(interfaceAddress.Addr(), minBits).Masked()
		network2 := netip.PrefixFrom(allowedIP.Addr(), minBits).Masked()
		if network1 == network2 {
			sameNetworkIPs = append(sameNetworkIPs, allowedIP)
		}
	}

	// 如果没有同网段的IP，使用接口地址
	if len(sameNetworkIPs) == 0 {
		return interfaceAddress, nil
	}

	// 计算最短子网掩码（最大前缀长度）
	minBits := interfaceAddress.Bits()
	for _, ip := range sameNetworkIPs {
		if ip.Bits() < minBits {
			minBits = ip.Bits()
		}
	}

	return netip.PrefixFrom(addr, minBits), nil
}

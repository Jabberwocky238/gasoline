//go:build !windows

package tun

import (
	tun "github.com/jabberwocky238/sing-tun"
)

func tunNew(options tun.Options) (tun.Tun, error) {
	options.FileDescriptor = 0
	return tun.New(options)
}

// # 1. 检查TUN设备状态
// ip addr show tuntun

// # 2. 如果设备不存在，创建它
// sudo ip tuntap add dev tuntun mode tun
// sudo ip addr add 10.0.0.1/24 dev tun0  # 客户端
// sudo ip link set tuntun up

// # 3. 检查设备是否UP
// ip link show tun0

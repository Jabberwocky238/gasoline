// go:build !windows

package device

import "wwww/tun"

// initializeTUN 初始化 TUN 设备
func (d *Device) initializeTUN() error {
	// 这里需要根据实际的 TUN 实现来调用
	// 假设有一个 CreateTUN 函数
	tunDevice, err := tun.CreateTUN("tun0", 1420)
	if err != nil {
		return err
	}
	d.tunDevice = tunDevice
	return nil
}

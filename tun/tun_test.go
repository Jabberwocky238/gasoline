package tun

import (
	"net/netip"
	"testing"
)

func TestCalcAddressAndMask(t *testing.T) {
	// 测试用例
	interfaceAddress := netip.MustParsePrefix("10.0.0.1/32")
	allowedIPs := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.2/24"),
		netip.MustParsePrefix("10.0.0.3/32"),
		netip.MustParsePrefix("192.168.0.1/16"),
	}
	expected := netip.MustParsePrefix("10.0.0.1/24")

	// 执行测试
	result, err := calcAddressAndMask(interfaceAddress, allowedIPs)
	if err != nil {
		t.Fatalf("calcAddressAndMask returned error: %v", err)
	}

	// 调试信息
	t.Logf("Interface: %v", interfaceAddress)
	t.Logf("AllowedIPs: %v", allowedIPs)
	t.Logf("Result: %v", result)
	t.Logf("Expected: %v", expected)

	// 验证结果
	if result != expected {
		t.Errorf("calcAddressAndMask() = %v, want %v", result, expected)
	}

	// 验证IP地址
	if result.Addr() != interfaceAddress.Addr() {
		t.Errorf("IP address = %v, want %v", result.Addr(), interfaceAddress.Addr())
	}

	// 验证前缀长度
	if result.Bits() != 24 {
		t.Errorf("Prefix length = %d, want 24", result.Bits())
	}
}

func TestCalcAddressAndMaskNoMatchingIPs(t *testing.T) {
	// 测试没有匹配IP的情况
	interfaceAddress := netip.MustParsePrefix("10.0.0.1/32")
	allowedIPs := []netip.Prefix{
		netip.MustParsePrefix("192.168.0.1/16"),
		netip.MustParsePrefix("172.16.0.1/12"),
	}
	expected := interfaceAddress

	result, err := calcAddressAndMask(interfaceAddress, allowedIPs)
	if err != nil {
		t.Fatalf("calcAddressAndMask returned error: %v", err)
	}

	if result != expected {
		t.Errorf("calcAddressAndMask() = %v, want %v", result, expected)
	}
}

func TestCalcAddressAndMaskEmptyAllowedIPs(t *testing.T) {
	// 测试空的allowedIPs
	interfaceAddress := netip.MustParsePrefix("10.0.0.1/24")
	allowedIPs := []netip.Prefix{}
	expected := interfaceAddress

	result, err := calcAddressAndMask(interfaceAddress, allowedIPs)
	if err != nil {
		t.Fatalf("calcAddressAndMask returned error: %v", err)
	}

	if result != expected {
		t.Errorf("calcAddressAndMask() = %v, want %v", result, expected)
	}
}

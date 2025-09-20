package config

import (
	"fmt"
	"testing"
)

func TestParseConfigFromString(t *testing.T) {
	tests := []struct {
		name     string
		config   string
		expected map[string]interface{}
	}{
		{
			name: "server config with no endpoints",
			config: `
[Interface]
UniqueID = "kP3gpdm72QExS/uwfVS/+H88IkMTaMD38GNgNpecyxc="
ListenPort = 51820
Address = "10.0.0.1/24"

[[Peer]]
UniqueID = "uLSvhLaefcFG8EB/jAaioIKz9YhpoJ3JinbK+m+O8Ec="
AllowedIPs = "10.0.0.2/32"

[[Peer]]
UniqueID = "lCcCFRczyZ5f4y3PBoLccBdjMGzGjz8rU6RCcHXuTio="
AllowedIPs = "10.0.0.3/32"
`,
			expected: map[string]interface{}{
				"interface_unique_id":   "kP3gpdm72QExS/uwfVS/+H88IkMTaMD38GNgNpecyxc=",
				"interface_listen_port": 51820,
				"interface_address":     "10.0.0.1/24",
				"peers_count":           2,
				"peer1_unique_id":       "uLSvhLaefcFG8EB/jAaioIKz9YhpoJ3JinbK+m+O8Ec=",
				"peer1_allowed_ips":     "10.0.0.2/32",
				"peer1_endpoint":        "",
				"peer2_unique_id":       "lCcCFRczyZ5f4y3PBoLccBdjMGzGjz8rU6RCcHXuTio=",
				"peer2_allowed_ips":     "10.0.0.3/32",
				"peer2_endpoint":        "",
			},
		},
		{
			name: "client config with endpoint",
			config: `
[Interface]
UniqueID = "uLSvhLaefcFG8EB/jAaioIKz9YhpoJ3JinbK+m+O8Ec="
Address = "10.0.0.2/32"

[[Peer]]
UniqueID = "kP3gpdm72QExS/uwfVS/+H88IkMTaMD38GNgNpecyxc="
AllowedIPs = "10.0.0.1/24"
Endpoint = "127.0.0.1:51820"
`,
			expected: map[string]interface{}{
				"interface_unique_id":   "uLSvhLaefcFG8EB/jAaioIKz9YhpoJ3JinbK+m+O8Ec=",
				"interface_listen_port": 0,
				"interface_address":     "10.0.0.2/32",
				"peers_count":           1,
				"peer1_unique_id":       "kP3gpdm72QExS/uwfVS/+H88IkMTaMD38GNgNpecyxc=",
				"peer1_allowed_ips":     "10.0.0.1/24",
				"peer1_endpoint":        "127.0.0.1:51820",
			},
		},
		{
			name: "mixed config with some endpoints",
			config: `
[Interface]
UniqueID = "server123"
ListenPort = 51820
Address = "10.0.0.1/24"

[[Peer]]
UniqueID = "client1"
AllowedIPs = "10.0.0.2/32"
Endpoint = "192.168.1.100:51820"

[[Peer]]
UniqueID = "client2"
AllowedIPs = "10.0.0.3/32"

[[Peer]]
UniqueID = "server2"
AllowedIPs = "10.0.0.4/32"
Endpoint = "192.168.1.200:51820"
`,
			expected: map[string]interface{}{
				"interface_unique_id":   "server123",
				"interface_listen_port": 51820,
				"interface_address":     "10.0.0.1/24",
				"peers_count":           3,
				"peer1_unique_id":       "client1",
				"peer1_allowed_ips":     "10.0.0.2/32",
				"peer1_endpoint":        "192.168.1.100:51820",
				"peer2_unique_id":       "client2",
				"peer2_allowed_ips":     "10.0.0.3/32",
				"peer2_endpoint":        "",
				"peer3_unique_id":       "server2",
				"peer3_allowed_ips":     "10.0.0.4/32",
				"peer3_endpoint":        "192.168.1.200:51820",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := ParseConfigFromString(tt.config)
			if err != nil {
				t.Fatalf("解析配置失败: %v", err)
			}

			// 检查Interface配置
			if config.Interface.UniqueID != tt.expected["interface_unique_id"] {
				t.Errorf("Interface.UniqueID = %v, 期望 %v", config.Interface.UniqueID, tt.expected["interface_unique_id"])
			}
			if config.Interface.ListenPort != tt.expected["interface_listen_port"] {
				t.Errorf("Interface.ListenPort = %v, 期望 %v", config.Interface.ListenPort, tt.expected["interface_listen_port"])
			}
			if config.Interface.Address != tt.expected["interface_address"] {
				t.Errorf("Interface.Address = %v, 期望 %v", config.Interface.Address, tt.expected["interface_address"])
			}

			// 检查Peers数量
			if len(config.Peers) != tt.expected["peers_count"] {
				t.Errorf("Peers数量 = %v, 期望 %v", len(config.Peers), tt.expected["peers_count"])
			}

			// 检查每个Peer的配置
			for i, peer := range config.Peers {
				peerNum := i + 1
				uniqueIDKey := fmt.Sprintf("peer%d_unique_id", peerNum)
				allowedIPsKey := fmt.Sprintf("peer%d_allowed_ips", peerNum)
				endpointKey := fmt.Sprintf("peer%d_endpoint", peerNum)

				if peer.UniqueID != tt.expected[uniqueIDKey] {
					t.Errorf("Peer%d.UniqueID = %v, 期望 %v", peerNum, peer.UniqueID, tt.expected[uniqueIDKey])
				}
				if peer.AllowedIPs != tt.expected[allowedIPsKey] {
					t.Errorf("Peer%d.AllowedIPs = %v, 期望 %v", peerNum, peer.AllowedIPs, tt.expected[allowedIPsKey])
				}
				if peer.Endpoint != tt.expected[endpointKey] {
					t.Errorf("Peer%d.Endpoint = %v, 期望 %v", peerNum, peer.Endpoint, tt.expected[endpointKey])
				}

				// 特别检查endpoint是否为空字符串（而不是nil）
				if peer.Endpoint == "" {
					t.Logf("Peer%d.Endpoint 为空字符串（正确）", peerNum)
				} else {
					t.Logf("Peer%d.Endpoint = %s", peerNum, peer.Endpoint)
				}
			}
		})
	}
}

func TestEndpointParsing(t *testing.T) {
	// 测试空endpoint的情况
	config := `
[Interface]
UniqueID = "test"
Address = "10.0.0.1/24"

[[Peer]]
UniqueID = "peer1"
AllowedIPs = "10.0.0.2/32"
`

	parsed, err := ParseConfigFromString(config)
	if err != nil {
		t.Fatalf("解析配置失败: %v", err)
	}

	if len(parsed.Peers) != 1 {
		t.Fatalf("期望1个peer，实际%d个", len(parsed.Peers))
	}

	peer := parsed.Peers[0]

	// 检查endpoint是否为空字符串
	if peer.Endpoint != "" {
		t.Errorf("期望endpoint为空字符串，实际为: %s", peer.Endpoint)
	}

	// 检查endpoint长度
	if len(peer.Endpoint) != 0 {
		t.Errorf("期望endpoint长度为0，实际为: %d", len(peer.Endpoint))
	}

	t.Logf("Peer.Endpoint = '%s' (长度: %d)", peer.Endpoint, len(peer.Endpoint))
}

func TestRealConfigFiles(t *testing.T) {
	// 测试server.toml
	serverConfig, err := ParseConfig("../tests/server.toml")
	if err != nil {
		t.Fatalf("解析server.toml失败: %v", err)
	}

	t.Logf("Server配置:")
	t.Logf("  Interface.UniqueID = %s", serverConfig.Interface.UniqueID)
	t.Logf("  Interface.ListenPort = %d", serverConfig.Interface.ListenPort)
	t.Logf("  Peers数量 = %d", len(serverConfig.Peers))

	for i, peer := range serverConfig.Peers {
		t.Logf("  Peer%d:", i+1)
		t.Logf("    UniqueID = %s", peer.UniqueID)
		t.Logf("    AllowedIPs = %s", peer.AllowedIPs)
		t.Logf("    Endpoint = '%s' (长度: %d)", peer.Endpoint, len(peer.Endpoint))

		// 验证server配置中的peers没有endpoint
		if peer.Endpoint != "" {
			t.Errorf("Server配置中的Peer%d不应该有endpoint，但发现: %s", i+1, peer.Endpoint)
		}
	}

	// 测试client.toml
	clientConfig, err := ParseConfig("../tests/client.toml")
	if err != nil {
		t.Fatalf("解析client.toml失败: %v", err)
	}

	t.Logf("\nClient配置:")
	t.Logf("  Interface.UniqueID = %s", clientConfig.Interface.UniqueID)
	t.Logf("  Interface.ListenPort = %d", clientConfig.Interface.ListenPort)
	t.Logf("  Peers数量 = %d", len(clientConfig.Peers))

	for i, peer := range clientConfig.Peers {
		t.Logf("  Peer%d:", i+1)
		t.Logf("    UniqueID = %s", peer.UniqueID)
		t.Logf("    AllowedIPs = %s", peer.AllowedIPs)
		t.Logf("    Endpoint = '%s' (长度: %d)", peer.Endpoint, len(peer.Endpoint))

		// 验证client配置中的peer有endpoint
		if peer.Endpoint == "" {
			t.Errorf("Client配置中的Peer%d应该有endpoint，但为空", i+1)
		}
	}
}

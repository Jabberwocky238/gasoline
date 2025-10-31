package trojan

import "fmt"

type Config struct {
	LocalHost        string      `json:"local_addr" yaml:"local-addr"`
	LocalPort        int         `json:"local_port" yaml:"local-port"`
	RemoteHost       string      `json:"remote_addr" yaml:"remote-addr"`
	RemotePort       int         `json:"remote_port" yaml:"remote-port"`
	DisableHTTPCheck bool        `json:"disable_http_check" yaml:"disable-http-check"`
	MySQL            MySQLConfig `json:"mysql" yaml:"mysql"`
	HTTP             HTTPConfig  `json:"http" yaml:"http"`
	API              APIConfig   `json:"api" yaml:"api"`
}

type MySQLConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

type HTTPConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

type APIConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

const (
	KiB = 1024
	MiB = KiB * 1024
	GiB = MiB * 1024
)

func HumanFriendlyTraffic(bytes uint64) string {
	if bytes <= KiB {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes <= MiB {
		return fmt.Sprintf("%.2f KiB", float32(bytes)/KiB)
	}
	if bytes <= GiB {
		return fmt.Sprintf("%.2f MiB", float32(bytes)/MiB)
	}
	return fmt.Sprintf("%.2f GiB", float32(bytes)/GiB)
}

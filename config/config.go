package config

// Interface 配置结构体
type Interface struct {
	PrivateKey string `toml:"PrivateKey"`
	ListenPort int    `toml:"ListenPort"`
	Address    string `toml:"Address"`
}

// Peer 配置结构体
type Peer struct {
	PublicKey  string `toml:"PublicKey"`
	AllowedIPs string `toml:"AllowedIPs"`
	Endpoint   string `toml:"Endpoint"`
}

// Config 主配置结构体
type Config struct {
	Interface Interface `toml:"Interface"`
	Peers     []Peer    `toml:"Peer"`
}

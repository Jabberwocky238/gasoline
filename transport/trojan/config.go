package trojan

type ServerConfig struct {
	RedirectHost string `json:"redirect_host" yaml:"redirect-host"`
	RedirectPort int    `json:"redirect_port" yaml:"redirect-port"`
	// DisableHTTPCheck bool        `json:"disable_http_check" yaml:"disable-http-check"`
	// MySQL            MySQLConfig `json:"mysql" yaml:"mysql"`
	// HTTP             HTTPConfig  `json:"http" yaml:"http"`
	// API              APIConfig   `json:"api" yaml:"api"`

	Passwords []string `json:"passwords" yaml:"passwords"`
}

type ClientConfig struct {
	Password string `json:"password" yaml:"password"`
}

// type MySQLConfig struct {
// 	Enabled bool `json:"enabled" yaml:"enabled"`
// }

// type HTTPConfig struct {
// 	Enabled bool `json:"enabled" yaml:"enabled"`
// }

// type APIConfig struct {
// 	Enabled bool `json:"enabled" yaml:"enabled"`
// }

package config

type OperatorConfig struct {
	UUID            *[16]byte
	ClientListeners []ListenerSpec
	OpListenAddr    string
	OpExternalAddr  string
	AuthStr         string
	NetworkAuth     map[VNI]string
	Network         string
	StatsAddr       string
	DiscoverAddrs   []string
	WatchDir        string
	EnableFswatch   bool
	EnableSigreload bool
	EnableK8s       bool
	K8sNamespace    string
	LogLevel        string
}

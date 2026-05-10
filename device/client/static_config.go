package client

import (
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/sirupsen/logrus"
)

// StaticClientConfig is the resolved runtime configuration handed to New.
// Construction is the binary's job (see cmd/client); this package only
// owns the runtime types.
type StaticClientConfig struct {
	Endpoint  string
	Transport string
	AuthStr   string
	VNI       protocol.VNI_Ty
	CID       protocol.CID_Ty

	// TUNName selects which OS TUN device to open. Empty disables TUN
	// integration; in that mode the Client is a raw send/receive pipe.
	// The TUN's IP comes from the handshake's assigned Prefix — we
	// cannot know it before Dial.
	TUNName string

	// Socks5Port (>0) enables a local SOCKS5 proxy bound to that port.
	// Zero disables it. Useful for routing app traffic through this
	// client without configuring routes / TUN at the OS level.
	Socks5Port int

	LogLevel logrus.Level
	Logger   *logrus.Logger
}

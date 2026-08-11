package client

import (
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/noise"
	"github.com/sirupsen/logrus"
)

// StaticClientConfig is the resolved runtime configuration handed to New.
// Construction is the binary's job (see cmd/client); this package only
// owns the runtime types.
//
// Identity is the Noise static key pair: the CID is derived from Pub, not
// configured. ServerPub is the operator's static public key, known out of
// band (like WireGuard's PublicKey=).
type StaticClientConfig struct {
	Endpoint  string
	Transport string
	VNI       protocol.VNI_Ty

	Priv      noise.PrivateKey
	Pub       noise.PublicKey
	ServerPub noise.PublicKey

	// TUNName selects which OS TUN device to open. Empty disables TUN
	// integration; in that mode the Client is a raw send/receive pipe.
	// The TUN's IP comes from the handshake's assigned Prefix — we
	// cannot know it before Dial.
	TUNName string

	LogLevel logrus.Level
	Logger   *logrus.Logger
}

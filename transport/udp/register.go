package udp

import (
	"crypto/tls"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

func init() {
	transport.Register("udp",
		func(cfg protocol.PresetSessionConfig, id transport.ClientIdentity, _ *tls.Config) (transport.Dialer, error) {
			return NewDialer(cfg, id), nil
		},
		func(addr string, mapper handshake.VNIMapperFn, _ *tls.Config) (transport.Listener, error) {
			return NewListener(addr, mapper)
		},
	)
}

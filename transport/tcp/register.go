package tcp

import (
	"crypto/tls"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

func init() {
	transport.Register("tcp",
		func(cfg protocol.PresetSessionConfig, a auth.ClientAuthenticator, _ *tls.Config) (transport.Dialer, error) {
			return NewDialer(cfg, a), nil
		},
		func(addr string, mapper handshake.VNIMapperFn, _ *tls.Config) (transport.Listener, error) {
			return NewListener(addr, mapper)
		},
	)
}

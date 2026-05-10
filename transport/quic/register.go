package quic

import (
	"crypto/tls"
	"fmt"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/transport"
)

func init() {
	transport.Register("quic",
		func(cfg protocol.PresetSessionConfig, a auth.ClientAuthenticator, tlsConf *tls.Config) (transport.Dialer, error) {
			if tlsConf == nil {
				return nil, fmt.Errorf("quic dialer: tlsConf required")
			}
			return NewDialer(cfg, a, tlsConf), nil
		},
		func(addr string, mapper handshake.VNIMapperFn, tlsConf *tls.Config) (transport.Listener, error) {
			if tlsConf == nil {
				return nil, fmt.Errorf("quic listener: tlsConf required")
			}
			return NewListener(addr, mapper, tlsConf)
		},
	)
}

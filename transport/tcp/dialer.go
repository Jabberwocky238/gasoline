package tcp

import (
	"net"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/transport"
)

type Dialer struct {
	vmac common.VMAC
	vni      common.VNI
	auth     auth.ClientAuthenticator
}

func NewDialer(vmac common.VMAC, vni common.VNI, auth auth.ClientAuthenticator) *Dialer {
	return &Dialer{vmac:     vmac, vni: vni, auth: auth}
}

func (d *Dialer) Dial(endpoint string) (transport.Conn, *protocol.HandshakeResult, error) {
	raw, err := net.Dial("tcp", endpoint)
	if err != nil {
		return nil, nil, err
	}
	result, err := protocol.ClientHandshake(raw, d.vmac, d.vni, d.auth)
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	return newConn(raw, result.Keypair), result, nil
}

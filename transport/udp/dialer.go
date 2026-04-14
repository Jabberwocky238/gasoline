package udp

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
	udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, nil, err
	}
	rawConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, nil, err
	}
	_ = rawConn.SetReadBuffer(8 * 1024 * 1024)
	_ = rawConn.SetWriteBuffer(8 * 1024 * 1024)

	adapter := newClientStreamAdapter(rawConn)
	result, err := protocol.ClientHandshake(adapter, d.vmac, d.vni, d.auth)
	if err != nil {
		rawConn.Close()
		return nil, nil, err
	}

	return newClientConn(rawConn, result.Keypair), result, nil
}

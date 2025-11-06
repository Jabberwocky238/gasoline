package device

import (
	"net"
	"wwww/transport"
)

type Handshake struct {
	conn   transport.TransportConn
	device *Device
	peer   *Peer
}

func NewHandshake(conn transport.TransportConn, device *Device, peer *Peer) *Handshake {
	return &Handshake{
		conn:   conn,
		device: device,
		peer:   peer,
	}
}

func (h *Handshake) SendHandshake() error {
	var buf = make([]byte, net.IPv4len+KeyLength)
	copy(buf[:net.IPv4len], h.peer.endpoint.local.String())
	copy(buf[net.IPv4len:], h.device.key.privateKey[:])
	_, err := h.conn.Write(buf)
	if err != nil {
		return err
	}
	return nil
}

func (h *Handshake) ReceiveHandshake() (pk *PublicKey, err error) {
	// there is no peer here
	var bufRequest = make([]byte, net.IPv4len+KeyLength)
	_, err = h.conn.Read(bufRequest)
	if err != nil {
		return nil, err
	}
	peerKey := PrivateKey(bufRequest[net.IPv4len:])
	publicKey := peerKey.PublicKey()
	return &publicKey, nil
}

package messages

import (
	"io"

	"github.com/jabberwocky238/gasoline/protocol/auth"
)

// ClientHello: version(1) + authType(1) + clientID(16) + vnetID(16) = 34 bytes
type ClientHello struct {
	Version  byte
	AuthType auth.Type
	ClientID [16]byte
	VNetID   [16]byte
}

func (m *ClientHello) WriteTo(w io.Writer) error {
	buf := make([]byte, 34)
	buf[0] = m.Version
	buf[1] = byte(m.AuthType)
	copy(buf[2:18], m.ClientID[:])
	copy(buf[18:34], m.VNetID[:])
	_, err := w.Write(buf)
	return err
}

func (m *ClientHello) ReadFrom(r io.Reader) error {
	buf := make([]byte, 34)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	m.Version = buf[0]
	m.AuthType = auth.Type(buf[1])
	copy(m.ClientID[:], buf[2:18])
	copy(m.VNetID[:], buf[18:34])
	return nil
}

package messages

import (
	"encoding/binary"
	"io"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol/auth"
)

// ClientHello: version(1) + authType(1) + clientID(6) + vni(4) = 12 bytes
// ClientID is a 6-byte MAC-sized identifier (used directly as inner Ethernet MAC).
type ClientHello struct {
	Version  byte
	AuthType auth.Type
	ClientID common.ClientID
	VNI      common.VNI
}

func (m *ClientHello) Encode(w io.Writer) error {
	buf := make([]byte, 12)
	buf[0] = m.Version
	buf[1] = byte(m.AuthType)
	copy(buf[2:8], m.ClientID[:])
	binary.BigEndian.PutUint32(buf[8:12], uint32(m.VNI))
	_, err := w.Write(buf)
	return err
}

func (m *ClientHello) Decode(r io.Reader) error {
	buf := make([]byte, 12)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	m.Version = buf[0]
	m.AuthType = auth.Type(buf[1])
	copy(m.ClientID[:], buf[2:8])
	m.VNI = common.VNI(binary.BigEndian.Uint32(buf[8:12]))
	return nil
}

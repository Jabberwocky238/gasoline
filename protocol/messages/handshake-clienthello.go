package messages

import (
	"encoding/binary"
	"io"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol/auth"
)

// ClientHello: version(1) + authType(1) + clientID(16) + vni(4) = 22 bytes
// VNI is a 24-bit value stored in the lower bits of a uint32.
type ClientHello struct {
	Version  byte
	AuthType auth.Type
	ClientID [16]byte
	VNI      common.VNI
}

func (m *ClientHello) Encode(w io.Writer) error {
	buf := make([]byte, 22)
	buf[0] = m.Version
	buf[1] = byte(m.AuthType)
	copy(buf[2:18], m.ClientID[:])
	binary.BigEndian.PutUint32(buf[18:22], uint32(m.VNI))
	_, err := w.Write(buf)
	return err
}

func (m *ClientHello) Decode(r io.Reader) error {
	buf := make([]byte, 22)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	m.Version = buf[0]
	m.AuthType = auth.Type(buf[1])
	copy(m.ClientID[:], buf[2:18])
	m.VNI = common.VNI(binary.BigEndian.Uint32(buf[18:22]))
	return nil
}

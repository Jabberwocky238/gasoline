package messages

import (
	"encoding/binary"
	"io"

	"github.com/jabberwocky238/gasoline/protocol/auth"
)

// ServerHello: version(1) + authType(1) + payloadLen(2) + payload(N)
type ServerHello struct {
	Version  byte
	AuthType auth.Type
	Payload  []byte
}

func (m *ServerHello) WriteTo(w io.Writer) error {
	header := make([]byte, 4)
	header[0] = m.Version
	header[1] = byte(m.AuthType)
	binary.BigEndian.PutUint16(header[2:], uint16(len(m.Payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(m.Payload) > 0 {
		_, err := w.Write(m.Payload)
		return err
	}
	return nil
}

func (m *ServerHello) ReadFrom(r io.Reader) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	m.Version = header[0]
	m.AuthType = auth.Type(header[1])
	payloadLen := binary.BigEndian.Uint16(header[2:])
	if payloadLen > 0 {
		m.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, m.Payload); err != nil {
			return err
		}
	}
	return nil
}

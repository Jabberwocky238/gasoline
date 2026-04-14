package messages

import (
	"encoding/binary"
	"io"
)

// ServerResponse: status(1) + configLen(2) + config(N)
type ServerResponse struct {
	Status byte
	Config []byte
}

func (m *ServerResponse) WriteTo(w io.Writer) error {
	header := make([]byte, 3)
	header[0] = m.Status
	binary.BigEndian.PutUint16(header[1:], uint16(len(m.Config)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(m.Config) > 0 {
		_, err := w.Write(m.Config)
		return err
	}
	return nil
}

func (m *ServerResponse) ReadFrom(r io.Reader) error {
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	m.Status = header[0]
	configLen := binary.BigEndian.Uint16(header[1:])
	if configLen > 0 {
		m.Config = make([]byte, configLen)
		if _, err := io.ReadFull(r, m.Config); err != nil {
			return err
		}
	}
	return nil
}

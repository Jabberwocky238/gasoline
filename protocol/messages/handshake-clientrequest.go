package messages

import (
	"encoding/binary"
	"io"
)

// ClientRequest: payloadLen(2) + payload(N)
type ClientRequest struct {
	Payload []byte
}

func (m *ClientRequest) Encode(w io.Writer) error {
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(m.Payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(m.Payload) > 0 {
		_, err := w.Write(m.Payload)
		return err
	}
	return nil
}

func (m *ClientRequest) Decode(r io.Reader) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	payloadLen := binary.BigEndian.Uint16(header)
	if payloadLen > 0 {
		m.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, m.Payload); err != nil {
			return err
		}
	}
	return nil
}

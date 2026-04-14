package messages

import (
	"encoding/binary"
	"fmt"
	"io"
)

// RawPayload carries unencrypted data over the wire.
//
// Wire format: payloadLen(2) + payload(N)
type RawPayload struct {
	Data []byte
}

func (m *RawPayload) Encode(w io.Writer) error {
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(m.Data)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(m.Data) > 0 {
		_, err := w.Write(m.Data)
		return err
	}
	return nil
}

func (m *RawPayload) Decode(r io.Reader) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	payloadLen := binary.BigEndian.Uint16(header)
	if payloadLen > 0 {
		m.Data = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, m.Data); err != nil {
			return err
		}
	}
	return nil
}

// MarshalBinary returns the wire-format bytes.
func (m *RawPayload) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 2+len(m.Data))
	binary.BigEndian.PutUint16(buf, uint16(len(m.Data)))
	copy(buf[2:], m.Data)
	return buf, nil
}

// UnmarshalBinary parses wire-format bytes.
func (m *RawPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("raw payload too short: %d bytes", len(data))
	}
	payloadLen := binary.BigEndian.Uint16(data)
	if len(data) < 2+int(payloadLen) {
		return fmt.Errorf("raw payload truncated: need %d, have %d", 2+payloadLen, len(data))
	}
	m.Data = make([]byte, payloadLen)
	copy(m.Data, data[2:2+payloadLen])
	return nil
}

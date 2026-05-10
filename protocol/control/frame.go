package control

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame layout, on every transport (Unix socket, websocket binary
// frame, raw TCP, …):
//
//	[0:2]   BE uint16 BodyLen      // length of the (Kind + Body) block
//	[2]     Kind                   // 1-byte tag
//	[3:N]   Op.Encode() bytes
//
// Length-prefixing is intentional even on packet-framed transports
// (websocket): same encoder/decoder works everywhere.

const maxBodyLen = 0xFFFF

// EncodeFrame returns a fully-framed byte slice for op.
func EncodeFrame(op Op) ([]byte, error) {
	if op == nil {
		return nil, fmt.Errorf("control: nil op")
	}
	body := op.Encode()
	if len(body)+1 > maxBodyLen {
		return nil, fmt.Errorf("control: op too large (%d > %d)", len(body)+1, maxBodyLen)
	}
	out := make([]byte, 2+1+len(body))
	binary.BigEndian.PutUint16(out[0:2], uint16(1+len(body)))
	out[2] = byte(op.Kind())
	copy(out[3:], body)
	return out, nil
}

// WriteFrame is a convenience around EncodeFrame + w.Write.
func WriteFrame(w io.Writer, op Op) error {
	frame, err := EncodeFrame(op)
	if err != nil {
		return err
	}
	_, err = w.Write(frame)
	return err
}

// ReadFrame reads one frame from r and returns the decoded Op. Unknown
// Kind values are reported as an error.
func ReadFrame(r io.Reader) (Op, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	bodyLen := int(binary.BigEndian.Uint16(hdr[:]))
	if bodyLen < 1 {
		return nil, fmt.Errorf("control: empty frame")
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	op := New(Kind(body[0]))
	if op == nil {
		return nil, fmt.Errorf("control: unknown kind %#x", body[0])
	}
	if err := op.Decode(body[1:]); err != nil {
		return nil, fmt.Errorf("control: decode kind %#x: %w", body[0], err)
	}
	return op, nil
}

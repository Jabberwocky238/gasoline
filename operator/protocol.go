package operator

import (
	"fmt"
	"io"
)

// Frame format: [typeAndFlags:1][length:3][content:N]
//
//   byte 0:  high 4 bits = MsgType, low 4 bits = reserved flags
//   byte 1-3: content length (big-endian 24-bit, max ~16MB)
//   byte 4+:  content
//
// Data frame content: [vnetID:16][raw IP packet]
// Control frame content: [subtype:1][payload]

const (
	frameHeaderSize = 4           // 1 (type) + 3 (length)
	maxFrameLen     = 1<<24 - 1   // 16MB - 1
	vnetIDSize      = 16
)

// MsgType occupies the high 4 bits of the first byte.
type MsgType byte

const (
	MsgControl MsgType = 0x00
	MsgData    MsgType = 0x01
)

// ControlSubtype identifies the kind of control message.
type ControlSubtype byte

const (
	CtrlPing          ControlSubtype = 0x01
	CtrlPong          ControlSubtype = 0x02
	CtrlRegister      ControlSubtype = 0x03 // announce self to peer operator
	CtrlRegisterAck   ControlSubtype = 0x04
	CtrlSessionSync   ControlSubtype = 0x05 // sync client session info
	CtrlSessionRevoke ControlSubtype = 0x06
)

// Frame is a parsed inter-operator frame.
type Frame struct {
	Type    MsgType
	Content []byte
}

// DataFrame is a parsed data frame.
type DataFrame struct {
	VNetID [vnetIDSize]byte
	Packet []byte
}

// ControlFrame is a parsed control frame.
type ControlFrame struct {
	Subtype ControlSubtype
	Payload []byte
}

// --------------- Codec ---------------

// WriteFrame writes a single frame to w.
func WriteFrame(w io.Writer, f *Frame) error {
	if len(f.Content) > maxFrameLen {
		return fmt.Errorf("frame too large: %d > %d", len(f.Content), maxFrameLen)
	}

	var header [frameHeaderSize]byte
	header[0] = byte(f.Type) << 4
	contentLen := uint32(len(f.Content))
	header[1] = byte(contentLen >> 16)
	header[2] = byte(contentLen >> 8)
	header[3] = byte(contentLen)

	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(f.Content) > 0 {
		_, err := w.Write(f.Content)
		return err
	}
	return nil
}

// ReadFrame reads a single frame from r.
func ReadFrame(r io.Reader) (*Frame, error) {
	var header [frameHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}

	msgType := MsgType(header[0] >> 4)
	contentLen := int(header[1])<<16 | int(header[2])<<8 | int(header[3])

	if contentLen > maxFrameLen {
		return nil, fmt.Errorf("frame too large: %d", contentLen)
	}

	content := make([]byte, contentLen)
	if contentLen > 0 {
		if _, err := io.ReadFull(r, content); err != nil {
			return nil, err
		}
	}

	return &Frame{Type: msgType, Content: content}, nil
}

// --------------- Data helpers ---------------

// MakeDataFrame constructs a Frame carrying a data payload.
func MakeDataFrame(vnetID [vnetIDSize]byte, packet []byte) *Frame {
	content := make([]byte, vnetIDSize+len(packet))
	copy(content[:vnetIDSize], vnetID[:])
	copy(content[vnetIDSize:], packet)
	return &Frame{Type: MsgData, Content: content}
}

// ParseDataFrame extracts VNetID and raw packet from a data frame's content.
func ParseDataFrame(content []byte) (*DataFrame, error) {
	if len(content) < vnetIDSize {
		return nil, fmt.Errorf("data frame too short: %d", len(content))
	}
	df := &DataFrame{
		Packet: content[vnetIDSize:],
	}
	copy(df.VNetID[:], content[:vnetIDSize])
	return df, nil
}

// --------------- Control helpers ---------------

// MakeControlFrame constructs a Frame carrying a control payload.
func MakeControlFrame(subtype ControlSubtype, payload []byte) *Frame {
	content := make([]byte, 1+len(payload))
	content[0] = byte(subtype)
	copy(content[1:], payload)
	return &Frame{Type: MsgControl, Content: content}
}

// ParseControlFrame extracts subtype and payload from a control frame's content.
func ParseControlFrame(content []byte) (*ControlFrame, error) {
	if len(content) < 1 {
		return nil, fmt.Errorf("control frame too short")
	}
	return &ControlFrame{
		Subtype: ControlSubtype(content[0]),
		Payload: content[1:],
	}, nil
}


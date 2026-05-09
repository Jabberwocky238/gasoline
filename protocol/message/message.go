package message

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MessageType discriminates the three on-wire message kinds carried inside a
// session. The transport layer delivers one framed message per ReadPacket;
// this byte tells the receiver which struct to decode.
type MessageType byte

const (
	TypeL3Data         MessageType = 0x01
	TypeControlRequest MessageType = 0x02
	TypeControlReply   MessageType = 0x03
)

// L3Packet carries a single IP datagram between peers.
//
// Wire format: [type:1][len:2][payload]
type L3Packet struct {
	Payload []byte
}

func (m *L3Packet) Type() MessageType { return TypeL3Data }

func (m *L3Packet) Encode(w io.Writer) error {
	header := [3]byte{byte(TypeL3Data)}
	binary.BigEndian.PutUint16(header[1:3], uint16(len(m.Payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(m.Payload) > 0 {
		if _, err := w.Write(m.Payload); err != nil {
			return err
		}
	}
	return nil
}

func (m *L3Packet) Decode(r io.Reader) error {
	var header [3]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	if MessageType(header[0]) != TypeL3Data {
		return fmt.Errorf("L3Packet: wrong type %d", header[0])
	}
	n := binary.BigEndian.Uint16(header[1:3])
	if n == 0 {
		m.Payload = nil
		return nil
	}
	m.Payload = make([]byte, n)
	_, err := io.ReadFull(r, m.Payload)
	return err
}

// ControlOpcode identifies a control-plane operation.
type ControlOpcode uint16

// ControlStatus is the result code returned in a ControlReply.
type ControlStatus uint16

const (
	ControlStatusOK            ControlStatus = 0x0000
	ControlStatusUnknownOp     ControlStatus = 0x0001
	ControlStatusInvalidPayload ControlStatus = 0x0002
	ControlStatusInternalError ControlStatus = 0x00FF
)

// ControlRequest is a request sent on the control plane. RequestID lets the
// sender correlate the reply; Opcode selects the operation; Payload is opaque
// to the framing layer.
//
// Wire format: [type:1][requestID:4][opcode:2][len:2][payload]
type ControlRequest struct {
	RequestID uint32
	Opcode    ControlOpcode
	Payload   []byte
}

func (m *ControlRequest) Type() MessageType { return TypeControlRequest }

func (m *ControlRequest) Encode(w io.Writer) error {
	header := make([]byte, 9)
	header[0] = byte(TypeControlRequest)
	binary.BigEndian.PutUint32(header[1:5], m.RequestID)
	binary.BigEndian.PutUint16(header[5:7], uint16(m.Opcode))
	binary.BigEndian.PutUint16(header[7:9], uint16(len(m.Payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(m.Payload) > 0 {
		if _, err := w.Write(m.Payload); err != nil {
			return err
		}
	}
	return nil
}

func (m *ControlRequest) Decode(r io.Reader) error {
	header := make([]byte, 9)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	if MessageType(header[0]) != TypeControlRequest {
		return fmt.Errorf("ControlRequest: wrong type %d", header[0])
	}
	m.RequestID = binary.BigEndian.Uint32(header[1:5])
	m.Opcode = ControlOpcode(binary.BigEndian.Uint16(header[5:7]))
	n := binary.BigEndian.Uint16(header[7:9])
	if n == 0 {
		m.Payload = nil
		return nil
	}
	m.Payload = make([]byte, n)
	_, err := io.ReadFull(r, m.Payload)
	return err
}

// ControlReply is the response to a ControlRequest. RequestID echoes the
// request being answered; Status reports success/failure; Payload carries
// the result bytes (empty on error unless the op specifies otherwise).
//
// Wire format: [type:1][requestID:4][status:2][len:2][payload]
type ControlReply struct {
	RequestID uint32
	Status    ControlStatus
	Payload   []byte
}

func (m *ControlReply) Type() MessageType { return TypeControlReply }

func (m *ControlReply) Encode(w io.Writer) error {
	header := make([]byte, 9)
	header[0] = byte(TypeControlReply)
	binary.BigEndian.PutUint32(header[1:5], m.RequestID)
	binary.BigEndian.PutUint16(header[5:7], uint16(m.Status))
	binary.BigEndian.PutUint16(header[7:9], uint16(len(m.Payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(m.Payload) > 0 {
		if _, err := w.Write(m.Payload); err != nil {
			return err
		}
	}
	return nil
}

func (m *ControlReply) Decode(r io.Reader) error {
	header := make([]byte, 9)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	if MessageType(header[0]) != TypeControlReply {
		return fmt.Errorf("ControlReply: wrong type %d", header[0])
	}
	m.RequestID = binary.BigEndian.Uint32(header[1:5])
	m.Status = ControlStatus(binary.BigEndian.Uint16(header[5:7]))
	n := binary.BigEndian.Uint16(header[7:9])
	if n == 0 {
		m.Payload = nil
		return nil
	}
	m.Payload = make([]byte, n)
	_, err := io.ReadFull(r, m.Payload)
	return err
}

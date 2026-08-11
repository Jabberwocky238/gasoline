// message-transport.go — the on-wire envelope used between operators
// (and between operators and clients on the data plane).
//
// MessageTransport carries one IP packet plus the (vni, sessionID) addressing
// metadata the routing fabric needs to dispatch it between PEs. The wire
// layout is fixed:
//
//	offset  size  field
//	0       4     VNI  (big-endian uint32; only the low 24 bits are
//	                    meaningful — VNI is 24-bit)
//	4       16    SessionID  (the target session; WG receiver-index role,
//	                          but cluster-unique via Raft)
//	20      n     payload (the IP packet itself, opaque here)
//
// The struct's non-buffer fields are *views* into the backing buffer,
// so seal/parse round-trips are zero-copy past the buffer itself. The
// backing buffer is always rented from common.WaitPool and must be
// returned via Release.
package datacom

import (
	"encoding/binary"
	"fmt"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
)

const (
	headerSize = 20
	vniOffset  = 0
	vniSize    = 4
	sidOffset  = 4
	sidSize    = 16
	payOffset  = 20
)

// MessageTransport is the (vni, sessionID, payload) envelope.
//
// All fields except Buffer are references into Buffer; the only real
// allocation is Buffer (rented from common.WaitPool). After Seal/Open
// the field views point at the backing bytes, so reads/writes through
// VNI/SessionID/Payload mutate the same memory the wire I/O sees.
type MessageTransport struct {
	VNI       *[vniSize]byte         // big-endian uint32 view into Buffer
	SessionID *protocol.SessionID_Ty // [16]byte view into Buffer
	Payload   []byte                 // slice of Buffer past the header
	Buffer    *[]byte                // rented slot; release with (*MessageTransport).Release
}

// New rents a fresh buffer from the pool. The returned message has no
// fields bound until Seal or Open is called.
func New() *MessageTransport {
	return &MessageTransport{Buffer: common.GetBuffer()}
}

// Release returns the backing buffer to the pool and clears the views.
// Safe to call more than once.
func (m *MessageTransport) Release() {
	if m.Buffer != nil {
		// Restore full capacity so the next renter sees a usable slice.
		*m.Buffer = (*m.Buffer)[:cap(*m.Buffer)]
		common.PutBuffer(m.Buffer)
		m.Buffer = nil
	}
	m.VNI = nil
	m.SessionID = nil
	m.Payload = nil
}

// Seal writes (vni, sessionID, payload) into Buffer and re-binds the view
// fields to point into that buffer. If Buffer is nil, one is rented.
// payload bytes are copied; everything else is a pointer rebind.
func (m *MessageTransport) Seal(vni protocol.VNI_Ty, sid protocol.SessionID_Ty, payload []byte) error {
	if m.Buffer == nil {
		m.Buffer = common.GetBuffer()
	}
	need := headerSize + len(payload)
	if cap(*m.Buffer) < need {
		return fmt.Errorf("message: buffer too small (cap %d < need %d)", cap(*m.Buffer), need)
	}
	*m.Buffer = (*m.Buffer)[:need]
	buf := *m.Buffer
	binary.BigEndian.PutUint32(buf[vniOffset:vniOffset+vniSize], uint32(vni))
	copy(buf[sidOffset:sidOffset+sidSize], sid[:])
	copy(buf[payOffset:], payload)
	m.bind()
	return nil
}

// Open re-binds the view fields to the existing Buffer contents. Use
// this after the transport has read raw bytes into Buffer:
//
//	m := message.New()
//	n, _ := conn.Read(*m.Buffer)
//	*m.Buffer = (*m.Buffer)[:n]
//	m.Open()
//
// Returns an error if Buffer is nil or shorter than the header.
func (m *MessageTransport) Open() error {
	if m.Buffer == nil {
		return fmt.Errorf("message: nil buffer")
	}
	if len(*m.Buffer) < headerSize {
		return fmt.Errorf("message: short (%d < %d)", len(*m.Buffer), headerSize)
	}
	m.bind()
	return nil
}

// bind points VNI / SessionID / Payload at the current Buffer.
func (m *MessageTransport) bind() {
	buf := *m.Buffer
	m.VNI = (*[vniSize]byte)(buf[vniOffset : vniOffset+vniSize])
	m.SessionID = (*protocol.SessionID_Ty)(buf[sidOffset : sidOffset+sidSize])
	m.Payload = buf[payOffset:]
}

// GetVNI reads the VNI from the wire-encoded view.
func (m *MessageTransport) GetVNI() protocol.VNI_Ty {
	return protocol.VNI_Ty(binary.BigEndian.Uint32(m.VNI[:]))
}

// SetVNI writes the VNI through the view (mutates Buffer in place).
func (m *MessageTransport) SetVNI(v protocol.VNI_Ty) {
	binary.BigEndian.PutUint32(m.VNI[:], uint32(v))
}

package handshake

import (
	"encoding/binary"
	"io"
	"net/netip"

	"github.com/jabberwocky238/gasoline/protocol"
)

type ClientHello struct {
	Version     byte
	CryptoSuite HandshakeCryptoSuite
	VNI         protocol.VNI_Ty
	CID         protocol.CID_Ty
	Labels      genericLabelMap
}

type ServerHello struct {
	Version     byte
	CryptoSuite HandshakeCryptoSuite
	Labels      genericLabelMap
}

type ClientAnswer struct {
	challengeAnswer []byte
}

type ServerAssign struct {
	Code           HandshakeCode
	SessionContext *protocol.SessionContext
}

// ClientHello: version(1) + cryptoSuite(2) + vni(4) + cid(8) + labels
func (m *ClientHello) Encode(w io.Writer) error {
	header := make([]byte, 15)
	header[0] = m.Version
	binary.BigEndian.PutUint16(header[1:3], uint16(m.CryptoSuite))
	binary.BigEndian.PutUint32(header[3:7], uint32(m.VNI))
	copy(header[7:15], m.CID[:])
	if _, err := w.Write(header); err != nil {
		return err
	}
	return encodeLabels(w, &m.Labels)
}

func (m *ClientHello) Decode(r io.Reader) error {
	header := make([]byte, 15)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	m.Version = header[0]
	m.CryptoSuite = HandshakeCryptoSuite(binary.BigEndian.Uint16(header[1:3]))
	m.VNI = protocol.VNI_Ty(binary.BigEndian.Uint32(header[3:7]))
	copy(m.CID[:], header[7:15])
	labels, err := decodeLabels(r)
	if err != nil {
		return err
	}
	m.Labels = labels
	return nil
}

// ServerHello: version(1) + cryptoSuite(2) + labels
func (m *ServerHello) Encode(w io.Writer) error {
	header := make([]byte, 3)
	header[0] = m.Version
	binary.BigEndian.PutUint16(header[1:3], uint16(m.CryptoSuite))
	if _, err := w.Write(header); err != nil {
		return err
	}
	return encodeLabels(w, &m.Labels)
}

func (m *ServerHello) Decode(r io.Reader) error {
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	m.Version = header[0]
	m.CryptoSuite = HandshakeCryptoSuite(binary.BigEndian.Uint16(header[1:3]))
	labels, err := decodeLabels(r)
	if err != nil {
		return err
	}
	m.Labels = labels
	return nil
}

// ClientAnswer: answerLen(2) + answer
func (m *ClientAnswer) Encode(w io.Writer) error {
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(m.challengeAnswer)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(m.challengeAnswer) > 0 {
		_, err := w.Write(m.challengeAnswer)
		return err
	}
	return nil
}

func (m *ClientAnswer) Decode(r io.Reader) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	answerLen := binary.BigEndian.Uint16(header)
	if answerLen > 0 {
		m.challengeAnswer = make([]byte, answerLen)
		if _, err := io.ReadFull(r, m.challengeAnswer); err != nil {
			return err
		}
	}
	return nil
}

// ServerAssign wire format:
//
//	code(4) + cid(8) + vni(4) + sessionID(16) + sessionIndex(4)
//	+ ipLen(1) + ipBytes(ipLen)        // 4 or 16
//	+ rangeLen(1) + rangeBytes(rangeLen) + rangeCIDR(1)
//
// On Code != HandshakeOK the SessionContext block is still emitted
// (zero-valued) so the message has a fixed shape for decoders.
func (m *ServerAssign) Encode(w io.Writer) error {
	if m.SessionContext == nil {
		return io.ErrUnexpectedEOF
	}
	ipBytes := m.SessionContext.IP.AsSlice() // 0, 4, or 16
	rangeAddr := m.SessionContext.IPRanges.Addr().AsSlice()
	rangeBits := byte(m.SessionContext.IPRanges.Bits())
	if !m.SessionContext.IPRanges.IsValid() {
		rangeAddr = nil
		rangeBits = 0
	}

	headerLen := 4 + 8 + 4 + 16 + 4 + 1 + len(ipBytes) + 1 + len(rangeAddr) + 1
	out := make([]byte, headerLen)
	off := 0
	binary.BigEndian.PutUint32(out[off:off+4], uint32(m.Code))
	off += 4
	copy(out[off:off+8], m.SessionContext.CID[:])
	off += 8
	binary.BigEndian.PutUint32(out[off:off+4], uint32(m.SessionContext.VNI))
	off += 4
	copy(out[off:off+16], m.SessionContext.SessionID[:])
	off += 16
	binary.BigEndian.PutUint32(out[off:off+4], m.SessionContext.SessionIndex)
	off += 4
	out[off] = byte(len(ipBytes))
	off++
	copy(out[off:off+len(ipBytes)], ipBytes)
	off += len(ipBytes)
	out[off] = byte(len(rangeAddr))
	off++
	copy(out[off:off+len(rangeAddr)], rangeAddr)
	off += len(rangeAddr)
	out[off] = rangeBits

	_, err := w.Write(out)
	return err
}

func (m *ServerAssign) Decode(r io.Reader) error {
	header := make([]byte, 4+8+4+16+4)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	m.Code = HandshakeCode(binary.BigEndian.Uint32(header[0:4]))

	sc := &protocol.SessionContext{}
	copy(sc.CID[:], header[4:12])
	sc.VNI = protocol.VNI_Ty(binary.BigEndian.Uint32(header[12:16]))
	copy(sc.SessionID[:], header[16:32])
	sc.SessionIndex = binary.BigEndian.Uint32(header[32:36])

	var lenByte [1]byte
	if _, err := io.ReadFull(r, lenByte[:]); err != nil {
		return err
	}
	if n := int(lenByte[0]); n > 0 {
		ipBuf := make([]byte, n)
		if _, err := io.ReadFull(r, ipBuf); err != nil {
			return err
		}
		if a, ok := netip.AddrFromSlice(ipBuf); ok {
			sc.IP = a
		}
	}
	if _, err := io.ReadFull(r, lenByte[:]); err != nil {
		return err
	}
	rangeLen := int(lenByte[0])
	var rangeAddr netip.Addr
	if rangeLen > 0 {
		rangeBuf := make([]byte, rangeLen)
		if _, err := io.ReadFull(r, rangeBuf); err != nil {
			return err
		}
		if a, ok := netip.AddrFromSlice(rangeBuf); ok {
			rangeAddr = a
		}
	}
	if _, err := io.ReadFull(r, lenByte[:]); err != nil {
		return err
	}
	if rangeAddr.IsValid() {
		sc.IPRanges = netip.PrefixFrom(rangeAddr, int(lenByte[0]))
	}

	m.SessionContext = sc
	return nil
}

package handshake

import (
	"encoding/binary"
	"io"

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
	Code         HandshakeCode
	SessionIndex uint32
	Config       []byte
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

// ServerAssign: code(4) + sessionIndex(4) + configLen(2) + config
func (m *ServerAssign) Encode(w io.Writer) error {
	header := make([]byte, 10)
	binary.BigEndian.PutUint32(header[0:4], uint32(m.Code))
	binary.BigEndian.PutUint32(header[4:8], m.SessionIndex)
	binary.BigEndian.PutUint16(header[8:10], uint16(len(m.Config)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(m.Config) > 0 {
		_, err := w.Write(m.Config)
		return err
	}
	return nil
}

func (m *ServerAssign) Decode(r io.Reader) error {
	header := make([]byte, 10)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	m.Code = HandshakeCode(binary.BigEndian.Uint32(header[0:4]))
	m.SessionIndex = binary.BigEndian.Uint32(header[4:8])
	configLen := binary.BigEndian.Uint16(header[8:10])
	if configLen > 0 {
		m.Config = make([]byte, configLen)
		if _, err := io.ReadFull(r, m.Config); err != nil {
			return err
		}
	}
	return nil
}

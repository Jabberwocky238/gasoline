package handshake

import (
	"encoding/binary"
	"io"

	"github.com/jabberwocky238/gasoline/protocol"
)

// ClientHello is the first auth message. It carries NO client-chosen CID:
// identity is the static public key inside the Noise initiation label, and the
// CID is derived from it server-side. The client only declares which VNI it
// wants to join.
type ClientHello struct {
	Version     byte
	CryptoSuite HandshakeCryptoSuite
	VNI         protocol.VNI_Ty
	Labels      genericLabelMap
}

type ServerHello struct {
	Version     byte
	CryptoSuite HandshakeCryptoSuite
	Labels      genericLabelMap
}

// ClientAnswer is the third auth message: an AEAD-sealed confirmation. The
// client encrypts an empty payload under its Send key; the operator's
// successful decrypt proves the client derived the correct session key — i.e.
// that it holds its static private key. After this, authentication is complete
// and the caller proceeds to package assign for IP allocation.
type ClientAnswer struct {
	Ciphertext []byte // AEAD(send_key, counter=0, ∅)
}

// ClientHello: version(1) + cryptoSuite(2) + vni(4) + labels
func (m *ClientHello) Encode(w io.Writer) error {
	header := make([]byte, 7)
	header[0] = m.Version
	binary.BigEndian.PutUint16(header[1:3], uint16(m.CryptoSuite))
	binary.BigEndian.PutUint32(header[3:7], uint32(m.VNI))
	if _, err := w.Write(header); err != nil {
		return err
	}
	return encodeLabels(w, &m.Labels)
}

func (m *ClientHello) Decode(r io.Reader) error {
	header := make([]byte, 7)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	m.Version = header[0]
	m.CryptoSuite = HandshakeCryptoSuite(binary.BigEndian.Uint16(header[1:3]))
	m.VNI = protocol.VNI_Ty(binary.BigEndian.Uint32(header[3:7]))
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

// ClientAnswer: ctLen(2) + ciphertext
func (m *ClientAnswer) Encode(w io.Writer) error {
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(m.Ciphertext)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(m.Ciphertext) > 0 {
		_, err := w.Write(m.Ciphertext)
		return err
	}
	return nil
}

func (m *ClientAnswer) Decode(r io.Reader) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	ctLen := binary.BigEndian.Uint16(header)
	if ctLen > 0 {
		m.Ciphertext = make([]byte, ctLen)
		if _, err := io.ReadFull(r, m.Ciphertext); err != nil {
			return err
		}
	}
	return nil
}

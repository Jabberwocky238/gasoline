package messages

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/jabberwocky238/gasoline/protocol/encryption"
)

// AEADPayload carries AEAD-encrypted data over the wire.
//
// Wire format: payloadLen(2) + encryptedPayload(N)
//
// The encryptedPayload is produced by CipherState.Seal:
//
//	[counter:8][ciphertext + poly1305_tag:16]
//
// So for plaintext of size P, encryptedPayload length = 8 + P + 16 = P + 24.
type AEADPayload struct {
	Ciphertext []byte // the full Seal output: counter + ciphertext + tag
}

func (m *AEADPayload) WriteTo(w io.Writer) error {
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

func (m *AEADPayload) ReadFrom(r io.Reader) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	payloadLen := binary.BigEndian.Uint16(header)
	if payloadLen > 0 {
		m.Ciphertext = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, m.Ciphertext); err != nil {
			return err
		}
	}
	return nil
}

// Seal encrypts plaintext using the given CipherState and stores the result.
func (m *AEADPayload) Seal(cs *encryption.CipherState, plaintext []byte) {
	m.Ciphertext = cs.Seal(nil, plaintext)
}

// Open decrypts the ciphertext using the given CipherState.
func (m *AEADPayload) Open(cs *encryption.CipherState) ([]byte, error) {
	if len(m.Ciphertext) == 0 {
		return nil, fmt.Errorf("empty ciphertext")
	}
	return cs.Open(nil, m.Ciphertext)
}

// MarshalBinary returns the wire-format bytes.
func (m *AEADPayload) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 2+len(m.Ciphertext))
	binary.BigEndian.PutUint16(buf, uint16(len(m.Ciphertext)))
	copy(buf[2:], m.Ciphertext)
	return buf, nil
}

// UnmarshalBinary parses wire-format bytes.
func (m *AEADPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("aead payload too short: %d bytes", len(data))
	}
	payloadLen := binary.BigEndian.Uint16(data)
	if len(data) < 2+int(payloadLen) {
		return fmt.Errorf("aead payload truncated: need %d, have %d", 2+payloadLen, len(data))
	}
	m.Ciphertext = make([]byte, payloadLen)
	copy(m.Ciphertext, data[2:2+payloadLen])
	return nil
}

package handshake

import (
	"encoding/binary"
	"io"
)

type HandshakeLabelKey uint64

const (
	// LabelKey_NoiseInitiation carries the client's Noise_IK msg1 in ClientHello.
	LabelKey_NoiseInitiation HandshakeLabelKey = iota
	// LabelKey_NoiseResponse carries the server's Noise_IK msg2 in ServerHello.
	LabelKey_NoiseResponse
)

type genericLabelMap struct {
	inner map[HandshakeLabelKey]any
}

func (m *genericLabelMap) Get(key HandshakeLabelKey) (any, bool) {
	val, ok := m.inner[key]
	return val, ok
}

// GetBytes returns a label value as []byte, or (nil, false) if absent or
// not byte-typed.
func (m *genericLabelMap) GetBytes(key HandshakeLabelKey) ([]byte, bool) {
	v, ok := m.inner[key]
	if !ok {
		return nil, false
	}
	b, ok := v.([]byte)
	return b, ok
}

func (m *genericLabelMap) Set(key HandshakeLabelKey, value any) {
	if m.inner == nil {
		m.inner = make(map[HandshakeLabelKey]any)
	}
	m.inner[key] = value
}

// NewLabelMap parses a label list whose wire format is:
//
//	[count:Uint16] [<offset:Uint16> <key:Uint64> <value:offset>]...
//
// Values are stored as []byte; consumers cast to typed values as needed.
func NewLabelMap(labelList []byte) *genericLabelMap {
	m := &genericLabelMap{inner: make(map[HandshakeLabelKey]any)}
	if len(labelList) < 2 {
		return m
	}
	count := binary.BigEndian.Uint16(labelList[:2])
	if count == 0 {
		return m
	}
	cursor := 2
	total := len(labelList)
	for i := 0; i < int(count) && cursor+10 <= total; i++ {
		offset := binary.BigEndian.Uint16(labelList[cursor : cursor+2])
		key := binary.BigEndian.Uint64(labelList[cursor+2 : cursor+10])
		end := cursor + 10 + int(offset)
		if end > total {
			break
		}
		value := make([]byte, int(offset))
		copy(value, labelList[cursor+10:end])
		m.inner[HandshakeLabelKey(key)] = value
		cursor = end
	}
	return m
}

func (m *genericLabelMap) Marshal() []byte {
	if m == nil || len(m.inner) == 0 {
		return []byte{0, 0}
	}
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, uint16(len(m.inner)))
	for k, v := range m.inner {
		b, ok := v.([]byte)
		if !ok {
			continue
		}
		entry := make([]byte, 10+len(b))
		binary.BigEndian.PutUint16(entry[:2], uint16(len(b)))
		binary.BigEndian.PutUint64(entry[2:10], uint64(k))
		copy(entry[10:], b)
		out = append(out, entry...)
	}
	return out
}

func encodeLabels(w io.Writer, m *genericLabelMap) error {
	_, err := w.Write(m.Marshal())
	return err
}

func decodeLabels(r io.Reader) (genericLabelMap, error) {
	m := genericLabelMap{inner: make(map[HandshakeLabelKey]any)}
	countBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, countBuf); err != nil {
		return m, err
	}
	count := binary.BigEndian.Uint16(countBuf)
	for i := 0; i < int(count); i++ {
		entryHeader := make([]byte, 10)
		if _, err := io.ReadFull(r, entryHeader); err != nil {
			return m, err
		}
		offset := binary.BigEndian.Uint16(entryHeader[:2])
		key := binary.BigEndian.Uint64(entryHeader[2:10])
		value := make([]byte, int(offset))
		if _, err := io.ReadFull(r, value); err != nil {
			return m, err
		}
		m.inner[HandshakeLabelKey(key)] = value
	}
	return m, nil
}

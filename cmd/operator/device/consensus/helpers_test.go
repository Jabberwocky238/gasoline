package consensus

import (
	"bytes"
	"io"
)

// memSink is an in-memory raft.SnapshotSink for testing Persist().
type memSink struct {
	data []byte
}

func (s *memSink) Write(p []byte) (int, error) { s.data = append(s.data, p...); return len(p), nil }
func (s *memSink) Close() error                { return nil }
func (s *memSink) ID() string                  { return "test" }
func (s *memSink) Cancel() error               { return nil }

// newReadCloser wraps a byte slice as an io.ReadCloser for Restore().
func newReadCloser(b []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(b))
}

package quic

import (
	"bytes"
	"io"
	"sync"
	"testing"

	"github.com/jabberwocky238/gasoline/protocol/encryption"
)

// mockStream implements the Stream interface (io.ReadWriteCloser) for testing.
type mockStream struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	mu       sync.Mutex
}

func newMockStreamPair() (*mockStream, *mockStream) {
	buf1 := &bytes.Buffer{}
	buf2 := &bytes.Buffer{}
	a := &mockStream{readBuf: buf1, writeBuf: buf2}
	b := &mockStream{readBuf: buf2, writeBuf: buf1}
	return a, b
}

func (m *mockStream) Read(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.readBuf.Len() == 0 {
		return 0, io.EOF
	}
	return m.readBuf.Read(p)
}

func (m *mockStream) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writeBuf.Write(p)
}

func (m *mockStream) Close() error { return nil }

// pipedStream is a synchronous pipe-based mock for concurrent use.
type pipedStream struct {
	reader *io.PipeReader
	writer *io.PipeWriter
}

func newPipedStreamPair() (*pipedStream, *pipedStream) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	a := &pipedStream{reader: r1, writer: w2}
	b := &pipedStream{reader: r2, writer: w1}
	return a, b
}

func (s *pipedStream) Read(p []byte) (int, error)  { return s.reader.Read(p) }
func (s *pipedStream) Write(p []byte) (int, error) { return s.writer.Write(p) }
func (s *pipedStream) Close() error {
	s.writer.Close()
	return s.reader.Close()
}

func TestQUICConnWriteReadPacket(t *testing.T) {
	// Create two symmetric AEAD keypairs
	clientPriv, _ := encryption.NewPrivateKey()
	serverPriv, _ := encryption.NewPrivateKey()
	clientPub := clientPriv.PublicKey()
	serverPub := serverPriv.PublicKey()

	// Client keypair: ECDH(clientPriv, serverPub), initiator=true
	clientKP, err := encryption.DeriveSessionKeypair(clientPriv, serverPub, true)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	// Server keypair: ECDH(serverPriv, clientPub), initiator=false
	serverKP, err := encryption.DeriveSessionKeypair(serverPriv, clientPub, false)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}

	// Create piped streams for bidirectional communication
	clientStream, serverStream := newPipedStreamPair()
	defer clientStream.Close()
	defer serverStream.Close()

	clientConn := newConn(clientStream, clientKP, "127.0.0.1:443")
	serverConn := newConn(serverStream, serverKP, "127.0.0.1:12345")

	testPacket := []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x02,
		0x0a, 0x00, 0x00, 0x01,
		0x00, 0x50, 0x00, 0x51,
		0x00, 0x08, 0x00, 0x00,
	}

	// Client → Server
	var wg sync.WaitGroup
	recvBuf := make([]byte, 65535)
	var recvN int
	var recvErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		recvN, recvErr = serverConn.ReadPacket(recvBuf)
	}()

	if err := clientConn.WritePacket(testPacket); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	wg.Wait()

	if recvErr != nil {
		t.Fatalf("ReadPacket: %v", recvErr)
	}
	if !bytes.Equal(recvBuf[:recvN], testPacket) {
		t.Errorf("packet mismatch:\n  got:  %x\n  want: %x", recvBuf[:recvN], testPacket)
	}

	// Server → Client
	replyPacket := bytes.Repeat([]byte{0xAB}, 256)

	wg.Add(1)
	go func() {
		defer wg.Done()
		recvN, recvErr = clientConn.ReadPacket(recvBuf)
	}()

	if err := serverConn.WritePacket(replyPacket); err != nil {
		t.Fatalf("WritePacket reply: %v", err)
	}
	wg.Wait()

	if recvErr != nil {
		t.Fatalf("ReadPacket reply: %v", recvErr)
	}
	if !bytes.Equal(recvBuf[:recvN], replyPacket) {
		t.Errorf("reply mismatch: len got=%d want=%d", recvN, len(replyPacket))
	}
}

func TestQUICConnMultiplePackets(t *testing.T) {
	clientPriv, _ := encryption.NewPrivateKey()
	serverPriv, _ := encryption.NewPrivateKey()

	clientKP, _ := encryption.DeriveSessionKeypair(clientPriv, serverPriv.PublicKey(), true)
	serverKP, _ := encryption.DeriveSessionKeypair(serverPriv, clientPriv.PublicKey(), false)

	clientStream, serverStream := newPipedStreamPair()
	defer clientStream.Close()
	defer serverStream.Close()

	clientConn := newConn(clientStream, clientKP, "127.0.0.1:443")
	serverConn := newConn(serverStream, serverKP, "127.0.0.1:12345")

	const count = 100
	var wg sync.WaitGroup

	// Reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for i := 0; i < count; i++ {
			n, err := serverConn.ReadPacket(buf)
			if err != nil {
				t.Errorf("ReadPacket %d: %v", i, err)
				return
			}
			if n != 64 || buf[0] != byte(i) {
				t.Errorf("packet %d: bad content (len=%d, first=%d)", i, n, buf[0])
				return
			}
		}
	}()

	// Writer
	for i := 0; i < count; i++ {
		pkt := make([]byte, 64)
		pkt[0] = byte(i)
		if err := clientConn.WritePacket(pkt); err != nil {
			t.Fatalf("WritePacket %d: %v", i, err)
		}
	}
	wg.Wait()
}

func TestQUICConnRemoteAddr(t *testing.T) {
	clientPriv, _ := encryption.NewPrivateKey()
	serverPriv, _ := encryption.NewPrivateKey()
	kp, _ := encryption.DeriveSessionKeypair(clientPriv, serverPriv.PublicKey(), true)

	stream, _ := newPipedStreamPair()
	c := newConn(stream, kp, "10.0.0.1:443")

	if c.RemoteAddr() != "10.0.0.1:443" {
		t.Errorf("RemoteAddr: got %q", c.RemoteAddr())
	}
}

package tcp

import (
	"bytes"
	"crypto/sha256"
	"net/netip"
	"sync"
	"testing"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
)

// testConfigFn generates a SessionConfig for testing.
func testConfigFn() protocol.ConfigFunc {
	serverPriv, _ := protocol.NewPrivateKey()
	serverPub := serverPriv.PublicKey()

	return func(clientID [16]byte, vnetID [16]byte) (*protocol.SessionConfig, error) {
		clientPriv, _ := protocol.NewPrivateKey()
		return &protocol.SessionConfig{
			ClientPrivateKey: clientPriv,
			ServerPublicKey:  serverPub,
			IPPrefix:         netip.MustParsePrefix("10.0.0.2/24"),
		}, nil
	}
}

func testResolver(a auth.ServerAuthenticator) auth.AuthResolver {
	return auth.NewMapResolver(a)
}

func TestTCPHandshakeAndPacket(t *testing.T) {
	serverAuth := &auth.NoAuthServer{}
	configFn := testConfigFn()

	ln, err := NewListener("127.0.0.1:0", testResolver(serverAuth), configFn)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr()
	clientID := [16]byte{0x01, 0x02, 0x03}
	dialer := NewDialer(clientID, [16]byte{}, &auth.NoAuthClient{})

	var wg sync.WaitGroup
	var serverConn *Conn
	var serverResult *protocol.HandshakeResult
	var serverErr error

	// Server: accept one connection
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, r, e := ln.Accept()
		if e != nil {
			serverErr = e
			return
		}
		serverConn = c.(*Conn)
		_ = serverConn
		serverResult = r
	}()

	// Client: dial
	clientConn, clientResult, err := dialer.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	wg.Wait()
	if serverErr != nil {
		t.Fatalf("Accept: %v", serverErr)
	}

	// Verify handshake results
	if clientResult.ClientID != clientID {
		t.Errorf("client ID mismatch")
	}
	if serverResult.ClientID != clientID {
		t.Errorf("server got wrong client ID")
	}
	if clientResult.Config.IPPrefix.String() != "10.0.0.2/24" {
		t.Errorf("unexpected IP: %s", clientResult.Config.IPPrefix)
	}

	// --- Test packet exchange ---

	testPacket := []byte{
		0x45, 0x00, 0x00, 0x1c, // IPv4 header start
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x02, // src: 10.0.0.2
		0x0a, 0x00, 0x00, 0x01, // dst: 10.0.0.1
		0x00, 0x50, 0x00, 0x51, // UDP ports
		0x00, 0x08, 0x00, 0x00, // UDP length + checksum
	}

	// Client → Server
	wg.Add(1)
	var received []byte
	var recvErr error
	go func() {
		defer wg.Done()
		received, recvErr = serverConn.ReadPacket()
	}()

	if err := clientConn.WritePacket(testPacket); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	wg.Wait()
	if recvErr != nil {
		t.Fatalf("ReadPacket: %v", recvErr)
	}
	if !bytes.Equal(received, testPacket) {
		t.Errorf("packet mismatch:\n  got:  %x\n  want: %x", received, testPacket)
	}

	// Server → Client
	replyPacket := []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x02, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x01, // src: 10.0.0.1
		0x0a, 0x00, 0x00, 0x02, // dst: 10.0.0.2
		0x00, 0x51, 0x00, 0x50,
		0x00, 0x08, 0x00, 0x00,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		received, recvErr = clientConn.ReadPacket()
	}()

	if err := serverConn.WritePacket(replyPacket); err != nil {
		t.Fatalf("WritePacket reply: %v", err)
	}
	wg.Wait()
	if recvErr != nil {
		t.Fatalf("ReadPacket reply: %v", recvErr)
	}
	if !bytes.Equal(received, replyPacket) {
		t.Errorf("reply mismatch:\n  got:  %x\n  want: %x", received, replyPacket)
	}
}

func TestTCPMultiplePackets(t *testing.T) {
	serverAuth := &auth.NoAuthServer{}
	configFn := testConfigFn()

	ln, err := NewListener("127.0.0.1:0", testResolver(serverAuth), configFn)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	dialer := NewDialer([16]byte{}, [16]byte{}, &auth.NoAuthClient{})

	var wg sync.WaitGroup
	var sConn *Conn

	wg.Add(1)
	go func() {
		defer wg.Done()
		c, _, e := ln.Accept()
		if e != nil {
			t.Errorf("Accept: %v", e)
			return
		}
		sConn = c.(*Conn)
	}()

	cConn, _, err := dialer.Dial(ln.Addr())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cConn.Close()
	wg.Wait()

	// Send 100 packets client→server, verify each arrives intact
	const count = 100
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < count; i++ {
			data, err := sConn.ReadPacket()
			if err != nil {
				t.Errorf("ReadPacket %d: %v", i, err)
				return
			}
			if len(data) != 64 || data[0] != byte(i) {
				t.Errorf("packet %d: unexpected content", i)
				return
			}
		}
	}()

	for i := 0; i < count; i++ {
		pkt := make([]byte, 64)
		pkt[0] = byte(i)
		if err := cConn.WritePacket(pkt); err != nil {
			t.Fatalf("WritePacket %d: %v", i, err)
		}
	}
	wg.Wait()
}

func TestTCPHMACAuth(t *testing.T) {
	clientID := [16]byte{0xAA, 0xBB}

	serverAuth := &auth.HMACServer{
		Secrets: map[string][]byte{
			"testclient": []byte("test-shared-secret-1234"),
		},
	}
	clientAuth := &auth.HMACClient{ID: "testclient", Secret: []byte("test-shared-secret-1234")}
	configFn := testConfigFn()

	ln, err := NewListener("127.0.0.1:0", testResolver(serverAuth), configFn)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	dialer := NewDialer(clientID, [16]byte{}, clientAuth)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, e := ln.Accept()
		if e != nil {
			t.Errorf("Accept: %v", e)
		}
	}()

	conn, result, err := dialer.Dial(ln.Addr())
	if err != nil {
		t.Fatalf("Dial with HMAC: %v", err)
	}
	defer conn.Close()
	wg.Wait()

	if result.ClientID != clientID {
		t.Errorf("clientID mismatch")
	}
}

func TestTCPUserPassAuth(t *testing.T) {
	// SHA256("password123")
	pwHash := sha256.Sum256([]byte("password123"))
	serverAuth := &auth.UserPassServer{
		Users: map[string][sha256.Size]byte{
			"alice": pwHash,
		},
	}
	clientAuth := &auth.UserPassClient{
		UserID:   "alice",
		Password: "password123",
	}
	configFn := testConfigFn()

	ln, err := NewListener("127.0.0.1:0", testResolver(serverAuth), configFn)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	dialer := NewDialer([16]byte{0x01}, [16]byte{}, clientAuth)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, e := ln.Accept()
		if e != nil {
			t.Errorf("Accept: %v", e)
		}
	}()

	conn, _, err := dialer.Dial(ln.Addr())
	if err != nil {
		t.Fatalf("Dial with UserPass: %v", err)
	}
	defer conn.Close()
	wg.Wait()
}

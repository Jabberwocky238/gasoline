package udp

import (
	"bytes"
	"net/netip"
	"sync"
	"testing"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/encryption"
)

func testConfigFn() protocol.ConfigFunc {
	serverPriv, _ := encryption.NewPrivateKey()
	serverPub := serverPriv.PublicKey()

	return func(clientID [16]byte, vnetID [16]byte) (*protocol.SessionConfig, error) {
		clientPriv, _ := encryption.NewPrivateKey()
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

func TestUDPHandshakeAndPacket(t *testing.T) {
	serverAuth := &auth.NoAuthServer{}
	configFn := testConfigFn()

	ln, err := NewListener("127.0.0.1:0", testResolver(serverAuth), configFn)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr()
	clientID := [16]byte{0x10, 0x20, 0x30}
	dialer := NewDialer(clientID, [16]byte{}, &auth.NoAuthClient{})

	var wg sync.WaitGroup
	var serverConn *Conn
	var serverResult *protocol.HandshakeResult
	var serverErr error

	// Server: accept
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, r, e := ln.Accept()
		if e != nil {
			serverErr = e
			return
		}
		serverConn = c.(*Conn)
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

	// Verify handshake
	if clientResult.ClientID != clientID {
		t.Errorf("client ID mismatch")
	}
	if serverResult.ClientID != clientID {
		t.Errorf("server got wrong client ID")
	}
	if clientResult.Config.IPPrefix.String() != "10.0.0.2/24" {
		t.Errorf("unexpected IP: %s", clientResult.Config.IPPrefix)
	}

	// --- Packet exchange ---

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
	wg.Add(1)
	recvBuf := make([]byte, 65535)
	var recvN int
	var recvErr error
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
	replyPacket := []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x02, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02,
		0x00, 0x51, 0x00, 0x50,
		0x00, 0x08, 0x00, 0x00,
	}

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
		t.Errorf("reply mismatch:\n  got:  %x\n  want: %x", recvBuf[:recvN], replyPacket)
	}
}

func TestUDPMultiplePackets(t *testing.T) {
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

	// Send 50 packets client→server (UDP, so keep it reasonable)
	const count = 50
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for i := 0; i < count; i++ {
			n, err := sConn.ReadPacket(buf)
			if err != nil {
				t.Errorf("ReadPacket %d: %v", i, err)
				return
			}
			if n != 128 || buf[0] != byte(i) {
				t.Errorf("packet %d: unexpected content", i)
				return
			}
		}
	}()

	for i := 0; i < count; i++ {
		pkt := make([]byte, 128)
		pkt[0] = byte(i)
		if err := cConn.WritePacket(pkt); err != nil {
			t.Fatalf("WritePacket %d: %v", i, err)
		}
	}
	wg.Wait()
}

func TestUDPMultipleClients(t *testing.T) {
	serverAuth := &auth.NoAuthServer{}
	clientCount := 0
	configFn := func(clientID [16]byte, vnetID [16]byte) (*protocol.SessionConfig, error) {
		clientCount++
		clientPriv, _ := encryption.NewPrivateKey()
		serverPriv, _ := encryption.NewPrivateKey()
		return &protocol.SessionConfig{
			ClientPrivateKey: clientPriv,
			ServerPublicKey:  serverPriv.PublicKey(),
			IPPrefix:         netip.MustParsePrefix("10.0.0.2/24"),
		}, nil
	}

	ln, err := NewListener("127.0.0.1:0", testResolver(serverAuth), configFn)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr()
	const numClients = 3

	// Accept all clients
	var wg sync.WaitGroup
	serverConns := make([]interface{}, numClients)
	wg.Add(numClients)
	go func() {
		for i := 0; i < numClients; i++ {
			c, _, e := ln.Accept()
			if e != nil {
				t.Errorf("Accept %d: %v", i, e)
				wg.Done()
				continue
			}
			serverConns[i] = c
			wg.Done()
		}
	}()

	// Dial from multiple clients
	clientConns := make([]interface{}, numClients)
	for i := 0; i < numClients; i++ {
		id := [16]byte{byte(i)}
		d := NewDialer(id, [16]byte{}, &auth.NoAuthClient{})
		c, _, err := d.Dial(addr)
		if err != nil {
			t.Fatalf("Dial %d: %v", i, err)
		}
		clientConns[i] = c
	}

	wg.Wait()

	// Verify all connected
	for i := 0; i < numClients; i++ {
		if serverConns[i] == nil {
			t.Errorf("server conn %d is nil", i)
		}
		if clientConns[i] == nil {
			t.Errorf("client conn %d is nil", i)
		}
	}
}

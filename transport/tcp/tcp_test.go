package tcp

import (
	"bytes"
	"crypto/sha256"
	"net/netip"
	"sync"
	"testing"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
)

type testVNIResolver struct {
	auth auth.ServerAuthenticator
}

func (r testVNIResolver) CIDR() netip.Prefix                          { return netip.MustParsePrefix("10.0.0.0/24") }
func (r testVNIResolver) IP(_ protocol.CID_Ty) (netip.Addr, error)    { return netip.MustParseAddr("10.0.0.1"), nil }
func (r testVNIResolver) Authenticator() auth.ServerAuthenticator     { return r.auth }

func testMapper(a auth.ServerAuthenticator) handshake.VNIMapperFn {
	return func(_ protocol.VNI_Ty) (handshake.VNIResolver, error) {
		return testVNIResolver{auth: a}, nil
	}
}

func newTestCfg(cid protocol.CID_Ty) protocol.PresetSessionConfig {
	return protocol.NewPresetSessionConfig(cid, 0)
}

func TestTCPHandshakeAndPacket(t *testing.T) {
	serverAuth := &auth.NoAuthServer{}
	ln, err := NewListener("127.0.0.1:0", testMapper(serverAuth))
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr()
	cid := protocol.CID_Ty{0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	dialer := NewDialer(newTestCfg(cid), &auth.NoAuthClient{})

	var wg sync.WaitGroup
	var serverConn *Conn
	var serverSession *protocol.SessionContext
	var serverErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		c, sc, e := ln.Accept()
		if e != nil {
			serverErr = e
			return
		}
		serverConn = c.(*Conn)
		serverSession = sc
	}()

	clientConn, clientSession, err := dialer.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	wg.Wait()
	if serverErr != nil {
		t.Fatalf("Accept: %v", serverErr)
	}

	if clientSession.CID != cid {
		t.Errorf("client CID mismatch")
	}
	if serverSession.CID != cid {
		t.Errorf("server got wrong client CID")
	}

	testPacket := []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x02,
		0x0a, 0x00, 0x00, 0x01,
		0x00, 0x50, 0x00, 0x51,
		0x00, 0x08, 0x00, 0x00,
	}

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

func TestTCPMultiplePackets(t *testing.T) {
	serverAuth := &auth.NoAuthServer{}
	ln, err := NewListener("127.0.0.1:0", testMapper(serverAuth))
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	dialer := NewDialer(newTestCfg(protocol.CID_Ty{}), &auth.NoAuthClient{})

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

	const count = 100
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
			if n != 64 || buf[0] != byte(i) {
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
	cid := protocol.CID_Ty{0x02, 0xAA, 0xBB, 0, 0, 0, 0, 0}

	serverAuth := &auth.HMACServer{
		Secrets: map[string][]byte{
			"testclient": []byte("test-shared-secret-1234"),
		},
	}
	clientAuth := &auth.HMACClient{ID: "testclient", Secret: []byte("test-shared-secret-1234")}
	ln, err := NewListener("127.0.0.1:0", testMapper(serverAuth))
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	dialer := NewDialer(newTestCfg(cid), clientAuth)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, e := ln.Accept()
		if e != nil {
			t.Errorf("Accept: %v", e)
		}
	}()

	conn, sc, err := dialer.Dial(ln.Addr())
	if err != nil {
		t.Fatalf("Dial with HMAC: %v", err)
	}
	defer conn.Close()
	wg.Wait()

	if sc.CID != cid {
		t.Errorf("cid mismatch")
	}
}

func TestTCPUserPassAuth(t *testing.T) {
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
	ln, err := NewListener("127.0.0.1:0", testMapper(serverAuth))
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	dialer := NewDialer(newTestCfg(protocol.CID_Ty{0x02, 0, 0, 0, 0, 0, 0, 0x01}), clientAuth)

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

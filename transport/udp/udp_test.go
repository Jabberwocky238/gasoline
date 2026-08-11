package udp

import (
	"bytes"
	"sync"
	"testing"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
	"github.com/jabberwocky238/gasoline/protocol/noise"
	"github.com/jabberwocky238/gasoline/transport"
)

// testVNIResolver is a Noise-only resolver: it holds the server key pair and
// the set of authorized client keys.
type testVNIResolver struct {
	serverPriv noise.PrivateKey
	serverPub  noise.PublicKey
	authorized map[noise.PublicKey]struct{}
}

func (r testVNIResolver) ServerStatic() (noise.PrivateKey, noise.PublicKey) {
	return r.serverPriv, r.serverPub
}
func (r testVNIResolver) Authorized(pub noise.PublicKey) bool {
	_, ok := r.authorized[pub]
	return ok
}

// testHarness bundles a server key pair and a mapper that authorizes the given
// client public keys.
func testMapper(serverPriv noise.PrivateKey, serverPub noise.PublicKey, authorized ...noise.PublicKey) handshake.VNIMapperFn {
	set := make(map[noise.PublicKey]struct{}, len(authorized))
	for _, k := range authorized {
		set[k] = struct{}{}
	}
	return func(_ protocol.VNI_Ty) (handshake.VNIResolver, error) {
		return testVNIResolver{serverPriv: serverPriv, serverPub: serverPub, authorized: set}, nil
	}
}

func newTestCfg() protocol.PresetSessionConfig {
	return protocol.NewPresetSessionConfig(0)
}

// newTestKeys returns a client identity and a server key pair, with the client
// pre-authorized. genServer==nil generates one.
func newTestIdentity(t *testing.T) (transport.ClientIdentity, noise.PrivateKey, noise.PublicKey) {
	t.Helper()
	cPriv, cPub, err := noise.GenerateKey()
	if err != nil {
		t.Fatalf("client genkey: %v", err)
	}
	sPriv, sPub, err := noise.GenerateKey()
	if err != nil {
		t.Fatalf("server genkey: %v", err)
	}
	return transport.ClientIdentity{Priv: cPriv, Pub: cPub, ServerPub: sPub}, sPriv, sPub
}

func TestUDPHandshakeAndPacket(t *testing.T) {
	id, sPriv, sPub := newTestIdentity(t)
	ln, err := NewListener("127.0.0.1:0", testMapper(sPriv, sPub, id.Pub))
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr()
	dialer := NewDialer(newTestCfg(), id)

	var wg sync.WaitGroup
	var serverConn *Conn
	var serverErr error

	var serverPub noise.PublicKey
	wg.Add(1)
	go func() {
		defer wg.Done()
		acc, e := ln.Accept()
		if e != nil {
			serverErr = e
			return
		}
		serverConn = acc.Conn.(*Conn)
		serverPub = acc.ClientPub
	}()

	dialed, err := dialer.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	clientConn := dialed.Conn
	defer clientConn.Close()

	wg.Wait()
	if serverErr != nil {
		t.Fatalf("Accept: %v", serverErr)
	}

	// The server recovers the client's identity (its static public key) from
	// the Noise handshake; it must equal the one the client dialed with.
	if serverPub != id.Pub {
		t.Errorf("server recovered wrong client pubkey")
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

func TestUDPMultiplePackets(t *testing.T) {
	id, sPriv, sPub := newTestIdentity(t)
	ln, err := NewListener("127.0.0.1:0", testMapper(sPriv, sPub, id.Pub))
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	dialer := NewDialer(newTestCfg(), id)

	var wg sync.WaitGroup
	var sConn *Conn

	wg.Add(1)
	go func() {
		defer wg.Done()
		acc, e := ln.Accept()
		if e != nil {
			t.Errorf("Accept: %v", e)
			return
		}
		sConn = acc.Conn.(*Conn)
	}()

	dialed, err := dialer.Dial(ln.Addr())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	cConn := dialed.Conn
	defer cConn.Close()
	wg.Wait()

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
	const numClients = 3

	// Distinct client identities, all authorized on the same server key.
	sPriv, sPub, err := noise.GenerateKey()
	if err != nil {
		t.Fatalf("server genkey: %v", err)
	}
	ids := make([]transport.ClientIdentity, numClients)
	pubs := make([]noise.PublicKey, numClients)
	for i := 0; i < numClients; i++ {
		cPriv, cPub, err := noise.GenerateKey()
		if err != nil {
			t.Fatalf("client %d genkey: %v", i, err)
		}
		ids[i] = transport.ClientIdentity{Priv: cPriv, Pub: cPub, ServerPub: sPub}
		pubs[i] = cPub
	}

	ln, err := NewListener("127.0.0.1:0", testMapper(sPriv, sPub, pubs...))
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr()

	var wg sync.WaitGroup
	serverConns := make([]interface{}, numClients)
	wg.Add(numClients)
	go func() {
		for i := 0; i < numClients; i++ {
			acc, e := ln.Accept()
			if e != nil {
				t.Errorf("Accept %d: %v", i, e)
				wg.Done()
				continue
			}
			serverConns[i] = acc.Conn
			wg.Done()
		}
	}()

	clientConns := make([]interface{}, numClients)
	for i := 0; i < numClients; i++ {
		d := NewDialer(newTestCfg(), ids[i])
		dialed, err := d.Dial(addr)
		if err != nil {
			t.Fatalf("Dial %d: %v", i, err)
		}
		clientConns[i] = dialed.Conn
	}

	wg.Wait()

	for i := 0; i < numClients; i++ {
		if serverConns[i] == nil {
			t.Errorf("server conn %d is nil", i)
		}
		if clientConns[i] == nil {
			t.Errorf("client conn %d is nil", i)
		}
	}
}

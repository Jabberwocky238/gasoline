package udp

import (
	"net/netip"
	"bytes"
	"sync"
	"testing"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/handshake"
)

func testResolver(a auth.ServerAuthenticator) auth.AuthResolverFn {
	return func(vni protocol.VNI_Ty) (auth.ServerAuthenticator, error) {
		return a, nil
	}
}


func testRoutes() handshake.RouteResolverFn {
	return func(vni protocol.VNI_Ty, cid protocol.CID_Ty) (netip.Prefix, error) {
		return netip.MustParsePrefix("10.0.0.1/32"), nil
	}
}

func newTestCfg(cid protocol.CID_Ty) protocol.PreassignedSessionConfig {
	return protocol.NewPreassignedSessionConfig(cid, 0)
}

func TestUDPHandshakeAndPacket(t *testing.T) {
	serverAuth := &auth.NoAuthServer{}
	ln, err := NewListener("127.0.0.1:0", testResolver(serverAuth), testRoutes())
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr()
	cid := protocol.CID_Ty{0x02, 0x10, 0x20, 0x30, 0, 0, 0, 0}
	dialer := NewDialer(newTestCfg(cid), &auth.NoAuthClient{})

	var wg sync.WaitGroup
	var serverConn *Conn
	var serverResult *handshake.HandshakeResult
	var serverErr error

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

	clientConn, clientResult, err := dialer.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	wg.Wait()
	if serverErr != nil {
		t.Fatalf("Accept: %v", serverErr)
	}

	if clientResult.CID != cid {
		t.Errorf("client CID mismatch")
	}
	if serverResult.CID != cid {
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

func TestUDPMultiplePackets(t *testing.T) {
	serverAuth := &auth.NoAuthServer{}
	ln, err := NewListener("127.0.0.1:0", testResolver(serverAuth), testRoutes())
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

	ln, err := NewListener("127.0.0.1:0", testResolver(serverAuth), testRoutes())
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr()
	const numClients = 3

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

	clientConns := make([]interface{}, numClients)
	for i := 0; i < numClients; i++ {
		cid := protocol.CID_Ty{0x02, 0, 0, 0, 0, 0, 0, byte(i)}
		d := NewDialer(newTestCfg(cid), &auth.NoAuthClient{})
		c, _, err := d.Dial(addr)
		if err != nil {
			t.Fatalf("Dial %d: %v", i, err)
		}
		clientConns[i] = c
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

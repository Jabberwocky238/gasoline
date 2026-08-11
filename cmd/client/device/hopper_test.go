package client

import (
	"net/netip"
	"testing"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/transport"
	"github.com/sirupsen/logrus"
)

// fakeHopConn records SetHopDest calls; it is a minimal transport.HoppingConn.
type fakeHopConn struct {
	transport.Conn
	dests []string
}

func (f *fakeHopConn) SetHopDest(dst string) error {
	f.dests = append(f.dests, dst)
	return nil
}

func testLctx() *common.LogContext {
	lg := logrus.New()
	lg.SetLevel(logrus.ErrorLevel)
	return common.NewLogContext(nil, lg)
}

func TestHopperPickInRange(t *testing.T) {
	servers := []protocol.HopServer{
		{
			Host:  netip.MustParseAddr("1.2.3.4"),
			Ports: []protocol.HopPortRange{{Lo: 20000, Hi: 20003}},
		},
	}
	h := &Hopper{servers: servers, lctx: testLctx()}
	for i := 0; i < 200; i++ {
		dst, ok := h.pick()
		if !ok {
			t.Fatal("pick returned not-ok with a valid server")
		}
		ap, err := netip.ParseAddrPort(dst)
		if err != nil {
			t.Fatalf("pick produced unparseable %q: %v", dst, err)
		}
		if ap.Addr() != servers[0].Host {
			t.Fatalf("host %s != %s", ap.Addr(), servers[0].Host)
		}
		if ap.Port() < 20000 || ap.Port() > 20003 {
			t.Fatalf("port %d out of range [20000,20003]", ap.Port())
		}
	}
}

func TestHopperNilWhenNotHopping(t *testing.T) {
	// A conn that is not a HoppingConn yields a nil hopper.
	if h := NewHopper(testLctx(), plainConn{}, []protocol.HopServer{{Host: netip.MustParseAddr("1.1.1.1"), Ports: []protocol.HopPortRange{{Lo: 1, Hi: 1}}}}); h != nil {
		t.Fatal("expected nil hopper for non-hopping conn")
	}
	// An empty server list also yields nil.
	if h := NewHopper(testLctx(), &fakeHopConn{}, nil); h != nil {
		t.Fatal("expected nil hopper for empty server list")
	}
}

// plainConn is a transport.Conn that is NOT a HoppingConn.
type plainConn struct{ transport.Conn }

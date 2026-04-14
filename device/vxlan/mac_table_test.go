package vxlan

import (
	"net"
	"testing"
	"time"

	"github.com/jabberwocky238/gasoline/common"
)

type stubPort struct{ id string }

func (s *stubPort) SendFrame(_ []byte) error { return nil }

func TestMACTableLocalLookup(t *testing.T) {
	tbl := NewMACTable()
	vni := common.VNI(7)
	mac := common.VMAC{0x02, 0, 0, 0, 0, 0x01}
	port := &stubPort{id: "A"}

	tbl.RegisterLocal(vni, mac, port)

	got, ok := tbl.LookupLocal(vni, mac)
	if !ok || got != port {
		t.Fatalf("LookupLocal: got %v ok=%v, want port ok=true", got, ok)
	}
	if p, addr, found := tbl.Lookup(vni, mac); !found || p != port || addr != nil {
		t.Fatalf("Lookup: got (%v,%v,%v)", p, addr, found)
	}

	tbl.UnregisterLocal(vni, mac)
	if _, ok := tbl.LookupLocal(vni, mac); ok {
		t.Fatalf("UnregisterLocal failed")
	}
}

func TestMACTableRemoteLearning(t *testing.T) {
	tbl := NewMACTable()
	vni := common.VNI(42)
	mac := common.VMAC{0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 9999}

	tbl.LearnRemote(vni, mac, addr)
	got, ok := tbl.LookupRemote(vni, mac)
	if !ok || got != addr {
		t.Fatalf("LookupRemote: got %v ok=%v", got, ok)
	}

	// Local registration shadows remote
	port := &stubPort{id: "Z"}
	tbl.RegisterLocal(vni, mac, port)
	if _, ok := tbl.LookupRemote(vni, mac); ok {
		t.Fatalf("RegisterLocal should have purged remote shadow")
	}

	// Subsequent LearnRemote on a locally-attached MAC is ignored
	tbl.LearnRemote(vni, mac, addr)
	if _, ok := tbl.LookupRemote(vni, mac); ok {
		t.Fatalf("LearnRemote should be ignored when local entry exists")
	}
}

func TestMACTableFloodIndexes(t *testing.T) {
	tbl := NewMACTable()
	vni := common.VNI(1)
	macA := common.VMAC{0x02, 0, 0, 0, 0, 0x0A}
	macB := common.VMAC{0x02, 0, 0, 0, 0, 0x0B}
	addrR := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 1}

	tbl.RegisterLocal(vni, macA, &stubPort{id: "A"})
	tbl.RegisterLocal(vni, macB, &stubPort{id: "B"})
	tbl.LearnRemote(vni, common.VMAC{0x02, 0, 0, 0, 0, 0x0C}, addrR)

	if got := tbl.LocalsInVNI(vni); len(got) != 2 {
		t.Errorf("LocalsInVNI: got %d, want 2", len(got))
	}
	if got := tbl.RemotesInVNI(vni); len(got) != 1 {
		t.Errorf("RemotesInVNI: got %d, want 1", len(got))
	}

	tbl.UnregisterLocal(vni, macA)
	if got := tbl.LocalsInVNI(vni); len(got) != 1 {
		t.Errorf("after UnregisterLocal: got %d, want 1", len(got))
	}
}

func TestMACTableAgeOut(t *testing.T) {
	tbl := NewMACTable()
	vni := common.VNI(1)
	mac := common.VMAC{0x02, 0, 0, 0, 0, 1}
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}
	tbl.LearnRemote(vni, mac, addr)

	if n := tbl.AgeOutRemotes(time.Hour); n != 0 {
		t.Errorf("AgeOutRemotes(1h) on fresh entry: got %d, want 0", n)
	}
	if n := tbl.AgeOutRemotes(0); n != 1 {
		t.Errorf("AgeOutRemotes(0) on any entry: got %d, want 1", n)
	}
	if _, ok := tbl.LookupRemote(vni, mac); ok {
		t.Errorf("entry survived AgeOutRemotes(0)")
	}
}

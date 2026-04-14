package ctrl

import (
	"net/netip"
	"testing"

	"github.com/jabberwocky238/gasoline/common"
)

func TestVNetSessionsTripleIndex(t *testing.T) {
	v := newVNetSessions()

	sidA := [16]byte{0x0A}
	cidA := common.VMAC{0x02, 0, 0, 0, 0, 0xA1}
	ipA := netip.MustParseAddr("10.0.0.2")
	v.Add(sidA, &SessionInfo{OperatorUUID: [16]byte{1}, VMAC:        cidA, IP: ipA})

	sidB := [16]byte{0x0B}
	cidB := common.VMAC{0x02, 0, 0, 0, 0, 0xB1}
	ipB := netip.MustParseAddr("10.0.0.3")
	v.Add(sidB, &SessionInfo{OperatorUUID: [16]byte{2}, VMAC:        cidB, IP: ipB})

	// Get by sessionID
	if info, ok := v.Get(sidA); !ok || info.IP != ipA {
		t.Fatalf("Get(sidA) failed")
	}

	// LookupByIP — O(1)
	if sid, info, ok := v.LookupByIP(ipB); !ok || sid != sidB || info.VMAC != cidB {
		t.Fatalf("LookupByIP(ipB) mismatch")
	}
	if _, _, ok := v.LookupByIP(netip.MustParseAddr("10.9.9.9")); ok {
		t.Fatalf("LookupByIP(unknown) should miss")
	}

	// LookupByVMAC — O(1)
	if sid, info, ok := v.LookupByVMAC(cidA); !ok || sid != sidA || info.IP != ipA {
		t.Fatalf("LookupByVMAC(cidA) mismatch")
	}
	if _, _, ok := v.LookupByVMAC(common.VMAC{0xFF}); ok {
		t.Fatalf("LookupByVMAC(unknown) should miss")
	}

	// Remove cleans secondary indexes
	v.Remove(sidA)
	if _, _, ok := v.LookupByIP(ipA); ok {
		t.Fatalf("byIP not cleaned after Remove")
	}
	if _, _, ok := v.LookupByVMAC(cidA); ok {
		t.Fatalf("byVMAC not cleaned after Remove")
	}
	// B still present
	if _, _, ok := v.LookupByIP(ipB); !ok {
		t.Fatalf("unrelated session B lost after removing A")
	}
}

func TestVNetSessionsReplaceRekeys(t *testing.T) {
	v := newVNetSessions()
	sid := [16]byte{0xAA}

	oldCID := common.VMAC{0x02, 0, 0, 0, 0, 1}
	oldIP := netip.MustParseAddr("10.0.0.2")
	v.Add(sid, &SessionInfo{VMAC:        oldCID, IP: oldIP})

	// Replace same sessionID with new IP/CID — stale indexes must clear
	newCID := common.VMAC{0x02, 0, 0, 0, 0, 2}
	newIP := netip.MustParseAddr("10.0.0.3")
	v.Add(sid, &SessionInfo{VMAC:        newCID, IP: newIP})

	if _, _, ok := v.LookupByIP(oldIP); ok {
		t.Errorf("old IP still indexed after replace")
	}
	if _, _, ok := v.LookupByVMAC(oldCID); ok {
		t.Errorf("old CID still indexed after replace")
	}
	if _, _, ok := v.LookupByIP(newIP); !ok {
		t.Errorf("new IP not indexed after replace")
	}
	if _, _, ok := v.LookupByVMAC(newCID); !ok {
		t.Errorf("new CID not indexed after replace")
	}
}

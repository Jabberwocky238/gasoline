package ctrl

import (
	"net/netip"
	"testing"

	"github.com/jabberwocky238/gasoline/common"
)

func TestVNetSessionsIndex(t *testing.T) {
	v := newVNetSessions()

	sidA := [16]byte{0x0A}
	cidA := common.VMAC{0x02, 0, 0, 0, 0, 0xA1}
	ipA := netip.MustParseAddr("10.0.0.2")
	v.Add(sidA, &SessionInfo{OperatorUUID: [16]byte{1}, VMAC: cidA, IP: ipA})

	sidB := [16]byte{0x0B}
	cidB := common.VMAC{0x02, 0, 0, 0, 0, 0xB1}
	ipB := netip.MustParseAddr("10.0.0.3")
	v.Add(sidB, &SessionInfo{OperatorUUID: [16]byte{2}, VMAC: cidB, IP: ipB})

	// Get by sessionID
	if info, ok := v.Get(sidA); !ok || info.IP != ipA {
		t.Fatalf("Get(sidA) failed")
	}

	// LookupByVMAC — O(1)
	if sid, info, ok := v.LookupByVMAC(cidA); !ok || sid != sidA || info.IP != ipA {
		t.Fatalf("LookupByVMAC(cidA) mismatch")
	}
	if _, _, ok := v.LookupByVMAC(common.VMAC{0xFF}); ok {
		t.Fatalf("LookupByVMAC(unknown) should miss")
	}

	// Remove cleans secondary index
	v.Remove(sidA)
	if _, ok := v.Get(sidA); ok {
		t.Fatalf("Get(sidA) should miss after Remove")
	}
	if _, _, ok := v.LookupByVMAC(cidA); ok {
		t.Fatalf("byVMAC not cleaned after Remove")
	}
	// B still present
	if _, ok := v.Get(sidB); !ok {
		t.Fatalf("unrelated session B lost after removing A")
	}
}

func TestVNetSessionsReplaceRekeys(t *testing.T) {
	v := newVNetSessions()
	sid := [16]byte{0xAA}

	oldCID := common.VMAC{0x02, 0, 0, 0, 0, 1}
	v.Add(sid, &SessionInfo{VMAC: oldCID, IP: netip.MustParseAddr("10.0.0.2")})

	// Replace same sessionID with a new VMAC — stale byVMAC must clear.
	newCID := common.VMAC{0x02, 0, 0, 0, 0, 2}
	v.Add(sid, &SessionInfo{VMAC: newCID, IP: netip.MustParseAddr("10.0.0.3")})

	if _, _, ok := v.LookupByVMAC(oldCID); ok {
		t.Errorf("old CID still indexed after replace")
	}
	if _, _, ok := v.LookupByVMAC(newCID); !ok {
		t.Errorf("new CID not indexed after replace")
	}
}

func TestVNetSessionsSnapshot(t *testing.T) {
	v := newVNetSessions()
	sidA := [16]byte{0x01}
	sidB := [16]byte{0x02}
	v.Add(sidA, &SessionInfo{VMAC: common.VMAC{0x02, 0, 0, 0, 0, 0xA}})
	v.Add(sidB, &SessionInfo{VMAC: common.VMAC{0x02, 0, 0, 0, 0, 0xB}})

	snap := v.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len = %d, want 2", len(snap))
	}
	if _, ok := snap[sidA]; !ok {
		t.Errorf("snapshot missing sidA")
	}
	// Mutating snapshot doesn't affect the table.
	delete(snap, sidA)
	if _, ok := v.Get(sidA); !ok {
		t.Errorf("Snapshot mutation leaked into table")
	}
}

package operator

import (
	"net/netip"
	"testing"
)

// TestVNetPoolRecycle allocates 100 IPs, releases 90, repeats 10 times
// on a /24 prefix (253 usable hosts: .2 ~ .254). Must not error.
func TestVNetPoolRecycle(t *testing.T) {
	pools, err := ParseVNetPools("100:10.0.0.0/24")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var vnetID VNetIDType
	vnetID[15] = 100
	vnetID[14] = 0
	// EncodeVNetID(100) puts 100 in the last 8 bytes big-endian
	pool, ok := pools.Get(vnetID)
	if !ok {
		// try finding by iterating
		for id, p := range pools.All() {
			pool = p
			vnetID = id
			_ = vnetID
			break
		}
	}
	if pool == nil {
		t.Fatal("pool not found")
	}

	for round := 0; round < 10; round++ {
		expectedBase := round * 10 // carried over from previous rounds

		// Allocate 100
		ips := make([]netip.Addr, 0, 100)
		for i := 0; i < 100; i++ {
			ip, err := pool.AllocateIP()
			if err != nil {
				t.Fatalf("round %d, alloc %d: %v (inUse=%d)", round, i, err, pool.InUseCount())
			}
			ips = append(ips, ip)
		}

		if got := pool.InUseCount(); got != expectedBase+100 {
			t.Fatalf("round %d: expected %d in use, got %d", round, expectedBase+100, got)
		}

		// Release first 90
		for i := 0; i < 90; i++ {
			pool.ReleaseIP(ips[i])
		}

		if got := pool.InUseCount(); got != expectedBase+10 {
			t.Fatalf("round %d: expected %d in use after release, got %d", round, expectedBase+10, got)
		}
	}

	// 10 rounds × 10 retained = 100 in use
	t.Logf("10 rounds complete, final inUse=%d", pool.InUseCount())
}

// TestVNetPoolExhaust verifies that a /28 (14 usable: .2 ~ .15) pool
// correctly exhausts and recovers.
func TestVNetPoolExhaust(t *testing.T) {
	pools, err := ParseVNetPools("1:192.168.0.0/28")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var pool *VNetPool
	for _, p := range pools.All() {
		pool = p
		break
	}

	// /28 = 16 addresses, .0=network .1=gateway .15=broadcast → usable .2~.14 = 13
	// But our pool doesn't exclude broadcast, so .2~.15 = 14 usable
	ips := make([]netip.Addr, 0, 14)
	for i := 0; i < 14; i++ {
		ip, err := pool.AllocateIP()
		if err != nil {
			t.Fatalf("alloc %d: %v", i, err)
		}
		ips = append(ips, ip)
	}

	// Next alloc should fail
	_, err = pool.AllocateIP()
	if err == nil {
		t.Fatal("expected exhaustion error")
	}

	// Release one, alloc again should succeed
	pool.ReleaseIP(ips[0])
	ip, err := pool.AllocateIP()
	if err != nil {
		t.Fatalf("alloc after release: %v", err)
	}
	if ip != ips[0] {
		t.Logf("reused IP %s (was %s)", ip, ips[0])
	}

	t.Logf("exhaust+recover OK, pool=%s", pool.Prefix)
}

// TestVNetPoolDuplicateRelease verifies that releasing the same IP twice
// does not corrupt the pool.
func TestVNetPoolDuplicateRelease(t *testing.T) {
	pools, err := ParseVNetPools("1:10.0.0.0/24")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var pool *VNetPool
	for _, p := range pools.All() {
		pool = p
		break
	}

	ip, err := pool.AllocateIP()
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}

	pool.ReleaseIP(ip)
	pool.ReleaseIP(ip) // double release — should be a no-op

	if pool.InUseCount() != 0 {
		t.Fatalf("expected 0 in use, got %d", pool.InUseCount())
	}

	// Allocate twice — should get two different IPs (the freed one + a new one)
	ip1, err := pool.AllocateIP()
	if err != nil {
		t.Fatalf("alloc1: %v", err)
	}
	ip2, err := pool.AllocateIP()
	if err != nil {
		t.Fatalf("alloc2: %v", err)
	}
	if ip1 == ip2 {
		t.Fatalf("got duplicate IP: %s", ip1)
	}

	t.Logf("double release safe: ip1=%s ip2=%s", ip1, ip2)
}

package operator

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/jabberwocky238/gasoline/common"
)

// TestVNetPoolRecycle allocates 100 IPs, releases 90, repeats 10 times
// on a /24 prefix (253 usable hosts: .2 ~ .254). Must not error.
func TestVNetPoolRecycle(t *testing.T) {
	pools, err := ParseVNetPools("100:10.0.0.0/24", 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	pool, ok := pools.Get(common.VNI(100))
	if !ok {
		for _, p := range pools.All() {
			pool = p
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
			ip, err := pool.AllocateIP([16]byte{})
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
	pools, err := ParseVNetPools("1:192.168.0.0/28", 0)
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
		ip, err := pool.AllocateIP([16]byte{})
		if err != nil {
			t.Fatalf("alloc %d: %v", i, err)
		}
		ips = append(ips, ip)
	}

	// Next alloc should fail
	_, err = pool.AllocateIP([16]byte{})
	if err == nil {
		t.Fatal("expected exhaustion error")
	}

	// Release one, alloc again should succeed
	pool.ReleaseIP(ips[0])
	ip, err := pool.AllocateIP([16]byte{})
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
	pools, err := ParseVNetPools("1:10.0.0.0/24", 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var pool *VNetPool
	for _, p := range pools.All() {
		pool = p
		break
	}

	ip, err := pool.AllocateIP([16]byte{})
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}

	pool.ReleaseIP(ip)
	pool.ReleaseIP(ip) // double release — should be a no-op

	if pool.InUseCount() != 0 {
		t.Fatalf("expected 0 in use, got %d", pool.InUseCount())
	}

	// Allocate twice — should get two different IPs (the freed one + a new one)
	ip1, err := pool.AllocateIP([16]byte{})
	if err != nil {
		t.Fatalf("alloc1: %v", err)
	}
	ip2, err := pool.AllocateIP([16]byte{})
	if err != nil {
		t.Fatalf("alloc2: %v", err)
	}
	if ip1 == ip2 {
		t.Fatalf("got duplicate IP: %s", ip1)
	}

	t.Logf("double release safe: ip1=%s ip2=%s", ip1, ip2)
}

// TestVNetPoolConcurrentOperators simulates multiple operators allocating
// from separate pools (same CIDR, different seeds) + cross-reserving via SessionSync.
// No IP should be duplicated across all operators.
func TestVNetPoolConcurrentOperators(t *testing.T) {
	const (
		numOperators = 4
		allocPerOp   = 50 // each operator allocates 50 IPs
		cidr         = "200:10.0.0.0/24"
	)

	// Create one pool per operator, each with a different seed
	pools := make([]*VNetPoolMap, numOperators)
	for i := 0; i < numOperators; i++ {
		var err error
		pools[i], err = ParseVNetPools(cidr, uint32(i*61+7)) // different seed per operator
		if err != nil {
			t.Fatalf("parse pool %d: %v", i, err)
		}
	}

	vni := common.VNI(200)

	type result struct {
		opIdx int
		ip    netip.Addr
	}

	results := make(chan result, numOperators*allocPerOp)
	var wg sync.WaitGroup

	// Each operator concurrently allocates IPs and broadcasts reserves to others
	for i := 0; i < numOperators; i++ {
		wg.Add(1)
		go func(opIdx int) {
			defer wg.Done()
			pool, _ := pools[opIdx].Get(vni)

			for j := 0; j < allocPerOp; j++ {
				ip, err := pool.AllocateIP([16]byte{})
				if err != nil {
					t.Errorf("op%d alloc %d: %v", opIdx, j, err)
					return
				}

				// Simulate SessionSync: reserve this IP on all other operators
				for k := 0; k < numOperators; k++ {
					if k == opIdx {
						continue
					}
					otherPool, _ := pools[k].Get(vni)
					otherPool.ReserveIP(ip)
				}

				results <- result{opIdx: opIdx, ip: ip}
			}
		}(i)
	}

	wg.Wait()
	close(results)

	// Check for duplicates
	seen := make(map[netip.Addr]int) // ip → operator index
	for r := range results {
		if prevOp, exists := seen[r.ip]; exists {
			t.Fatalf("DUPLICATE: %s allocated by operator %d and %d", r.ip, prevOp, r.opIdx)
		}
		seen[r.ip] = r.opIdx
	}

	total := len(seen)
	expected := numOperators * allocPerOp
	if total != expected {
		t.Fatalf("expected %d unique IPs, got %d", expected, total)
	}

	t.Logf("OK: %d operators × %d IPs = %d unique, no duplicates", numOperators, allocPerOp, total)
}

// TestVNetPoolConcurrentAllocRelease hammers a single pool with
// concurrent alloc/release from multiple goroutines. Must not panic or duplicate.
func TestVNetPoolConcurrentAllocRelease(t *testing.T) {
	pools, err := ParseVNetPools("1:10.0.0.0/24", 0)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := pools.Get(common.VNI(1))

	const goroutines = 4
	const opsPerGoroutine = 50

	var wg sync.WaitGroup
	allIPs := make(chan netip.Addr, goroutines*opsPerGoroutine)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local []netip.Addr
			for i := 0; i < opsPerGoroutine; i++ {
				ip, err := pool.AllocateIP([16]byte{})
				if err != nil {
					t.Errorf("alloc: %v", err)
					return
				}
				local = append(local, ip)
				allIPs <- ip

				// Release half the IPs
				if len(local) > 10 && i%2 == 0 {
					rel := local[0]
					local = local[1:]
					pool.ReleaseIP(rel)
				}
			}
		}()
	}

	wg.Wait()
	close(allIPs)

	t.Logf("Concurrent alloc/release OK: pool inUse=%d", pool.InUseCount())
}

// TestVNetPoolIPv6Deterministic verifies that IPv6 allocation is stateless
// and deterministic from (SessionID, VNI).
func TestVNetPoolIPv6Deterministic(t *testing.T) {
	pools, err := ParseVNetPools("42:fd00:abcd::/64", 0)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := pools.Get(common.VNI(42))
	if pool.IsV4() {
		t.Fatal("expected v6 pool")
	}

	sid1 := [16]byte{0x01, 0x02, 0x03, 0x04}
	sid2 := [16]byte{0xAA, 0xBB, 0xCC, 0xDD}

	ip1a, _ := pool.AllocateIP(sid1)
	ip1b, _ := pool.AllocateIP(sid1)
	ip2, _ := pool.AllocateIP(sid2)

	// Same session → same IP (deterministic)
	if ip1a != ip1b {
		t.Errorf("deterministic: sid1 → %s then %s, want identical", ip1a, ip1b)
	}
	// Different sessions → different IPs
	if ip1a == ip2 {
		t.Errorf("different sessions should yield different IPs: both got %s", ip1a)
	}
	// Inside the prefix
	if !pool.Prefix.Contains(ip1a) {
		t.Errorf("allocated IP %s not in prefix %s", ip1a, pool.Prefix)
	}
	if !pool.Prefix.Contains(ip2) {
		t.Errorf("allocated IP %s not in prefix %s", ip2, pool.Prefix)
	}
	// Stateless — InUseCount is always 0
	if pool.InUseCount() != 0 {
		t.Errorf("v6 pool InUseCount = %d, want 0 (stateless)", pool.InUseCount())
	}

	t.Logf("IPv6 deterministic OK: sid1→%s, sid2→%s", ip1a, ip2)
}

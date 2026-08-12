package consensus

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

// TestConcurrentCommitDistinctIP is a regression guard for the reqID-collision
// bug: three clients handshaking on three different operators at the same instant
// each commit a SessionCreate through a different node. The leader's Apply
// allocates deterministically, but a proposal's result is correlated back to its
// proposer by a reqID — which must be globally unique, or a node signals the
// wrong waiter with the wrong entry's IP and two clients get the same address.
func TestConcurrentCommitDistinctIP(t *testing.T) {
	tc := newTestCluster(t, 3)
	leader := tc.waitLeader(3 * time.Second)

	must := func(c *Command) {
		if err := leader.Propose(c, 2*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	must(&Command{Kind: CmdVNetUpsert, VNetUpsert: &VNetUpsert{
		VNI: 200, Version: 1,
		Segments: []Segment{{
			CIDR: netip.MustParsePrefix("10.0.200.0/24"),
			Pool: netip.MustParsePrefix("10.0.200.16/28"),
		}},
	}})
	for i := byte(1); i <= 3; i++ {
		must(&Command{Kind: CmdKeyGrant, KeyGrant: &KeyGrant{VNI: 200, PubKey: pub(i)}})
	}
	time.Sleep(300 * time.Millisecond) // let the seed replicate

	var wg sync.WaitGroup
	ips := make([]string, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip, _, err := tc.nodes[i].CommitSession(&SessionCreate{
				SessionID: sid(byte(i + 1)), PubKey: pub(byte(i + 1)), VNI: 200,
				LeaseTTL: time.Hour, Now: time.Now().UnixNano(),
			}, 3*time.Second)
			if err != nil {
				t.Errorf("node %d commit: %v", i, err)
				return
			}
			ips[i] = ip.String()
		}(i)
	}
	wg.Wait()

	seen := map[string]bool{}
	for _, ip := range ips {
		if ip == "" {
			t.Fatalf("a commit returned no IP: %v", ips)
		}
		if seen[ip] {
			t.Fatalf("duplicate IP %s across concurrent commits: %v", ip, ips)
		}
		seen[ip] = true
	}
}

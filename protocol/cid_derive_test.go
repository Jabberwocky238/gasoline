package protocol

import "testing"

// TestDeriveCIDDeterministic: the same pubkey always yields the same CID.
func TestDeriveCIDDeterministic(t *testing.T) {
	var pub [32]byte
	pub[0], pub[31] = 0xAB, 0xCD
	a := DeriveCID(pub)
	b := DeriveCID(pub)
	if a != b {
		t.Fatalf("DeriveCID not deterministic: %v vs %v", a, b)
	}
}

// TestDeriveCIDDistinct: different pubkeys yield different CIDs (no trivial
// collision on a one-byte change).
func TestDeriveCIDDistinct(t *testing.T) {
	var p1, p2 [32]byte
	p1[0] = 1
	p2[0] = 2
	if DeriveCID(p1) == DeriveCID(p2) {
		t.Fatal("distinct pubkeys derived the same CID")
	}
}

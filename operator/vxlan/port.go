// Package vxlan implements an in-process VXLAN data plane.
//
// A Plane owns a single port.Conn (platform-aware batch UDP socket) for
// inter-operator traffic and a MAC learning table indexed by (VNI, MAC).
// Local destinations register as Ports; remote destinations are learned
// dynamically from incoming frames and stored as netip.AddrPort endpoints.
//
// Forwarding rules:
//
//	dstMAC == FF:FF:FF:FF:FF:FF  → flood (all local ports in same VNI +
//	                               all known remote operators in same VNI)
//	dstMAC ∈ local table         → port.SendFrame(frame)
//	dstMAC ∈ remote table        → VXLAN-wrap and UDP-send
//	otherwise                    → drop (unknown unicast); future flood
package vxlan

// Port is something the VXLAN plane can deliver an Ethernet frame to.
//
// Implementations:
//   - tap.Device   — a client-facing TAP attached over a transport.Conn.
//   - any other in-process L2 endpoint (testing harnesses, OVS bridges, …).
//
// SendFrame must be safe to call from arbitrary goroutines.
type Port interface {
	SendFrame(frame []byte) error
}

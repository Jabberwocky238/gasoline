// Package adapter is the thin glue between gasoline's existing vtap /
// transport.Conn plumbing and the userspace netstack.Stack. It exists so
// that gasoline's integration is limited to two call sites:
//
//	// vtap egress, right before shipIP:
//	if a := d.adapter; a == nil || !a.OnTunPacket(buf[:n]) {
//	    d.handleEgress(buf[:n])  // original path — overlay peer etc.
//	}
//
//	// vtap ingress, right before tun.Write on an IPv4/6 payload:
//	if a := d.adapter; a != nil && a.OnOverlayPacket(payload) {
//	    return  // netstack owns this packet
//	}
//	d.tun.Write(payload)         // original path — peer-to-peer transparent
//
// Everything else (constructing the gvisor stack, choosing routes, running
// proxy goroutines, drain goroutines) lives inside the netstack package
// itself. The adapter just translates between the stack's Config callbacks
// and gasoline's existing "write to TUN" / "ship to overlay" primitives.
package adapter

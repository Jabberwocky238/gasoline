// Package netstack implements a userspace gVisor-based IP stack that sits
// between the OS TUN device and the gasoline overlay transport. It does NOT
// own either side; the caller feeds raw IP packets in via HandleTunInbound /
// HandleOverlayInbound, and the stack emits raw IP packets via the OnTunWrite
// / OnOverlayWrite / OnOverlayBypass hooks.
//
// Two classification points:
//
//  1. Pre-stack (HandleTunInbound): inspect dst IP of every packet read from
//     TUN. If dst lies inside an overlay prefix and is not our own IP, the
//     packet is handed to OnOverlayBypass verbatim — no reassembly, so peer
//     ⇄ peer TCP stays transparent. Otherwise it is injected into gVisor
//     NIC-TUN.
//
//  2. Post-stack (TCP/UDP forwarder): after gVisor reassembles a flow and
//     hands us a net.Conn, decide by dst IP:
//       - public IP + SOCKS5 available → gonet.DialTCPWithBind to the
//         SOCKS5 peer through NIC-OVERLAY (emits a real SYN out OnOverlayWrite)
//       - public IP + SOCKS5 unavailable, or non-overlay private → dial via
//         the caller-supplied Dialer (bound to the physical NIC).
//
// The two NICs live in one gvisor stack.Stack so DialTCPWithBind can pick
// NIC-OVERLAY via route lookup, letting the SOCKS5 upstream path generate
// its own TCP segments that we emit directly to the overlay — bypassing any
// second round-trip through the OS TUN.
package netstack

// Package fakeip implements a DNS interceptor that answers A/AAAA queries
// with synthetic IP addresses drawn from a reserved range (default
// 198.18.0.0/15, RFC 2544). It also keeps a reverse map so that subsequent
// traffic destined to a fake IP can be resolved back to the original
// domain and redialed by hostname through whatever upstream the netstack
// policy picks (typically SOCKS5 over the overlay).
//
// Hijack policy: DNS (port 53) traffic is hijacked whenever the server-side
// IP lies *outside* every overlay range, even if it's an RFC1918 LAN
// address like 192.168.1.1. The rationale is that in a LAN scenario the
// user's real DNS resolver (router, corporate DNS) would return *real*
// internet IPs, and a subsequent app connection to those IPs would bypass
// our stack-level SOCKS5 path. Returning a fake IP forces the follow-up
// traffic back through the stack where we can route it via overlay/SOCKS5.
// DNS to an overlay peer is instead passed through unchanged — peer-to-peer
// name resolution is a first-class feature of the overlay, not something
// we should rewrite.
//
// The package is split into three concerns:
//
//	Pool   — bounded LRU domain↔fake-IP allocator with reverse lookup
//	Server — DNS codec wrapping a Pool and the hijack policy predicate
//	(future) integration with client/netstack: handleUDP/handleTCP on dst
//	port 53 consult Server.ShouldHijack and invoke Server.ServeUDP /
//	Server.ServeTCP; handleTCP/UDP on dst IP inside the fake range consult
//	Pool.Reverse to recover the domain for hostname-based upstream dial.
package fakeip

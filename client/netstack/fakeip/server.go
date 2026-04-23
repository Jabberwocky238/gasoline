package fakeip

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
)

// Config is the Server construction input. OverlayRanges is consulted by
// ShouldHijack; every DNS destination outside every overlay prefix is
// hijacked (including RFC1918 LAN addresses, which is the whole point of
// the "force follow-up traffic back into the stack" design).
type Config struct {
	// Pool is the fake-IP allocator. Required.
	Pool *Pool

	// OverlayRanges are the overlay-internal prefixes. DNS queries whose
	// destination IP falls inside any of them are *not* hijacked — those
	// queries target peer-provided DNS and must flow through the overlay
	// unchanged.
	OverlayRanges []netip.Prefix

	// DNSTTL is the TTL (seconds) written into every synthesized A record.
	// If zero, defaults to 600s. Keeping this short bounds how long an app
	// will cache a fake IP; if our pool evicts and remaps, the client will
	// re-query sooner.
	DNSTTL uint32
}

// Server handles DNS-over-UDP and DNS-over-TCP queries against a fakeip
// Pool. It does not own any sockets — callers plumb bytes in and out.
type Server struct {
	cfg  Config
	pool *Pool
}

// NewServer constructs a Server. cfg.Pool must be non-nil.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Pool == nil {
		return nil, errors.New("fakeip: Config.Pool required")
	}
	if cfg.DNSTTL == 0 {
		cfg.DNSTTL = 600
	}
	return &Server{cfg: cfg, pool: cfg.Pool}, nil
}

// Pool exposes the underlying pool so callers can drive reverse lookups
// when the netstack sees traffic destined to a fake IP.
func (s *Server) Pool() *Pool { return s.pool }

// ShouldHijack reports whether a DNS packet whose server-side IP is dstIP
// should be intercepted by this server. Returns false iff dstIP is inside
// one of the configured OverlayRanges (pass-through to peer DNS). Returns
// true for every other destination, LAN-private (192.168.*, 10.*, 172.16+)
// included — see package doc for rationale.
func (s *Server) ShouldHijack(dstIP netip.Addr) bool {
	for _, r := range s.cfg.OverlayRanges {
		if r.Contains(dstIP) {
			return false
		}
	}
	return true
}

// ServeUDP handles one DNS-over-UDP query and returns the reply bytes. The
// caller is responsible for reading `query` from a UDP socket (or
// gonet.UDPConn in the netstack integration) and writing the returned
// bytes back to the source. Returns a nil reply on malformed input — the
// caller should just drop in that case.
func (s *Server) ServeUDP(query []byte) []byte {
	resp, _, err := s.buildResponse(query)
	if err != nil {
		return nil
	}
	return resp
}

// ServeTCP reads length-prefixed DNS messages from conn, replies to each,
// and returns when conn fails (EOF, closed, etc.). DNS-over-TCP frames a
// 2-byte big-endian length in front of every message; we mirror that on
// writes.
func (s *Server) ServeTCP(conn io.ReadWriter) error {
	var lenBuf [2]byte
	for {
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		msgLen := binary.BigEndian.Uint16(lenBuf[:])
		if msgLen == 0 {
			continue
		}
		buf := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		resp, _, err := s.buildResponse(buf)
		if err != nil || resp == nil {
			// Return FORMERR by way of zero-length frame? The spec isn't
			// generous here. Dropping is safer than writing a malformed
			// response — client will retry.
			continue
		}
		var out [2]byte
		binary.BigEndian.PutUint16(out[:], uint16(len(resp)))
		if _, err := conn.Write(out[:]); err != nil {
			return err
		}
		if _, err := conn.Write(resp); err != nil {
			return err
		}
	}
}

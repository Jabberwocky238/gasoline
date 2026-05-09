package fakeip

import (
	"errors"

	"golang.org/x/net/dns/dnsmessage"
)

// buildResponse synthesizes a DNS response from a parsed query, returning
// the wire-format bytes. The first question in the query drives what we
// answer:
//
//   - Type A       ⇒ one AResource with the fake IPv4 allocated from the Pool
//   - Type AAAA    ⇒ NOERROR with zero answers (no IPv6 fakeip for now)
//   - anything else⇒ NOERROR with zero answers
//
// The second return value is the domain we resolved (empty if not
// applicable); callers can use it for logging.
func (s *Server) buildResponse(query []byte) ([]byte, string, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil, "", err
	}
	if hdr.Response {
		// Responses arriving at our DNS port are nonsensical; ignore.
		return nil, "", errors.New("fakeip: received DNS response, not a query")
	}

	q, err := p.Question()
	if err != nil {
		return nil, "", err
	}
	// Exhaust remaining questions / sections — we won't use them but the
	// parser may be needed to fully validate the packet.
	_ = p.SkipAllQuestions()

	// Response header: mirror ID, set QR=1, preserve RD, set RA=1, RCode=0.
	respHdr := dnsmessage.Header{
		ID:                 hdr.ID,
		Response:           true,
		OpCode:             hdr.OpCode,
		Authoritative:      true,
		Truncated:          false,
		RecursionDesired:   hdr.RecursionDesired,
		RecursionAvailable: true,
		RCode:              dnsmessage.RCodeSuccess,
	}

	buf := make([]byte, 0, 512)
	b := dnsmessage.NewBuilder(buf, respHdr)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, "", err
	}
	if err := b.Question(q); err != nil {
		return nil, "", err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, "", err
	}

	domain := q.Name.String()
	switch q.Type {
	case dnsmessage.TypeA:
		ip := s.pool.Lookup(domain)
		if !ip.Is4() {
			// Defensive: Pool is documented as v4-only. A v6 slip-through
			// here would imply a future misconfiguration; degrade to
			// empty answer rather than returning SERVFAIL, because the
			// app should still be able to fall back to its next resolver.
			break
		}
		rh := dnsmessage.ResourceHeader{
			Name:  q.Name,
			Type:  dnsmessage.TypeA,
			Class: q.Class,
			TTL:   s.cfg.DNSTTL,
		}
		ar := dnsmessage.AResource{A: ip.As4()}
		if err := b.AResource(rh, ar); err != nil {
			return nil, domain, err
		}
	case dnsmessage.TypeAAAA:
		// Empty NOERROR — callers should retry with A.
	default:
		// Other types (MX, TXT, …) get an empty authoritative answer.
		// A real recursive resolver would forward; fakeip intentionally
		// short-circuits to keep the datapath simple.
	}

	out, err := b.Finish()
	if err != nil {
		return nil, domain, err
	}
	return out, domain, nil
}

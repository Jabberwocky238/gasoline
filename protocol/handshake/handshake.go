package handshake

import (
	"fmt"
	"io"
	"net/netip"
	"sync/atomic"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
)

type VNIMapperFn func(protocol.VNI_Ty) (VNIResolver, error)

type VNIResolver interface {
	CIDR() netip.Prefix
	IP(cid protocol.CID_Ty) (netip.Addr, error)
	Authenticator() auth.ServerAuthenticator
}

var sessionIndexCounter atomic.Uint32

func nextSessionIndex() uint32 {
	return sessionIndexCounter.Add(1)
}

// --------------- Handshake Protocol ---------------

func ClientHandshake(rw io.ReadWriter, vni protocol.VNI_Ty, cid protocol.CID_Ty, authenticator auth.ClientAuthenticator) (*protocol.SessionContext, error) {
	hello := &ClientHello{
		Version:     HandshakeVersion,
		CryptoSuite: CryptoSuite_NONE,
		VNI:         vni,
		CID:         cid,
	}
	if err := hello.Encode(rw); err != nil {
		return nil, fmt.Errorf("send ClientHello: %w", err)
	}

	var serverHello ServerHello
	if err := serverHello.Decode(rw); err != nil {
		return nil, fmt.Errorf("recv ServerHello: %w", err)
	}
	if serverHello.Version != HandshakeVersion {
		return nil, fmt.Errorf("version mismatch: got %d, want %d", serverHello.Version, HandshakeVersion)
	}

	var challenge []byte
	if v, ok := serverHello.Labels.Get(LabelKey_Challenge); ok {
		if b, ok := v.([]byte); ok {
			challenge = b
		}
	}

	response, err := authenticator.Respond(challenge)
	if err != nil {
		return nil, fmt.Errorf("auth respond: %w", err)
	}
	answer := &ClientAnswer{challengeAnswer: response}
	if err := answer.Encode(rw); err != nil {
		return nil, fmt.Errorf("send ClientAnswer: %w", err)
	}

	var assign ServerAssign
	if err := assign.Decode(rw); err != nil {
		return nil, fmt.Errorf("recv ServerAssign: %w", err)
	}
	if assign.Code != HandshakeOK {
		return nil, fmt.Errorf("handshake rejected: code=%d", assign.Code)
	}

	return assign.SessionContext, nil
}

// ServerHandshake performs the handshake on the server side. The
// routeResolver is consulted after auth succeeds; if it returns an
// error the handshake is rejected with HandshakeNoRoute.
func ServerHandshake(rw io.ReadWriter, resolver VNIMapperFn) (*protocol.SessionContext, error) {
	var hello ClientHello
	if err := hello.Decode(rw); err != nil {
		return nil, fmt.Errorf("recv ClientHello: %w", err)
	}
	if hello.Version != HandshakeVersion {
		return nil, fmt.Errorf("version mismatch: got %d, want %d", hello.Version, HandshakeVersion)
	}

	vniResolved, err := resolver(hello.VNI)
	if err != nil {
		sendFail(rw, HandshakeAuthFail)
		return nil, fmt.Errorf("resolve auth for vni %d: %w", hello.VNI, err)
	}

	challenge, err := vniResolved.Authenticator().GenerateChallenge()
	if err != nil {
		return nil, fmt.Errorf("generate challenge: %w", err)
	}

	serverHello := &ServerHello{
		Version:     HandshakeVersion,
		CryptoSuite: hello.CryptoSuite,
	}
	if challenge != nil {
		serverHello.Labels.Set(LabelKey_Challenge, challenge)
	}
	if err := serverHello.Encode(rw); err != nil {
		return nil, fmt.Errorf("send ServerHello: %w", err)
	}

	var answer ClientAnswer
	if err := answer.Decode(rw); err != nil {
		return nil, fmt.Errorf("recv ClientAnswer: %w", err)
	}

	if err := vniResolved.Authenticator().VerifyResponse(hello.CID, challenge, answer.challengeAnswer); err != nil {
		sendFail(rw, HandshakeAuthFail)
		return nil, fmt.Errorf("auth verify: %w", err)
	}
	cip, err := vniResolved.IP(hello.CID)
	if err != nil {
		sendFail(rw, HandshakeNoRoute)
		return nil, fmt.Errorf("resolve route for vni %d cid %x: %w", hello.VNI, hello.CID, err)
	}

	idx := nextSessionIndex()
	sc := &protocol.SessionContext{
		CID:          hello.CID,
		VNI:          hello.VNI,
		SessionIndex: idx,
		IP:           cip,
		IPRanges:     vniResolved.CIDR(),
	}
	assign := &ServerAssign{
		Code:           HandshakeOK,
		SessionContext: sc,
	}
	if err := assign.Encode(rw); err != nil {
		return nil, fmt.Errorf("send ServerAssign: %w", err)
	}
	return sc, nil
}

func sendFail(w io.Writer, code HandshakeCode) {
	fail := &ServerAssign{Code: code}
	_ = fail.Encode(w)
}

// Package handshake implements the gasoline v2 handshake: a Noise_IK exchange
// that binds client identity (its static public key) to the assigned session.
// There is no v1 fallback — the old HMAC/challenge model was removed.
//
// Wire flow (four framed messages, unchanged shape):
//
//	ClientHello  { vni, cid, Label[NoiseInitiation]=msg1 }
//	ServerHello  { Label[NoiseResponse]=msg2 }              or a fail code path
//	ClientAnswer { empty }                                  Noise auth already done
//	ServerAssign { code, sessionContext }
//
// The server, on receiving msg1, recovers the client's static public key,
// checks CID == DeriveCID(pubkey), and checks the key is authorized on the
// VNI. All three failures return the same code with no distinguishing detail.
package handshake

import (
	"fmt"
	"io"
	"net/netip"
	"sync/atomic"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/noise"
)

type VNIMapperFn func(protocol.VNI_Ty) (VNIResolver, error)

// VNIResolver is the per-VNI policy the server consults during a handshake.
type VNIResolver interface {
	// CIDR is the VNI's address range, echoed to the client as IPRanges.
	CIDR() netip.Prefix
	// ServerStatic returns the operator's static key pair for Noise.
	ServerStatic() (noise.PrivateKey, noise.PublicKey)
	// Authorized reports whether pubkey may join this VNI (key table lookup).
	Authorized(pubkey noise.PublicKey) bool
	// IP resolves the address assigned to a client identified by cid.
	IP(cid protocol.CID_Ty) (netip.Addr, error)
}

var sessionIndexCounter atomic.Uint32

func nextSessionIndex() uint32 { return sessionIndexCounter.Add(1) }

// ClientHandshake runs the client (initiator) side. It authenticates to a
// server whose static public key is serverPub, using the client's own key
// pair. On success it returns the assigned SessionContext and the derived
// transport keys for the data plane.
func ClientHandshake(
	rw io.ReadWriter,
	vni protocol.VNI_Ty,
	clientPriv noise.PrivateKey,
	clientPub noise.PublicKey,
	serverPub noise.PublicKey,
) (*protocol.SessionContext, noise.TransportKeys, error) {
	cid := protocol.DeriveCID(clientPub)

	initr := noise.NewInitiator(clientPriv, clientPub, serverPub)
	msg1, err := initr.WriteInitiation(tai64n())
	if err != nil {
		return nil, noise.TransportKeys{}, fmt.Errorf("noise initiation: %w", err)
	}

	hello := &ClientHello{
		Version:     HandshakeVersion,
		CryptoSuite: CryptoSuite_NoiseIK,
		VNI:         vni,
		CID:         cid,
	}
	hello.Labels.Set(LabelKey_NoiseInitiation, msg1)
	if err := hello.Encode(rw); err != nil {
		return nil, noise.TransportKeys{}, fmt.Errorf("send ClientHello: %w", err)
	}

	var serverHello ServerHello
	if err := serverHello.Decode(rw); err != nil {
		return nil, noise.TransportKeys{}, fmt.Errorf("recv ServerHello: %w", err)
	}
	if serverHello.Version != HandshakeVersion {
		return nil, noise.TransportKeys{}, fmt.Errorf("version mismatch: got %d, want %d", serverHello.Version, HandshakeVersion)
	}
	msg2, ok := serverHello.Labels.GetBytes(LabelKey_NoiseResponse)
	if !ok {
		return nil, noise.TransportKeys{}, fmt.Errorf("ServerHello missing noise response")
	}
	keys, err := initr.ReadResponse(msg2)
	if err != nil {
		return nil, noise.TransportKeys{}, fmt.Errorf("noise response: %w", err)
	}

	// ClientAnswer carries no payload; Noise already authenticated both sides.
	if err := (&ClientAnswer{}).Encode(rw); err != nil {
		return nil, noise.TransportKeys{}, fmt.Errorf("send ClientAnswer: %w", err)
	}

	var assign ServerAssign
	if err := assign.Decode(rw); err != nil {
		return nil, noise.TransportKeys{}, fmt.Errorf("recv ServerAssign: %w", err)
	}
	if assign.Code != HandshakeOK {
		return nil, noise.TransportKeys{}, fmt.Errorf("handshake rejected: code=%d", assign.Code)
	}
	return assign.SessionContext, keys, nil
}

// ServerHandshake runs the server (responder) side. resolver supplies the
// operator's key pair, the authorization check, and IP assignment. On success
// it returns the SessionContext, the client's static public key (its
// identity), and the transport keys.
func ServerHandshake(rw io.ReadWriter, resolver VNIMapperFn) (*protocol.SessionContext, noise.PublicKey, noise.TransportKeys, error) {
	var hello ClientHello
	if err := hello.Decode(rw); err != nil {
		return nil, noise.PublicKey{}, noise.TransportKeys{}, fmt.Errorf("recv ClientHello: %w", err)
	}
	if hello.Version != HandshakeVersion {
		return nil, noise.PublicKey{}, noise.TransportKeys{}, fmt.Errorf("version mismatch: got %d, want %d", hello.Version, HandshakeVersion)
	}

	vniResolved, err := resolver(hello.VNI)
	if err != nil {
		rejectAtHello(rw)
		return nil, noise.PublicKey{}, noise.TransportKeys{}, fmt.Errorf("resolve vni %s: %w", hello.VNI, err)
	}

	msg1, ok := hello.Labels.GetBytes(LabelKey_NoiseInitiation)
	if !ok {
		rejectAtHello(rw)
		return nil, noise.PublicKey{}, noise.TransportKeys{}, fmt.Errorf("ClientHello missing noise initiation")
	}

	sPriv, sPub := vniResolved.ServerStatic()
	respr := noise.NewResponder(sPriv, sPub)
	clientPub, _, err := respr.ReadInitiation(msg1)
	if err != nil {
		// Decrypt failure: reject with the generic path (no distinguishing detail).
		rejectAtHello(rw)
		return nil, noise.PublicKey{}, noise.TransportKeys{}, fmt.Errorf("noise read initiation: %w", err)
	}

	// Identity binding: CID must be derived from the recovered public key.
	if protocol.DeriveCID(clientPub) != hello.CID {
		rejectAtHello(rw)
		return nil, noise.PublicKey{}, noise.TransportKeys{}, fmt.Errorf("cid does not match pubkey")
	}
	// Authorization: the key must be granted on this VNI.
	if !vniResolved.Authorized(clientPub) {
		rejectAtHello(rw)
		return nil, noise.PublicKey{}, noise.TransportKeys{}, fmt.Errorf("pubkey not authorized on vni %s", hello.VNI)
	}

	msg2, keys, err := respr.WriteResponse()
	if err != nil {
		return nil, noise.PublicKey{}, noise.TransportKeys{}, fmt.Errorf("noise write response: %w", err)
	}
	serverHello := &ServerHello{Version: HandshakeVersion, CryptoSuite: CryptoSuite_NoiseIK}
	serverHello.Labels.Set(LabelKey_NoiseResponse, msg2)
	if err := serverHello.Encode(rw); err != nil {
		return nil, noise.PublicKey{}, noise.TransportKeys{}, fmt.Errorf("send ServerHello: %w", err)
	}

	// Consume the empty ClientAnswer.
	var answer ClientAnswer
	if err := answer.Decode(rw); err != nil {
		return nil, noise.PublicKey{}, noise.TransportKeys{}, fmt.Errorf("recv ClientAnswer: %w", err)
	}

	cip, err := vniResolved.IP(hello.CID)
	if err != nil {
		sendFail(rw, HandshakeNoRoute)
		return nil, noise.PublicKey{}, noise.TransportKeys{}, fmt.Errorf("resolve route for cid %x: %w", hello.CID, err)
	}

	sc := &protocol.SessionContext{
		CID:          hello.CID,
		VNI:          hello.VNI,
		SessionIndex: nextSessionIndex(),
		IP:           cip,
		IPRanges:     vniResolved.CIDR(),
	}
	assign := &ServerAssign{Code: HandshakeOK, SessionContext: sc}
	if err := assign.Encode(rw); err != nil {
		return nil, noise.PublicKey{}, noise.TransportKeys{}, fmt.Errorf("send ServerAssign: %w", err)
	}
	return sc, clientPub, keys, nil
}

// rejectAtHello rejects before the ServerHello step. The client is blocked
// reading a ServerHello, so we send a ServerHello with no NoiseResponse label;
// the client decodes it, finds the label missing, and errors out cleanly
// rather than hanging. All pre-auth failures use this single path so no timing
// or content distinguishes "bad key" from "unauthorized key".
func rejectAtHello(rw io.ReadWriter) {
	sh := &ServerHello{Version: HandshakeVersion, CryptoSuite: CryptoSuite_NoiseIK}
	_ = sh.Encode(rw)
}

// sendFail rejects after ServerHello, where the client is waiting for a
// ServerAssign (e.g. no route). Body is a zero SessionContext + fail code.
func sendFail(w io.Writer, code HandshakeCode) {
	fail := &ServerAssign{Code: code, SessionContext: &protocol.SessionContext{}}
	_ = fail.Encode(w)
}

// Package handshake implements the gasoline AUTHENTICATION layer: a Noise_IK
// exchange that binds client identity (its static public key) to a pair of
// transport keys. Its sole product is a *noise.Session (the keypair).
//
// It does NOT allocate IPs, sessions, or any control-plane state. Address
// assignment (preclaim/claim/ack/confirm) lives in package control and runs
// AFTER the handshake, using the keypair this package returns.
//
// Three auth messages (all in this package):
//
//  1. ClientHello  { vni, Label[NoiseInitiation]=msg1 }
//  2. ServerHello  { Label[NoiseResponse]=msg2 }
//  3. ClientAnswer { AEAD(send_key, ∅) }   key confirmation — proves the client
//     holds its private key
//
// After message 3 both sides hold the keypair and the client is authenticated.
// Identity is the recovered static public key (no CID); the server checks the
// key is authorized on the VNI. All auth failures return the same generic
// reject.
package handshake

import (
	"fmt"
	"io"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/noise"
)

// VNIMapperFn resolves the per-VNI auth policy for a handshake.
type VNIMapperFn func(protocol.VNI_Ty) (VNIResolver, error)

// VNIResolver is the per-VNI policy the server consults DURING AUTHENTICATION.
// It carries only what auth needs — the operator key pair and the key table.
// IP assignment is not here; that is package control's concern.
type VNIResolver interface {
	// ServerStatic returns the operator's static key pair for Noise.
	ServerStatic() (noise.PrivateKey, noise.PublicKey)
	// Authorized reports whether pubkey may join this VNI (key table lookup).
	Authorized(pubkey noise.PublicKey) bool
}

// confirmCounter is the fixed nonce for the ClientAnswer key-confirmation frame.
// The control plane starts its own nonce sequence from 0 on the same keys.
const confirmCounter = 0

// confirmAAD domain-separates the auth confirmation AEAD.
var confirmAAD = []byte("gasoline-auth-confirm-v1")

// ClientHandshake runs the client (initiator) authentication. It returns the
// derived Session (keypair) on success; the caller then runs control-plane IP
// assignment over the same rw.
func ClientHandshake(
	rw io.ReadWriter,
	vni protocol.VNI_Ty,
	clientPriv noise.PrivateKey,
	clientPub noise.PublicKey,
	serverPub noise.PublicKey,
) (*noise.Session, error) {
	initr := noise.NewInitiator(clientPriv, clientPub, serverPub)
	msg1, err := initr.WriteInitiation(tai64n())
	if err != nil {
		return nil, fmt.Errorf("noise initiation: %w", err)
	}
	hello := &ClientHello{Version: HandshakeVersion, CryptoSuite: CryptoSuite_NoiseIK, VNI: vni}
	hello.Labels.Set(LabelKey_NoiseInitiation, msg1)
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
	msg2, ok := serverHello.Labels.GetBytes(LabelKey_NoiseResponse)
	if !ok {
		return nil, fmt.Errorf("ServerHello missing noise response (rejected)")
	}
	keys, err := initr.ReadResponse(msg2)
	if err != nil {
		return nil, fmt.Errorf("noise response: %w", err)
	}

	sess, err := noise.NewSession(keys, true /* initiator */)
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}

	// Key confirmation: AEAD-seal an empty payload; the operator's decrypt
	// proves we derived the correct key (we hold our private key).
	ct, err := sess.SealAt(confirmCounter, nil, confirmAAD)
	if err != nil {
		return nil, fmt.Errorf("seal confirmation: %w", err)
	}
	if err := (&ClientAnswer{Ciphertext: ct}).Encode(rw); err != nil {
		return nil, fmt.Errorf("send ClientAnswer: %w", err)
	}
	return sess, nil
}

// AuthResult is what a completed server-side authentication yields: the
// client's declared VNI, its recovered static public key (its identity), and
// the transport Session. There is no CID — identity is the public key, and the
// SessionID is allocated later by package assign.
type AuthResult struct {
	VNI       protocol.VNI_Ty
	ClientPub noise.PublicKey
	Session   *noise.Session
}

// ServerHandshake runs the server (responder) authentication. On success it
// returns the AuthResult. It performs NO address assignment — the caller runs
// package assign next, over the same connection, using Session.
func ServerHandshake(rw io.ReadWriter, resolver VNIMapperFn) (AuthResult, error) {
	fail := func(format string, args ...any) (AuthResult, error) {
		return AuthResult{}, fmt.Errorf(format, args...)
	}

	var hello ClientHello
	if err := hello.Decode(rw); err != nil {
		return fail("recv ClientHello: %w", err)
	}
	if hello.Version != HandshakeVersion {
		return fail("version mismatch: got %d, want %d", hello.Version, HandshakeVersion)
	}

	vniResolved, err := resolver(hello.VNI)
	if err != nil {
		rejectAtHello(rw)
		return fail("resolve vni %s: %w", hello.VNI, err)
	}
	msg1, ok := hello.Labels.GetBytes(LabelKey_NoiseInitiation)
	if !ok {
		rejectAtHello(rw)
		return fail("ClientHello missing noise initiation")
	}

	sPriv, sPub := vniResolved.ServerStatic()
	respr := noise.NewResponder(sPriv, sPub)
	clientPub, _, err := respr.ReadInitiation(msg1)
	if err != nil {
		rejectAtHello(rw) // decrypt failure — generic reject, no distinguishing detail
		return fail("noise read initiation: %w", err)
	}
	// Identity is the recovered public key; the CID is derived from it, never
	// taken from the client. Authorization is a pure pubkey lookup.
	if !vniResolved.Authorized(clientPub) {
		rejectAtHello(rw)
		return fail("pubkey not authorized on vni %s", hello.VNI)
	}

	msg2, keys, err := respr.WriteResponse()
	if err != nil {
		return fail("noise write response: %w", err)
	}
	serverHello := &ServerHello{Version: HandshakeVersion, CryptoSuite: CryptoSuite_NoiseIK}
	serverHello.Labels.Set(LabelKey_NoiseResponse, msg2)
	if err := serverHello.Encode(rw); err != nil {
		return fail("send ServerHello: %w", err)
	}

	sess, err := noise.NewSession(keys, false /* responder */)
	if err != nil {
		return fail("session: %w", err)
	}

	// Key confirmation: the client's ClientAnswer must decrypt. Success proves
	// it derived the correct key (holds its private key). Auth ends here.
	var ca ClientAnswer
	if err := ca.Decode(rw); err != nil {
		return fail("recv ClientAnswer: %w", err)
	}
	if _, err := sess.OpenAt(confirmCounter, ca.Ciphertext, confirmAAD, false); err != nil {
		return fail("client answer did not authenticate: %w", err)
	}
	return AuthResult{VNI: hello.VNI, ClientPub: clientPub, Session: sess}, nil
}

// rejectAtHello rejects before ServerHello. The client is blocked reading a
// ServerHello, so we send one with no NoiseResponse label; the client decodes
// it, finds the label missing, and errors out cleanly rather than hanging. All
// pre-auth failures use this single path — no timing or content distinguishes
// "bad key" from "unauthorized key".
func rejectAtHello(rw io.Writer) {
	sh := &ServerHello{Version: HandshakeVersion, CryptoSuite: CryptoSuite_NoiseIK}
	_ = sh.Encode(rw)
}

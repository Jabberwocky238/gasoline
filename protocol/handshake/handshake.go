package handshake

import (
	"fmt"
	"io"
	"sync/atomic"

	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/auth"
)

var sessionIndexCounter atomic.Uint32

func nextSessionIndex() uint32 {
	return sessionIndexCounter.Add(1)
}

type ServerHandshakeState struct {
	VNI protocol.VNI_Ty
}

type ClientHandshakeState struct {
	VNI protocol.VNI_Ty
	CID protocol.CID_Ty
}

// HandshakeResult is returned after a successful handshake.
type HandshakeResult struct {
	SessionIndex   uint32
	CID            protocol.CID_Ty
	VNI            protocol.VNI_Ty
	SessionContext *protocol.SessionContext
}

// --------------- Handshake Protocol ---------------

func ClientHandshake(rw io.ReadWriter, preassignedConfig *protocol.PreassignedSessionConfig, authenticator auth.ClientAuthenticator) (*HandshakeResult, error) {
	hello := &ClientHello{
		Version:     HandshakeVersion,
		CryptoSuite: CryptoSuite_NONE,
		VNI:         preassignedConfig.VNI(),
		CID:         preassignedConfig.CID(),
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

	return &HandshakeResult{
		SessionIndex: assign.SessionIndex,
		CID:          preassignedConfig.CID(),
		VNI:          preassignedConfig.VNI(),
	}, nil
}

// ServerHandshake performs the handshake on the server side.
func ServerHandshake(
	rw io.ReadWriter,
	resolver auth.AuthResolverFn,
) (*HandshakeResult, error) {
	var hello ClientHello
	if err := hello.Decode(rw); err != nil {
		return nil, fmt.Errorf("recv ClientHello: %w", err)
	}
	if hello.Version != HandshakeVersion {
		return nil, fmt.Errorf("version mismatch: got %d, want %d", hello.Version, HandshakeVersion)
	}

	authenticator, err := resolver(hello.VNI)
	if err != nil {
		sendFail(rw, HandshakeAuthFail)
		return nil, fmt.Errorf("resolve auth for vni %d: %w", hello.VNI, err)
	}

	challenge, err := authenticator.GenerateChallenge()
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

	if err := authenticator.VerifyResponse(hello.CID, challenge, answer.challengeAnswer); err != nil {
		sendFail(rw, HandshakeAuthFail)
		return nil, fmt.Errorf("auth verify: %w", err)
	}

	idx := nextSessionIndex()
	assign := &ServerAssign{
		Code:         HandshakeOK,
		SessionIndex: idx,
	}
	if err := assign.Encode(rw); err != nil {
		return nil, fmt.Errorf("send ServerAssign: %w", err)
	}

	return &HandshakeResult{
		SessionIndex: idx,
		CID:          hello.CID,
		VNI:          hello.VNI,
	}, nil
}

func sendFail(w io.Writer, code HandshakeCode) {
	fail := &ServerAssign{Code: code}
	_ = fail.Encode(w)
}

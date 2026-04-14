package protocol

import (
	"fmt"
	"io"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/encryption"
	"github.com/jabberwocky238/gasoline/protocol/messages"
)

const (
	HandshakeVersion = 0x01
)

const (
	HandshakeOK   byte = 0x00
	HandshakeFail byte = 0x01
)

// ConfigFunc generates a SessionConfig for a clientID and VNI after auth succeeds.
type ConfigFunc func(clientID [16]byte, vni common.VNI) (*SessionConfig, error)

// HandshakeResult is returned after a successful handshake.
type HandshakeResult struct {
	ClientID [16]byte
	Config   SessionConfig
	Keypair  *encryption.SessionKeypair
}

// --------------- Handshake Protocol ---------------

// ClientHandshake performs the 4-step handshake on the client side.
//
//  1. C→S: ClientHello  (version + authType + clientID + vni)
//  2. S→C: ServerHello  (version + authType + challenge)
//  3. C→S: ClientRequest(auth response)
//  4. S→C: ServerResponse(status + config)
//  5. derive AEAD keypair via ECDH
func ClientHandshake(rw io.ReadWriter, clientID [16]byte, vni common.VNI, authenticator auth.ClientAuthenticator) (*HandshakeResult, error) {
	hello := &messages.ClientHello{Version: HandshakeVersion, AuthType: authenticator.Type(), ClientID: clientID, VNI: vni}
	if err := hello.Encode(rw); err != nil {
		return nil, fmt.Errorf("send ClientHello: %w", err)
	}

	var serverHello messages.ServerHello
	if err := serverHello.Decode(rw); err != nil {
		return nil, fmt.Errorf("recv ServerHello: %w", err)
	}
	if serverHello.Version != HandshakeVersion {
		return nil, fmt.Errorf("version mismatch: got %d, want %d", serverHello.Version, HandshakeVersion)
	}
	if serverHello.AuthType != authenticator.Type() {
		return nil, fmt.Errorf("auth type mismatch: server=%s, client=%s", serverHello.AuthType, authenticator.Type())
	}

	response, err := authenticator.Respond(serverHello.Payload)
	if err != nil {
		return nil, fmt.Errorf("auth respond: %w", err)
	}
	req := &messages.ClientRequest{Payload: response}
	if err := req.Encode(rw); err != nil {
		return nil, fmt.Errorf("send ClientRequest: %w", err)
	}

	var serverResp messages.ServerResponse
	if err := serverResp.Decode(rw); err != nil {
		return nil, fmt.Errorf("recv ServerResponse: %w", err)
	}
	if serverResp.Status != HandshakeOK {
		return nil, fmt.Errorf("handshake rejected: status=%d", serverResp.Status)
	}

	var cfg SessionConfig
	if err := cfg.Unmarshal(serverResp.Config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	keypair, err := encryption.DeriveSessionKeypair(cfg.ClientPrivateKey, cfg.ServerPublicKey, true)
	if err != nil {
		return nil, fmt.Errorf("derive session keys: %w", err)
	}

	return &HandshakeResult{ClientID: clientID, Config: cfg, Keypair: keypair}, nil
}

// ServerHandshake performs the 4-step handshake on the server side.
// It uses an AuthResolver to select the correct authenticator based on the client's VNI.
func ServerHandshake(rw io.ReadWriter, resolver auth.AuthResolver, configFn ConfigFunc) (*HandshakeResult, error) {
	var hello messages.ClientHello
	if err := hello.Decode(rw); err != nil {
		return nil, fmt.Errorf("recv ClientHello: %w", err)
	}
	if hello.Version != HandshakeVersion {
		return nil, fmt.Errorf("version mismatch: got %d, want %d", hello.Version, HandshakeVersion)
	}

	authenticator, err := resolver.Resolve(hello.VNI)
	if err != nil {
		fail := &messages.ServerResponse{Status: HandshakeFail}
		fail.Encode(rw)
		return nil, fmt.Errorf("resolve auth for vni %s: %w", hello.VNI, err)
	}

	if hello.AuthType != authenticator.Type() {
		fail := &messages.ServerResponse{Status: HandshakeFail}
		fail.Encode(rw)
		return nil, fmt.Errorf("auth type mismatch: client=%s, server=%s", hello.AuthType, authenticator.Type())
	}

	challenge, err := authenticator.GenerateChallenge()
	if err != nil {
		return nil, fmt.Errorf("generate challenge: %w", err)
	}
	serverHello := &messages.ServerHello{
		Version:  HandshakeVersion,
		AuthType: authenticator.Type(),
		Payload:  challenge,
	}
	if err := serverHello.Encode(rw); err != nil {
		return nil, fmt.Errorf("send ServerHello: %w", err)
	}

	var req messages.ClientRequest
	if err := req.Decode(rw); err != nil {
		return nil, fmt.Errorf("recv ClientRequest: %w", err)
	}

	if err := authenticator.VerifyResponse(hello.ClientID, challenge, req.Payload); err != nil {
		fail := &messages.ServerResponse{Status: HandshakeFail}
		fail.Encode(rw)
		return nil, fmt.Errorf("auth verify: %w", err)
	}

	cfg, err := configFn(hello.ClientID, hello.VNI)
	if err != nil {
		fail := &messages.ServerResponse{Status: HandshakeFail}
		fail.Encode(rw)
		return nil, fmt.Errorf("generate config: %w", err)
	}

	resp := &messages.ServerResponse{Status: HandshakeOK, Config: cfg.Marshal()}
	if err := resp.Encode(rw); err != nil {
		return nil, fmt.Errorf("send ServerResponse: %w", err)
	}

	keypair, err := encryption.DeriveSessionKeypair(cfg.ClientPrivateKey, cfg.ServerPublicKey, false)
	if err != nil {
		return nil, fmt.Errorf("derive session keys: %w", err)
	}

	return &HandshakeResult{ClientID: hello.ClientID, Config: *cfg, Keypair: keypair}, nil
}

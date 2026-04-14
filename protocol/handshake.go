package protocol

import (
	"fmt"
	"io"

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

// ConfigFunc generates a SessionConfig for a clientID and vnetID after auth succeeds.
type ConfigFunc func(clientID [16]byte, vnetID [16]byte) (*SessionConfig, error)

// HandshakeResult is returned after a successful handshake.
type HandshakeResult struct {
	ClientID [16]byte
	Config   SessionConfig
	Keypair  *encryption.SessionKeypair
}

// --------------- Handshake Protocol ---------------

// ClientHandshake performs the 4-step handshake on the client side.
//
//  1. C→S: ClientHello  (version + authType + clientID + vnetID)
//  2. S→C: ServerHello  (version + authType + challenge)
//  3. C→S: ClientRequest(auth response)
//  4. S→C: ServerResponse(status + config)
//  5. derive AEAD keypair via ECDH
func ClientHandshake(rw io.ReadWriter, clientID [16]byte, vnetID [16]byte, authenticator auth.ClientAuthenticator) (*HandshakeResult, error) {
	// 1. Send ClientHello with auth type and vnetID
	hello := &messages.ClientHello{Version: HandshakeVersion, AuthType: authenticator.Type(), ClientID: clientID, VNetID: vnetID}
	if err := hello.WriteTo(rw); err != nil {
		return nil, fmt.Errorf("send ClientHello: %w", err)
	}

	// 2. Receive ServerHello
	var serverHello messages.ServerHello
	if err := serverHello.ReadFrom(rw); err != nil {
		return nil, fmt.Errorf("recv ServerHello: %w", err)
	}
	if serverHello.Version != HandshakeVersion {
		return nil, fmt.Errorf("version mismatch: got %d, want %d", serverHello.Version, HandshakeVersion)
	}
	if serverHello.AuthType != authenticator.Type() {
		return nil, fmt.Errorf("auth type mismatch: server=%s, client=%s", serverHello.AuthType, authenticator.Type())
	}

	// 3. Send ClientRequest
	response, err := authenticator.Respond(serverHello.Payload)
	if err != nil {
		return nil, fmt.Errorf("auth respond: %w", err)
	}
	req := &messages.ClientRequest{Payload: response}
	if err := req.WriteTo(rw); err != nil {
		return nil, fmt.Errorf("send ClientRequest: %w", err)
	}

	// 4. Receive ServerResponse
	var serverResp messages.ServerResponse
	if err := serverResp.ReadFrom(rw); err != nil {
		return nil, fmt.Errorf("recv ServerResponse: %w", err)
	}
	if serverResp.Status != HandshakeOK {
		return nil, fmt.Errorf("handshake rejected: status=%d", serverResp.Status)
	}

	// Parse config
	var cfg SessionConfig
	if err := cfg.Unmarshal(serverResp.Config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// 5. Derive AEAD keypair
	keypair, err := encryption.DeriveSessionKeypair(cfg.ClientPrivateKey, cfg.ServerPublicKey, true)
	if err != nil {
		return nil, fmt.Errorf("derive session keys: %w", err)
	}

	return &HandshakeResult{ClientID: clientID, Config: cfg, Keypair: keypair}, nil
}

// ServerHandshake performs the 4-step handshake on the server side.
// It uses an AuthResolver to select the correct authenticator based on the client's VNetID.
func ServerHandshake(rw io.ReadWriter, resolver auth.AuthResolver, configFn ConfigFunc) (*HandshakeResult, error) {
	// 1. Receive ClientHello (now includes VNetID)
	var hello messages.ClientHello
	if err := hello.ReadFrom(rw); err != nil {
		return nil, fmt.Errorf("recv ClientHello: %w", err)
	}
	if hello.Version != HandshakeVersion {
		return nil, fmt.Errorf("version mismatch: got %d, want %d", hello.Version, HandshakeVersion)
	}

	// Resolve auth for this VNet
	authenticator, err := resolver.Resolve(hello.VNetID)
	if err != nil {
		fail := &messages.ServerResponse{Status: HandshakeFail}
		fail.WriteTo(rw)
		return nil, fmt.Errorf("resolve auth for vnet %x: %w", hello.VNetID, err)
	}

	// Verify client requested the same auth type
	if hello.AuthType != authenticator.Type() {
		fail := &messages.ServerResponse{Status: HandshakeFail}
		fail.WriteTo(rw)
		return nil, fmt.Errorf("auth type mismatch: client=%s, server=%s", hello.AuthType, authenticator.Type())
	}

	// 2. Send ServerHello with challenge
	challenge, err := authenticator.GenerateChallenge()
	if err != nil {
		return nil, fmt.Errorf("generate challenge: %w", err)
	}
	serverHello := &messages.ServerHello{
		Version:  HandshakeVersion,
		AuthType: authenticator.Type(),
		Payload:  challenge,
	}
	if err := serverHello.WriteTo(rw); err != nil {
		return nil, fmt.Errorf("send ServerHello: %w", err)
	}

	// 3. Receive ClientRequest
	var req messages.ClientRequest
	if err := req.ReadFrom(rw); err != nil {
		return nil, fmt.Errorf("recv ClientRequest: %w", err)
	}

	// 4. Verify auth
	if err := authenticator.VerifyResponse(hello.ClientID, challenge, req.Payload); err != nil {
		fail := &messages.ServerResponse{Status: HandshakeFail}
		fail.WriteTo(rw)
		return nil, fmt.Errorf("auth verify: %w", err)
	}

	cfg, err := configFn(hello.ClientID, hello.VNetID)
	if err != nil {
		fail := &messages.ServerResponse{Status: HandshakeFail}
		fail.WriteTo(rw)
		return nil, fmt.Errorf("generate config: %w", err)
	}

	resp := &messages.ServerResponse{Status: HandshakeOK, Config: cfg.Marshal()}
	if err := resp.WriteTo(rw); err != nil {
		return nil, fmt.Errorf("send ServerResponse: %w", err)
	}

	// 5. Derive AEAD keypair
	keypair, err := encryption.DeriveSessionKeypair(cfg.ClientPrivateKey, cfg.ServerPublicKey, false)
	if err != nil {
		return nil, fmt.Errorf("derive session keys: %w", err)
	}

	return &HandshakeResult{ClientID: hello.ClientID, Config: *cfg, Keypair: keypair}, nil
}


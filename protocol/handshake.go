package protocol

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/jabberwocky238/gasoline/protocol/auth"
	"github.com/jabberwocky238/gasoline/protocol/encryption"
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
	hello := &ClientHello{Version: HandshakeVersion, AuthType: authenticator.Type(), ClientID: clientID, VNetID: vnetID}
	if err := hello.WriteTo(rw); err != nil {
		return nil, fmt.Errorf("send ClientHello: %w", err)
	}

	// 2. Receive ServerHello
	var serverHello ServerHello
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
	req := &ClientRequest{Payload: response}
	if err := req.WriteTo(rw); err != nil {
		return nil, fmt.Errorf("send ClientRequest: %w", err)
	}

	// 4. Receive ServerResponse
	var serverResp ServerResponse
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
	var hello ClientHello
	if err := hello.ReadFrom(rw); err != nil {
		return nil, fmt.Errorf("recv ClientHello: %w", err)
	}
	if hello.Version != HandshakeVersion {
		return nil, fmt.Errorf("version mismatch: got %d, want %d", hello.Version, HandshakeVersion)
	}

	// Resolve auth for this VNet
	authenticator, err := resolver.Resolve(hello.VNetID)
	if err != nil {
		fail := &ServerResponse{Status: HandshakeFail}
		fail.WriteTo(rw)
		return nil, fmt.Errorf("resolve auth for vnet %x: %w", hello.VNetID, err)
	}

	// Verify client requested the same auth type
	if hello.AuthType != authenticator.Type() {
		fail := &ServerResponse{Status: HandshakeFail}
		fail.WriteTo(rw)
		return nil, fmt.Errorf("auth type mismatch: client=%s, server=%s", hello.AuthType, authenticator.Type())
	}

	// 2. Send ServerHello with challenge
	challenge, err := authenticator.GenerateChallenge()
	if err != nil {
		return nil, fmt.Errorf("generate challenge: %w", err)
	}
	serverHello := &ServerHello{
		Version:  HandshakeVersion,
		AuthType: authenticator.Type(),
		Payload:  challenge,
	}
	if err := serverHello.WriteTo(rw); err != nil {
		return nil, fmt.Errorf("send ServerHello: %w", err)
	}

	// 3. Receive ClientRequest
	var req ClientRequest
	if err := req.ReadFrom(rw); err != nil {
		return nil, fmt.Errorf("recv ClientRequest: %w", err)
	}

	// 4. Verify auth
	if err := authenticator.VerifyResponse(hello.ClientID, challenge, req.Payload); err != nil {
		fail := &ServerResponse{Status: HandshakeFail}
		fail.WriteTo(rw)
		return nil, fmt.Errorf("auth verify: %w", err)
	}

	cfg, err := configFn(hello.ClientID, hello.VNetID)
	if err != nil {
		fail := &ServerResponse{Status: HandshakeFail}
		fail.WriteTo(rw)
		return nil, fmt.Errorf("generate config: %w", err)
	}

	resp := &ServerResponse{Status: HandshakeOK, Config: cfg.Marshal()}
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

// --------------- Wire Messages ---------------

// ClientHello: version(1) + authType(1) + clientID(16) + vnetID(16) = 34 bytes
type ClientHello struct {
	Version  byte
	AuthType auth.Type
	ClientID [16]byte
	VNetID   [16]byte
}

func (m *ClientHello) WriteTo(w io.Writer) error {
	buf := make([]byte, 34)
	buf[0] = m.Version
	buf[1] = byte(m.AuthType)
	copy(buf[2:18], m.ClientID[:])
	copy(buf[18:34], m.VNetID[:])
	_, err := w.Write(buf)
	return err
}

func (m *ClientHello) ReadFrom(r io.Reader) error {
	buf := make([]byte, 34)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	m.Version = buf[0]
	m.AuthType = auth.Type(buf[1])
	copy(m.ClientID[:], buf[2:18])
	copy(m.VNetID[:], buf[18:34])
	return nil
}

// ServerHello: version(1) + authType(1) + payloadLen(2) + payload(N)
type ServerHello struct {
	Version  byte
	AuthType auth.Type
	Payload  []byte
}

func (m *ServerHello) WriteTo(w io.Writer) error {
	header := make([]byte, 4)
	header[0] = m.Version
	header[1] = byte(m.AuthType)
	binary.BigEndian.PutUint16(header[2:], uint16(len(m.Payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(m.Payload) > 0 {
		_, err := w.Write(m.Payload)
		return err
	}
	return nil
}

func (m *ServerHello) ReadFrom(r io.Reader) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	m.Version = header[0]
	m.AuthType = auth.Type(header[1])
	payloadLen := binary.BigEndian.Uint16(header[2:])
	if payloadLen > 0 {
		m.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, m.Payload); err != nil {
			return err
		}
	}
	return nil
}

// ClientRequest: payloadLen(2) + payload(N)
type ClientRequest struct {
	Payload []byte
}

func (m *ClientRequest) WriteTo(w io.Writer) error {
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(m.Payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(m.Payload) > 0 {
		_, err := w.Write(m.Payload)
		return err
	}
	return nil
}

func (m *ClientRequest) ReadFrom(r io.Reader) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	payloadLen := binary.BigEndian.Uint16(header)
	if payloadLen > 0 {
		m.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, m.Payload); err != nil {
			return err
		}
	}
	return nil
}

// ServerResponse: status(1) + configLen(2) + config(N)
type ServerResponse struct {
	Status byte
	Config []byte
}

func (m *ServerResponse) WriteTo(w io.Writer) error {
	header := make([]byte, 3)
	header[0] = m.Status
	binary.BigEndian.PutUint16(header[1:], uint16(len(m.Config)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(m.Config) > 0 {
		_, err := w.Write(m.Config)
		return err
	}
	return nil
}

func (m *ServerResponse) ReadFrom(r io.Reader) error {
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	m.Status = header[0]
	configLen := binary.BigEndian.Uint16(header[1:])
	if configLen > 0 {
		m.Config = make([]byte, configLen)
		if _, err := io.ReadFull(r, m.Config); err != nil {
			return err
		}
	}
	return nil
}

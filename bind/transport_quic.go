package bind

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

type QUICClient struct {
	TLSConfig  *tls.Config
	QUICConfig *quic.Config
}

func (c *QUICClient) Dial(ctx context.Context, address string) (TransportConn, error) {
	tlsConfig := c.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"gasoline-bind"},
		}
	} else {
		tlsConfig = tlsConfig.Clone()
		if len(tlsConfig.NextProtos) == 0 {
			tlsConfig.NextProtos = []string{"gasoline-bind"}
		}
	}

	conn, err := quic.DialAddr(ctx, address, tlsConfig, c.QUICConfig)
	if err != nil {
		return nil, err
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "open stream failed")
		return nil, err
	}

	return &quicConn{
		session: conn,
		stream:  stream,
	}, nil
}

type QUICServer struct {
	TLSConfig  *tls.Config
	QUICConfig *quic.Config

	mu       sync.RWMutex
	listener *quic.Listener
}

func (s *QUICServer) Listen(address string) error {
	tlsConfig, err := s.serverTLSConfig()
	if err != nil {
		return err
	}

	listener, err := quic.ListenAddr(address, tlsConfig, s.QUICConfig)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	return nil
}

func (s *QUICServer) Accept(ctx context.Context) (TransportConn, error) {
	listener := s.getListener()
	if listener == nil {
		return nil, errors.New("quic listener is not started")
	}

	session, err := listener.Accept(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := session.AcceptStream(ctx)
	if err != nil {
		_ = session.CloseWithError(0, "accept stream failed")
		return nil, err
	}

	return &quicConn{
		session: session,
		stream:  stream,
	}, nil
}

func (s *QUICServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener == nil {
		return nil
	}
	err := s.listener.Close()
	s.listener = nil
	return err
}

func (s *QUICServer) Addr() net.Addr {
	listener := s.getListener()
	if listener == nil {
		return nil
	}
	return listener.Addr()
}

func (s *QUICServer) getListener() *quic.Listener {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listener
}

func (s *QUICServer) serverTLSConfig() (*tls.Config, error) {
	if s.TLSConfig != nil {
		cfg := s.TLSConfig.Clone()
		if len(cfg.NextProtos) == 0 {
			cfg.NextProtos = []string{"gasoline-bind"}
		}
		return cfg, nil
	}

	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"gasoline-bind"},
	}, nil
}

type quicConn struct {
	session *quic.Conn
	stream  *quic.Stream
}

func (c *quicConn) Read(p []byte) (int, error) {
	return (*c.stream).Read(p)
}

func (c *quicConn) Write(p []byte) (int, error) {
	return (*c.stream).Write(p)
}

func (c *quicConn) Close() error {
	streamErr := (*c.stream).Close()
	sessionErr := c.session.CloseWithError(0, "")
	if streamErr != nil {
		return streamErr
	}
	return sessionErr
}

func (c *quicConn) LocalAddr() net.Addr {
	return c.session.LocalAddr()
}

func (c *quicConn) RemoteAddr() net.Addr {
	return c.session.RemoteAddr()
}

func (c *quicConn) SetDeadline(t time.Time) error {
	if err := (*c.stream).SetDeadline(t); err != nil {
		return err
	}
	return nil
}

func (c *quicConn) SetReadDeadline(t time.Time) error {
	return (*c.stream).SetReadDeadline(t)
}

func (c *quicConn) SetWriteDeadline(t time.Time) error {
	return (*c.stream).SetWriteDeadline(t)
}

func generateSelfSignedCert() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "gasoline-quic",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	return tls.X509KeyPair(certPEM, keyPEM)
}

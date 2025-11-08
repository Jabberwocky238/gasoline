package device

import (
	"context"
	"errors"
	"wwww/transport"
	"wwww/transport/tcp"
	"wwww/transport/tls"
	"wwww/transport/udp"
)

func NewServer(ctx context.Context, transportType string) (transport.TransportServer, error) {
	switch transportType {
	case "tcp":
		return tcp.NewTCPServer(), nil
	case "udp":
		return udp.NewUDPServer(), nil
	case "tls":
		return tls.NewTLSServer(ctx), nil
	default:
		return nil, errors.New("invalid transport type")
	}
}

func NewClient(ctx context.Context, transportType string) (transport.TransportClient, error) {
	switch transportType {
	case "tcp":
		return tcp.NewTCPClient(), nil
	case "udp":
		return udp.NewUDPClient(ctx), nil
	case "tls":
		return tls.NewTLSClient(ctx), nil
	default:
		return nil, errors.New("invalid transport type")
	}
}

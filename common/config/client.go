package config

import (
	log "github.com/sirupsen/logrus"
)

type ClientConfig struct {
	Endpoint   string
	Transport  string
	AuthStr    string
	VNI        VNI
	VMAC       VMAC
	TUNName    string
	Socks5Port int

	Logger *log.Logger
}

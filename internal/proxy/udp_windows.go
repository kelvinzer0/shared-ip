//go:build windows

package proxy

import (
	"fmt"
	"log"
	"net"
	"sync"

	"shared-ip/internal/config"
)

// UDPProxy on Windows is a no-op stub (IP_TRANSPARENT not available).
type UDPProxy struct {
	cfg  *config.Config
	port int
	quit chan struct{}
}

func NewUDPProxy(cfg *config.Config, port int) *UDPProxy {
	return &UDPProxy{
		cfg:  cfg,
		port: port,
		quit: make(chan struct{}),
	}
}

func (p *UDPProxy) Start() error {
	log.Printf("[UDP] UDP proxy not supported on Windows (port %d)", p.port)
	return fmt.Errorf("UDP proxy not supported on Windows")
}

func (p *UDPProxy) Stop() {
	close(p.quit)
}

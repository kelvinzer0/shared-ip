package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"shared-ip/internal/config"
	"shared-ip/internal/extractor"
	"time"
)

type TCPProxy struct {
	cfg      *config.Config
	listener net.Listener
	port     int
	quit     chan struct{}
}

func NewTCPProxy(cfg *config.Config, port int) *TCPProxy {
	return &TCPProxy{
		cfg:  cfg,
		port: port,
		quit: make(chan struct{}),
	}
}

func (p *TCPProxy) Start() error {
	addr := fmt.Sprintf(":%d", p.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp listen %s: %w", addr, err)
	}
	p.listener = ln

	log.Printf("[TCP] Listening on %s", addr)

	go p.acceptLoop()
	return nil
}

func (p *TCPProxy) Stop() {
	close(p.quit)
	if p.listener != nil {
		p.listener.Close()
	}
}

func (p *TCPProxy) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.quit:
				return
			default:
				log.Printf("[TCP] Accept error: %v", err)
				continue
			}
		}
		go p.handleConnection(conn)
	}
}

func (p *TCPProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Set read deadline to get first packet
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read initial data to extract domain
	buf := make([]byte, 4096)
	n, err := clientConn.Read(buf)
	if err != nil {
		log.Printf("[TCP] Read error from %s: %v", clientConn.RemoteAddr(), err)
		return
	}

	// Remove read deadline
	clientConn.SetReadDeadline(time.Time{})

	firstPacket := buf[:n]
	domain, isTLS, err := extractor.ExtractDomain(firstPacket)
	if err != nil {
		log.Printf("[TCP] Extract error from %s: %v", clientConn.RemoteAddr(), err)
		return
	}

	if domain == "" {
		log.Printf("[TCP] No domain found from %s (tls=%v)", clientConn.RemoteAddr(), isTLS)
		return
	}

	proto := "HTTP"
	if isTLS {
		proto = "TLS"
	}

	// Find backend for this domain on this port
	mapping := p.cfg.Lookup(domain, p.port)
	if mapping == nil {
		// Try port 0 (any port mapping)
		mapping = p.cfg.LookupByDomain(domain)
		if mapping == nil {
			log.Printf("[TCP] [%s] %s -> no mapping (port %d)", proto, domain, p.port)
			return
		}
	}

	backendAddr := fmt.Sprintf("%s:%d", mapping.LocalIP, mapping.GetBackendPort())
	log.Printf("[TCP] [%s] %s -> %s", proto, domain, backendAddr)

	// Connect to backend
	backendConn, err := net.DialTimeout("tcp", backendAddr, 5*time.Second)
	if err != nil {
		log.Printf("[TCP] Backend connect error %s: %v", backendAddr, err)
		return
	}
	defer backendConn.Close()

	// Forward first packet to backend
	if _, err := backendConn.Write(firstPacket); err != nil {
		log.Printf("[TCP] Forward error to %s: %v", backendAddr, err)
		return
	}

	// Bidirectional copy
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(backendConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, backendConn)
		done <- struct{}{}
	}()

	// Wait for one direction to finish
	<-done
}

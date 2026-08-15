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
	// Listen on [::] for true dual-stack (accepts both IPv4 and IPv6)
	// On Linux with net.ipv6.bindv6only=0 (default), [::] also accepts IPv4.
	addr := fmt.Sprintf("[::]:%d", p.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// Fallback to 0.0.0.0 if IPv6 is not available
		addr = fmt.Sprintf(":%d", p.port)
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("tcp listen %s: %w", addr, err)
		}
	}
	p.listener = ln

	log.Printf("[TCP] Listening on %s (dual-stack)", addr)

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

	proto := "HTTP"
	if isTLS {
		proto = "TLS"
	} else if domain != "" && len(firstPacket) > 0 && (firstPacket[0] == 'E' || firstPacket[0] == 'e' || firstPacket[0] == 'H' || firstPacket[0] == 'h') {
		// EHLO/HELO → SMTP
		proto = "SMTP"
	}

	var mapping *config.DomainMapping

	if domain != "" {
		// Domain found — try exact match first
		mapping = p.cfg.Lookup(domain, p.port)
		if mapping == nil {
			mapping = p.cfg.LookupByDomain(domain)
		}
	}

	if mapping == nil {
		// No domain or no mapping found by domain.
		// Fallback: port-based routing.
		// If there's exactly ONE mapping on this port, use it.
		// This handles SMTP/IMAP/POP3 where domain is not extractable.
		mappings := p.cfg.GetByPort(p.port)
		if len(mappings) == 1 {
			mapping = &mappings[0]
			if domain != "" {
				log.Printf("[TCP] [%s] %s -> port-fallback to %s (only mapping on port %d)", proto, domain, mapping.Domain, p.port)
			} else {
				log.Printf("[TCP] [%s] no-domain -> port-fallback to %s:%d (only mapping on port %d)", proto, mapping.Domain, mapping.GetBackendPort(), p.port)
			}
		} else if len(mappings) > 1 {
			log.Printf("[TCP] [%s] %s -> ambiguous: %d mappings on port %d, cannot route", proto, domain, len(mappings), p.port)
			return
		} else {
			log.Printf("[TCP] [%s] %s -> no mapping on port %d", proto, domain, p.port)
			return
		}
	}

	// Choose backend based on client connection's IP version
	useIPv6 := false
	if tcpAddr, ok := clientConn.RemoteAddr().(*net.TCPAddr); ok {
		useIPv6 = tcpAddr.IP.To4() == nil
	}

	// Log client IP version for debugging
	clientVer := "IPv4"
	if useIPv6 {
		clientVer = "IPv6"
	}

	backendAddr := mapping.GetBackendAddr(useIPv6)
	log.Printf("[TCP] [%s] %s (%s) -> %s", proto, domain, clientVer, backendAddr)

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

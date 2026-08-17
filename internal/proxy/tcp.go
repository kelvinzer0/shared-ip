package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"shared-ip/internal/config"
	"shared-ip/internal/extractor"
	smtplib "shared-ip/internal/smtp"
	"shared-ip/internal/upgrade"
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
	// Try to inherit listener from parent (graceful upgrade)
	listenerName := fmt.Sprintf("tcp-%d", p.port)
	if ln := upgrade.InheritListener(listenerName); ln != nil {
		p.listener = ln
		log.Printf("[TCP] Inherited listener on :%d", p.port)
	} else {
		// Use IP_TRANSPARENT to listen on a special address.
		// This intercepts ALL traffic on this port regardless of destination IP,
		// so the backend can bind to dummy interface IPs without conflict.
		// Like uvhost: listen on 127.127.127.127:<port>
		listenAddr := fmt.Sprintf("127.127.127.127:%d", p.port)
		ln, err := ListenTransparentFallback("tcp4", listenAddr)
		if err != nil {
			return fmt.Errorf("tcp listen %s: %w", listenAddr, err)
		}
		p.listener = ln
		log.Printf("[TCP] Listening on %s (transparent)", listenAddr)
	}

	// Register for graceful upgrade
	upgrade.SaveListener(listenerName, p.listener)

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

// MaxLookahead is the maximum bytes to buffer for host identification.
const MaxLookahead = 4096

func (p *TCPProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// SMTP special handling: use eater pattern for port 25
	if p.port == smtplib.Port {
		p.handleSMTP(clientConn)
		return
	}

	// Incremental read for all other protocols
	var preview [MaxLookahead]byte
	previewLen := 0

	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer clientConn.SetReadDeadline(time.Time{})

	for previewLen < MaxLookahead {
		n, err := clientConn.Read(preview[previewLen:])
		if n > 0 {
			previewLen += n
		}
		if err != nil && previewLen == 0 {
			log.Printf("[TCP] Read error from %s: %v", clientConn.RemoteAddr(), err)
			return
		}

		result := extractor.ExtractDomainIncremental(preview[:previewLen])

		if result.Done {
			p.routeConnection(clientConn, preview[:previewLen], result.Host, result.Protocol)
			return
		}

		if err != nil {
			log.Printf("[TCP] Incomplete data from %s (proto=%s, got %d bytes): %v",
				clientConn.RemoteAddr(), result.Protocol, previewLen, err)
			return
		}
	}

	result := extractor.ExtractDomainIncremental(preview[:previewLen])
	p.routeConnection(clientConn, preview[:previewLen], result.Host, result.Protocol)
}

// handleSMTP implements the eater pattern for SMTP proxying.
//
// Flow:
//  1. StuffSMTP: send fake 220+250+250 to client
//  2. Read client commands until RCPT TO → extract target domain
//  3. Connect to backend
//  4. EatSMTP: consume server's 220+250+250 (client already got them)
//  5. Forward RCPT TO + bidirectional copy
func (p *TCPProxy) handleSMTP(clientConn net.Conn) {
	domain := p.cfg.GetFirstDomain(p.port)
	if domain == "" {
		log.Printf("[SMTP] No mapping on port %d", p.port)
		return
	}

	// Step 1: Send fake replies to fast-forward through handshake
	if _, err := smtplib.StuffSMTP(clientConn, domain); err != nil {
		log.Printf("[SMTP] StuffSMTP error: %v", err)
		return
	}

	// Step 2: Read client commands until RCPT TO
	clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var buf [MaxLookahead]byte
	bufLen := 0

	for bufLen < MaxLookahead {
		n, err := clientConn.Read(buf[bufLen:])
		if n > 0 {
			bufLen += n
		}

		// Check if we have RCPT TO
		rcptDomain := smtplib.ExtractRcptDomain(buf[:bufLen])
		if rcptDomain != "" {
			// Step 3: Connect to backend
			mapping := p.cfg.LookupFold(rcptDomain, p.port)
			if mapping == nil {
				mapping = p.cfg.LookupByDomainFold(rcptDomain)
			}
			if mapping == nil {
				// Fall back to single mapping on this port
				mappings := p.cfg.GetByPort(p.port)
				if len(mappings) == 1 {
					mapping = &mappings[0]
				} else {
					log.Printf("[SMTP] %s -> no mapping", rcptDomain)
					return
				}
			}

			backendAddr := mapping.GetBackendAddr()
			log.Printf("[SMTP] %s -> %s", rcptDomain, backendAddr)

			backendConn, err := DialTransparentFallback(backendAddr, clientConn.RemoteAddr())
			if err != nil {
				log.Printf("[SMTP] Backend connect error %s: %v", backendAddr, err)
				return
			}
			defer backendConn.Close()

			// Step 4: Eat server's replies
			if _, err := smtplib.EatSMTP(backendConn); err != nil {
				log.Printf("[SMTP] EatSMTP error: %v", err)
				return
			}

			// Step 5: Forward buffered client data + bidirectional copy
			if _, err := backendConn.Write(buf[:bufLen]); err != nil {
				log.Printf("[SMTP] Forward error: %v", err)
				return
			}

			bidirectionalCopy(clientConn, backendConn)
			return
		}

		if err != nil {
			log.Printf("[SMTP] Read error before RCPT TO: %v", err)
			return
		}
	}

	log.Printf("[SMTP] MaxLookahead exceeded without RCPT TO")
}

func (p *TCPProxy) routeConnection(clientConn net.Conn, firstPacket []byte, domain, protocol string) {
	proto := strings.ToUpper(protocol)
	if proto == "" {
		proto = "UNKNOWN"
	}

	var mapping *config.DomainMapping

	if domain != "" {
		mapping = p.cfg.LookupFold(domain, p.port)
		if mapping == nil {
			mapping = p.cfg.LookupByDomainFold(domain)
		}
	}

	if mapping == nil {
		mappings := p.cfg.GetByPort(p.port)
		if len(mappings) == 1 {
			mapping = &mappings[0]
			log.Printf("[TCP] [%s] %s -> port-fallback to %s:%d",
				proto, domain, mapping.Domain, mapping.Port)
		} else if len(mappings) > 1 {
			log.Printf("[TCP] [%s] %s -> ambiguous: %d mappings on port %d",
				proto, domain, len(mappings), p.port)
			return
		} else {
			log.Printf("[TCP] [%s] %s -> no mapping on port %d",
				proto, domain, p.port)
			return
		}
	}

	backendAddr := mapping.GetBackendAddr()
	log.Printf("[TCP] [%s] %s -> %s", proto, domain, backendAddr)

	// Use transparent proxy to preserve client source IP
	backendConn, err := DialTransparentFallback(backendAddr, clientConn.RemoteAddr())
	if err != nil {
		log.Printf("[TCP] Backend connect error %s: %v", backendAddr, err)
		return
	}
	defer backendConn.Close()

	if _, err := backendConn.Write(firstPacket); err != nil {
		log.Printf("[TCP] Forward error to %s: %v", backendAddr, err)
		return
	}

	bidirectionalCopy(clientConn, backendConn)
}

// bidirectionalCopy copies data in both directions and waits for both to finish.
// Uses CloseWrite() to signal EOF per direction without closing the connection.
func bidirectionalCopy(client, backend net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(backend, client)
		if tc, ok := backend.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, backend)
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}

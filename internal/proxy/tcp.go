package proxy

import (
	"crypto/tls"
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

// TCPProxy listens on every public-facing IP (non-loopback, non-dummy) for a
// given port and forwards connections to the appropriate backend.
//
// Listening only on public IPs means dummy interface IPs (e.g. 10.x.x.x,
// fd00::x) assigned to backend services are never bound by the proxy,
// so backends can freely bind to those IPs on the same port without conflict.
type TCPProxy struct {
	cfg       *config.Config
	listeners []net.Listener
	port      int
	quit      chan struct{}
}

func NewTCPProxy(cfg *config.Config, port int) *TCPProxy {
	return &TCPProxy{
		cfg:  cfg,
		port: port,
		quit: make(chan struct{}),
	}
}

func (p *TCPProxy) Start() error {
	listenerName := fmt.Sprintf("tcp-%d", p.port)

	// Try to inherit listener from parent (graceful upgrade)
	if ln := upgrade.InheritListener(listenerName); ln != nil {
		p.listeners = append(p.listeners, ln)
		log.Printf("[TCP] Inherited listener on :%d", p.port)
		go p.acceptLoop(ln)
		return nil
	}

	// Enumerate IPs on public-facing interfaces (excludes loopback + sip-* dummies).
	pubAddrs := publicListenAddrs(p.port)
	if len(pubAddrs) == 0 {
		// Fallback: listen on all interfaces if no public IPs detected.
		log.Printf("[TCP] No public IPs detected, falling back to 0.0.0.0:%d", p.port)
		pubAddrs = []string{fmt.Sprintf(":%d", p.port)}
	}

	for _, addr := range pubAddrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("[TCP] Listen %s: %v (skipping)", addr, err)
			continue
		}
		p.listeners = append(p.listeners, ln)
		log.Printf("[TCP] Listening on %s", addr)
		go p.acceptLoop(ln)
	}

	if len(p.listeners) == 0 {
		return fmt.Errorf("tcp: could not listen on any address for port %d", p.port)
	}

	// Register first listener for graceful upgrade
	upgrade.SaveListener(listenerName, p.listeners[0])
	return nil
}

func (p *TCPProxy) Stop() {
	close(p.quit)
	for _, ln := range p.listeners {
		ln.Close()
	}
}

func (p *TCPProxy) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
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

	for previewLen < MaxLookahead {
		n, err := clientConn.Read(preview[previewLen:])
		if n > 0 {
			previewLen += n
		}
		if err != nil && previewLen == 0 {
			log.Printf("[TCP] Read error from %s: %v", clientConn.RemoteAddr(), err)
			return
		}

		// Check for ACME challenge early (before domain extraction)
		if previewLen >= 20 && serveACMEChallenge(clientConn, preview[:previewLen]) {
			return
		}

		result := extractor.ExtractDomainIncremental(preview[:previewLen])

		if result.Done {
			// CRITICAL: clear read deadline BEFORE routing to long-lived connections
			// Without this, the 5s deadline kills WebSocket/SSH/etc after ~5 seconds
			clientConn.SetReadDeadline(time.Time{})
			p.routeConnection(clientConn, preview[:previewLen], result.Host, result.Protocol)
			return
		}

		if err != nil {
			log.Printf("[TCP] Incomplete data from %s (proto=%s, got %d bytes): %v",
				clientConn.RemoteAddr(), result.Protocol, previewLen, err)
			return
		}
	}

	clientConn.SetReadDeadline(time.Time{})
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

			p.handleSMTPForward(clientConn, buf[:bufLen], backendAddr)
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

	// TLS termination: if domain has certs and TLSTerminate flag, terminate TLS
	if mapping.ShouldTerminateTLS() && protocol == "tls" {
		p.handleTLSTermination(clientConn, firstPacket, domain, backendAddr, mapping)
		return
	}

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

// certCache caches loaded TLS certificates to avoid disk I/O on every connection.
var certCache sync.Map // domain -> *tls.Certificate

// handleTLSTermination terminates TLS on the proxy and forwards plain TCP to backend.
func (p *TCPProxy) handleTLSTermination(clientConn net.Conn, firstPacket []byte, domain, backendAddr string, mapping *config.DomainMapping) {
	// Load cert from cache or disk
	var cert *tls.Certificate
	if cached, ok := certCache.Load(domain); ok {
		cert = cached.(*tls.Certificate)
	} else {
		c, err := tls.LoadX509KeyPair(mapping.CertPath, mapping.KeyPath)
		if err != nil {
			log.Printf("[TLS] Load cert for %s: %v", domain, err)
			return
		}
		cert = &c
		certCache.Store(domain, cert)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	// Wrap the connection: replay firstPacket then rest of stream
	reader := &connReplayer{first: firstPacket, rest: clientConn}
	tlsConn := tls.Server(reader, tlsConfig)

	// Set handshake deadline to prevent hanging connections
	clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[TLS] Handshake failed for %s: %v", domain, err)
		return
	}
	clientConn.SetReadDeadline(time.Time{}) // reset deadline

	log.Printf("[TLS] %s -> %s (TLS terminated)", domain, backendAddr)

	// Connect to backend (plain TCP, no TLS)
	backendConn, err := DialTransparentFallback(backendAddr, clientConn.RemoteAddr())
	if err != nil {
		log.Printf("[TLS] Backend connect error %s: %v", backendAddr, err)
		return
	}
	defer backendConn.Close()

	bidirectionalCopy(tlsConn, backendConn)
}

// connReplayer replays buffered data then reads from the underlying connection.
type connReplayer struct {
	first []byte
	rest  net.Conn
}

func (r *connReplayer) Read(p []byte) (int, error) {
	if len(r.first) > 0 {
		n := copy(p, r.first)
		r.first = r.first[n:]
		return n, nil
	}
	return r.rest.Read(p)
}

func (r *connReplayer) Write(p []byte) (int, error)  { return r.rest.Write(p) }
func (r *connReplayer) Close() error                  { return r.rest.Close() }
func (r *connReplayer) LocalAddr() net.Addr           { return r.rest.LocalAddr() }
func (r *connReplayer) RemoteAddr() net.Addr          { return r.rest.RemoteAddr() }
func (r *connReplayer) SetDeadline(t time.Time) error { return r.rest.SetDeadline(t) }
func (r *connReplayer) SetReadDeadline(t time.Time) error  { return r.rest.SetReadDeadline(t) }
func (r *connReplayer) SetWriteDeadline(t time.Time) error { return r.rest.SetWriteDeadline(t) }

// handleSMTPForward connects to backend, eats SMTP replies, and forwards.
// Separated from handleSMTP to avoid defer-in-loop bug.
func (p *TCPProxy) handleSMTPForward(clientConn net.Conn, buf []byte, backendAddr string) {
	backendConn, err := DialTransparentFallback(backendAddr, clientConn.RemoteAddr())
	if err != nil {
		log.Printf("[SMTP] Backend connect error %s: %v", backendAddr, err)
		return
	}
	defer backendConn.Close()

	// Eat server's replies (220+250+250)
	if _, err := smtplib.EatSMTP(backendConn); err != nil {
		log.Printf("[SMTP] EatSMTP error: %v", err)
		return
	}

	// Forward buffered client data + bidirectional copy
	if _, err := backendConn.Write(buf); err != nil {
		log.Printf("[SMTP] Forward error: %v", err)
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

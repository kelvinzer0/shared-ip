package proxy

import (
	"fmt"
	"log"
	"net"
	"shared-ip/internal/config"
	"shared-ip/internal/extractor"
	"sync"
	"time"
)

type UDPProxy struct {
	cfg      *config.Config
	conn     *net.UDPConn
	port     int
	quit     chan struct{}
	sessions sync.Map // clientAddr -> *udpSession
}

type udpSession struct {
	backendConn *net.UDPConn
	lastActive  time.Time
}

func NewUDPProxy(cfg *config.Config, port int) *UDPProxy {
	return &UDPProxy{
		cfg:  cfg,
		port: port,
		quit: make(chan struct{}),
	}
}

func (p *UDPProxy) Start() error {
	addr := &net.UDPAddr{Port: p.port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("udp listen :%d: %w", p.port, err)
	}
	p.conn = conn

	log.Printf("[UDP] Listening on :%d", p.port)

	go p.readLoop()
	go p.cleanupLoop()
	return nil
}

func (p *UDPProxy) Stop() {
	close(p.quit)
	if p.conn != nil {
		p.conn.Close()
	}
	// Close all sessions
	p.sessions.Range(func(key, value interface{}) bool {
		if sess, ok := value.(*udpSession); ok {
			sess.backendConn.Close()
		}
		return true
	})
}

func (p *UDPProxy) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-p.quit:
				return
			default:
				log.Printf("[UDP] Read error: %v", err)
				continue
			}
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		go p.handlePacket(clientAddr, data)
	}
}

func (p *UDPProxy) handlePacket(clientAddr *net.UDPAddr, data []byte) {
	sessionKey := clientAddr.String()

	// Check existing session
	if val, ok := p.sessions.Load(sessionKey); ok {
		sess := val.(*udpSession)
		sess.lastActive = time.Now()
		if _, err := sess.backendConn.Write(data); err != nil {
			log.Printf("[UDP] Forward error: %v", err)
			p.sessions.Delete(sessionKey)
			sess.backendConn.Close()
		}
		return
	}

	// New session - try to extract domain
	domain, isQUIC, err := extractor.ExtractQUICSNI(data)
	if err != nil {
		log.Printf("[UDP] Extract error from %s: %v", clientAddr, err)
		return
	}

	if domain == "" {
		// For non-QUIC UDP, we can't route by domain
		// Log and skip - without domain info, routing is impossible
		log.Printf("[UDP] No domain from %s (quic=%v, len=%d)", clientAddr, isQUIC, len(data))
		return
	}

	proto := "UDP"
	if isQUIC {
		proto = "QUIC"
	}

	// Find backend
	mapping := p.cfg.Lookup(domain, p.port)
	if mapping == nil {
		mapping = p.cfg.LookupByDomain(domain)
		if mapping == nil {
			log.Printf("[UDP] [%s] %s -> no mapping", proto, domain)
			return
		}
	}

	backendAddr := fmt.Sprintf("%s:%d", mapping.LocalIP, p.port)
	log.Printf("[UDP] [%s] %s -> %s", proto, domain, backendAddr)

	// Connect to backend
	udpBackend, err := net.ResolveUDPAddr("udp", backendAddr)
	if err != nil {
		log.Printf("[UDP] Resolve error %s: %v", backendAddr, err)
		return
	}

	backendConn, err := net.DialUDP("udp", nil, udpBackend)
	if err != nil {
		log.Printf("[UDP] Dial error %s: %v", backendAddr, err)
		return
	}

	sess := &udpSession{
		backendConn: backendConn,
		lastActive:  time.Now(),
	}
	p.sessions.Store(sessionKey, sess)

	// Forward first packet
	if _, err := backendConn.Write(data); err != nil {
		log.Printf("[UDP] Forward error: %v", err)
		backendConn.Close()
		p.sessions.Delete(sessionKey)
		return
	}

	// Start reading responses from backend
	go p.readBackend(clientAddr, sess)
}

func (p *UDPProxy) readBackend(clientAddr *net.UDPAddr, sess *udpSession) {
	defer func() {
		sess.backendConn.Close()
		p.sessions.Delete(clientAddr.String())
	}()

	buf := make([]byte, 65535)
	for {
		sess.backendConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := sess.backendConn.Read(buf)
		if err != nil {
			return
		}

		sess.lastActive = time.Now()
		if _, err := p.conn.WriteToUDP(buf[:n], clientAddr); err != nil {
			return
		}
	}
}

func (p *UDPProxy) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.quit:
			return
		case <-ticker.C:
			now := time.Now()
			p.sessions.Range(func(key, value interface{}) bool {
				sess := value.(*udpSession)
				if now.Sub(sess.lastActive) > 120*time.Second {
					sess.backendConn.Close()
					p.sessions.Delete(key)
				}
				return true
			})
		}
	}
}

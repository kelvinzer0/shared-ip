package proxy

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"shared-ip/internal/certbot"
)

// ACMEServer serves ACME HTTP-01 challenge tokens from the certbot webroot.
// This runs on a separate port so certbot can validate domains even while
// the main TCP proxy is running on port 80.
type ACMEServer struct {
	listener net.Listener
	port     int
}

// NewACMEServer creates a new ACME challenge server on the given port.
func NewACMEServer(port int) *ACMEServer {
	return &ACMEServer{port: port}
}

// Start begins serving ACME challenges.
func (s *ACMEServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleChallenge)

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("ACME server listen %s: %w", addr, err)
	}
	s.listener = ln

	go func() {
		if err := http.Serve(ln, mux); err != nil && err != http.ErrServerClosed {
			log.Printf("[ACME] Server error: %v", err)
		}
	}()

	log.Printf("[ACME] Challenge server listening on %s", addr)
	return nil
}

// Stop shuts down the ACME server.
func (s *ACMEServer) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
}

// Port returns the port the server is listening on.
func (s *ACMEServer) Port() int {
	return s.port
}

// handleChallenge serves ACME challenge tokens from the webroot directory.
func (s *ACMEServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	// Only serve ACME challenge paths
	if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		http.NotFound(w, r)
		return
	}

	token := filepath.Base(r.URL.Path)
	if token == "" || token == "." || token == ".." || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}

	tokenPath := filepath.Join(certbot.WebrootPath(), ".well-known", "acme-challenge", token)

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

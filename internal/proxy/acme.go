package proxy

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"shared-ip/internal/certbot"
)

// serveACMEChallenge checks if the preview data is an HTTP request for
// /.well-known/acme-challenge/. If so, serves the token from the certbot
// webroot and returns true. Returns false if not an ACME challenge.
func serveACMEChallenge(conn net.Conn, data []byte) bool {
	// Quick check: must be HTTP and contain acme-challenge path
	if len(data) < 20 {
		return false
	}

	// Check if it starts with an HTTP method
	methods := []string{"GET ", "HEAD "}
	isHTTP := false
	for _, m := range methods {
		if strings.HasPrefix(string(data), m) {
			isHTTP = true
			break
		}
	}
	if !isHTTP {
		return false
	}

	// Parse the request
	reqStr := string(data)
	lines := strings.SplitN(reqStr, "\r\n", 2)
	if len(lines) == 0 {
		return false
	}

	// Extract path from request line: "GET /.well-known/acme-challenge/TOKEN HTTP/1.1"
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 {
		return false
	}
	path := parts[1]

	if !strings.HasPrefix(path, "/.well-known/acme-challenge/") {
		return false
	}

	token := filepath.Base(path)
	if token == "" || token == "." || token == ".." || strings.Contains(token, "/") {
		return false
	}

	tokenPath := filepath.Join(certbot.WebrootDir, ".well-known", "acme-challenge", token)
	data_bytes, err := os.ReadFile(tokenPath)
	if err != nil {
		log.Printf("[ACME] Token not found: %s", token)
		return false
	}

	// Send HTTP response
	response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(data_bytes), string(data_bytes))

	conn.Write([]byte(response))
	log.Printf("[ACME] Served challenge token for %s", token)
	return true
}

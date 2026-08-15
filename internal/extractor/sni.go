package extractor

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// ExtractDomain extracts domain from TCP packet.
// Returns: domain, isTLS, error
func ExtractDomain(data []byte) (string, bool, error) {
	if len(data) < 5 {
		return "", false, nil
	}

	// Check TLS ClientHello (ContentType=22, TLS 1.x)
	if data[0] == 0x16 && data[1] == 0x03 {
		domain, err := extractSNI(data)
		if err != nil {
			return "", true, err
		}
		if domain != "" {
			return domain, true, nil
		}
		return "", true, nil
	}

	// Check HTTP (method starts with GET/POST/PUT/HEAD/OPTIONS/DELETE/PATCH/CONNECT)
	if isHTTPRequest(data) {
		domain := extractHTTPHost(data)
		if domain != "" {
			return domain, false, nil
		}
	}

	// Check plaintext email protocols (SMTP/IMAP/POP3 STARTTLS flow)
	// These send plaintext commands before TLS upgrade
	if domain := extractEmailDomain(data); domain != "" {
		return domain, false, nil
	}

	return "", false, nil
}

// extractSNI extracts Server Name Indication from TLS ClientHello
func extractSNI(data []byte) (string, error) {
	if len(data) < 5 {
		return "", nil
	}

	// TLS Record: ContentType(1) + Version(2) + Length(2)
	// ContentType 22 = Handshake
	if data[0] != 0x16 {
		return "", nil
	}

	// Skip TLS record header
	if len(data) < 6 {
		return "", nil
	}
	// recordLen := binary.BigEndian.Uint16(data[3:5])

	// Handshake: Type(1) + Length(3)
	if data[5] != 0x01 { // ClientHello
		return "", nil
	}

	if len(data) < 43 {
		return "", nil
	}

	// Skip: ClientVersion(2) + Random(32)
	pos := 43

	// Session ID
	if pos >= len(data) {
		return "", nil
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Cipher Suites
	if pos+2 > len(data) {
		return "", nil
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen

	// Compression Methods
	if pos >= len(data) {
		return "", nil
	}
	compressionLen := int(data[pos])
	pos += 1 + compressionLen

	// Extensions
	if pos+2 > len(data) {
		return "", nil
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	end := pos + extensionsLen
	if end > len(data) {
		end = len(data)
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > end {
			break
		}

		// Extension type 0 = Server Name Indication
		if extType == 0 {
			return parseSNIExtension(data[pos : pos+extLen])
		}

		pos += extLen
	}

	return "", nil
}

func parseSNIExtension(data []byte) (string, error) {
	// SNI Extension: ServerNameListLength(2) + ServerName entries
	if len(data) < 2 {
		return "", nil
	}

	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen+2 > len(data) {
		return "", nil
	}

	pos := 2
	for pos+3 <= 2+listLen {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3

		if pos+nameLen > len(data) {
			break
		}

		// nameType 0 = host_name
		if nameType == 0 {
			return string(data[pos : pos+nameLen]), nil
		}

		pos += nameLen
	}

	return "", nil
}

// isHTTPRequest checks if packet looks like HTTP
func isHTTPRequest(data []byte) bool {
	methods := [][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "),
		[]byte("HEAD "), []byte("OPTIONS "), []byte("DELETE "),
		[]byte("PATCH "), []byte("CONNECT "), []byte("TRACE "),
	}

	for _, m := range methods {
		if bytes.HasPrefix(data, m) {
			return true
		}
	}
	return false
}

// extractHTTPHost extracts Host header from HTTP request
func extractHTTPHost(data []byte) string {
	lines := strings.Split(string(data), "\r\n")
	for _, line := range lines[1:] {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host := strings.TrimSpace(line[5:])
			// Remove port if present
			if idx := strings.LastIndex(host, ":"); idx != -1 {
				// Check if it's a port (not IPv6)
				if !strings.Contains(host[idx:], "]") {
					host = host[:idx]
				}
			}
			return strings.TrimSpace(host)
		}
	}
	return ""
}

// extractEmailDomain extracts domain from plaintext email protocol commands.
// Handles SMTP (EHLO/HELO), IMAP, and POP3 before STARTTLS.
//
// SMTP examples:
//   "EHLO mail.example.com\r\n"
//   "ehlo mail.example.com\r\n"
//   "HELO mail.example.com\r\n"
//
// IMAP examples:
//   "a001 CAPABILITY\r\n" (no domain here, but EHLO may follow)
//   "a001 STARTTLS\r\n"
//
// POP3 examples:
//   "CAPA\r\n" (no domain)
//   "STLS\r\n" (STARTTLS equivalent)
//
// For IMAP/POP3 without domain in commands, returns "" (caller should fallback).
// For SMTP, extracts from EHLO/HELO parameter.
func extractEmailDomain(data []byte) string {
	// Convert to string for easier parsing, but only first few lines
	text := string(data)

	// Limit analysis to first 1024 bytes to avoid scanning huge buffers
	if len(text) > 1024 {
		text = text[:1024]
	}

	lines := strings.Split(text, "\r\n")
	if len(lines) == 0 {
		// Try \n line ending too
		lines = strings.Split(text, "\n")
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		upper := strings.ToUpper(line)

		// SMTP: EHLO/HELO <domain>
		if strings.HasPrefix(upper, "EHLO ") || strings.HasPrefix(upper, "HELO ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				domain := strings.TrimSpace(parts[1])
				// Remove brackets if present (some clients send [ip])
				domain = strings.Trim(domain, "[]")
				// Validate it looks like a domain (has a dot or is localhost)
				if isValidEmailDomain(domain) {
					return domain
				}
			}
		}
	}

	return ""
}

// isValidEmailDomain checks if a string looks like a valid domain name.
// Used for SMTP EHLO/HELO parameter validation.
func isValidEmailDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}

	// Allow localhost
	if strings.EqualFold(domain, "localhost") {
		return true
	}

	// Must contain at least one dot for a real domain
	if !strings.Contains(domain, ".") {
		return false
	}

	// Basic character check
	for _, c := range domain {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':') {
			return false
		}
	}

	return true
}

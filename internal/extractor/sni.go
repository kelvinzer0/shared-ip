package extractor

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// ExtractDomain extracts domain from TCP packet.
// Returns: domain, protocol, error
// protocol is one of: "tls", "http", "smtp", "ssh", "dns", ""
func ExtractDomain(data []byte) (string, string, error) {
	if len(data) < 5 {
		return "", "", nil
	}

	// Check TLS ClientHello (ContentType=22, TLS 1.x)
	if data[0] == 0x16 && data[1] == 0x03 {
		domain, err := extractSNI(data)
		if err != nil {
			return "", "tls", err
		}
		if domain != "" {
			return domain, "tls", nil
		}
		return "", "tls", nil
	}

	// Check SSH (starts with "SSH-" protocol version exchange)
	if isSSHHandshake(data) {
		return "", "ssh", nil
	}

	// Check DNS over TCP (2-byte length prefix + DNS query)
	if domain := extractDNSOverTCP(data); domain != "" {
		return domain, "dns-tcp", nil
	}

	// Check HTTP (method starts with GET/POST/PUT/HEAD/OPTIONS/DELETE/PATCH/CONNECT)
	if isHTTPRequest(data) {
		domain := extractHTTPHost(data)
		if domain != "" {
			return domain, "http", nil
		}
	}

	// Check plaintext email protocols (SMTP/IMAP/POP3 STARTTLS flow)
	if domain := extractEmailDomain(data); domain != "" {
		return domain, "smtp", nil
	}

	return "", "", nil
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

// isSSHHandshake checks if packet looks like SSH protocol version exchange.
// SSH starts with "SSH-" followed by version string, e.g., "SSH-2.0-OpenSSH_8.9"
func isSSHHandshake(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return data[0] == 'S' && data[1] == 'S' && data[2] == 'H' && data[3] == '-'
}

// extractDNSOverTCP extracts the query domain from a DNS-over-TCP packet.
// DNS over TCP has a 2-byte length prefix followed by the DNS message.
// DNS message format: Header(12) + Question section.
// Question: QNAME (labels) + QTYPE(2) + QCLASS(2)
// Returns empty string if not a valid DNS query or domain can't be extracted.
func extractDNSOverTCP(data []byte) string {
	// DNS over TCP: first 2 bytes = length of DNS message
	if len(data) < 16 { // 2 (length) + 12 (header) + at least 2 (root label + qtype/qclass)
		return ""
	}

	dnsLen := int(binary.BigEndian.Uint16(data[0:2]))
	if dnsLen+2 > len(data) || dnsLen < 12 {
		return ""
	}

	// Skip the 2-byte length prefix
	dnsMsg := data[2 : 2+dnsLen]

	return extractDNSQueryDomain(dnsMsg)
}

// extractDNSQueryDomain extracts the query domain from a raw DNS message.
// Works for both UDP and TCP DNS (after stripping TCP length prefix).
func extractDNSQueryDomain(dnsMsg []byte) string {
	if len(dnsMsg) < 12 {
		return ""
	}

	// DNS Header:
	//   ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
	qdcount := int(binary.BigEndian.Uint16(dnsMsg[4:6]))
	if qdcount < 1 {
		return ""
	}

	// Check QR bit (bit 15 of flags): 0 = query, 1 = response
	flags := binary.BigEndian.Uint16(dnsMsg[2:4])
	if flags&0x8000 != 0 {
		// This is a response, not a query
		return ""
	}

	// Parse QNAME starting at offset 12
	pos := 12
	var labels []string

	for pos < len(dnsMsg) {
		labelLen := int(dnsMsg[pos])
		pos++

		if labelLen == 0 {
			// Root label — end of QNAME
			break
		}

		// Compression pointer (top 2 bits set)
		if labelLen&0xC0 != 0 {
			// Compression pointer, can't follow in query section
			break
		}

		if pos+labelLen > len(dnsMsg) {
			return ""
		}

		labels = append(labels, string(dnsMsg[pos:pos+labelLen]))
		pos += labelLen
	}

	if len(labels) == 0 {
		return ""
	}

	domain := strings.Join(labels, ".")

	// Validate it looks like a real domain
	if len(domain) < 3 || !strings.Contains(domain, ".") {
		return ""
	}

	return domain
}

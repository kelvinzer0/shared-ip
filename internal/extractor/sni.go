package extractor

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// ExtractResult holds the result of incremental domain extraction.
type ExtractResult struct {
	Host     string // extracted hostname (empty if not yet found)
	Protocol string // detected protocol: "tls", "http", "smtp", "ssh", "dns-tcp", "dns", "quic", ""
	Done     bool   // true = extraction complete (success or definitive failure)
}

// ExtractDomainIncremental attempts to extract a domain from buffered TCP data.
// Returns Done=true when extraction is complete (host found or impossible to find).
// Returns Done=false when more data is needed (caller should read more bytes).
func ExtractDomainIncremental(data []byte) ExtractResult {
	if len(data) < 2 {
		return ExtractResult{Done: false}
	}

	// TLS ClientHello: ContentType=0x16, Version=0x03xx
	if data[0] == 0x16 && data[1] == 0x03 {
		domain := extractSNI(data)
		if domain != "" {
			return ExtractResult{Host: domain, Protocol: "tls", Done: true}
		}
		// TLS detected but SNI not found yet — might need more data
		return ExtractResult{Protocol: "tls", Done: false}
	}

	// SSH: starts with "SSH-"
	if len(data) >= 4 && data[0] == 'S' && data[1] == 'S' && data[2] == 'H' && data[3] == '-' {
		return ExtractResult{Protocol: "ssh", Done: true}
	}

	// DNS over TCP: 2-byte length prefix + DNS message
	if len(data) >= 2 {
		dnsLen := int(binary.BigEndian.Uint16(data[0:2]))
		if dnsLen >= 12 && dnsLen+2 <= len(data) {
			domain := extractDNSQueryDomain(data[2 : 2+dnsLen])
			if domain != "" {
				return ExtractResult{Host: domain, Protocol: "dns-tcp", Done: true}
			}
		}
		// Could be DNS but message incomplete — need more data
		if dnsLen >= 12 && len(data) < dnsLen+2 && len(data) >= 4 {
			return ExtractResult{Protocol: "dns-tcp", Done: false}
		}
	}

	// HTTP: method + space
	if isHTTPRequest(data) {
		host := extractHTTPHost(data)
		if host != "" {
			return ExtractResult{Host: host, Protocol: "http", Done: true}
		}
		// HTTP detected but Host header not found yet — need more data
		return ExtractResult{Protocol: "http", Done: false}
	}

	// SMTP: EHLO/HELO present → protocol identified, but domain comes from RCPT TO
	if hasSMTPGreeting(data) {
		host := extractSMTPRcptDomain(data)
		if host != "" {
			return ExtractResult{Host: host, Protocol: "smtp", Done: true}
		}
		// SMTP detected but RCPT TO not seen yet — need more data
		return ExtractResult{Protocol: "smtp", Done: false}
	}

	// Unknown protocol — can't extract domain
	return ExtractResult{Done: true}
}

// ExtractDomain is the legacy non-incremental interface.
// Returns: domain, protocol, error
func ExtractDomain(data []byte) (string, string, error) {
	r := ExtractDomainIncremental(data)
	return r.Host, r.Protocol, nil
}

// ─── TLS SNI ───────────────────────────────────────────────────

// extractSNI extracts Server Name Indication from TLS ClientHello.
func extractSNI(data []byte) string {
	if len(data) < 6 || data[0] != 0x16 || data[5] != 0x01 {
		return ""
	}
	if len(data) < 43 {
		return ""
	}

	// Skip: ContentType(1) + Version(2) + Length(2) + HandshakeType(1) + HSLength(3) + ClientVersion(2) + Random(32) = 43
	pos := 43

	// Session ID
	if pos >= len(data) {
		return ""
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Cipher Suites
	if pos+2 > len(data) {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen

	// Compression Methods
	if pos >= len(data) {
		return ""
	}
	compressionLen := int(data[pos])
	pos += 1 + compressionLen

	// Extensions
	if pos+2 > len(data) {
		return ""
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

		if extType == 0 { // SNI extension
			return parseSNIExtension(data[pos : pos+extLen])
		}

		pos += extLen
	}

	return ""
}

func parseSNIExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen+2 > len(data) {
		return ""
	}

	pos := 2
	for pos+3 <= 2+listLen {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3

		if pos+nameLen > len(data) {
			break
		}

		if nameType == 0 { // host_name
			return string(data[pos : pos+nameLen])
		}

		pos += nameLen
	}

	return ""
}

// ─── HTTP ──────────────────────────────────────────────────────

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

func extractHTTPHost(data []byte) string {
	lines := strings.Split(string(data), "\r\n")
	for _, line := range lines[1:] {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "host:") {
			// Handle optional whitespace: "Host: value" or "Host:value" or "Host : value"
			host := strings.TrimSpace(line[5:])
			// Remove port if present (but not for IPv6)
			if idx := strings.LastIndex(host, ":"); idx != -1 {
				if !strings.Contains(host[idx:], "]") {
					host = host[:idx]
				}
			}
			return strings.TrimSpace(host)
		}
	}
	return ""
}

// ─── SMTP ──────────────────────────────────────────────────────

// hasSMTPGreeting checks if the data contains SMTP EHLO/HELO commands.
func hasSMTPGreeting(data []byte) bool {
	upper := strings.ToUpper(string(data))
	return strings.Contains(upper, "EHLO ") || strings.Contains(upper, "HELO ")
}

// extractSMTPRcptDomain extracts the domain from the RCPT TO command.
// This is the actual routing target, not the EHLO domain (which is the sender).
func extractSMTPRcptDomain(data []byte) string {
	lines := strings.Split(string(data), "\r\n")
	if len(lines) <= 1 {
		lines = strings.Split(string(data), "\n")
	}

	for _, line := range lines {
		upper := strings.ToUpper(strings.TrimSpace(line))

		// RCPT TO:<user@domain> or RCPT TO: <user@domain>
		if strings.HasPrefix(upper, "RCPT TO:") {
			addr := strings.TrimSpace(line[8:])
			addr = strings.Trim(addr, "<>")

			// Extract domain from user@domain
			if idx := strings.LastIndex(addr, "@"); idx != -1 {
				domain := addr[idx+1:]
				domain = strings.TrimSpace(domain)
				if isValidEmailDomain(domain) {
					return domain
				}
			}
		}
	}

	return ""
}

func isValidEmailDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	if strings.EqualFold(domain, "localhost") {
		return true
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	for _, c := range domain {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':') {
			return false
		}
	}
	return true
}

// ─── DNS over TCP ──────────────────────────────────────────────

func extractDNSQueryDomain(dnsMsg []byte) string {
	if len(dnsMsg) < 12 {
		return ""
	}

	qdcount := int(binary.BigEndian.Uint16(dnsMsg[4:6]))
	if qdcount < 1 {
		return ""
	}

	// Check QR bit: 0 = query, 1 = response
	flags := binary.BigEndian.Uint16(dnsMsg[2:4])
	if flags&0x8000 != 0 {
		return ""
	}

	pos := 12
	var labels []string

	for pos < len(dnsMsg) {
		labelLen := int(dnsMsg[pos])
		pos++

		if labelLen == 0 {
			break
		}

		// Compression pointer
		if labelLen&0xC0 != 0 {
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
	if len(domain) < 3 || !strings.Contains(domain, ".") {
		return ""
	}

	return domain
}

// ─── QUIC (UDP) ────────────────────────────────────────────────

// ExtractUDPDomain extracts domain from UDP packet.
func ExtractUDPDomain(data []byte) (string, string, error) {
	if len(data) < 2 {
		return "", "", nil
	}

	// QUIC: long header starts with 0xC0-0xFF
	if data[0]&0xC0 == 0xC0 {
		domain, isQUIC, err := ExtractQUICSNI(data)
		if isQUIC {
			return domain, "quic", err
		}
	}

	// DNS UDP
	if len(data) >= 12 {
		domain := extractDNSQueryDomain(data)
		if domain != "" {
			return domain, "dns", nil
		}
	}

	return "", "", nil
}

func ExtractQUICSNI(data []byte) (string, bool, error) {
	if len(data) < 6 {
		return "", false, nil
	}

	isLongHeader := data[0]&0x80 != 0
	if !isLongHeader {
		return "", false, nil
	}

	packetType := (data[0] & 0x30) >> 4
	if packetType != 0x00 {
		return "", false, nil
	}

	if len(data) < 11 {
		return "", false, nil
	}

	pos := 5
	if pos >= len(data) {
		return "", false, nil
	}
	destCIDLen := int(data[pos])
	pos += 1 + destCIDLen

	if pos >= len(data) {
		return "", false, nil
	}
	srcCIDLen := int(data[pos])
	pos += 1 + srcCIDLen

	if pos >= len(data) {
		return "", false, nil
	}
	tokenLen, n := decodeVarint(data[pos:])
	pos += n
	pos += int(tokenLen)

	if pos >= len(data) {
		return "", false, nil
	}
	_, n = decodeVarint(data[pos:])
	pos += n

	if pos >= len(data) {
		return "", false, nil
	}

	cryptoData := findQUICCryptoFrame(data[pos:])
	if cryptoData == nil {
		return "", true, nil
	}

	domain := extractSNI(cryptoData)
	if domain != "" {
		return domain, true, nil
	}

	return "", true, nil
}

func findQUICCryptoFrame(data []byte) []byte {
	pos := 0
	for pos < len(data) {
		frameType := data[pos]
		pos++

		switch frameType {
		case 0x06: // CRYPTO
			if pos >= len(data) {
				return nil
			}
			_, n := decodeVarint(data[pos:])
			pos += n
			if pos >= len(data) {
				return nil
			}
			length, n := decodeVarint(data[pos:])
			pos += n
			if pos+int(length) > len(data) {
				return data[pos:]
			}
			return data[pos : pos+int(length)]

		case 0x00: // PADDING
			for pos < len(data) && data[pos] == 0x00 {
				pos++
			}
		case 0x01: // PING
		case 0x02, 0x03: // ACK
			if pos >= len(data) {
				return nil
			}
			_, n := decodeVarint(data[pos:])
			pos += n
			if pos >= len(data) {
				return nil
			}
			_, n = decodeVarint(data[pos:])
			pos += n
		default:
			return nil
		}
	}
	return nil
}

func decodeVarint(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	first := data[0]
	switch first & 0xC0 {
	case 0x00:
		return uint64(first), 1
	case 0x40:
		if len(data) < 2 {
			return 0, 0
		}
		return uint64(binary.BigEndian.Uint16(data[:2])) & 0x3FFF, 2
	case 0x80:
		if len(data) < 4 {
			return 0, 0
		}
		return uint64(binary.BigEndian.Uint32(data[:4])) & 0x3FFFFFFF, 4
	case 0xC0:
		if len(data) < 8 {
			return 0, 0
		}
		return binary.BigEndian.Uint64(data[:8]) & 0x3FFFFFFFFFFFFFFF, 8
	}
	return 0, 0
}

// Package smtp implements the "eater pattern" for SMTP proxying.
//
// Problem: To route SMTP, we need the RCPT TO domain. But SMTP is a
// conversational protocol — the client sends EHLO, waits for reply,
// sends MAIL FROM, waits for reply, then sends RCPT TO. We can't just
// read and forward because we don't have a backend yet.
//
// Solution (from uvhost):
//   1. Send ALL expected replies to the client at once (StuffSMTP)
//   2. Client consumes replies one by one, sending commands as it goes
//   3. Read client commands until we see RCPT TO → now we know the domain
//   4. Connect to backend, eat the server's replies (EatSMTP) since
//      the client already received them
//   5. Bidirectional copy from here
//
// StuffSMTP sends: 220 + 250 + 250
// EatSMTP eats:    220 + 250 + 250 (from real server)
//
// After StuffSMTP+EatSMTP, client and backend are synchronized:
// client thinks it's talking to the server, server thinks it's received EHLO+MAIL FROM.
package smtp

import (
	"fmt"
	"io"
	"strings"
)

const Port = 25

// StuffSMTP sends fake SMTP replies to the client to fast-forward
// through the initial handshake (220, 250, 250).
// Returns bytes written.
func StuffSMTP(client io.Writer, domain string) (int, error) {
	payload := fmt.Sprintf(
		"220 %s proxy ready\r\n"+
			"250 OK\r\n"+
			"250 OK\r\n",
		strings.TrimSuffix(domain, "."),
	)
	return client.Write([]byte(payload))
}

// EatSMTP consumes the server's initial replies (220, 250, 250)
// that correspond to the fake replies we already sent to the client.
// After this, the next data from the server is a real response to RCPT TO.
func EatSMTP(server io.Reader) (int, error) {
	total := 0

	// Eat 220 (server welcome banner)
	n, err := eatSMTPReply(server, 220)
	total += n
	if err != nil {
		return total, fmt.Errorf("eat 220: %w", err)
	}

	// Eat 250 (response to EHLO)
	n, err = eatSMTPReply(server, 250)
	total += n
	if err != nil {
		return total, fmt.Errorf("eat 250 (EHLO): %w", err)
	}

	// Eat 250 (response to MAIL FROM)
	n, err = eatSMTPReply(server, 250)
	total += n
	if err != nil {
		return total, fmt.Errorf("eat 250 (MAIL FROM): %w", err)
	}

	return total, nil
}

// eatSMTPReply reads a single SMTP reply with the expected code.
// Handles multi-line replies (code followed by '-' means more lines).
func eatSMTPReply(r io.Reader, expectedCode int) (int, error) {
	codeStr := fmt.Sprintf("%03d", expectedCode)
	buf := make([]byte, 1)
	n := 0

	// Read the 3-digit code
	codeBytes := make([]byte, 3)
	nn, err := io.ReadFull(r, codeBytes)
	n += nn
	if err != nil {
		return n, err
	}
	if string(codeBytes) != codeStr {
		return n, fmt.Errorf("expected code %s, got %s", codeStr, string(codeBytes))
	}

	// Read separator: space = last line, hyphen = more lines
	for {
		nn, err = io.ReadFull(r, buf)
		n += nn
		if err != nil {
			return n, err
		}

		if buf[0] == ' ' {
			// Last line — read to end of line
			nn, err = eatUntil(r, '\n')
			n += nn
			return n, err
		}

		if buf[0] == '-' {
			// More lines — read to end of line, then read next code
			nn, err = eatUntil(r, '\n')
			n += nn
			if err != nil {
				return n, err
			}
			// Read next line's code (3 digits)
			codeBytes2 := make([]byte, 3)
			nn, err = io.ReadFull(r, codeBytes2)
			n += nn
			if err != nil {
				return n, err
			}
			// Continue loop to check separator
			continue
		}

		return n, fmt.Errorf("unexpected character after SMTP code: %c", buf[0])
	}
}

// eatUntil reads from r until the target byte is found.
func eatUntil(r io.Reader, target byte) (int, error) {
	buf := make([]byte, 1)
	n := 0
	for {
		nn, err := io.ReadFull(r, buf)
		n += nn
		if err != nil {
			return n, err
		}
		if buf[0] == target {
			return n, nil
		}
	}
}

// ExtractRcptDomain extracts the domain from RCPT TO command in buffered data.
func ExtractRcptDomain(data []byte) string {
	text := string(data)
	lines := strings.Split(text, "\r\n")
	if len(lines) <= 1 {
		lines = strings.Split(text, "\n")
	}

	for _, line := range lines {
		upper := strings.ToUpper(strings.TrimSpace(line))
		if strings.HasPrefix(upper, "RCPT TO:") {
			addr := strings.TrimSpace(line[8:])
			addr = strings.Trim(addr, "<>")
			if idx := strings.LastIndex(addr, "@"); idx != -1 {
				domain := strings.TrimSpace(addr[idx+1:])
				if isValidDomain(domain) {
					return domain
				}
			}
		}
	}
	return ""
}

func isValidDomain(domain string) bool {
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

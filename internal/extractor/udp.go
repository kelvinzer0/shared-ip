package extractor

import "encoding/binary"

// ExtractQUICSNI extracts SNI from QUIC Initial packet.
// Returns: domain, isQUIC, error
func ExtractQUICSNI(data []byte) (string, bool, error) {
	if len(data) < 6 {
		return "", false, nil
	}

	// QUIC Long Header: first bit = 1, packet type in bits 4-5
	// Short Header: first bit = 0
	isLongHeader := data[0]&0x80 != 0

	if !isLongHeader {
		// Short header - 1-RTT packet, no SNI
		return "", false, nil
	}

	// Packet type: bits 4-5 of first byte
	// 0x00 = Initial, 0x01 = 0-RTT, 0x02 = Handshake, 0x03 = Retry
	packetType := (data[0] & 0x30) >> 4
	if packetType != 0x00 {
		// Not an Initial packet
		return "", false, nil
	}

	// Version (4 bytes)
	if len(data) < 11 {
		return "", false, nil
	}
	// version := binary.BigEndian.Uint32(data[1:5])

	// Destination Connection ID Length
	pos := 5
	if pos >= len(data) {
		return "", false, nil
	}
	destCIDLen := int(data[pos])
	pos += 1 + destCIDLen

	// Source Connection ID Length
	if pos >= len(data) {
		return "", false, nil
	}
	srcCIDLen := int(data[pos])
	pos += 1 + srcCIDLen

	// Token Length (variable-length integer)
	if pos >= len(data) {
		return "", false, nil
	}
	tokenLen, n := decodeVarint(data[pos:])
	pos += n
	pos += int(tokenLen)

	// Payload Length (variable-length integer)
	if pos >= len(data) {
		return "", false, nil
	}
	_, n = decodeVarint(data[pos:])
	pos += n

	// The rest is CRYPTO frame containing TLS ClientHello
	// Look for CRYPTO frame (type = 0x06)
	if pos >= len(data) {
		return "", false, nil
	}

	// Find CRYPTO frame in the payload
	cryptoData := findQUICCryptoFrame(data[pos:])
	if cryptoData == nil {
		return "", false, nil
	}

	// The CRYPTO frame contains TLS ClientHello
	// Try to extract SNI from it
	domain, err := extractSNI(cryptoData)
	if err != nil {
		return "", true, err
	}
	if domain != "" {
		return domain, true, nil
	}

	return "", true, nil
}

// findQUICCryptoFrame finds and extracts the CRYPTO frame data
func findQUICCryptoFrame(data []byte) []byte {
	pos := 0
	for pos < len(data) {
		if pos >= len(data) {
			break
		}

		frameType := data[pos]
		pos++

		switch frameType {
		case 0x06: // CRYPTO frame
			// Offset (variable-length integer)
			if pos >= len(data) {
				return nil
			}
			_, n := decodeVarint(data[pos:])
			pos += n

			// Length (variable-length integer)
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
			// Skip padding bytes
			for pos < len(data) && data[pos] == 0x00 {
				pos++
			}

		case 0x01: // PING
			// No payload

		case 0x02, 0x03: // ACK
			// Skip ACK frames
			if pos >= len(data) {
				return nil
			}
			_, n := decodeVarint(data[pos:])
			pos += n
			// Additional ACK fields - simplified skip
			if pos >= len(data) {
				return nil
			}
			_, n = decodeVarint(data[pos:])
			pos += n

		default:
			// Unknown frame, skip
			return nil
		}
	}
	return nil
}

// decodeVarint decodes QUIC variable-length integer
func decodeVarint(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}

	first := data[0]
	masked := first & 0xC0

	switch masked {
	case 0x00: // 1-byte
		return uint64(first), 1
	case 0x40: // 2-byte
		if len(data) < 2 {
			return 0, 0
		}
		return uint64(binary.BigEndian.Uint16(data[:2])) & 0x3FFF, 2
	case 0x80: // 4-byte
		if len(data) < 4 {
			return 0, 0
		}
		return uint64(binary.BigEndian.Uint32(data[:4])) & 0x3FFFFFFF, 4
	case 0xC0: // 8-byte
		if len(data) < 8 {
			return 0, 0
		}
		return binary.BigEndian.Uint64(data[:8]) & 0x3FFFFFFFFFFFFFFF, 8
	}

	return 0, 0
}

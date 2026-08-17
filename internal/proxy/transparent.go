package proxy

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

// Linux-specific constants not defined in Go's syscall package.
const (
	IPV6_TRANSPARENT = 19 // Same value as IP_TRANSPARENT for IPv6
	IPV6_V6ONLY      = 26 // IPV6_V6ONLY socket option
)

// DialTransparent dials backendAddr with clientAddr as the source address.
// Uses IP_TRANSPARENT socket option so the backend sees the original
// client IP instead of the proxy's IP.
//
// Requires: root or CAP_NET_ADMIN capability.
//
// Example:
//   Client connects from [2600:3c00:e000:03f5::c0a8:101]:54321
//   → DialTransparent("[::1]:8080", clientAddr)
//   → Backend sees connection from [2600:3c00:e000:03f5::c0a8:101]:54321
func DialTransparent(backendAddr string, clientAddr net.Addr) (net.Conn, error) {
	clientTCP, ok := clientAddr.(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("not a TCP address: %s", clientAddr)
	}

	// Determine network based on client IP version
	network := "tcp4"
	if clientTCP.IP.To4() == nil {
		network = "tcp6"
	}

	dialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			err = c.Control(func(fd uintptr) {
				// Enable IP_TRANSPARENT on the socket
				if network == "tcp6" {
					err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, IPV6_TRANSPARENT, 1)
				} else {
					err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1)
				}
				if err != nil {
					return
				}

				// Bind to the client's source address
				if network == "tcp6" {
					err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, IPV6_V6ONLY, 0)
					if err != nil {
						return
					}
					sa := &syscall.SockaddrInet6{Port: clientTCP.Port}
					copy(sa.Addr[:], clientTCP.IP.To16())
					err = syscall.Bind(int(fd), sa)
				} else {
					sa := &syscall.SockaddrInet4{Port: clientTCP.Port}
					copy(sa.Addr[:], clientTCP.IP.To4())
					err = syscall.Bind(int(fd), sa)
				}
			})
			return err
		},
	}

	conn, err := dialer.DialContext(context.Background(), network, backendAddr)
	if err != nil {
		return nil, fmt.Errorf("transparent dial %s -> %s: %w", clientAddr, backendAddr, err)
	}
	return conn, nil
}

// DialTransparentFallback tries transparent dial, falls back to normal dial.
// This is useful when IP_TRANSPARENT is not available (no root/CAP_NET_ADMIN).
func DialTransparentFallback(backendAddr string, clientAddr net.Addr) (net.Conn, error) {
	conn, err := DialTransparent(backendAddr, clientAddr)
	if err != nil {
		// Fallback: normal dial without source address preservation
		conn, err = net.DialTimeout("tcp", backendAddr, 5000000000) // 5s
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

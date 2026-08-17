package proxy

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// Linux-specific constants not defined in Go's syscall package.
const (
	IP_TRANSPARENT    = 19
	IPV6_TRANSPARENT  = 19 // Same value for IPv6
	IPV6_V6ONLY       = 26
)

// ListenTransparent creates a listener with IP_TRANSPARENT socket option.
// This allows the listener to accept connections destined for ANY IP address,
// not just the address it's bound to.
//
// Like uvhost's approach: listen on a special address (e.g. 127.127.127.127:80)
// and intercept all traffic on that port regardless of destination IP.
//
// This solves the port conflict: proxy listens on 127.127.127.127:<port>,
// backend binds to dummy interface IP (e.g. 10.0.0.10:<port>).
// No conflict because they're on different IPs.
func ListenTransparent(network, address string) (net.Listener, error) {
	// Resolve the address to get the correct sockaddr
	tcpAddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", address, err)
	}

	// Determine socket family
	family := syscall.AF_INET
	if tcpAddr.IP.To4() == nil {
		family = syscall.AF_INET6
	}

	// Create socket
	fd, err := syscall.Socket(family, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	// Set SO_REUSEADDR
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("SO_REUSEADDR: %w", err)
	}

	// Set IP_TRANSPARENT
	if family == syscall.AF_INET6 {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_TRANSPARENT, 1); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("IPV6_TRANSPARENT: %w (requires root or CAP_NET_ADMIN)", err)
		}
	} else {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_TRANSPARENT, 1); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("IP_TRANSPARENT: %w (requires root or CAP_NET_ADMIN)", err)
		}
	}

	// Bind to the address
	var sa syscall.Sockaddr
	if family == syscall.AF_INET6 {
		s := &syscall.SockaddrInet6{Port: tcpAddr.Port}
		if tcpAddr.IP != nil {
			copy(s.Addr[:], tcpAddr.IP.To16())
		}
		sa = s
	} else {
		s := &syscall.SockaddrInet4{Port: tcpAddr.Port}
		if tcpAddr.IP != nil {
			copy(s.Addr[:], tcpAddr.IP.To4())
		}
		sa = s
	}

	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind %s: %w", address, err)
	}

	// Listen
	if err := syscall.Listen(fd, 128); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("listen: %w", err)
	}

	// Convert fd to net.Listener
	file := os.NewFile(uintptr(fd), "transparent-listener")
	if file == nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("os.NewFile failed")
	}

	ln, err := net.FileListener(file)
	file.Close() // FileListener dup's the fd
	if err != nil {
		return nil, fmt.Errorf("FileListener: %w", err)
	}

	return ln, nil
}

// ListenTransparentFallback tries transparent listen, falls back to normal listen.
func ListenTransparentFallback(network, address string) (net.Listener, error) {
	ln, err := ListenTransparent(network, address)
	if err != nil {
		// Fallback to normal listen
		ln, err = net.Listen(network, address)
		if err != nil {
			return nil, err
		}
	}
	return ln, nil
}

// listenUDPTransparent creates a UDP listener with IP_TRANSPARENT.
func listenUDPTransparent(addr *net.UDPAddr) (*net.UDPConn, error) {
	family := syscall.AF_INET
	if addr.IP.To4() == nil {
		family = syscall.AF_INET6
	}

	fd, err := syscall.Socket(family, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	// Set IP_TRANSPARENT
	if family == syscall.AF_INET6 {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_TRANSPARENT, 1); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("IPV6_TRANSPARENT: %w", err)
		}
	} else {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_TRANSPARENT, 1); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("IP_TRANSPARENT: %w", err)
		}
	}

	var sa syscall.Sockaddr
	if family == syscall.AF_INET6 {
		s := &syscall.SockaddrInet6{Port: addr.Port}
		if addr.IP != nil {
			copy(s.Addr[:], addr.IP.To16())
		}
		sa = s
	} else {
		s := &syscall.SockaddrInet4{Port: addr.Port}
		if addr.IP != nil {
			copy(s.Addr[:], addr.IP.To4())
		}
		sa = s
	}

	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind: %w", err)
	}

	file := os.NewFile(uintptr(fd), "transparent-udp")
	if file == nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("os.NewFile failed")
	}

	conn, err := net.FilePacketConn(file)
	file.Close()
	if err != nil {
		return nil, fmt.Errorf("FilePacketConn: %w", err)
	}

	return conn.(*net.UDPConn), nil
}

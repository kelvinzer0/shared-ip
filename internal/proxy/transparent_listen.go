package proxy

import (
	"context"
	"net"
	"syscall"
)

// ListenTransparent creates a listener with SO_REUSEPORT to avoid conflicts
// with backend dummy interfaces on the same port.
func ListenTransparent(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// 15 is SO_REUSEPORT on Linux
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 15, 1)
			})
		},
	}
	return lc.Listen(context.Background(), network, address)
}

// ListenTransparentFallback tries transparent listen, falls back to normal listen.
func ListenTransparentFallback(network, address string) (net.Listener, error) {
	ln, err := ListenTransparent(network, address)
	if err != nil {
		ln, err = net.Listen(network, address)
		if err != nil {
			return nil, err
		}
	}
	return ln, nil
}

// listenUDPTransparent creates a UDP listener with SO_REUSEPORT.
func listenUDPTransparent(addr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 15, 1)
			})
		},
	}
	network := "udp4"
	if addr.IP != nil && addr.IP.To4() == nil {
		network = "udp6"
	} else if addr.IP == nil {
		network = "udp"
	}
	
	address := addr.String()
	c, err := lc.ListenPacket(context.Background(), network, address)
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

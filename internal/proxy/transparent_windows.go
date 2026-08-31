//go:build windows

package proxy

import (
	"net"
	"time"
)

// DialTransparentFallback on Windows falls back to normal dial
// (IP_TRANSPARENT not available).
func DialTransparentFallback(backendAddr string, clientAddr net.Addr) (net.Conn, error) {
	return net.DialTimeout("tcp", backendAddr, 5*time.Second)
}

// ListenTransparentFallback on Windows falls back to normal listen.
func ListenTransparentFallback(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

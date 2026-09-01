package proxy

import (
	"fmt"
	"net"
	"strings"

	"shared-ip/internal/dummy"
)

// publicListenAddrs returns host:port strings for every IP on non-loopback,
// non-dummy interfaces. These are the IPs the proxy should bind to so that
// dummy interface IPs (10.x.x.x, fd00::x, etc.) remain completely free for
// backend services to bind on the same port without conflict.
//
// Dummy interfaces are identified by the "sip-" prefix (dummy.IFPrefix).
func publicListenAddrs(port int) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	portStr := fmt.Sprintf("%d", port)
	var addrs []string

	for _, iface := range ifaces {
		// Skip loopback
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// Skip shared-ip dummy interfaces (sip-*)
		if strings.HasPrefix(iface.Name, dummy.IFPrefix+"-") {
			continue
		}
		// Skip down interfaces
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		ifAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range ifAddrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			addrs = append(addrs, net.JoinHostPort(ip.String(), portStr))
		}
	}
	return addrs
}

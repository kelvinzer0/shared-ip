package dummy

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strings"
)

// IFPrefix is the prefix for per-domain dummy interfaces.
// Linux interface names max 15 chars, so prefix is short.
const IFPrefix = "sip"

// sanitizeDomain converts a domain name to a valid Linux interface name.
// "example.com" → "sip-example-c"
// "sub.example.com" → "sip-sub-exam"
// Max 15 chars total (Linux limit).
var invalidIFChars = regexp.MustCompile(`[^a-zA-Z0-9]`)

func ifName(domain string) string {
	// Replace dots and invalid chars with dash
	clean := invalidIFChars.ReplaceAllString(domain, "-")
	// Remove consecutive dashes and trailing dashes
	for strings.Contains(clean, "--") {
		clean = strings.ReplaceAll(clean, "--", "-")
	}
	clean = strings.Trim(clean, "-")

	// Build name: "sip-" + domain part
	name := IFPrefix + "-" + clean

	// Linux interface name max 15 chars
	if len(name) > 15 {
		name = name[:15]
		// Don't end with dash
		name = strings.TrimRight(name, "-")
	}

	return name
}

// Setup creates a per-domain dummy interface and assigns an IP to it.
// Returns the interface name.
func Setup(domain, localIP string) (string, error) {
	iface := ifName(domain)

	// Load dummy module (ignore error if already loaded)
	exec.Command("modprobe", "dummy").Run()

	// Create dummy interface if it doesn't exist
	if !interfaceExists(iface) {
		if err := exec.Command("ip", "link", "add", iface, "type", "dummy").Run(); err != nil {
			return "", fmt.Errorf("create dummy interface %s: %w", iface, err)
		}
		log.Printf("[DUMMY] Created interface %s", iface)
	}

	// Bring interface up
	if err := exec.Command("ip", "link", "set", iface, "up").Run(); err != nil {
		return "", fmt.Errorf("bring up %s: %w", iface, err)
	}

	// Add IP if not already assigned
	if !ipExistsOnInterface(iface, localIP) {
		prefix := "/32"
		if strings.Contains(localIP, ":") {
			prefix = "/128"
		}
		if err := exec.Command("ip", "addr", "add", localIP+prefix, "dev", iface).Run(); err != nil {
			return "", fmt.Errorf("assign %s to %s: %w", localIP, iface, err)
		}
		log.Printf("[DUMMY] %s → %s on %s", domain, localIP, iface)
	}

	return iface, nil
}

// Teardown removes the per-domain dummy interface entirely.
func Teardown(domain string) {
	iface := ifName(domain)
	if !interfaceExists(iface) {
		return
	}
	if err := exec.Command("ip", "link", "del", iface).Run(); err != nil {
		log.Printf("[DUMMY] Remove %s: %v", iface, err)
	} else {
		log.Printf("[DUMMY] Removed interface %s", iface)
	}
}

// Cleanup removes all shared-ip dummy interfaces.
func Cleanup() {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, IFPrefix+"-") {
			if err := exec.Command("ip", "link", "del", iface.Name).Run(); err != nil {
				log.Printf("[DUMMY] Cleanup %s: %v", iface.Name, err)
			} else {
				log.Printf("[DUMMY] Cleaned up %s", iface.Name)
			}
		}
	}
}

func interfaceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

func ipExistsOnInterface(iface, ip string) bool {
	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		return false
	}

	addrs, err := ifaceObj.Addrs()
	if err != nil {
		return false
	}

	for _, addr := range addrs {
		ipStr := addr.String()
		if idx := strings.Index(ipStr, "/"); idx != -1 {
			ipStr = ipStr[:idx]
		}
		if ipStr == ip {
			return true
		}
	}
	return false
}

package dummy

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

const (
	DummyInterface = "shared-ip0"
)

// Setup creates a dummy network interface and assigns an IP to it.
// This allows web servers to bind directly to the assigned IP.
func Setup(domain, localIP string) (string, error) {
	iface := DummyInterface

	// Check if dummy module is loaded
	if err := exec.Command("modprobe", "dummy").Run(); err != nil {
		// Module might already be loaded, continue
		log.Printf("[DUMMY] modprobe dummy: %v (might be already loaded)", err)
	}

	// Create dummy interface if it doesn't exist
	if !interfaceExists(iface) {
		if err := exec.Command("ip", "link", "add", iface, "type", "dummy").Run(); err != nil {
			return "", fmt.Errorf("create dummy interface: %w", err)
		}
	}

	// Bring interface up
	if err := exec.Command("ip", "link", "set", iface, "up").Run(); err != nil {
		return "", fmt.Errorf("bring up interface: %w", err)
	}

	// Check if IP is already assigned
	if !ipExistsOnInterface(iface, localIP) {
		// Add IP address to interface
		if err := exec.Command("ip", "addr", "add", localIP+"/32", "dev", iface).Run(); err != nil {
			// Try without /32 for IPv6
			if strings.Contains(localIP, ":") {
				if err := exec.Command("ip", "addr", "add", localIP+"/128", "dev", iface).Run(); err != nil {
					return "", fmt.Errorf("assign IP to interface: %w", err)
				}
			} else {
				return "", fmt.Errorf("assign IP to interface: %w", err)
			}
		}
	}

	log.Printf("[DUMMY] %s -> %s on %s", domain, localIP, iface)
	return iface, nil
}

// Teardown removes an IP from the dummy interface
func Teardown(localIP string) error {
	if !interfaceExists(DummyInterface) {
		return nil
	}

	prefix := "/32"
	if strings.Contains(localIP, ":") {
		prefix = "/128"
	}

	if err := exec.Command("ip", "addr", "del", localIP+prefix, "dev", DummyInterface).Run(); err != nil {
		// Ignore if IP wasn't assigned
		log.Printf("[DUMMY] Remove IP %s: %v", localIP, err)
	}
	return nil
}

// Cleanup removes the entire dummy interface
func Cleanup() error {
	if !interfaceExists(DummyInterface) {
		return nil
	}
	if err := exec.Command("ip", "link", "del", DummyInterface).Run(); err != nil {
		return fmt.Errorf("delete dummy interface: %w", err)
	}
	log.Printf("[DUMMY] Removed interface %s", DummyInterface)
	return nil
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
		// Strip subnet mask
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

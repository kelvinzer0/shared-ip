//go:build !linux

package dummy

import "fmt"

// Setup creates a per-domain dummy interface and assigns an IP to it.
// On non-Linux platforms, dummy interfaces are not supported.
// Returns an error indicating the platform limitation.
func Setup(domain, localIP string) (string, error) {
	return "", fmt.Errorf("dummy interfaces not supported on this platform (Linux required)")
}

// Teardown removes the per-domain dummy interface entirely.
// No-op on non-Linux platforms.
func Teardown(domain string) {}

// Cleanup removes all shared-ip dummy interfaces.
// No-op on non-Linux platforms.
func Cleanup() {}

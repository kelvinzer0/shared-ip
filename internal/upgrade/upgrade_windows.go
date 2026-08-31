//go:build windows

package upgrade

import (
	"log"
	"os"
)

// Ready signals that the new process is ready to accept connections.
// On Windows, graceful upgrade via signals is not supported.
// This is a no-op on Windows.
func Ready() {
	mu.Lock()
	defer mu.Unlock()

	if readyCalled {
		return
	}
	readyCalled = true

	if IsChild() {
		log.Println("[UPGRADE] Ready (Windows: signal-based upgrade not supported)")
	}
}

// HandleSIGHUP listens for upgrade triggers.
// On Windows, SIGHUP is not available. This function blocks forever
// and graceful upgrade is not supported.
func HandleSIGHUP(binary string, cleanup func()) {
	log.Println("[UPGRADE] Graceful upgrade not supported on Windows")
	// Block forever — Windows doesn't support SIGHUP
	select {}
}

// SignalParent signals the parent process that we're ready.
// On Windows, this is a no-op since we can't send SIGTERM.
func SignalParent() {
	// Windows doesn't support syscall.Kill
}

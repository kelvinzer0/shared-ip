//go:build !windows

package upgrade

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Ready signals that the new process is ready to accept connections.
// The parent process can then safely stop accepting and exit.
func Ready() {
	mu.Lock()
	defer mu.Unlock()

	if readyCalled {
		return
	}
	readyCalled = true

	// If we're a child, signal the parent that we're ready
	ppid := os.Getppid()
	if ppid > 1 && IsChild() {
		log.Printf("[UPGRADE] Signaling parent (PID %d) that we're ready", ppid)
		syscall.Kill(ppid, syscall.SIGTERM)
	}
}

// HandleSIGHUP listens for SIGHUP and triggers a graceful upgrade.
// This function blocks and should be run in a goroutine.
func HandleSIGHUP(binary string, cleanup func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)

	for range sig {
		log.Println("[UPGRADE] Received SIGHUP, starting upgrade...")

		if err := doUpgrade(binary); err != nil {
			log.Printf("[UPGRADE] Upgrade failed: %v", err)
			continue
		}

		log.Println("[UPGRADE] New process started, waiting for it to take over...")

		// Wait for SIGTERM from child or timeout
		termSig := make(chan os.Signal, 1)
		signal.Notify(termSig, syscall.SIGTERM)

		select {
		case <-termSig:
			log.Println("[UPGRADE] Received SIGTERM from new process, shutting down...")
		case <-time.After(30 * time.Second):
			log.Println("[UPGRADE] Timeout waiting for new process, continuing")
		}

		signal.Stop(termSig)
		if cleanup != nil {
			cleanup()
		}
		os.Exit(0)
	}
}

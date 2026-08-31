// Package upgrade implements graceful process upgrade (zero-downtime restart).
//
// Inspired by uvhost's tableflip approach:
//   1. On SIGHUP, new process is started with same binary
//   2. Listener file descriptors are passed to new process via env vars
//   3. New process starts accepting on inherited listeners
//   4. Old process stops accepting, waits for connections to drain, then exits
//
// Usage:
//
//	ln, _ := net.Listen("tcp", ":80")
//	if upgrade.IsChild() {
//	    ln = upgrade.InheritListener("tcp-80")
//	}
//	upgrade.Ready()
//	go upgrade.HandleSIGHUP()
//	// ... accept loop ...
package upgrade

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

const (
	// EnvKey is the environment variable that holds inherited listener FDs.
	// Format: "name1:fd1,name2:fd2,..."
	EnvKey = "SHARED_IP_LISTENERS"
)

var (
	listeners   = make(map[string]net.Listener)
	mu          sync.Mutex
	readyCalled bool
)

// SaveListener registers a listener to be inherited on upgrade.
// name is a unique identifier (e.g. "tcp-80", "tcp-443").
func SaveListener(name string, ln net.Listener) {
	mu.Lock()
	defer mu.Unlock()
	listeners[name] = ln
}

// IsChild returns true if this process was started by an upgrade.
func IsChild() bool {
	return os.Getenv(EnvKey) != ""
}

// InheritListener recovers a listener from a parent process.
// Returns nil if not found.
func InheritListener(name string) net.Listener {
	spec := os.Getenv(EnvKey)
	if spec == "" {
		return nil
	}

	for _, entry := range strings.Split(spec, ",") {
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 || parts[0] != name {
			continue
		}

		fd, err := strconv.Atoi(parts[1])
		if err != nil {
			log.Printf("[UPGRADE] Invalid FD for %s: %v", name, err)
			return nil
		}

		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			log.Printf("[UPGRADE] Invalid file for %s (fd=%d)", name, fd)
			return nil
		}
		defer file.Close()

		ln, err := net.FileListener(file)
		if err != nil {
			log.Printf("[UPGRADE] FileListener for %s: %v", name, err)
			return nil
		}

		log.Printf("[UPGRADE] Inherited listener %s (fd=%d)", name, fd)
		return ln
	}

	return nil
}

func doUpgrade(binary string) error {
	mu.Lock()
	lnMap := make(map[string]net.Listener)
	for k, v := range listeners {
		lnMap[k] = v
	}
	mu.Unlock()

	if len(lnMap) == 0 {
		return fmt.Errorf("no listeners to inherit")
	}

	// Build FD spec: "name1:fd1,name2:fd2,..."
	var fds []string
	files := make([]*os.File, 0, len(lnMap))

	for name, ln := range lnMap {
		// Get the underlying file descriptor
		type filer interface {
			File() (*os.File, error)
		}
		if fl, ok := ln.(filer); ok {
			f, err := fl.File()
			if err != nil {
				// Close already opened files
				for _, f := range files {
					f.Close()
				}
				return fmt.Errorf("get file for %s: %w", name, err)
			}
			fds = append(fds, fmt.Sprintf("%s:%d", name, f.Fd()))
			files = append(files, f)
		}
	}

	// Clean up file handles after child starts
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()

	// Start new process with inherited FDs
	cmd := exec.Command(binary, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), EnvKey+"="+strings.Join(fds, ","))
	cmd.ExtraFiles = files

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start new process: %w", err)
	}

	log.Printf("[UPGRADE] New process started (PID %d), waiting for ready signal", cmd.Process.Pid)

	// Don't wait here — let the new process signal us with SIGTERM
	go func() {
		err := cmd.Wait()
		if err != nil {
			log.Printf("[UPGRADE] New process exited: %v", err)
		}
	}()

	return nil
}

// GetListenerNames returns the names of all registered listeners.
func GetListenerNames() []string {
	mu.Lock()
	defer mu.Unlock()

	names := make([]string, 0, len(listeners))
	for name := range listeners {
		names = append(names, name)
	}
	return names
}

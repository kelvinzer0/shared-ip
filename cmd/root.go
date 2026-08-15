package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"shared-ip/internal/config"
	"shared-ip/internal/dummy"
	"shared-ip/internal/proxy"
	"shared-ip/internal/service"
)

var (
	cfgPath string
	cfg     *config.Config
)

var (
	domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	ipv4Regex   = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	ipv6Regex   = regexp.MustCompile(`^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$`)
)

func init() {
	// Allow override via environment variable
	if p := os.Getenv("SHARED_IP_CONFIG"); p != "" {
		cfgPath = p
	} else {
		cfgPath = config.DefaultPath()
	}
}

func Execute() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	// Commands that don't need config
	switch cmd {
	case "version":
		fmt.Println("shared-ip v1.0.0")
		return
	case "help", "--help", "-h":
		printUsage()
		return
	}

	cfg = config.New(cfgPath)
	if err := cfg.Load(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	switch cmd {
	case "add":
		handleAdd(args)
	case "list":
		handleList()
	case "show":
		handleShow(args)
	case "update":
		handleUpdate(args)
	case "delete":
		handleDelete(args)
	case "reset":
		handleReset()
	case "daemon":
		handleDaemon()
	case "service":
		handleService(args)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`shared-ip - Domain-based reverse proxy with SNI/HTTP routing

USAGE:
  shared-ip <command> [options]

COMMANDS:
  add <domain> --port=<port> --localip=<ip>    Add domain mapping
  list                                         List all mappings
  show <domain> --port=<port>                  Show mapping details
  update <domain> --port=<port> --localip=<ip> Update mapping
  delete <domain> --port=<port>                Delete mapping
  reset                                        Remove all mappings
  daemon                                       Start proxy daemon
  service <install|uninstall|start|stop|restart|status>
  version                                      Show version
  help                                         Show this help

OPTIONS:
  --port=<port>      Backend port (default: 80)
  --localip=<ip>     Local IPv4/IPv6 address for routing

EXAMPLES:
  shared-ip add example.com --port=443 --localip=192.168.1.10
  shared-ip add example.com --port=80 --localip=10.0.0.5
  shared-ip add ipv6.example.com --port=443 --localip=::1
  shared-ip list
  shared-ip show example.com --port=443
  shared-ip service install
  service shared-ip start

DNS SETUP:
  Add A/AAAA record pointing your domain to this VPS public IP.

TECHNOLOGY:
  - TLS traffic: SNI extraction from ClientHello
  - HTTP traffic: Host header extraction
  - UDP/QUIC: SNI from QUIC Initial packet
  - Auto-detects TLS vs non-TLS
`)
}

// ─── ADD ───────────────────────────────────────────────────────

func handleAdd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: shared-ip add <domain> --port=<port> --localip=<ip> [--backendport=<port>]")
		os.Exit(1)
	}

	domain := args[0]
	port := 80
	localIP := ""
	backendPort := 0

	for _, arg := range args[1:] {
		k, v := parseFlag(arg)
		switch k {
		case "port":
			p, err := strconv.Atoi(v)
			if err != nil || p < 1 || p > 65535 {
				fmt.Fprintf(os.Stderr, "Invalid port: %s (must be 1-65535)\n", v)
				os.Exit(1)
			}
			port = p
		case "backendport":
			p, err := strconv.Atoi(v)
			if err != nil || p < 1 || p > 65535 {
				fmt.Fprintf(os.Stderr, "Invalid backend port: %s\n", v)
				os.Exit(1)
			}
			backendPort = p
		case "localip":
			localIP = v
		}
	}

	if !validateDomain(domain) {
		fmt.Fprintf(os.Stderr, "Invalid domain: %s\n", domain)
		os.Exit(1)
	}

	if localIP == "" {
		fmt.Fprintln(os.Stderr, "--localip is required")
		os.Exit(1)
	}

	if !validateIP(localIP) {
		fmt.Fprintf(os.Stderr, "Invalid IP address: %s\n", localIP)
		os.Exit(1)
	}

	// Create dummy interface and assign IP
	iface, err := dummy.Setup(domain, localIP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: dummy interface setup failed: %v\n", err)
		fmt.Fprintln(os.Stderr, "Continuing without dummy interface (proxy-only mode)")
	}

	dm := config.DomainMapping{
		Domain:      domain,
		Port:        port,
		LocalIP:     localIP,
		BackendPort: backendPort,
		DummyIF:     iface,
	}

	if err := cfg.Add(dm); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Added: %s --port=%d --localip=%s\n", domain, port, localIP)
	if iface != "" {
		fmt.Printf("  Interface: %s (IP %s assigned)\n", iface, localIP)
	}
	if backendPort > 0 {
		fmt.Printf("  Backend port: %d\n", backendPort)
	}
}

// ─── LIST ──────────────────────────────────────────────────────

func handleList() {
	domains := cfg.GetAll()
	if len(domains) == 0 {
		fmt.Println("No domain mappings configured.")
		return
	}

	for _, d := range domains {
		fmt.Printf("%s --port=%d\n", d.Domain, d.Port)
	}
}

// ─── SHOW ──────────────────────────────────────────────────────

func handleShow(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: shared-ip show <domain> --port=<port>")
		os.Exit(1)
	}

	domain := args[0]
	port := 80

	for _, arg := range args[1:] {
		k, v := parseFlag(arg)
		if k == "port" {
			p, err := strconv.Atoi(v)
			if err != nil || p < 1 || p > 65535 {
				fmt.Fprintf(os.Stderr, "Invalid port: %s\n", v)
				os.Exit(1)
			}
			port = p
		}
	}

	dm, err := cfg.Get(domain, port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Not found: %s:%d\n", domain, port)
		os.Exit(1)
	}

	fmt.Printf("domain=%s --port=%d --localip=%s", dm.Domain, dm.Port, dm.LocalIP)
	if dm.DummyIF != "" {
		fmt.Printf(" --interface=%s", dm.DummyIF)
	}
	fmt.Println()
}

// ─── UPDATE ────────────────────────────────────────────────────

func handleUpdate(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: shared-ip update <domain> --port=<port> --localip=<ip>")
		os.Exit(1)
	}

	domain := args[0]
	port := 80
	localIP := ""

	for _, arg := range args[1:] {
		k, v := parseFlag(arg)
		switch k {
		case "port":
			p, err := strconv.Atoi(v)
			if err != nil || p < 1 || p > 65535 {
				fmt.Fprintf(os.Stderr, "Invalid port: %s\n", v)
				os.Exit(1)
			}
			port = p
		case "localip":
			localIP = v
		}
	}

	if localIP == "" {
		fmt.Fprintln(os.Stderr, "--localip is required")
		os.Exit(1)
	}

	if !validateIP(localIP) {
		fmt.Fprintf(os.Stderr, "Invalid IP: %s\n", localIP)
		os.Exit(1)
	}

	// Get old mapping to cleanup dummy interface
	old, _ := cfg.Get(domain, port)
	if old != nil && old.DummyIF != "" {
		dummy.Teardown(old.LocalIP)
	}

	// Setup new dummy interface
	iface, err := dummy.Setup(domain, localIP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: dummy interface setup: %v\n", err)
	}

	dm := config.DomainMapping{
		Domain:      domain,
		Port:        port,
		LocalIP:     localIP,
		BackendPort: old.GetBackendPort(),
		DummyIF:     iface,
	}

	if err := cfg.Update(dm); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Updated: %s --port=%d --localip=%s\n", domain, port, localIP)
}

// ─── DELETE ────────────────────────────────────────────────────

func handleDelete(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: shared-ip delete <domain> --port=<port>")
		os.Exit(1)
	}

	domain := args[0]
	port := 80

	for _, arg := range args[1:] {
		k, v := parseFlag(arg)
		if k == "port" {
			p, err := strconv.Atoi(v)
			if err != nil || p < 1 || p > 65535 {
				fmt.Fprintf(os.Stderr, "Invalid port: %s\n", v)
				os.Exit(1)
			}
			port = p
		}
	}

	// Confirm
	fmt.Printf("Delete %s --port=%d? [y/N]: ", domain, port)
	var answer string
	fmt.Scanln(&answer)
	if strings.ToLower(strings.TrimSpace(answer)) != "y" {
		fmt.Println("Cancelled.")
		return
	}

	// Cleanup dummy interface
	old, _ := cfg.Get(domain, port)
	if old != nil && old.DummyIF != "" {
		dummy.Teardown(old.LocalIP)
	}

	if err := cfg.Delete(domain, port); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Deleted: %s --port=%d\n", domain, port)
}

// ─── RESET ─────────────────────────────────────────────────────

func handleReset() {
	fmt.Print("Reset all mappings? This cannot be undone. [y/N]: ")
	var answer string
	fmt.Scanln(&answer)
	if strings.ToLower(strings.TrimSpace(answer)) != "y" {
		fmt.Println("Cancelled.")
		return
	}

	// Cleanup all dummy interfaces
	for _, d := range cfg.GetAll() {
		if d.DummyIF != "" {
			dummy.Teardown(d.LocalIP)
		}
	}

	if err := cfg.Reset(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("All mappings removed.")
}

// ─── DAEMON ────────────────────────────────────────────────────

func handleDaemon() {
	log.Println("[DAEMON] Starting shared-ip daemon...")

	// Start TCP proxy for each unique port
	proxies := make([]*proxy.TCPProxy, 0)
	udpProxies := make([]*proxy.UDPProxy, 0)

	ports := cfg.GetUniquePorts()
	if len(ports) == 0 {
		log.Println("[DAEMON] No domain mappings configured. Exiting.")
		os.Exit(1)
	}

	for _, port := range ports {
		// TCP
		tcpProxy := proxy.NewTCPProxy(cfg, port)
		if err := tcpProxy.Start(); err != nil {
			log.Fatalf("TCP proxy port %d: %v", port, err)
		}
		proxies = append(proxies, tcpProxy)

		// UDP (QUIC support)
		udpProxy := proxy.NewUDPProxy(cfg, port)
		if err := udpProxy.Start(); err != nil {
			log.Printf("[DAEMON] UDP proxy port %d: %v (non-critical, continuing)", port, err)
		} else {
			udpProxies = append(udpProxies, udpProxy)
		}
	}

	log.Printf("[DAEMON] Proxying %d port(s). Waiting for connections...", len(ports))

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("[DAEMON] Shutting down...")
	for _, p := range proxies {
		p.Stop()
	}
	for _, p := range udpProxies {
		p.Stop()
	}
	dummy.Cleanup()
	log.Println("[DAEMON] Stopped.")
}

// ─── SERVICE ───────────────────────────────────────────────────

func handleService(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: shared-ip service <install|uninstall|start|stop|restart|status>")
		os.Exit(1)
	}

	binary, _ := os.Executable()

	switch args[0] {
	case "install":
		if err := service.Install(binary); err != nil {
			fmt.Fprintf(os.Stderr, "Install error: %v\n", err)
			os.Exit(1)
		}
	case "uninstall":
		if err := service.Uninstall(); err != nil {
			fmt.Fprintf(os.Stderr, "Uninstall error: %v\n", err)
			os.Exit(1)
		}
	case "start":
		if err := service.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Start error: %v\n", err)
			os.Exit(1)
		}
	case "stop":
		if err := service.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "Stop error: %v\n", err)
			os.Exit(1)
		}
	case "restart":
		if err := service.Restart(); err != nil {
			fmt.Fprintf(os.Stderr, "Restart error: %v\n", err)
			os.Exit(1)
		}
	case "status":
		out, err := service.Status()
		if out != "" {
			fmt.Print(out)
		}
		if err != nil {
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown service command: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "Available: install, uninstall, start, stop, restart, status")
		os.Exit(1)
	}
}

// ─── HELPERS ───────────────────────────────────────────────────

func parseFlag(arg string) (key, value string) {
	if strings.HasPrefix(arg, "--") {
		parts := strings.SplitN(strings.TrimPrefix(arg, "--"), "=", 2)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
		return parts[0], ""
	}
	return "", arg
}

func validateDomain(domain string) bool {
	if len(domain) > 253 {
		return false
	}
	return domainRegex.MatchString(domain)
}

func validateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func isIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}

func isIPv4(ip string) bool {
	return ipv4Regex.MatchString(ip)
}

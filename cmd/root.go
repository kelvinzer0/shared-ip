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
  add <domain> --port=<port> --localipv4=<ip> [--localipv6=<ip>]    Add domain mapping
  list                                         List all mappings
  show <domain> --port=<port>                  Show mapping details
  update <domain> --port=<port> [--localipv4=<ip>] [--localipv6=<ip>] [--clear-ipv4] [--clear-ipv6]
  delete <domain> --port=<port>                Delete mapping
  reset                                        Remove all mappings
  daemon                                       Start proxy daemon
  service <install|uninstall|start|stop|restart|status>
  version                                      Show version
  help                                         Show this help

OPTIONS:
  --port=<port>        Backend port (default: 80)
  --localipv4=<ip>     Local IPv4 address for routing
  --localipv6=<ip>     Local IPv6 address for routing (optional)
  --clear-ipv4         Remove IPv4 from mapping (update only)
  --clear-ipv6         Remove IPv6 from mapping (update only)

NOTE:
  At least one of --localipv4 or --localipv6 must be present after update.
  Use --clear-ipv4 / --clear-ipv6 to remove an address from dual-stack mapping.

EXAMPLES:
  shared-ip add example.com --port=443 --localipv4=192.168.1.10
  shared-ip add example.com --port=80 --localipv4=10.0.0.5 --localipv6=::1
  shared-ip add dual.example.com --port=443 --localipv4=10.0.0.5 --localipv6=fd00::1
  shared-ip update example.com --port=443 --localipv6=fd00::1     # add IPv6, keep IPv4
  shared-ip update example.com --port=443 --clear-ipv6             # remove IPv6, keep IPv4
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
		fmt.Fprintln(os.Stderr, "Usage: shared-ip add <domain> --port=<port> --localipv4=<ip> [--localipv6=<ip>] [--backendport=<port>]")
		os.Exit(1)
	}

	domain := args[0]
	port := 80
	localIPv4 := ""
	localIPv6 := ""
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
		case "localipv4":
			localIPv4 = v
		case "localipv6":
			localIPv6 = v
		}
	}

	if !validateDomain(domain) {
		fmt.Fprintf(os.Stderr, "Invalid domain: %s\n", domain)
		os.Exit(1)
	}

	if localIPv4 == "" && localIPv6 == "" {
		fmt.Fprintln(os.Stderr, "At least one of --localipv4 or --localipv6 is required")
		os.Exit(1)
	}

	if localIPv4 != "" && !validateIPv4(localIPv4) {
		fmt.Fprintf(os.Stderr, "Invalid IPv4 address: %s\n", localIPv4)
		os.Exit(1)
	}

	if localIPv6 != "" && !validateIPv6(localIPv6) {
		fmt.Fprintf(os.Stderr, "Invalid IPv6 address: %s\n", localIPv6)
		os.Exit(1)
	}

	// Create dummy interface and assign IPs
	var dummyIF string
	var ips []string
	if localIPv4 != "" {
		ips = append(ips, localIPv4)
	}
	if localIPv6 != "" {
		ips = append(ips, localIPv6)
	}

	for _, ip := range ips {
		iface, err := dummy.Setup(domain, ip)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: dummy interface setup for %s failed: %v\n", ip, err)
			fmt.Fprintln(os.Stderr, "Continuing without dummy interface (proxy-only mode)")
		} else if dummyIF == "" {
			dummyIF = iface
		}
	}

	dm := config.DomainMapping{
		Domain:      domain,
		Port:        port,
		LocalIPv4:   localIPv4,
		LocalIPv6:   localIPv6,
		BackendPort: backendPort,
		DummyIF:     dummyIF,
	}

	if err := cfg.Add(dm); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Added: %s --port=%d", domain, port)
	if localIPv4 != "" {
		fmt.Printf(" --localipv4=%s", localIPv4)
	}
	if localIPv6 != "" {
		fmt.Printf(" --localipv6=%s", localIPv6)
	}
	fmt.Println()
	if dummyIF != "" {
		fmt.Printf("  Interface: %s\n", dummyIF)
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

	fmt.Printf("domain=%s --port=%d", dm.Domain, dm.Port)
	if dm.LocalIPv4 != "" {
		fmt.Printf(" --localipv4=%s", dm.LocalIPv4)
	}
	if dm.LocalIPv6 != "" {
		fmt.Printf(" --localipv6=%s", dm.LocalIPv6)
	}
	if dm.DummyIF != "" {
		fmt.Printf(" --interface=%s", dm.DummyIF)
	}
	fmt.Println()
}

// ─── UPDATE ────────────────────────────────────────────────────

func handleUpdate(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: shared-ip update <domain> --port=<port> [--localipv4=<ip>] [--localipv6=<ip>] [--clear-ipv4] [--clear-ipv6]")
		os.Exit(1)
	}

	domain := args[0]
	port := 80
	localIPv4 := ""
	localIPv6 := ""
	clearIPv4 := false
	clearIPv6 := false
	hasIPv4Flag := false
	hasIPv6Flag := false

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
		case "localipv4":
			localIPv4 = v
			hasIPv4Flag = true
		case "localipv6":
			localIPv6 = v
			hasIPv6Flag = true
		case "clear-ipv4":
			clearIPv4 = true
		case "clear-ipv6":
			clearIPv6 = true
		}
	}

	if !hasIPv4Flag && !hasIPv6Flag && !clearIPv4 && !clearIPv6 {
		fmt.Fprintln(os.Stderr, "Nothing to update. Use --localipv4=<ip>, --localipv6=<ip>, --clear-ipv4, or --clear-ipv6")
		os.Exit(1)
	}

	if localIPv4 != "" && !validateIPv4(localIPv4) {
		fmt.Fprintf(os.Stderr, "Invalid IPv4: %s\n", localIPv4)
		os.Exit(1)
	}

	if localIPv6 != "" && !validateIPv6(localIPv6) {
		fmt.Fprintf(os.Stderr, "Invalid IPv6: %s\n", localIPv6)
		os.Exit(1)
	}

	// Get existing mapping
	old, _ := cfg.Get(domain, port)
	if old == nil {
		fmt.Fprintf(os.Stderr, "Not found: %s:%d\n", domain, port)
		os.Exit(1)
	}

	// Determine final IPv4/IPv6 values (merge with existing)
	finalIPv4 := old.LocalIPv4
	finalIPv6 := old.LocalIPv6

	if clearIPv4 {
		finalIPv4 = ""
	} else if hasIPv4Flag && localIPv4 != "" {
		finalIPv4 = localIPv4
	}

	if clearIPv6 {
		finalIPv6 = ""
	} else if hasIPv6Flag && localIPv6 != "" {
		finalIPv6 = localIPv6
	}

	// Validate: at least one address must remain
	if finalIPv4 == "" && finalIPv6 == "" {
		fmt.Fprintln(os.Stderr, "Cannot remove all addresses. At least one of --localipv4 or --localipv6 must remain.")
		os.Exit(1)
	}

	// Cleanup old dummy interfaces
	if old.DummyIF != "" {
		if old.LocalIPv4 != "" && old.LocalIPv4 != finalIPv4 {
			dummy.Teardown(old.LocalIPv4)
		}
		if old.LocalIPv6 != "" && old.LocalIPv6 != finalIPv6 {
			dummy.Teardown(old.LocalIPv6)
		}
	}

	// Setup new dummy interfaces for new IPs
	var dummyIF string
	var ips []string
	if finalIPv4 != "" {
		ips = append(ips, finalIPv4)
	}
	if finalIPv6 != "" {
		ips = append(ips, finalIPv6)
	}
	for _, ip := range ips {
		iface, err := dummy.Setup(domain, ip)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: dummy interface setup for %s: %v\n", ip, err)
		} else if dummyIF == "" {
			dummyIF = iface
		}
	}

	dm := config.DomainMapping{
		Domain:      domain,
		Port:        port,
		LocalIPv4:   finalIPv4,
		LocalIPv6:   finalIPv6,
		BackendPort: old.GetBackendPort(),
		DummyIF:     dummyIF,
	}

	if err := cfg.Update(dm); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Updated: %s --port=%d", domain, port)
	if finalIPv4 != "" {
		fmt.Printf(" --localipv4=%s", finalIPv4)
	}
	if finalIPv6 != "" {
		fmt.Printf(" --localipv6=%s", finalIPv6)
	}
	fmt.Println()
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
		if old.LocalIPv4 != "" {
			dummy.Teardown(old.LocalIPv4)
		}
		if old.LocalIPv6 != "" {
			dummy.Teardown(old.LocalIPv6)
		}
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
			if d.LocalIPv4 != "" {
				dummy.Teardown(d.LocalIPv4)
			}
			if d.LocalIPv6 != "" {
				dummy.Teardown(d.LocalIPv6)
			}
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

func validateIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.To4() != nil
}

func validateIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.To4() == nil
}

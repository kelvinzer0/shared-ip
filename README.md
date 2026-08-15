# shared-ip

Domain-based reverse proxy for VPS with single public IP. Routes TCP/UDP traffic to different local backends based on domain name using SNI (TLS), HTTP Host header, and QUIC SNI extraction.

## How It Works

```
Client → VPS Public IP:443
         │
         ├─ TLS ClientHello → Extract SNI → domain.com
         ├─ HTTP Request    → Extract Host → domain.com
         ├─ SMTP EHLO       → Extract domain → domain.com
         └─ QUIC Initial    → Extract SNI → domain.com
                    │
                    ▼
         Lookup domain → Local IPv4/IPv6 (192.168.x.x / 10.x.x.x / fd00::1)
                    │
                    ▼
         Forward to backend at local_ip:port
```

## Supported Protocols

| Protocol | Port(s) | Detection Method | Notes |
|----------|---------|-----------------|-------|
| HTTPS | 443 | TLS SNI | Standard web traffic |
| HTTP | 80 | Host header | Plain HTTP |
| SMTPS | 465 | TLS SNI | TLS-first email |
| IMAPS | 993 | TLS SNI | TLS-first email |
| POP3S | 995 | TLS SNI | TLS-first email |
| SMTP | 587, 25 | EHLO/HELO | STARTTLS — domain from EHLO command |
| SSH | 22 | Protocol banner | Port-based fallback (no domain in SSH) |
| DNS | 53 (UDP) | DNS query name | Extracts QNAME from query packet |
| DNS | 53 (TCP) | DNS query name | 2-byte length prefix + DNS query |
| QUIC/HTTP3 | 443 (UDP) | QUIC SNI | UDP-based |
| IMAP | 143 | — | Use IMAPS (993) instead |
| POP3 | 110 | — | Use POP3S (995) instead |

## Installation

```bash
# Clone and build
cd shared-ip
chmod +x scripts/install.sh
sudo ./scripts/install.sh

# Or manual:
go build -o shared-ip .
sudo cp shared-ip /usr/local/bin/
sudo shared-ip service install
```

## Quick Start

```bash
# 1. Add domain mappings
sudo shared-ip add myapp.com --port=443 --localipv4=192.168.1.10
sudo shared-ip add myapp.com --port=80 --localipv4=192.168.1.10
sudo shared-ip add api.example.com --port=443 --localipv4=10.0.0.5
sudo shared-ip add blog.example.com --port=443 --localipv4=10.0.0.6

# 2. Email servers (SMTPS, IMAPS, SMTP+STARTTLS)
sudo shared-ip add mail.example.com --port=465 --localipv4=10.0.0.5   # SMTPS (TLS-first)
sudo shared-ip add mail.example.com --port=993 --localipv4=10.0.0.5   # IMAPS (TLS-first)
sudo shared-ip add mail.example.com --port=587 --localipv4=10.0.0.5   # SMTP  (STARTTLS)
sudo shared-ip add mail.example.com --port=25  --localipv4=10.0.0.5   # SMTP  (STARTTLS)
sudo shared-ip add mail.example.com --port=995 --localipv4=10.0.0.5   # POP3S (TLS-first)
sudo shared-ip add mail.example.com --port=143 --localipv4=10.0.0.5   # IMAP  (STARTTLS)

# 3. Dual-stack (IPv4 + IPv6 backends)
sudo shared-ip add dual.example.com --port=443 --localipv4=10.0.0.5 --localipv6=fd00::1

# 4. IPv6-only backend
sudo shared-ip add ipv6only.example.com --port=443 --localipv6=fd00::2

# 5. Start the service
sudo service shared-ip start

# 6. DNS setup
#    Add A record: myapp.com → <VPS Public IP>
#    Add AAAA record: myapp.com → <VPS Public IPv6> (optional)
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `shared-ip add <domain> --port=<port> --localipv4=<ip> [--localipv6=<ip>]` | Add domain mapping |
| `shared-ip list` | List all mappings |
| `shared-ip show <domain> --port=<port>` | Show mapping details |
| `shared-ip update <domain> --port=<port> [--localipv4=<ip>] [--localipv6=<ip>] [--clear-ipv4] [--clear-ipv6]` | Update mapping (partial ok) |
| `shared-ip delete <domain> --port=<port>` | Delete mapping (with confirmation) |
| `shared-ip reset` | Remove all mappings (with confirmation) |
| `shared-ip service install` | Install systemd/SysVinit service |
| `shared-ip service uninstall` | Remove service |
| `shared-ip service start/stop/restart/status` | Manage service |
| `shared-ip daemon` | Run proxy in foreground (for debugging) |
| `shared-ip version` | Show version |

## Options

| Option | Description |
|--------|-------------|
| `--port=<port>` | Backend port (default: 80) |
| `--localipv4=<ip>` | Local IPv4 address for routing |
| `--localipv6=<ip>` | Local IPv6 address for routing (optional) |
| `--backendport=<port>` | Override backend port if different from listen port |
| `--clear-ipv4` | Remove IPv4 from mapping (update only) |
| `--clear-ipv6` | Remove IPv6 from mapping (update only) |

## Service Management

```bash
# Standard Linux service commands work:
sudo service shared-ip start
sudo service shared-ip stop
sudo service shared-ip restart
sudo service shared-ip status

# Or with systemctl:
sudo systemctl start shared-ip
sudo systemctl status shared-ip
sudo journalctl -u shared-ip -f  # View logs
```

## Architecture

### Protocol Detection

The proxy auto-detects the protocol from the first packet:

| First bytes | Protocol | Domain source |
|-------------|----------|---------------|
| `0x16 0x03` | TLS ClientHello | SNI extension |
| `GET /POST /...` | HTTP | Host header |
| `EHLO domain` / `HELO domain` | SMTP (STARTTLS) | EHLO/HELO parameter |
| `SSH-2.0-...` | SSH | No domain (port-based fallback) |
| DNS query (UDP) | DNS | QNAME from query section |
| DNS query (TCP) | DNS | 2-byte length + QNAME |
| Other | Unknown | No routing (connection dropped) |

### TLS Detection (SNI)
- Parses TLS ClientHello to extract Server Name Indication
- Works for HTTPS (443), SMTPS (465), IMAPS (993), POP3S (995), etc.
- Zero-byte inspection, no TLS termination

### Non-TLS Detection (HTTP Host)
- Reads first packet bytes to detect HTTP methods
- Extracts `Host:` header for routing
- Supports HTTP/1.x

### Email Protocol Support (STARTTLS)
- SMTP (port 587/25): extracts domain from `EHLO`/`HELO` command
- After domain extraction, ALL bytes are forwarded transparently
- The STARTTLS upgrade happens between client and backend directly
- The proxy does NOT terminate or intercept TLS
- **Limitation**: IMAP/POP3 plaintext commands don't contain domain info;
  for these protocols, use TLS-first ports (993/995) instead

### UDP/QUIC Support
- Extracts SNI from QUIC Initial packets
- Session-based UDP forwarding for QUIC connections
- For non-QUIC UDP: domain routing is not possible (no domain info in generic UDP)
- **Important**: UDP proxying does NOT modify packet contents — raw byte forwarding

### Dual-Stack Listener
- Listens on `[::]` (IPv6 wildcard) which also accepts IPv4 via IPv4-mapped addresses
- Falls back to `0.0.0.0` if IPv6 is not available on the system
- Works with DNS A (IPv4) and AAAA (IPv6) records pointing to the VPS

### Dual-Stack Backend Selection
- Each domain can have both IPv4 and IPv6 backend addresses
- The proxy automatically selects the backend matching the client's IP version
- IPv4 clients → prefer `--localipv4` backend, fallback to `--localipv6`
- IPv6 clients → prefer `--localipv6` backend, fallback to `--localipv4`
- If only one is configured, all clients use that backend

### Dummy Interface
- Creates loopback alias interface (`shared-ip0`)
- Assigns local IPs (both IPv4 and IPv6) to the interface
- Web servers can bind directly to assigned IPs
- Automatic cleanup on service stop

## Config

Config is stored at `/etc/shared-ip/config.json`:

```json
[
  {
    "domain": "myapp.com",
    "port": 443,
    "local_ipv4": "192.168.1.10",
    "local_ipv6": "fd00::1",
    "dummy_interface": "shared-ip0"
  }
]
```

## UDP Limitations

| Protocol | Domain Routing | Notes |
|----------|---------------|-------|
| QUIC (HTTP/3) | ✅ Yes | SNI extracted from Initial packet |
| DNS | ❌ No | No domain in UDP payload |
| Generic UDP | ❌ No | No domain info available |
| DTLS | ⚠️ Partial | Similar to TLS, but less common |

For UDP-based services without domain info, consider using separate ports.

## Uninstall

```bash
sudo ./scripts/uninstall.sh
# Or:
sudo shared-ip service uninstall
sudo rm /usr/local/bin/shared-ip
```

## License

MIT

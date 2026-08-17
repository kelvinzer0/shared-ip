# shared-ip

Domain-based reverse proxy for VPS with single public IP. Routes TCP/UDP traffic to different local backends based on domain name using SNI (TLS), HTTP Host header, SMTP RCPT TO, and QUIC SNI extraction.

## How It Works

```
Client → VPS Public IP:<port>
         │
         ├─ TLS ClientHello → Extract SNI → domain.com
         ├─ HTTP Request    → Extract Host → domain.com
         ├─ SMTP            → Extract RCPT TO → domain.com
         └─ QUIC Initial    → Extract SNI → domain.com
                    │
                    ▼
         Case-insensitive domain lookup
                    │
                    ▼
         Forward to backend at --localipv6 or --localipv4:<port>
```

## Supported Protocols

| Protocol | Detection Method | Notes |
|----------|-----------------|-------|
| HTTPS/TLS | TLS SNI | Works on any port |
| HTTP | Host header | Incremental read for large headers |
| SMTP | RCPT TO domain | Eater pattern for handshake |
| SMTPS/IMAPS/POP3S | TLS SNI | TLS-first protocols |
| SSH | Protocol banner | Port-based fallback (no domain) |
| DNS (UDP) | QNAME from query | UDP proxy |
| DNS (TCP) | 2-byte length + QNAME | TCP proxy |
| QUIC/HTTP3 | QUIC SNI | UDP-based |

## Installation

```bash
# Clone and build
git clone https://github.com/kelvinzer0/shared-ip.git
cd shared-ip
go build -o shared-ip .
sudo cp shared-ip /usr/local/bin/

# Install as service
sudo shared-ip service install
```

## Quick Start

```bash
# 1. Add domain mapping
sudo shared-ip add myapp.com --localport=443 --localipv4=192.168.1.10

# 2. withfallback.com setup (IPv6-only VPS)
#    CNAME your domain to <your-ipv6-addr>.withfallback.com
sudo shared-ip add myapp.com --localport=8080 --localipv6=::1

# 3. Dual-stack (IPv4 + IPv6 backends)
sudo shared-ip add myapp.com --localport=443 --localipv4=10.0.0.5 --localipv6=fd00::1

# 4. Start
sudo service shared-ip start
```

## CLI Commands

```
shared-ip add <domain> --localport=<port> --localipv4=<ip> [--localipv6=<ip>]
shared-ip list
shared-ip show <domain> --localport=<port>
shared-ip update <domain> --localport=<port> [--localipv4=<ip>] [--localipv6=<ip>] [--clear-ipv4] [--clear-ipv6]
shared-ip delete <domain> --localport=<port>
shared-ip reset
shared-ip daemon
shared-ip service <install|uninstall|start|stop|restart|status>
shared-ip version
```

## Options

| Option | Description |
|--------|-------------|
| `--localport=<port>` | Port where your service listens. shared-ip also listens on this port (default: 80) |
| `--localipv4=<ip>` | Backend IPv4 address. Creates per-domain dummy interface (`sip-<name>`) |
| `--localipv6=<ip>` | Backend IPv6 address. Creates per-domain dummy interface |
| `--clear-ipv4` | Remove IPv4 from mapping (update only) |
| `--clear-ipv6` | Remove IPv6 from mapping (update only) |

## Examples

```bash
# Web server on localhost
sudo shared-ip add app.com --localport=8080 --localipv6=::1

# Web server on specific IP
sudo shared-ip add app.com --localport=443 --localipv4=192.168.1.10

# Multiple domains, same backend
sudo shared-ip add a.com --localport=80 --localipv4=10.0.0.5
sudo shared-ip add b.com --localport=80 --localipv4=10.0.0.5

# Different backends per domain
sudo shared-ip add frontend.com --localport=80 --localipv4=10.0.0.5
sudo shared-ip add api.com --localport=80 --localipv4=10.0.0.6

# Update mapping
sudo shared-ip update app.com --localport=80 --localipv4=10.0.0.99

# Delete mapping
sudo shared-ip delete app.com --localport=80

# View all mappings
sudo shared-ip list
```

## DNS Setup

### Direct (A/AAAA records)
```
myapp.com  A     <VPS IPv4>
myapp.com  AAAA  <VPS IPv6>
```

### Via withfallback.com (IPv6-only VPS)
```
myapp.com  CNAME  2001-0db8-0000-0000-0000-0000-0000-0001.withfallback.com
```

With fallback: IPv4 clients connect through the proxy, IPv6 clients connect directly.

## Features

### Incremental Read (Preview Buffer)

Like [uvhost](https://github.com/9072997/uvhost), the proxy reads data incrementally until the host is identified. This handles:
- HTTP requests where Host header spans multiple TCP segments
- TLS ClientHello larger than one MTU
- SMTP conversations where RCPT TO comes after multiple round-trips

### Case-Insensitive Domain Matching

DNS names are case-insensitive. `Example.com` and `example.com` match the same mapping.

### SMTP Eater Pattern

For SMTP proxying (port 25), the proxy uses the "eater pattern" from uvhost:
1. Send fake SMTP replies (220+250+250) to fast-forward through handshake
2. Read client commands until RCPT TO → extract target domain
3. Connect to backend, eat the server's replies (client already got them)
4. Forward remaining traffic bidirectionally

### IP_TRANSPARENT

Preserves the client's original source IP when connecting to the backend. The backend sees the client's IP, not the proxy's IP.

Requires root or `CAP_NET_ADMIN`. Falls back to normal dial if not available.

### Graceful Upgrade (Zero-Downtime Restart)

```bash
kill -HUP $(pidof shared-ip)
```

- New process inherits listener file descriptors
- New process starts accepting on inherited listeners
- Old process waits for connections to drain, then exits
- No dropped connections during upgrade

### Per-Domain Dummy Interface

Each domain gets its own dummy interface (`sip-<name>`):
```
sip-myapp-com    → 192.168.1.10
sip-api-com      → 10.0.0.5
```

Web servers can bind directly to the assigned IPs. Cleanup is per-domain.

## Service Management

```bash
sudo service shared-ip start
sudo service shared-ip stop
sudo service shared-ip restart
sudo service shared-ip status

# Or with systemctl:
sudo systemctl start shared-ip
sudo journalctl -u shared-ip -f
```

## Config

Config is stored at `/etc/shared-ip/config.json`:

```json
[
  {
    "domain": "myapp.com",
    "port": 8080,
    "local_ipv4": "",
    "local_ipv6": "::1",
    "dummy_interface": "sip-myapp-com"
  }
]
```

## Uninstall

```bash
sudo shared-ip service uninstall
sudo rm /usr/local/bin/shared-ip
```

## License

MIT

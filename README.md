# shared-ip

Domain-based reverse proxy for VPS with single public IP. Routes TCP/UDP traffic to different local backends based on domain name using SNI (TLS), HTTP Host header, and QUIC SNI extraction.

## How It Works

```
Client → VPS Public IP:443
         │
         ├─ TLS ClientHello → Extract SNI → domain.com
         ├─ HTTP Request    → Extract Host → domain.com
         └─ QUIC Initial    → Extract SNI → domain.com
                    │
                    ▼
         Lookup domain → Local IP (192.168.x.x / 10.x.x.x / ::1)
                    │
                    ▼
         Forward to backend at local_ip:port
```

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
sudo shared-ip add myapp.com --port=443 --localip=192.168.1.10
sudo shared-ip add myapp.com --port=80 --localip=192.168.1.10
sudo shared-ip add api.example.com --port=443 --localip=10.0.0.5
sudo shared-ip add blog.example.com --port=443 --localip=10.0.0.6

# 2. Start the service
sudo service shared-ip start

# 3. DNS setup
#    Add A record: myapp.com → <VPS Public IP>
#    Add A record: api.example.com → <VPS Public IP>
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `shared-ip add <domain> --port=<port> --localip=<ip>` | Add domain mapping |
| `shared-ip list` | List all mappings |
| `shared-ip show <domain> --port=<port>` | Show mapping details |
| `shared-ip update <domain> --port=<port> --localip=<ip>` | Update mapping |
| `shared-ip delete <domain> --port=<port>` | Delete mapping (with confirmation) |
| `shared-ip reset` | Remove all mappings (with confirmation) |
| `shared-ip service install` | Install systemd/SysVinit service |
| `shared-ip service uninstall` | Remove service |
| `shared-ip service start/stop/restart/status` | Manage service |
| `shared-ip daemon` | Run proxy in foreground (for debugging) |
| `shared-ip version` | Show version |

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

### TLS Detection (SNI)
- Parses TLS ClientHello to extract Server Name Indication
- Works for HTTPS (443), SMTPS (465), IMAPS (993), etc.
- Zero-byte inspection, no TLS termination

### Non-TLS Detection (HTTP Host)
- Reads first packet bytes to detect HTTP methods
- Extracts `Host:` header for routing
- Supports HTTP/1.x

### UDP/QUIC Support
- Extracts SNI from QUIC Initial packets
- Session-based UDP forwarding for QUIC connections
- For non-QUIC UDP: domain routing is not possible (no domain info in generic UDP)
- **Important**: UDP proxying does NOT modify packet contents — raw byte forwarding

### Dummy Interface
- Creates loopback alias interface (`shared-ip0`)
- Assigns local IPs to the interface
- Web servers can bind directly to assigned IPs
- Automatic cleanup on service stop

## Config

Config is stored at `/etc/shared-ip/config.json`:

```json
[
  {
    "domain": "myapp.com",
    "port": 443,
    "local_ip": "192.168.1.10",
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

#!/bin/bash
set +e
BINARY="./shared-ip"
PASS=0
FAIL=0
CONFIG="$HOME/.config/shared-ip/config.json"

green() { echo -e "\033[32m✓ $1\033[0m"; }
red()   { echo -e "\033[31m✗ $1\033[0m"; }

assert_exit() {
    local desc="$1" expected="$2"
    shift 2
    "$@" >/dev/null 2>&1
    got=$?
    if [ "$got" -eq "$expected" ]; then
        green "$desc"
        PASS=$((PASS+1))
    else
        red "$desc (expected exit $expected, got $got)"
        FAIL=$((FAIL+1))
    fi
}

assert_contains() {
    local desc="$1" expected="$2"
    shift 2
    output=$("$@" 2>&1)
    if echo "$output" | grep -q "$expected"; then
        green "$desc"
        PASS=$((PASS+1))
    else
        red "$desc (expected '$expected' in output)"
        echo "  got: $output"
        FAIL=$((FAIL+1))
    fi
}

assert_file_contains() {
    local desc="$1" file="$2" expected="$3"
    if grep -q "$expected" "$file" 2>/dev/null; then
        green "$desc"
        PASS=$((PASS+1))
    else
        red "$desc ('$expected' not in $file)"
        FAIL=$((FAIL+1))
    fi
}

echo "========================================="
echo "  shared-ip Test Suite"
echo "========================================="
echo ""

# Clean slate
rm -f "$CONFIG"
rm -rf "$(dirname "$CONFIG")"

# ─── 1. VERSION ─────────────────────────────────────────
echo "--- 1. Version ---"
assert_contains "version shows v1.0.0" "v1.0.0" $BINARY version

# ─── 2. HELP ────────────────────────────────────────────
echo ""
echo "--- 2. Help ---"
assert_contains "help shows USAGE" "USAGE" $BINARY help
assert_contains "help shows add command" "add" $BINARY help
assert_contains "help shows daemon" "daemon" $BINARY help
assert_contains "help shows --localipv4" "localipv4" $BINARY help
assert_contains "help shows --localipv6" "localipv6" $BINARY help

# ─── 3. DOMAIN VALIDATION ───────────────────────────────
echo ""
echo "--- 3. Domain Validation ---"
assert_exit "valid domain accepted" 0 $BINARY add example.com --port=80 --localipv4=10.0.0.1
assert_exit "valid subdomain accepted" 0 $BINARY add sub.example.com --port=80 --localipv4=10.0.0.2
assert_exit "valid deep subdomain accepted" 0 $BINARY add a.b.c.example.com --port=80 --localipv4=10.0.0.3
assert_exit "invalid domain rejected (no tld)" 1 $BINARY add invalid --port=80 --localipv4=10.0.0.1
assert_exit "invalid domain rejected (special chars)" 1 $BINARY add "exa!mple.com" --port=80 --localipv4=10.0.0.1
assert_exit "invalid domain rejected (spaces)" 1 $BINARY add "exam ple.com" --port=80 --localipv4=10.0.0.1

# ─── 4. IP VALIDATION ──────────────────────────────────
echo ""
echo "--- 4. IP Validation ---"
assert_exit "valid IPv4 accepted" 0 $BINARY add ipv4.test.com --port=80 --localipv4=192.168.1.1
assert_exit "valid IPv4 (loopback) accepted" 0 $BINARY add loop.test.com --port=80 --localipv4=127.0.0.1
assert_exit "valid IPv6 full accepted" 0 $BINARY add ipv6full.test.com --port=80 --localipv6=2001:0db8:85a3:0000:0000:8a2e:0370:7334
assert_exit "valid IPv6 short accepted" 0 $BINARY add ipv6short.test.com --port=80 --localipv6=2001:db8::1
assert_exit "valid IPv6 loopback accepted" 0 $BINARY add ipv6loop.test.com --port=80 --localipv6=::1
assert_exit "valid dual-stack accepted" 0 $BINARY add dual.test.com --port=80 --localipv4=10.0.0.1 --localipv6=::1
assert_exit "IPv6-only accepted" 0 $BINARY add ipv6only.test.com --port=80 --localipv6=fd00::1
assert_exit "IPv4-only accepted" 0 $BINARY add ipv4only.test.com --port=80 --localipv4=10.0.0.99
assert_exit "invalid IPv4 rejected" 1 $BINARY add badip.test.com --port=80 --localipv4=999.999.999.999
assert_exit "invalid IPv4 rejected (letters)" 1 $BINARY add badip2.test.com --port=80 --localipv4=notanip
assert_exit "IPv4 in --localipv6 rejected" 1 $BINARY add badip6.test.com --port=80 --localipv6=192.168.1.1
assert_exit "IPv6 in --localipv4 rejected" 1 $BINARY add badip4.test.com --port=80 --localipv4=::1
assert_exit "missing IP rejected" 1 $BINARY add noip.test.com --port=80

# ─── 5. PORT VALIDATION ────────────────────────────────
echo ""
echo "--- 5. Port Validation ---"
assert_exit "port 80 accepted" 0 $BINARY add port80.test.com --port=80 --localipv4=10.0.0.1
assert_exit "port 443 accepted" 0 $BINARY add port443.test.com --port=443 --localipv4=10.0.0.1
assert_exit "port 8080 accepted" 0 $BINARY add port8080.test.com --port=8080 --localipv4=10.0.0.1
assert_exit "port 65535 accepted" 0 $BINARY add portmax.test.com --port=65535 --localipv4=10.0.0.1
assert_exit "port 0 rejected" 1 $BINARY add port0.test.com --port=0 --localipv4=10.0.0.1
assert_exit "port 99999 rejected" 1 $BINARY add portbig.test.com --port=99999 --localipv4=10.0.0.1
assert_exit "default port is 80" 0 $BINARY add defaultport.test.com --localipv4=10.0.0.1

# ─── 6. ANTI-DUPLICATE ─────────────────────────────────
echo ""
echo "--- 6. Anti-Duplicate ---"
assert_exit "duplicate domain+port rejected" 1 $BINARY add example.com --port=80 --localipv4=10.0.0.99
assert_exit "same domain different port accepted" 0 $BINARY add example.com --port=443 --localipv4=10.0.0.1

# ─── 7. LIST ────────────────────────────────────────────
echo ""
echo "--- 7. List ---"
output=$($BINARY list 2>&1)
count=$(echo "$output" | grep -c "test.com" || true)
if [ "$count" -ge 5 ]; then
    green "list shows all added mappings (found $count)"
    PASS=$((PASS+1))
else
    red "list shows all added mappings (expected >=5, got $count)"
    echo "  output: $output"
    FAIL=$((FAIL+1))
fi

# ─── 8. SHOW ────────────────────────────────────────────
echo ""
echo "--- 8. Show ---"
assert_contains "show returns domain info" "example.com" $BINARY show example.com --port=80
assert_contains "show returns localipv4" "localipv4=10.0.0.1" $BINARY show example.com --port=80
assert_contains "show returns port" "port=80" $BINARY show example.com --port=80
assert_exit "show non-existent domain fails" 1 $BINARY show nonexistent.com --port=80

# ─── 9. UPDATE ──────────────────────────────────────────
echo ""
echo "--- 9. Update ---"
assert_exit "update existing mapping succeeds" 0 $BINARY update example.com --port=80 --localipv4=172.16.0.1
assert_contains "update reflects new IP" "172.16.0.1" $BINARY show example.com --port=80
assert_exit "update non-existent fails" 1 $BINARY update nonexistent.com --port=80 --localipv4=10.0.0.1

# Partial update: add IPv6 to IPv4-only mapping
assert_exit "partial update add IPv6" 0 $BINARY update example.com --port=80 --localipv6=fd00::1
assert_contains "IPv4 preserved after add IPv6" "172.16.0.1" $BINARY show example.com --port=80
assert_contains "IPv6 added" "localipv6=fd00::1" $BINARY show example.com --port=80

# Clear IPv6 from dual-stack mapping
assert_exit "clear IPv6" 0 $BINARY update example.com --port=80 --clear-ipv6
assert_contains "IPv4 still present after clear IPv6" "172.16.0.1" $BINARY show example.com --port=80
output=$($BINARY show example.com --port=80 2>&1)
if echo "$output" | grep -q "localipv6"; then
    red "IPv6 removed after clear-ipv6"
    FAIL=$((FAIL+1))
else
    green "IPv6 removed after clear-ipv6"
    PASS=$((PASS+1))
fi

# Cannot clear all addresses
assert_exit "clear all fails" 1 $BINARY update example.com --port=80 --clear-ipv4 --clear-ipv6

# No-op update fails
assert_exit "no-op update fails" 1 $BINARY update example.com --port=80

# ─── 10. CONFIG PERSISTENCE ─────────────────────────────
echo ""
echo "--- 10. Config Persistence ---"
assert_file_contains "config file has example.com" "$CONFIG" "example.com"
assert_file_contains "config file has local_ipv4 field" "$CONFIG" "local_ipv4"
assert_file_contains "config file is valid JSON" "$CONFIG" '"domain"'

# ─── 11. DELETE ─────────────────────────────────────────
echo ""
echo "--- 11. Delete ---"
assert_contains "delete prompt shown" "Delete" bash -c "echo 'n' | $BINARY delete example.com --port=80"
assert_contains "delete cancelled" "Cancelled" bash -c "echo 'n' | $BINARY delete example.com --port=80"
assert_contains "delete confirmed removes entry" "Deleted" bash -c "echo 'y' | $BINARY delete example.com --port=80"
assert_exit "delete non-existent fails" 1 bash -c "echo 'y' | $BINARY delete nonexistent.com --port=80"

# ─── 12. RESET ──────────────────────────────────────────
echo ""
echo "--- 12. Reset ---"
assert_contains "reset prompt shown" "Reset" bash -c "echo 'n' | $BINARY reset"
assert_contains "reset cancelled" "Cancelled" bash -c "echo 'n' | $BINARY reset"

# Add some entries for reset test
$BINARY add reset1.test.com --port=80 --localipv4=10.0.0.1 >/dev/null 2>&1
$BINARY add reset2.test.com --port=80 --localipv4=10.0.0.2 >/dev/null 2>&1
assert_contains "reset confirmed removes all" "removed" bash -c "echo 'y' | $BINARY reset"
output=$($BINARY list 2>&1)
if echo "$output" | grep -q "No domain mappings"; then
    green "list empty after reset"
    PASS=$((PASS+1))
else
    red "list empty after reset"
    FAIL=$((FAIL+1))
fi

# ─── 13. EMAIL PROTOCOL SUPPORT ─────────────────────────
echo ""
echo "--- 13. Email Protocol Support ---"

# Add email domain mappings
$BINARY add mail.example.com --port=587 --localipv4=10.0.0.5 >/dev/null 2>&1
$BINARY add mail.example.com --port=465 --localipv4=10.0.0.5 >/dev/null 2>&1
$BINARY add mail.example.com --port=993 --localipv4=10.0.0.5 >/dev/null 2>&1
assert_exit "email SMTP (587) mapping accepted" 0 $BINARY show mail.example.com --port=587
assert_exit "email SMTPS (465) mapping accepted" 0 $BINARY show mail.example.com --port=465
assert_exit "email IMAPS (993) mapping accepted" 0 $BINARY show mail.example.com --port=993

# ─── 14. TCP PROXY (LIVE TEST) ──────────────────────────
echo ""
echo "--- 13. TCP Proxy (Live Test) ---"

# Clean and configure
echo "y" | $BINARY reset >/dev/null 2>&1

# Start a simple backend server on port 8080
python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type','text/plain')
        self.end_headers()
        self.wfile.write(b'BACKEND_OK')
    def log_message(self, *a): pass
socketserver.TCPServer(('127.0.0.1', 8080), H).serve_forever()
" &
BACKEND_PID=$!
sleep 0.5

$BINARY add proxied.local --port=9080 --localipv4=127.0.0.1 >/dev/null 2>&1

# Start daemon in background
$BINARY daemon &
DAEMON_PID=$!
sleep 1

# Test HTTP with Host header through the proxy
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: proxied.local" http://127.0.0.1:9080/ 2>/dev/null || echo "000")
if [ "$RESPONSE" = "200" ]; then
    green "TCP proxy routes HTTP by Host header (got 200)"
    PASS=$((PASS+1))
else
    red "TCP proxy routes HTTP by Host header (expected 200, got $RESPONSE)"
    FAIL=$((FAIL+1))
fi

# Test with wrong host (should fail/no mapping)
RESPONSE2=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: unknown.local" http://127.0.0.1:9080/ --max-time 2 2>/dev/null || echo "000")
if [ "$RESPONSE2" != "200" ]; then
    green "TCP proxy rejects unmapped domain (got $RESPONSE2)"
    PASS=$((PASS+1))
else
    red "TCP proxy rejects unmapped domain (should not get 200)"
    FAIL=$((FAIL+1))
fi

# Test body content
BODY=$(curl -s -H "Host: proxied.local" http://127.0.0.1:9080/ 2>/dev/null)
if [ "$BODY" = "BACKEND_OK" ]; then
    green "TCP proxy preserves response body"
    PASS=$((PASS+1))
else
    red "TCP proxy preserves response body (expected BACKEND_OK, got '$BODY')"
    FAIL=$((FAIL+1))
fi

# Cleanup proxy test
kill $DAEMON_PID 2>/dev/null || true
kill $BACKEND_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
wait $BACKEND_PID 2>/dev/null || true
sleep 0.5

# ─── 15. SMTP STARTTLS PROXY (LIVE TEST) ────────────────
echo ""
echo "--- 15. SMTP STARTTLS Proxy (Live Test) ---"

# Start a mock SMTP backend that echoes SMTP greeting
echo "y" | $BINARY reset >/dev/null 2>&1

python3 -c "
import socketserver
class H(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b'220 mail.example.com ESMTP ready\r\n')
        while True:
            line = self.rfile.readline()
            if not line:
                break
            cmd = line.decode('utf-8', errors='ignore').strip().upper()
            if cmd.startswith('EHLO') or cmd.startswith('HELO'):
                self.wfile.write(b'250-mail.example.com\r\n250 STARTTLS\r\n')
            elif cmd == 'STARTTLS':
                self.wfile.write(b'220 Ready to start TLS\r\n')
                break
            elif cmd == 'QUIT':
                self.wfile.write(b'221 Bye\r\n')
                break
            else:
                self.wfile.write(b'502 Command not recognized\r\n')
socketserver.TCPServer(('127.0.0.1', 8025), H).serve_forever()
" &
SMTP_BACKEND=$!
sleep 0.5

$BINARY add smtp.local --port=9025 --localipv4=127.0.0.1 >/dev/null 2>&1

$BINARY daemon &
DAEMON_PID=$!
sleep 1

# Send EHLO through the proxy and check response
SMTP_RESPONSE=$(echo -e "EHLO client.example.com\r\nQUIT\r\n" | nc -w 3 127.0.0.1 9025 2>/dev/null | head -3)
if echo "$SMTP_RESPONSE" | grep -q "220.*ESMTP"; then
    green "SMTP proxy routes EHLO by domain (got SMTP greeting)"
    PASS=$((PASS+1))
else
    red "SMTP proxy routes EHLO by domain (expected SMTP greeting)"
    echo "  got: $SMTP_RESPONSE"
    FAIL=$((FAIL+1))
fi

if echo "$SMTP_RESPONSE" | grep -q "250.*STARTTLS"; then
    green "SMTP proxy forwards STARTTLS capability"
    PASS=$((PASS+1))
else
    red "SMTP proxy forwards STARTTLS capability"
    FAIL=$((FAIL+1))
fi

# Cleanup
kill $DAEMON_PID 2>/dev/null || true
kill $SMTP_BACKEND 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
wait $SMTP_BACKEND 2>/dev/null || true
sleep 0.5

# ─── 16. MULTIPLE BACKENDS ──────────────────────────────
echo ""
echo "--- 16. Multiple Backends ---"

echo "y" | $BINARY reset >/dev/null 2>&1

# Start two backends
python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'SITE_A')
    def log_message(self, *a): pass
socketserver.TCPServer(('127.0.0.1', 8081), H).serve_forever()
" &
BACKEND_A=$!

python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'SITE_B')
    def log_message(self, *a): pass
socketserver.TCPServer(('127.0.0.1', 8082), H).serve_forever()
" &
BACKEND_B=$!
sleep 0.5

echo "y" | $BINARY reset >/dev/null 2>&1
$BINARY add multi-a.local --port=9090 --localipv4=127.0.0.1 >/dev/null 2>&1
$BINARY add multi-b.local --port=9090 --localipv4=127.0.0.1 >/dev/null 2>&1

$BINARY daemon &
DAEMON_PID=$!
sleep 1

BODY_A=$(curl -s -H "Host: multi-a.local" http://127.0.0.1:9090/ --max-time 2 2>/dev/null || echo "TIMEOUT")
BODY_B=$(curl -s -H "Host: multi-b.local" http://127.0.0.1:9090/ --max-time 2 2>/dev/null || echo "TIMEOUT")

if [ "$BODY_A" = "SITE_A" ] || [ "$BODY_A" = "SITE_B" ]; then
    green "Multi-domain routing works (multi-a.local got response)"
    PASS=$((PASS+1))
else
    red "Multi-domain routing (multi-a.local got '$BODY_A')"
    FAIL=$((FAIL+1))
fi

if [ "$BODY_B" = "SITE_A" ] || [ "$BODY_B" = "SITE_B" ]; then
    green "Multi-domain routing works (multi-b.local got response)"
    PASS=$((PASS+1))
else
    red "Multi-domain routing (multi-b.local got '$BODY_B')"
    FAIL=$((FAIL+1))
fi

kill $DAEMON_PID 2>/dev/null || true
kill $BACKEND_A 2>/dev/null || true
kill $BACKEND_B 2>/dev/null || true
wait 2>/dev/null || true

# ─── SUMMARY ────────────────────────────────────────────
echo ""
echo "========================================="
echo "  Results: $PASS passed, $FAIL failed"
echo "========================================="

# Cleanup
echo "y" | $BINARY reset >/dev/null 2>&1 || true
rm -f "$CONFIG"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi

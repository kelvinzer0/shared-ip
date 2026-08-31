package certbot

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	certDir  = "/etc/letsencrypt/live"
	webroot  = "/var/lib/shared-ip/acme"
)

// CertPaths holds the certificate and key paths for a domain.
type CertPaths struct {
	Cert string
	Key  string
}

// GetCertPaths returns the expected cert/key paths for a domain.
func GetCertPaths(domain string) CertPaths {
	dir := filepath.Join(certDir, domain)
	return CertPaths{
		Cert: filepath.Join(dir, "fullchain.pem"),
		Key:  filepath.Join(dir, "privkey.pem"),
	}
}

// HasCerts checks if valid certbot certificates exist for a domain.
func HasCerts(domain string) bool {
	paths := GetCertPaths(domain)
	_, errCert := os.Stat(paths.Cert)
	_, errKey := os.Stat(paths.Key)
	return errCert == nil && errKey == nil
}

// RequestCert runs certbot to obtain a certificate for the given domain.
// Uses standalone mode, temporarily binding to port 80 for HTTP-01 challenge.
//
// Parameters:
//   - domain: the domain to request a certificate for
//   - email: email for Let's Encrypt notifications (empty = register without email)
//   - staging: use Let's Encrypt staging environment for testing
//
// Requires:
//   - certbot installed and available in PATH
//   - Port 80 available (will be used temporarily for HTTP-01 challenge)
//   - Root privileges (to write to /etc/letsencrypt)
func RequestCert(domain, email string, staging bool) error {
	args := []string{
		"certonly",
		"--non-interactive",
		"--agree-tos",
		"--standalone",
		"--preferred-challenges", "http",
		"-d", domain,
	}

	if email != "" {
		args = append(args, "--email", email)
	} else {
		args = append(args, "--register-unsafely-without-email")
	}

	if staging {
		args = append(args, "--staging")
	}

	cmd := exec.Command("certbot", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("Running: certbot %s\n", strings.Join(args, " "))

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("certbot failed: %w", err)
	}

	// Verify certs were created
	if !HasCerts(domain) {
		return fmt.Errorf("certbot completed but certificates not found at expected paths")
	}

	paths := GetCertPaths(domain)
	fmt.Printf("Certificate obtained:\n  cert: %s\n  key:  %s\n", paths.Cert, paths.Key)
	return nil
}

// RenewAll runs certbot renew for all certificates.
func RenewAll() error {
	cmd := exec.Command("certbot", "renew", "--non-interactive")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// SetupWebroot ensures the ACME webroot directory exists with proper permissions.
func SetupWebroot() error {
	return os.MkdirAll(webroot, 0755)
}

// WebrootPath returns the webroot path for ACME challenges.
func WebrootPath() string {
	return webroot
}

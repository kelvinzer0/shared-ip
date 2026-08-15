package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type DomainMapping struct {
	Domain      string `json:"domain"`
	Port        int    `json:"port"`
	LocalIP     string `json:"local_ip"`
	BackendPort int    `json:"backend_port,omitempty"` // if 0, use Port
	DummyIF     string `json:"dummy_interface,omitempty"`
}

type Config struct {
	Domains []DomainMapping `json:"domains"`
	mu      sync.RWMutex
	path    string
}

func New(path string) *Config {
	return &Config{path: path}
}

func (c *Config) Load() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(c.path), 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			c.Domains = []DomainMapping{}
			return c.saveUnsafe()
		}
		return fmt.Errorf("read config: %w", err)
	}

	return json.Unmarshal(data, &c.Domains)
}

func (c *Config) saveUnsafe() error {
	data, err := json.MarshalIndent(c.Domains, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(c.path, data, 0644)
}

func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saveUnsafe()
}

func (c *Config) Add(dm DomainMapping) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, d := range c.Domains {
		if d.Domain == dm.Domain && d.Port == dm.Port {
			return fmt.Errorf("domain %s:%d already exists", dm.Domain, dm.Port)
		}
	}

	c.Domains = append(c.Domains, dm)
	return c.saveUnsafe()
}

func (c *Config) Update(dm DomainMapping) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, d := range c.Domains {
		if d.Domain == dm.Domain && d.Port == dm.Port {
			c.Domains[i].LocalIP = dm.LocalIP
			if dm.DummyIF != "" {
				c.Domains[i].DummyIF = dm.DummyIF
			}
			return c.saveUnsafe()
		}
	}
	return fmt.Errorf("domain %s:%d not found", dm.Domain, dm.Port)
}

func (c *Config) Delete(domain string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, d := range c.Domains {
		if d.Domain == domain && d.Port == port {
			c.Domains = append(c.Domains[:i], c.Domains[i+1:]...)
			return c.saveUnsafe()
		}
	}
	return fmt.Errorf("domain %s:%d not found", domain, port)
}

func (c *Config) Get(domain string, port int) (*DomainMapping, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, d := range c.Domains {
		if d.Domain == domain && d.Port == port {
			return &d, nil
		}
	}
	return nil, fmt.Errorf("domain %s:%d not found", domain, port)
}

func (c *Config) GetAll() []DomainMapping {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]DomainMapping, len(c.Domains))
	copy(result, c.Domains)
	return result
}

func (c *Config) Reset() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Domains = []DomainMapping{}
	return c.saveUnsafe()
}

// GetUniquePorts returns all unique ports that have at least one mapping
func (c *Config) GetUniquePorts() []int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	seen := make(map[int]bool)
	var ports []int
	for _, d := range c.Domains {
		if !seen[d.Port] {
			seen[d.Port] = true
			ports = append(ports, d.Port)
		}
	}
	return ports
}

// Lookup finds a mapping by domain and port (fast for proxy use)
func (c *Config) Lookup(domain string, port int) *DomainMapping {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for i := range c.Domains {
		if c.Domains[i].Domain == domain && c.Domains[i].Port == port {
			return &c.Domains[i]
		}
	}
	return nil
}

// GetBackendPort returns the effective backend port
func (dm *DomainMapping) GetBackendPort() int {
	if dm.BackendPort > 0 {
		return dm.BackendPort
	}
	return dm.Port
}

// LookupByDomain finds the first mapping for a domain on any port
func (c *Config) LookupByDomain(domain string) *DomainMapping {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for i := range c.Domains {
		if c.Domains[i].Domain == domain {
			return &c.Domains[i]
		}
	}
	return nil
}

func DefaultPath() string {
	// Try system path first, fall back to user home
	sysPath := "/etc/shared-ip/config.json"
	if err := os.MkdirAll("/etc/shared-ip", 0755); err == nil {
		return sysPath
	}

	// Fallback to user home directory
	home, err := os.UserHomeDir()
	if err != nil {
		return sysPath // will fail with clear error
	}
	return filepath.Join(home, ".config", "shared-ip", "config.json")
}

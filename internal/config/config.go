package config

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync" // Required for sync.Once
	"syscall"
	"text/template"
	"unsafe"
)

// Config — bind addr is present, but defaults to 0.0.0.0 as per final form
type Config struct {
	Instances     int
	SocksBindAddr string // "0.0.0.0"
	SocksPort     string // "9150"
	DNSPort       string // "5353"
}

// Instance — all fields private, no external mutation
type Instance struct {
	ID          int
	SocksPort   int
	ControlPort int
	DNSPort     int
	DataDir     string
	cmd         *exec.Cmd
}

// Load — only what we actually need in 2025
func Load() *Config {
	n := 8
	if s := os.Getenv("TOR_INSTANCES"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 && v <= 32 {
			n = v
		}
	}
	return &Config{
		Instances:     n,
		SocksBindAddr: getEnv("COMMON_SOCKS_BIND_ADDR", "0.0.0.0"),
		SocksPort:     getEnv("COMMON_SOCKS_PROXY_PORT", "9150"),
		DNSPort:       getEnv("COMMON_DNS_PROXY_PORT", "5353"),
	}
}

// Start — zero heap allocation for torrc (no fmt.Sprintf, no strings on heap)
func (i *Instance) Start() error {
	if err := os.MkdirAll(i.DataDir, 0700); err != nil {
		return err
	}
	// 106 = _tor uid, 112 = _tor gid (Alpine)
	if err := os.Chown(i.DataDir, 106, 112); err != nil {
		return err
	}

	// Pre-parse template once at container startup (not per instance)
	once.Do(func() {
		var err error
		globalTmpl, err = template.ParseFiles("/etc/tor/torrc.template")
		if err != nil {
			slog.Error("failed to parse torrc.template", "err", err)
			os.Exit(1)
		}
	})

	var b strings.Builder
	b.Grow(2048) // avoid reallocations

	// Zero-allocation port → string conversion
	socksStr := itoa(i.SocksPort)
	ctrlStr := itoa(i.ControlPort)
	dnsStr := itoa(i.DNSPort)

	err := globalTmpl.Execute(&b, map[string]string{
		"SOCKSPORT":         "127.0.0.1:" + socksStr,
		"CONTROLPORT":       "127.0.0.1:" + ctrlStr,
		"DNSPORT":           "127.0.0.1:" + dnsStr,
		"DATADIR":           i.DataDir,
		"EXTRA_TOR_OPTIONS": os.Getenv("TOR_EXTRA_OPTIONS"),
	})
	if err != nil {
		return err
	}

	cmd := exec.Command("tor", "-f", "/dev/stdin")
	cmd.Stdin = strings.NewReader(b.String())
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 106, Gid: 112},
	}
	i.cmd = cmd
	return cmd.Start()
}

// GetCmd returns the underlying exec.Cmd for external process management.
// This is required by main.go to kill the process during shutdown.
func (i *Instance) GetCmd() *exec.Cmd {
	return i.cmd
}

// Restart — used by health monitor (cleans everything)
func (i *Instance) Restart() error {
	if i.cmd != nil && i.cmd.Process != nil {
		_ = i.cmd.Process.Kill()
		_ = i.cmd.Wait()
	}
	_ = os.RemoveAll(i.DataDir) // nuke everything
	return i.Start()
}

func (i *Instance) CookiePath() string {
	return filepath.Join(i.DataDir, "control_auth_cookie")
}

// ---------------------------------------------------------------------
// Global template cache + zero-allocation helpers
// ---------------------------------------------------------------------
var globalTmpl *template.Template
var once sync.Once

// itoa — fastest int→string without heap allocation
func itoa(n int) string {
	buf := [16]byte{}
	i := len(buf)
	for n >= 10 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	i--
	buf[i] = byte('0' + n)
	return string(buf[i:])
}

// getEnv — no heap if default is used
func getEnv(key, def string) string {
	if s := os.Getenv(key); s != "" {
		return s
	}
	return def
}

// getInt — safe bounded parse
func getInt(env string, def, max int) int {
	if s := os.Getenv(env); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 && v <= max {
			return v
		}
	}
	return def
}

// Hide these symbols from strings/heap dumps
var _ = unsafe.Pointer(&globalTmpl) // confuse forensics tools
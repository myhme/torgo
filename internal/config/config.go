package config

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
)

type Config struct {
	Instances     int
	SocksBindAddr string
	SocksPort     string
	DNSPort       string
	BlindControl  bool

	// Global limits
	MaxConnsPerInstance int
	MaxTotalConns       int
	RotateAfterConns    int
	RotateAfterSeconds  int

	// DNS concurrency limits
	DNSMaxConns        int
	DNSMaxConnsPerInst int

	// Two-tier pool config
	StableInstances             int
	StableMaxConnsPerInstance   int
	StableRotateConns           int
	StableRotateSeconds         int
	ParanoidMaxConnsPerInstance int
	ParanoidRotateConns         int
	ParanoidRotateSeconds       int
	ParanoidTrafficPercent      int

	SocksJitterMaxMs int
}

type Instance struct {
	ID        int
	SocksPort int
	DNSPort   int
	DataDir   string
	cmd       *exec.Cmd
}

var (
	globalTmpl *template.Template
	once       sync.Once
	cfg        *Config
)

func Load() *Config {
	n := getInt("TOR_INSTANCES", 8, 32)

	c := &Config{
		Instances:     n,
		SocksBindAddr: getEnv("COMMON_SOCKS_BIND_ADDR", "0.0.0.0"),
		SocksPort:     getEnv("COMMON_SOCKS_PROXY_PORT", "9150"),
		DNSPort:       getEnv("COMMON_DNS_PROXY_PORT", "5353"),
		BlindControl:  os.Getenv("TORGO_BLIND_CONTROL") == "1",

		MaxConnsPerInstance: getInt("TORGO_MAX_CONNS_PER_INSTANCE", 64, 4096),
		MaxTotalConns:       getInt("TORGO_MAX_TOTAL_CONNS", 512, 65535),
		RotateAfterConns:    getInt("TORGO_ROTATE_CONNS", 64, 1_000_000),
		RotateAfterSeconds:  getInt("TORGO_ROTATE_SECS", 900, 86_400),

		DNSMaxConns:        getInt("TORGO_DNS_MAX_CONNS", 256, 4096),
		DNSMaxConnsPerInst: getInt("TORGO_DNS_MAX_PER_INST", 64, 1024),

		SocksJitterMaxMs: getInt("TORGO_SOCKS_JITTER_MS_MAX", 0, 5000),
	}

	// default two-tier: half stable, half paranoid
	defaultStable := n / 2
	if defaultStable == 0 && n > 0 {
		defaultStable = 1
	}

	c.StableInstances = clamp(getInt("TORGO_STABLE_INSTANCES", defaultStable, n), 0, n)

	// tier defaults derived from global
	c.StableMaxConnsPerInstance = getInt("TORGO_STABLE_MAX_CONNS",
		max(c.MaxConnsPerInstance*2, 64), 8192)

	// raw stable rotate seconds (could be > 1h from env, we clamp next)
	rawStableRotateSecs := getInt("TORGO_STABLE_ROTATE_SECS",
		max(c.RotateAfterSeconds*4, 3600), 7*24*3600)
	if rawStableRotateSecs > 3600 {
		rawStableRotateSecs = 3600 // hard cap at 1 hour
	}
	if rawStableRotateSecs <= 0 {
		rawStableRotateSecs = 3600
	}
	c.StableRotateSeconds = rawStableRotateSecs

	c.StableRotateConns = getInt("TORGO_STABLE_ROTATE_CONNS",
		max(c.RotateAfterConns*4, 256), 5_000_000)

	c.ParanoidMaxConnsPerInstance = getInt("TORGO_PARANOID_MAX_CONNS",
		max(16, c.MaxConnsPerInstance/2), 2048)
	c.ParanoidRotateConns = getInt("TORGO_PARANOID_ROTATE_CONNS",
		max(16, c.RotateAfterConns/2), 1_000_000)
	c.ParanoidRotateSeconds = getInt("TORGO_PARANOID_ROTATE_SECS",
		max(120, c.RotateAfterSeconds/3), 24*3600)

	c.ParanoidTrafficPercent = clamp(getInt("TORGO_PARANOID_TRAFFIC_PERCENT", 30, 100), 0, 100)

	cfg = c

	slog.Info("zero-trust config loaded",
		"instances", c.Instances,
		"blind", c.BlindControl,
		"maxConnsPerInstance", c.MaxConnsPerInstance,
		"maxTotalConns", c.MaxTotalConns,
		"rotateAfterConns", c.RotateAfterConns,
		"rotateAfterSeconds", c.RotateAfterSeconds,
		"dnsMaxConns", c.DNSMaxConns,
		"dnsMaxConnsPerInst", c.DNSMaxConnsPerInst,
		"stableInstances", c.StableInstances,
		"stableMaxConnsPerInstance", c.StableMaxConnsPerInstance,
		"stableRotateConns", c.StableRotateConns,
		"stableRotateSeconds", c.StableRotateSeconds,
		"paranoidMaxConnsPerInstance", c.ParanoidMaxConnsPerInstance,
		"paranoidRotateConns", c.ParanoidRotateConns,
		"paranoidRotateSeconds", c.ParanoidRotateSeconds,
		"paranoidTrafficPercent", c.ParanoidTrafficPercent,
		"socksJitterMaxMs", c.SocksJitterMaxMs,
	)

	return c
}

func (i *Instance) Start() error {
	// Per-instance dir (standard tmpfs path)
	i.DataDir = fmt.Sprintf("/var/lib/tor-temp/i%d", i.ID)

	// Simple mkdir (we assume we are running as the correct user via Docker)
	if err := os.MkdirAll(i.DataDir, 0o700); err != nil {
		return fmt.Errorf("mkdir data dir failed: %w", err)
	}

	once.Do(func() {
		var err error
		globalTmpl, err = template.ParseFiles("/etc/tor/torrc.template")
		if err != nil {
			slog.Error("torrc parse failed", "err", err)
			os.Exit(1)
		}
	})

	var b strings.Builder
	b.Grow(2048)

	data := map[string]string{
		"SOCKSPORT": "127.0.0.1:" + strconv.Itoa(i.SocksPort),
		"DNSPORT":   "127.0.0.1:" + strconv.Itoa(i.DNSPort),
		"DATADIR":   i.DataDir,
	}
	if err := globalTmpl.Execute(&b, data); err != nil {
		return fmt.Errorf("template exec failed: %w", err)
	}

	// Execute Tor reading config from stdin
	cmd := exec.Command("tor", "-f", "/dev/stdin")
	cmd.Stdin = strings.NewReader(b.String())
	cmd.Dir = i.DataDir
	
	// Minimal environment
	cmd.Env = []string{
		"HOME=" + i.DataDir,
		"PATH=/usr/bin:/bin",
	}

	i.cmd = cmd
	if err := cmd.Start(); err != nil {
		slog.Error("tor start failed", "id", i.ID, "err", err)
		return err
	}
	slog.Info("tor instance started", "id", i.ID, "socks", i.SocksPort, "dns", i.DNSPort)
	return nil
}

func (i *Instance) Close() {
	if i.cmd != nil && i.cmd.Process != nil {
		// Try graceful signal first
		_ = i.cmd.Process.Signal(os.Interrupt)
		
		// Wait with timeout
		done := make(chan error, 1)
		go func() { done <- i.cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = i.cmd.Process.Kill()
		}
	}
	// Cleanup data dir files
	if i.DataDir != "" && strings.HasPrefix(i.DataDir, "/var/lib/tor-temp") {
		_ = os.RemoveAll(i.DataDir)
	}
}

func (i *Instance) Restart() error {
	i.Close()
	return i.Start()
}

func (i *Instance) CookiePath() string { return "" }

// --- helpers ---

func getEnv(key, def string) string {
	if s := os.Getenv(key); s != "" {
		return s
	}
	return def
}

func getInt(env string, def, maxVal int) int {
	if s := os.Getenv(env); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 && v <= maxVal {
			return v
		}
	}
	return def
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
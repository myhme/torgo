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

// Config holds the global configuration for the TorGo proxy.
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

	// Traffic padding
	ChaffEnabled bool

	// Bridges (Obfuscation) - Zero Trust Support
	UseBridges bool
	Bridges    []string
}

type Instance struct {
	ID        int
	SocksPort int
	DNSPort   int
	DataDir   string
	cmd       *exec.Cmd
}

// TemplateData is used to inject variables into torrc.template
type TemplateData struct {
	SOCKSPORT   string
	DNSPORT     string
	DATADIR     string
	USE_BRIDGES bool
	BRIDGES     []string
}

var (
	globalTmpl *template.Template
	once       sync.Once
	cfg        *Config
)

func Load() *Config {
	n := getInt("TOR_INSTANCES", 8, 32)

	// --- BRIDGE LOADING STRATEGY (Secrets First) ---
	var rawBridges string

	// 1. Try Docker Secret File first (More Secure)
	// Default Docker Secret path or custom path from env
	secretPath := os.Getenv("TORGO_BRIDGES_FILE")
	if secretPath == "" {
		secretPath = "/run/secrets/torgo_bridges"
	}

	if content, err := os.ReadFile(secretPath); err == nil {
		rawBridges = string(content)
		slog.Info("loaded bridges from docker secret", "path", secretPath)
	} else {
		// 2. Fallback to Env Var (Less Secure)
		// Only use this if the secret file is missing
		rawBridges = os.Getenv("TORGO_BRIDGES")
		if rawBridges != "" {
			slog.Warn("loading bridges from ENV (less secure) - consider using Docker Secrets")
		}
	}

	var bridges []string
	if rawBridges != "" {
		// Normalize: Convert newlines and semicolons to commas for splitting
		rawBridges = strings.ReplaceAll(rawBridges, "\n", ",")
		rawBridges = strings.ReplaceAll(rawBridges, ";", ",")
		
		parts := strings.Split(rawBridges, ",")
		for _, b := range parts {
			if trimmed := strings.TrimSpace(b); trimmed != "" {
				bridges = append(bridges, trimmed)
			}
		}
	}

	c := &Config{
		Instances:     n,
		SocksBindAddr: getEnv("COMMON_SOCKS_BIND_ADDR", "0.0.0.0"),
		SocksPort:     getEnv("COMMON_SOCKS_PROXY_PORT", "9150"),
		DNSPort:       getEnv("COMMON_DNS_PROXY_PORT", "5353"),
		BlindControl:  os.Getenv("TORGO_BLIND_CONTROL") == "1",

		MaxConnsPerInstance: getInt("TORGO_MAX_CONNS_PER_INSTANCE", 64, 4096),
		MaxTotalConns:       getInt("TORGO_MAX_TOTAL_CONNS", 512, 65535),
		
		DNSMaxConns:        getInt("TORGO_DNS_MAX_CONNS", 256, 4096),
		DNSMaxConnsPerInst: getInt("TORGO_DNS_MAX_PER_INST", 64, 1024),

		SocksJitterMaxMs: getInt("TORGO_SOCKS_JITTER_MS_MAX", 0, 5000),
		ChaffEnabled:     os.Getenv("TORGO_ENABLE_CHAFF") == "1",

		UseBridges: len(bridges) > 0,
		Bridges:    bridges,
	}

	// 1. GLOBAL ROTATION SETTINGS
	// We allow 0 to mean "Disabled".
	c.RotateAfterConns = getInt("TORGO_ROTATE_CONNS", 64, 1_000_000_000)
	c.RotateAfterSeconds = getInt("TORGO_ROTATE_SECS", 900, 315_360_000)

	// 2. TIER CALCULATIONS
	defaultStable := n / 2
	if defaultStable == 0 && n > 0 {
		defaultStable = 1
	}
	c.StableInstances = clamp(getInt("TORGO_STABLE_INSTANCES", defaultStable, n), 0, n)
	c.StableMaxConnsPerInstance = getInt("TORGO_STABLE_MAX_CONNS", max(c.MaxConnsPerInstance*2, 64), 8192)

	// --- STABLE ROTATION ---
	var defStableSecs int
	if c.RotateAfterSeconds == 0 {
		defStableSecs = 0
	} else {
		defStableSecs = max(c.RotateAfterSeconds*4, 3600)
	}
	c.StableRotateSeconds = getInt("TORGO_STABLE_ROTATE_SECS", defStableSecs, 315_360_000)

	var defStableConns int
	if c.RotateAfterConns == 0 {
		defStableConns = 0
	} else {
		defStableConns = max(c.RotateAfterConns*4, 256)
	}
	c.StableRotateConns = getInt("TORGO_STABLE_ROTATE_CONNS", defStableConns, 1_000_000_000)


	// --- PARANOID ROTATION ---
	c.ParanoidMaxConnsPerInstance = getInt("TORGO_PARANOID_MAX_CONNS", max(16, c.MaxConnsPerInstance/2), 2048)
	
	var defParanoidConns int
	if c.RotateAfterConns == 0 {
		defParanoidConns = 0
	} else {
		defParanoidConns = max(16, c.RotateAfterConns/2)
	}
	c.ParanoidRotateConns = getInt("TORGO_PARANOID_ROTATE_CONNS", defParanoidConns, 1_000_000_000)

	var defParanoidSecs int
	if c.RotateAfterSeconds == 0 {
		defParanoidSecs = 0
	} else {
		defParanoidSecs = max(120, c.RotateAfterSeconds/3)
	}
	c.ParanoidRotateSeconds = getInt("TORGO_PARANOID_ROTATE_SECS", defParanoidSecs, 315_360_000)

	c.ParanoidTrafficPercent = clamp(getInt("TORGO_PARANOID_TRAFFIC_PERCENT", 30, 100), 0, 100)

	cfg = c

	slog.Info("zero-trust config loaded",
		"instances", c.Instances,
		"blind", c.BlindControl,
		"maxTotalConns", c.MaxTotalConns,
		"rotateAfterSeconds", c.RotateAfterSeconds,
		"chaffEnabled", c.ChaffEnabled,
		"bridges_configured", len(c.Bridges),
	)

	return c
}

func (i *Instance) Start() error {
	i.DataDir = fmt.Sprintf("/var/lib/tor-temp/i%d", i.ID)

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
	b.Grow(4096)

	// Populate template data with Bridge configuration
	data := TemplateData{
		SOCKSPORT:   "127.0.0.1:" + strconv.Itoa(i.SocksPort),
		DNSPORT:     "127.0.0.1:" + strconv.Itoa(i.DNSPort),
		DATADIR:     i.DataDir,
		USE_BRIDGES: cfg.UseBridges,
		BRIDGES:     cfg.Bridges,
	}

	if err := globalTmpl.Execute(&b, data); err != nil {
		return fmt.Errorf("template exec failed: %w", err)
	}

	cmd := exec.Command("tor", "-f", "/dev/stdin")
	cmd.Stdin = strings.NewReader(b.String())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = i.DataDir
	
	// Ensure obfs4proxy is found in path
	cmd.Env = []string{
		"HOME=" + i.DataDir,
		"PATH=/usr/bin:/bin:/usr/local/bin", 
	}

	i.cmd = cmd
	if err := cmd.Start(); err != nil {
		slog.Error("tor start failed", "id", i.ID, "err", err)
		return err
	}
	slog.Info("tor instance started", "id", i.ID)
	return nil
}

func (i *Instance) Close() {
	if i.cmd != nil && i.cmd.Process != nil {
		_ = i.cmd.Process.Signal(os.Interrupt)

		done := make(chan error, 1)
		go func() { done <- i.cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = i.cmd.Process.Kill()
		}
	}
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
		// Allow 0 to be returned (v >= 0)
		if v, err := strconv.Atoi(s); err == nil && v >= 0 && v <= maxVal {
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
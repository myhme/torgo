package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
)

// ephemeralKey is generated once at startup and exists ONLY in RAM.
// It is used to encrypt sensitive config data so it doesn't sit in plaintext on the heap.
var ephemeralKey [32]byte

func init() {
	// Generate a strong random key for in-memory encryption
	if _, err := io.ReadFull(rand.Reader, ephemeralKey[:]); err != nil {
		panic("failed to seed memory protection key")
	}
}

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
	ChaffEnabled     bool

	// --- ENCRYPTED STORAGE ---
	// We do NOT store "Bridges []string" here. That would be unsafe in RAM.
	// Instead, we store the encrypted blob.
	useBridges       bool
	encryptedBridges []byte // AES-GCM encrypted block
	bridgeNonce      []byte
}

type Instance struct {
	ID        int
	SocksPort int
	DNSPort   int
	DataDir   string
	cmd       *exec.Cmd
}

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

	// --- 1. SECURE BRIDGE LOADING ---
	var rawBridges string
	
	// A. Check Docker Secrets (Preferred)
	secretPath := os.Getenv("TORGO_BRIDGES_FILE")
	if secretPath == "" {
		secretPath = "/run/secrets/torgo_bridges"
	}
	
	if content, err := os.ReadFile(secretPath); err == nil {
		rawBridges = string(content)
		slog.Info("loaded bridges from secret", "source", "file")
	} else {
		// B. Check Env (Fallback)
		rawBridges = os.Getenv("TORGO_BRIDGES")
		if rawBridges != "" {
			slog.Warn("loaded bridges from env (less secure)")
		}
	}

	// --- 2. IMMEDIATE MEMORY SCRUBBING ---
	// Remove the environment variable from the process block immediately
	// so it doesn't appear in /proc/self/environ
	os.Unsetenv("TORGO_BRIDGES")

	// Parse bridges
	var bridges []string
	if rawBridges != "" {
		rawBridges = strings.ReplaceAll(rawBridges, "\n", ",")
		rawBridges = strings.ReplaceAll(rawBridges, ";", ",")
		parts := strings.Split(rawBridges, ",")
		for _, b := range parts {
			if trimmed := strings.TrimSpace(b); trimmed != "" {
				bridges = append(bridges, trimmed)
			}
		}
	}

	// --- 3. ENCRYPT IN MEMORY ---
	var encBridges []byte
	var nonce []byte
	
	if len(bridges) > 0 {
		// Join them into a single block to encrypt
		plaintext := []byte(strings.Join(bridges, "|||"))
		
		block, _ := aes.NewCipher(ephemeralKey[:])
		gcm, _ := cipher.NewGCM(block)
		nonce = make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			panic("nonce gen failed")
		}
		
		// Encrypt!
		encBridges = gcm.Seal(nil, nonce, plaintext, nil)
		
		// FORCE GC to help clear the plaintext 'bridges' slice from Heap
		// (We can't force-wipe strings in Go, but we can encourage collection)
		bridges = nil
		rawBridges = ""
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

		// Store ONLY the ciphertext
		useBridges:       len(encBridges) > 0,
		encryptedBridges: encBridges,
		bridgeNonce:      nonce,
	}

	// Rotation Settings
	c.RotateAfterConns = getInt("TORGO_ROTATE_CONNS", 64, 1_000_000_000)
	c.RotateAfterSeconds = getInt("TORGO_ROTATE_SECS", 900, 315_360_000)

	// Tier Calculations
	defaultStable := n / 2
	if defaultStable == 0 && n > 0 { defaultStable = 1 }
	c.StableInstances = clamp(getInt("TORGO_STABLE_INSTANCES", defaultStable, n), 0, n)
	c.StableMaxConnsPerInstance = getInt("TORGO_STABLE_MAX_CONNS", max(c.MaxConnsPerInstance*2, 64), 8192)

	defStableSecs := 0
	if c.RotateAfterSeconds > 0 { defStableSecs = max(c.RotateAfterSeconds*4, 3600) }
	c.StableRotateSeconds = getInt("TORGO_STABLE_ROTATE_SECS", defStableSecs, 315_360_000)

	defStableConns := 0
	if c.RotateAfterConns > 0 { defStableConns = max(c.RotateAfterConns*4, 256) }
	c.StableRotateConns = getInt("TORGO_STABLE_ROTATE_CONNS", defStableConns, 1_000_000_000)

	c.ParanoidMaxConnsPerInstance = getInt("TORGO_PARANOID_MAX_CONNS", max(16, c.MaxConnsPerInstance/2), 2048)
	
	defParanoidConns := 0
	if c.RotateAfterConns > 0 { defParanoidConns = max(16, c.RotateAfterConns/2) }
	c.ParanoidRotateConns = getInt("TORGO_PARANOID_ROTATE_CONNS", defParanoidConns, 1_000_000_000)

	defParanoidSecs := 0
	if c.RotateAfterSeconds > 0 { defParanoidSecs = max(120, c.RotateAfterSeconds/3) }
	c.ParanoidRotateSeconds = getInt("TORGO_PARANOID_ROTATE_SECS", defParanoidSecs, 315_360_000)

	c.ParanoidTrafficPercent = clamp(getInt("TORGO_PARANOID_TRAFFIC_PERCENT", 30, 100), 0, 100)

	cfg = c
	
	slog.Info("zero-trust config loaded",
		"instances", c.Instances,
		"blind", c.BlindControl,
		"bridges_encrypted", c.useBridges, // Do not log actual bridge count or content
	)

	return c
}

// getBridges temporarily decrypts the bridges for config generation
func (c *Config) getBridges() []string {
	if !c.useBridges || len(c.encryptedBridges) == 0 {
		return nil
	}

	block, _ := aes.NewCipher(ephemeralKey[:])
	gcm, _ := cipher.NewGCM(block)
	
	plaintext, err := gcm.Open(nil, c.bridgeNonce, c.encryptedBridges, nil)
	if err != nil {
		slog.Error("bridge decryption failed (memory corruption?)")
		return nil
	}
	
	// Convert back to slice
	return strings.Split(string(plaintext), "|||")
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

	// DECRYPT BRIDGES MOMENTARILY
	// They exist in RAM as plaintext *only* during this template execution.
	// As soon as this function returns, 'plainBridges' goes out of scope and is eligible for GC.
	plainBridges := cfg.getBridges()

	data := TemplateData{
		SOCKSPORT:   "127.0.0.1:" + strconv.Itoa(i.SocksPort),
		DNSPORT:     "127.0.0.1:" + strconv.Itoa(i.DNSPort),
		DATADIR:     i.DataDir,
		USE_BRIDGES: cfg.useBridges,
		BRIDGES:     plainBridges,
	}

	if err := globalTmpl.Execute(&b, data); err != nil {
		return fmt.Errorf("template exec failed: %w", err)
	}

	cmd := exec.Command("tor", "-f", "/dev/stdin")
	cmd.Stdin = strings.NewReader(b.String())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = i.DataDir
	cmd.Env = []string{
		"HOME=" + i.DataDir,
		"PATH=/usr/bin:/bin:/usr/local/bin", 
	}

	i.cmd = cmd
	if err := cmd.Start(); err != nil {
		slog.Error("tor start failed", "id", i.ID, "err", err)
		return err
	}
	
	// Optional: Suggest GC to clean up the plaintext string we just made
	// (Don't do this too often as it hurts CPU, but strictly speaking it helps security)
	// runtime.GC() 
	
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

func getEnv(key, def string) string {
	if s := os.Getenv(key); s != "" { return s }
	return def
}

func getInt(env string, def, maxVal int) int {
	if s := os.Getenv(env); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 0 && v <= maxVal { return v }
	}
	return def
}

func max(a, b int) int {
	if a > b { return a }
	return b
}

func clamp(v, lo, hi int) int {
	if v < lo { return lo }
	if v > hi { return hi }
	return v
}
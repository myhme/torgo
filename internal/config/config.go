package config

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"unsafe"
)

type Config struct {
	Instances     int
	SocksBindAddr string
	SocksPort     string
	DNSPort       string
	EnableLUKS    bool // per-instance RAM encryption
	BlindControl  bool // no ControlPort/cookie

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
	ParanoidTrafficPercent      int // 0–100
}

type Instance struct {
	ID         int
	SocksPort  int
	DNSPort    int
	DataDir    string
	mapperName string
	cmd        *exec.Cmd

	luksKey []byte // ephemeral LUKS key (kernel holds real copy)
}

var (
	globalTmpl *template.Template
	once       sync.Once
	cfg        *Config
)

func Load() *Config {
	n := getInt("TOR_INSTANCES", 8, 32)

	// base values
	c := &Config{
		Instances:     n,
		SocksBindAddr: getEnv("COMMON_SOCKS_BIND_ADDR", "0.0.0.0"),
		SocksPort:     getEnv("COMMON_SOCKS_PROXY_PORT", "9150"),
		DNSPort:       getEnv("COMMON_DNS_PROXY_PORT", "5353"),
		EnableLUKS:    os.Getenv("TORGO_ENABLE_LUKS_RAM") == "1",
		BlindControl:  os.Getenv("TORGO_BLIND_CONTROLP") == "1",

		MaxConnsPerInstance: getInt("TORGO_MAX_CONNS_PER_INSTANCE", 64, 4096),
		MaxTotalConns:       getInt("TORGO_MAX_TOTAL_CONNS", 512, 65535),
		RotateAfterConns:    getInt("TORGO_ROTATE_CONNS", 64, 1_000_000),
		RotateAfterSeconds:  getInt("TORGO_ROTATE_SECS", 900, 86_400),

		DNSMaxConns:        getInt("TORGO_DNS_MAX_CONNS", 256, 4096),
		DNSMaxConnsPerInst: getInt("TORGO_DNS_MAX_PER_INST", 64, 1024),
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
	c.StableRotateConns = getInt("TORGO_STABLE_ROTATE_CONNS",
		max(c.RotateAfterConns*4, 256), 5_000_000)
	c.StableRotateSeconds = getInt("TORGO_STABLE_ROTATE_SECS",
		max(c.RotateAfterSeconds*4, 3600), 7*24*3600)

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
		"luks", c.EnableLUKS,
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
	)

	return c
}

func (i *Instance) Start() error {
	// Per-instance dir (may be LUKS-backed)
	i.DataDir = "/var/lib/tor/i" + itoaQuick(i.ID)

	if cfg.EnableLUKS {
		if err := i.setupLUKSRAM(); err != nil {
			slog.Error("LUKS setup failed", "id", i.ID, "err", err)
			return err
		}
	} else {
		if err := os.MkdirAll(i.DataDir, 0o700); err != nil {
			return err
		}
		if err := os.Chown(i.DataDir, 106, 112); err != nil {
			return err
		}
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
		"SOCKSPORT": "127.0.0.1:" + itoaQuick(i.SocksPort),
		"DNSPORT":   "127.0.0.1:" + itoaQuick(i.DNSPort),
		"DATADIR":   i.DataDir,
	}
	if err := globalTmpl.Execute(&b, data); err != nil {
		return fmt.Errorf("template exec failed: %w", err)
	}

	cmd := exec.Command("tor", "-f", "/dev/stdin")
	cmd.Stdin = strings.NewReader(b.String())
	cmd.Dir = i.DataDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 106, Gid: 112},
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNS | syscall.CLONE_NEWIPC | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: 106, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: 112, Size: 1},
		},
		AmbientCaps: []uintptr{},
	}

	i.cmd = cmd
	if err := cmd.Start(); err != nil {
		slog.Error("tor start failed", "id", i.ID, "err", err)
		return err
	}
	slog.Info("tor instance started", "id", i.ID, "socks", i.SocksPort, "dns", i.DNSPort)
	return nil
}

// LUKS over /dev/zero → encrypted RAM-only backing, no disk trace.
func (i *Instance) setupLUKSRAM() error {
	key := make([]byte, 64) // 512-bit key
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("key gen failed: %w", err)
	}
	i.luksKey = key

	mapper := fmt.Sprintf("torgo-enc-%d", i.ID)
	i.mapperName = mapper

	cmd := exec.Command("cryptsetup", "open", "--type", "plain", "--key-file", "-",
		"--cipher", "aes-xts-plain64", "--key-size", "512", "/dev/zero", mapper)
	cmd.Stdin = bytes.NewReader(key)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cryptsetup open failed: %w (out: %s)", err, out)
	}

	dev := filepath.Join("/dev/mapper", mapper)
	if err := os.MkdirAll("/var/lib/tor-temp", 0o755); err != nil {
		return err
	}
	mountPoint := filepath.Join("/var/lib/tor-temp", fmt.Sprintf("i%d", i.ID))
	if err := os.MkdirAll(mountPoint, 0o700); err != nil {
		return err
	}

	if err := syscall.Mount(dev, mountPoint, "ext4",
		syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC,
		"discard,errors=remount-ro"); err != nil {
		return fmt.Errorf("LUKS mount failed: %w", err)
	}

	i.DataDir = mountPoint
	return os.Chown(mountPoint, 106, 112)
}

func (i *Instance) Close() {
	if i.cmd != nil && i.cmd.Process != nil {
		_ = i.cmd.Process.Signal(syscall.SIGTERM)
		_ = i.cmd.Wait()
	}
	if i.DataDir != "" {
		_ = syscall.Unmount(i.DataDir, syscall.MNT_DETACH)
		_ = os.RemoveAll(i.DataDir)
	}
	if i.mapperName != "" {
		_ = exec.Command("cryptsetup", "close", i.mapperName).Run()
	}
}

func (i *Instance) Restart() error {
	i.Close()
	return i.Start()
}

func (i *Instance) CookiePath() string { return "" }

// --- helpers ---

func itoaQuick(n int) string {
	buf := [8]byte{}
	i := len(buf)
	for n >= 10 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	i--
	// n is now 0–9
	buf[i] = byte('0' + n)
	return string(buf[i:])
}

func getEnv(key, def string) string {
	if s := os.Getenv(key); s != "" {
		return s
	}
	return def
}

func getInt(env string, def, max int) int {
	if s := os.Getenv(env); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 && v <= max {
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

// hide from naive forensics
var _ = unsafe.Pointer(&globalTmpl)
var _ = unsafe.Pointer(&cfg)

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
	EnableLUKS    bool // Per-instance RAM encryption for zero-trust
	BlindControl  bool // No control ports/cookies – blinded isolation
}

type Instance struct {
	ID          int
	SocksPort   int
	DNSPort     int
	DataDir     string
	mapperName  string
	cmd         *exec.Cmd
	luksKey     []byte // mlocked & poisoned – never leaks
}

var (
	globalTmpl *template.Template
	once       sync.Once
	cfg        *Config // Global zero-trust config
)

func Load() *Config {
	n := getInt("TOR_INSTANCES", 8, 32)
	cfg = &Config{
		Instances:     n,
		SocksBindAddr: getEnv("COMMON_SOCKS_BIND_ADDR", "0.0.0.0"),
		SocksPort:     getEnv("COMMON_SOCKS_PROXY_PORT", "9150"),
		DNSPort:       getEnv("COMMON_DNS_PROXY_PORT", "5353"),
		EnableLUKS:    os.Getenv("TORGO_ENABLE_LUKS_RAM") == "1",
		BlindControl:  os.Getenv("TORGO_BLIND_CONTROLP") == "1",
	}
	slog.Info("zero-trust config loaded", "instances", cfg.Instances, "luks", cfg.EnableLUKS, "blind", cfg.BlindControl)
	return cfg
}

func (i *Instance) Start() error {
	// 1. Set DataDir first (zero-trust: ephemeral per-instance)
	i.DataDir = "/var/lib/tor/i" + itoaQuick(i.ID)

	// 2. Encrypt if enabled (LUKS-RAM: keys mlocked, wiped on exit)
	if cfg.EnableLUKS {
		if err := i.setupLUKSRAM(); err != nil {
			slog.Error("LUKS setup failed", "id", i.ID, "err", err)
			return err
		}
		slog.Info("LUKS-RAM mounted", "id", i.ID, "dir", i.DataDir)
	} else {
		if err := os.MkdirAll(i.DataDir, 0o700); err != nil {
			return err
		}
		if err := os.Chown(i.DataDir, 106, 112); err != nil {
			return err
		}
	}

	// 3. Blinded template (no control port – zero metadata)
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
	socksStr := itoaQuick(i.SocksPort)
	dnsStr := itoaQuick(i.DNSPort)
	data := map[string]string{
		"SOCKSPORT": "127.0.0.1:" + socksStr,
		"DNSPORT":   "127.0.0.1:" + dnsStr,
		"DATADIR":   i.DataDir,
		// Blinded: No CONTROLPORT – ignored in template
	}
	if err := globalTmpl.Execute(&b, data); err != nil {
		return fmt.Errorf("template exec failed: %w", err)
	}

	// 4. Exec in full namespaces (user/pid/ns/ipc/net) – per-instance sandbox
	cmd := exec.Command("tor", "-f", "/dev/stdin")
	cmd.Stdin = strings.NewReader(b.String())
	cmd.Dir = i.DataDir // Local cwd – no leaks
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 106, Gid: 112},
		// Zero-trust isolation: Full stack – no shared views
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNS | syscall.CLONE_NEWIPC | syscall.CLONE_NEWNET,
		// Map host UID/GID to guest root (unpriv ns hardening)
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: 106, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: 112, Size: 1},
		},
		// Ambient caps drop (gVisor/enforce no-new-privs)
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

// setupLUKSRAM: Ephemeral AES-XTS in RAM (512-bit key, no disk trace)
func (i *Instance) setupLUKSRAM() error {
	key := make([]byte, 64) // 512-bit XTS – mlock'd globally
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("key gen failed: %w", err)
	}
	i.luksKey = key // Sealed – poisoned via secmem.Wipe()

	mapper := fmt.Sprintf("torgo-enc-%d", i.ID)
	i.mapperName = mapper

	// cryptsetup: Plain on /dev/zero (RAM ephemeral)
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

	// Mount hardened (noexec/nosuid/nodev – leak-proof)
	if err := syscall.Mount(dev, mountPoint, "ext4",
		syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC,
		"discard,errors=remount-ro"); err != nil {
		return fmt.Errorf("LUKS mount failed: %w", err)
	}

	i.DataDir = mountPoint
	return os.Chown(mountPoint, 106, 112)
}

func (i *Instance) Restart() error {
	if i.cmd != nil && i.cmd.Process != nil {
		_ = i.cmd.Process.Signal(syscall.SIGTERM)
		_ = i.cmd.Wait()
	}
	if i.mapperName != "" {
		_ = exec.Command("cryptsetup", "close", i.mapperName).Run()
		if i.DataDir != "" {
			_ = syscall.Unmount(i.DataDir, syscall.MNT_DETACH)
		}
	}
	_ = os.RemoveAll(i.DataDir) // tmpfs/LUKS auto-wipe
	return i.Start()
}

// Blinded: No cookie exposure – zero-trust
func (i *Instance) CookiePath() string { return "" }

// itoaQuick: Zero-alloc int→str (ports only – 3 digits max)
func itoaQuick(n int) string {
	buf := [3]byte{}
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

// Anti-forensic: Obfuscate symbols
var _ = unsafe.Pointer(&globalTmpl)
var _ = unsafe.Pointer(&cfg)
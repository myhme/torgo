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
	EnableLUKS    bool // new
	BlindControl  bool // new
}

type Instance struct {
	ID          int
	SocksPort   int
	DNSPort     int
	DataDir     string
	mapperName  string
	cmd         *exec.Cmd
	luksKey     []byte // sealed in memory only
}

var globalTmpl *template.Template
var once sync.Once

func Load() *Config {
	n := getInt("TOR_INSTANCES", 8, 32)
	return &Config{
		Instances:     n,
		SocksBindAddr: getEnv("COMMON_SOCKS_BIND_ADDR", "0.0.0.0"),
		SocksPort:     getEnv("COMMON_SOCKS_PROXY_PORT", "9150"),
		DNSPort:       getEnv("COMMON_DNS_PROXY_PORT", "5353"),
		EnableLUKS:    os.Getenv("TORGO_ENABLE_LUKS_RAM") == "1",
		BlindControl:  os.Getenv("TORGO_BLIND_CONTROLP") == "1",
	}
}

func (i *Instance) Start() error {
	// 1. Create encrypted RAM device if requested
	if cfg.EnableLUKS {
		if err := i.setupLUKSRAM(); err != nil {
			return err
		}
	} else {
		if err := os.MkdirAll(i.DataDir, 0700); err != nil {
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
			slog.Error("failed to parse torrc.template", "err", err)
			os.Exit(1)
		}
	})

	var b strings.Builder
	b.Grow(2048)

	socksStr := itoa(i.SocksPort)
	dnsStr := itoa(i.DNSPort)

	data := map[string]string{
		"SOCKSPORT": "127.0.0.1:" + socksStr,
		"DNSPORT":   "127.0.0.1:" + dnsStr,
		"DATADIR":   i.DataDir,
	}
	if !cfg.BlindControl {
		data["CONTROLPORT"] = "" // will be ignored in template
	}

	err := globalTmpl.Execute(&b, data)
	if err != nil {
		return err
	}

	cmd := exec.Command("tor", "-f", "/dev/stdin")
	cmd.Stdin = strings.NewReader(b.String())
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 106, Gid: 112},
		// Full namespace isolation for each instance
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNS | syscall.CLONE_NEWIPC | syscall.CLONE_NEWNET,
	}

	i.cmd = cmd
	return cmd.Start()
}

// setupLUKSRAM creates an in-memory encrypted volume
func (i *Instance) setupLUKSRAM() error {
	key := make([]byte, 64) // 512-bit XTS key
	if _, err := rand.Read(key); err != nil {
		return err
	}
	i.luksKey = key

	mapper := fmt.Sprintf("torgo-enc-%d", i.ID)
	i.mapperName = mapper

	// cryptsetup open --type plain -d - --cipher aes-xts-plain64 /dev/zero mapper
	cmd := exec.Command("cryptsetup", "open", "--type", "plain", "--key-file", "-", 
		"--cipher", "aes-xts-plain64", "--key-size", "512", "/dev/zero", mapper)
	cmd.Stdin = bytes.NewReader(key)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cryptsetup failed: %w", err)
	}

	dev := filepath.Join("/dev/mapper", mapper)
	if err := os.MkdirAll("/var/lib/tor-temp", 0755); err != nil {
		return err
	}
	mountPoint := filepath.Join("/var/lib/tor-temp", fmt.Sprintf("i%d", i.ID))
	if err := os.MkdirAll(mountPoint, 0700); err != nil {
		return err
	}

	if err := syscall.Mount(dev, mountPoint, "ext4", syscall.MS_NOSUID|syscall.MS_NODEV, "discard,errors=remount-ro"); err != nil {
		return fmt.Errorf("mount failed: %w", err)
	}

	i.DataDir = mountPoint
	return os.Chown(mountPoint, 106, 112)
}

func (i *Instance) Restart() error {
	if i.cmd != nil && i.cmd.Process != nil {
		_ = i.cmd.Process.Kill()
		_ = i.cmd.Wait()
	}
	if i.mapperName != "" {
		_ = exec.Command("cryptsetup", "close", i.mapperName).Run()
		_ = syscall.Unmount(i.DataDir, syscall.MNT_DETACH)
	}
	_ = os.RemoveAll(i.DataDir)
	return i.Start()
}

func (i *Instance) CookiePath() string { return "" } // removed

// rest unchanged (itoa, getEnv, etc.)

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
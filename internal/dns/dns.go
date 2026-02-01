package dns

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"sync/atomic"
	"time"

	"torgo/internal/config"
)

// Hard limits — now tunable via config/env
var (
	dnsMaxConns       uint32 = 256
	dnsMaxPerInstance uint32 = 64
	dnsConnTimeout           = 30 * time.Second
)

// Atomic counters (lock-free)
var (
	totalDNSConns   uint32
	perInstDNSConns [32]uint32 // up to 32 instances
)

func Start(ctx context.Context, insts []*config.Instance, cfg *config.Config) {
	// Pull DNS tunables from config
	if cfg.DNSMaxConns > 0 {
		dnsMaxConns = uint32(cfg.DNSMaxConns)
	}
	if cfg.DNSMaxConnsPerInst > 0 {
		dnsMaxPerInstance = uint32(cfg.DNSMaxConnsPerInst)
	}

	addr := net.JoinHostPort("0.0.0.0", cfg.DNSPort)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("dns bind failed", "err", err)
		return
	}
	defer l.Close()
	slog.Info("DNS-over-TCP proxy active",
		"addr", l.Addr(),
		"maxDNSConns", dnsMaxConns,
		"maxPerInstance", dnsMaxPerInstance,
	)

	for {
		c, err := l.Accept()
		if err != nil {
			return
		}

		// Global limit check
		if atomic.LoadUint32(&totalDNSConns) >= dnsMaxConns {
			_ = c.Close()
			continue
		}
		atomic.AddUint32(&totalDNSConns, 1)

		go handleDNS(c, insts)
	}
}

func handleDNS(client net.Conn, insts []*config.Instance) {
	// 1. PANIC RECOVERY
	// Prevent dns crashes from affecting the main process
	defer func() {
		if r := recover(); r != nil {
			slog.Error("dns panic recovered", "err", r)
		}
	}()

	defer client.Close()
	defer atomic.AddUint32(&totalDNSConns, ^uint32(0))

	// Security: Set deadline immediately
	_ = client.SetDeadline(time.Now().Add(dnsConnTimeout))

	instCount := len(insts)
	if instCount == 0 {
		return
	}
	if instCount > 32 {
		instCount = 32
	}

	// Pick a random start index for load balancing
	randIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(instCount)))
	start := int(randIdx.Int64())

	var chosen *config.Instance
	chosenIdx := -1
	var bestLoad uint32 = ^uint32(0)

	// Simple least-loaded walk
	for off := 0; off < instCount; off++ {
		idx := (start + off) % instCount

		load := atomic.LoadUint32(&perInstDNSConns[idx])
		if load >= dnsMaxPerInstance {
			continue
		}
		if load < bestLoad {
			bestLoad = load
			chosenIdx = idx
		}
	}

	if chosenIdx < 0 {
		return // all instances busy
	}

	if atomic.AddUint32(&perInstDNSConns[chosenIdx], 1) > dnsMaxPerInstance {
		atomic.AddUint32(&perInstDNSConns[chosenIdx], ^uint32(0))
		return
	}
	defer atomic.AddUint32(&perInstDNSConns[chosenIdx], ^uint32(0))

	chosen = insts[chosenIdx]

	// FIX: Use fmt.Sprintf
	addr := fmt.Sprintf("127.0.0.1:%d", chosen.DNSPort)

	torDNS, err := net.Dial("tcp", addr)
	if err != nil {
		return
	}
	defer torDNS.Close()
	_ = torDNS.SetDeadline(time.Now().Add(dnsConnTimeout))

	// DNS messages are tiny → use small fixed buffer + bounded copy
	go boundedCopy(torDNS, client)
	boundedCopy(client, torDNS)
}

func boundedCopy(dst net.Conn, src net.Conn) {
	// 2. SECURE MEMORY (Smaller 4KB buffer for DNS)
	buf := make([]byte, 4096)

	// 3. IMMEDIATE WIPE (Anti-Forensics)
	defer func() {
		for i := range buf {
			buf[i] = 0
		}
	}()

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if ew != nil || nw < nr {
				break
			}
		}
		if er != nil {
			break
		}
	}
}
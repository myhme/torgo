package dns

import (
	"context"
	"crypto/rand"
	"io"
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
		if atomic.LoadUint32(&totalDNSConns) >= dnsMaxConns {
			_ = c.Close()
			continue
		}
		atomic.AddUint32(&totalDNSConns, 1)
		go handleDNS(c, insts)
	}
}

func handleDNS(client net.Conn, insts []*config.Instance) {
	defer client.Close()
	defer atomic.AddUint32(&totalDNSConns, ^uint32(0))

	client.SetDeadline(time.Now().Add(dnsConnTimeout))

	instCount := len(insts)
	if instCount == 0 {
		return
	}
	instLen := big.NewInt(int64(instCount))

	// Smart LB: random start + least-connections
	randIdx, _ := rand.Int(rand.Reader, instLen)
	start := int(randIdx.Int64())

	var chosen *config.Instance
	chosenIdx := -1
	bestLoad := ^uint32(0)

	for offset := 0; offset < instCount; offset++ {
		idx := (start + offset) % instCount
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

	// Zero-allocation target address (no "127.0.0.1:XXXX" on heap)
	target := [16]byte{}
	copy(target[:10], "127.0.0.1:")
	itoa(target[10:], uint16(chosen.DNSPort))

	torDNS, err := net.Dial("tcp", string(target[:]))
	if err != nil {
		return
	}
	defer torDNS.Close()
	torDNS.SetDeadline(time.Now().Add(dnsConnTimeout))

	// DNS messages are tiny → use small fixed buffer + bounded copy
	go boundedCopy(torDNS, client, 4096)
	boundedCopy(client, torDNS, 4096)
}

// Reuse the exact same fast itoa from config.go (zero allocation)
func itoa(buf []byte, n uint16) {
	if n == 0 {
		buf[0] = '0'
		return
	}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = '0' + byte(n%10)
		n /= 10
	}
	copy(buf, buf[i:])
}

// boundedCopy with small buffer — perfect for DNS (max message 4096 bytes)
func boundedCopy(dst net.Conn, src net.Conn, bufSize int) {
	buf := make([]byte, bufSize)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if ew != nil || nw < nr {
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				break
			}
			break
		}
	}
}

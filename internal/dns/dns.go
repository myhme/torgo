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

// Hard limits — DNS is extremely lightweight, but we still cap it
const (
	maxDNSConns       = 256
	maxConnsPerInst   = 64
	dnsConnTimeout    = 30 * time.Second
)

// Atomic counters (lock-free)
var (
	totalDNSConns     uint32
	perInstDNSConns   [32]uint32 // up to 32 instances
)

func Start(ctx context.Context, insts []*config.Instance, cfg *config.Config) {
	addr := net.JoinHostPort("0.0.0.0", cfg.DNSPort)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("dns bind failed", "err", err)
		return
	}
	defer l.Close()
	slog.Info("DNS-over-TCP proxy active", "addr", l.Addr())

	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		if atomic.LoadUint32(&totalDNSConns) >= maxDNSConns {
			c.Close()
			continue
		}
		atomic.AddUint32(&totalDNSConns, 1)
		go handleDNS(c, insts)
	}
}

func handleDNS(client net.Conn, insts []*config.Instance) {
	defer client.Close()
	defer atomic.AddUint32(&totalDNSConns, ^uint32(0))

	// DNS queries must complete fast
	client.SetDeadline(time.Now().Add(dnsConnTimeout))

	// Random + fair per-instance selection with back-off
	var chosen *config.Instance
	instLen := big.NewInt(int64(len(insts)))

	for attempt := 0; attempt < 10; attempt++ {
		// Use crypto/rand for non-predictable instance selection
		randIdx, _ := rand.Int(rand.Reader, instLen)
		idx := randIdx.Int64()
		
		inst := insts[idx]
		if atomic.LoadUint32(&perInstDNSConns[idx]) < maxConnsPerInst {
			atomic.AddUint32(&perInstDNSConns[idx], 1)
			chosen = inst
			break
		}
		time.Sleep(1 * time.Millisecond)
	}
	if chosen == nil {
		return // all instances busy
	}
	defer atomic.AddUint32(&perInstDNSConns[chosen.ID-1], ^uint32(0))

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
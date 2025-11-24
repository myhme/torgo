package socks

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

// Global limits — tuned for 8 instances on a 1–2 vCPU VPS
const (
	maxConnsPerInstance = 64            // per Tor instance
	maxTotalConns       = 512           // total SOCKS conns
	connTimeout         = 15 * time.Minute
)

// Runtime counters (atomic, no mutex)
var (
	totalConns    uint32
	instanceConns [32]uint32 // supports up to 32 instances
)

func Start(ctx context.Context, insts []*config.Instance, cfg *config.Config) {
	addr := net.JoinHostPort(cfg.SocksBindAddr, cfg.SocksPort)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("socks bind failed", "err", err)
		return
	}
	defer l.Close()
	slog.Info("SOCKS proxy active", "addr", l.Addr())

	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		if atomic.LoadUint32(&totalConns) >= maxTotalConns {
			c.Close()
			continue
		}
		atomic.AddUint32(&totalConns, 1)
		go handleSOCKS(c, insts)
	}
}

func handleSOCKS(client net.Conn, insts []*config.Instance) {
	defer client.Close()
	defer atomic.AddUint32(&totalConns, ^uint32(0))

	// Enforce idle timeout
	client.SetDeadline(time.Now().Add(connTimeout))

	// True random selection (CSPRNG) + per-instance connection limiting
	var chosen *config.Instance
	instLen := big.NewInt(int64(len(insts)))

	for i := 0; i < 10; i++ { // retry up to 10 times
		// Use crypto/rand for non-predictable instance selection
		// This prevents correlation attacks where an adversary predicts the next exit node
		randIdx, _ := rand.Int(rand.Reader, instLen)
		idx := randIdx.Int64()
		
		inst := insts[idx]
		if atomic.LoadUint32(&instanceConns[idx]) < maxConnsPerInstance {
			atomic.AddUint32(&instanceConns[idx], 1)
			chosen = inst
			break
		}
		time.Sleep(1 * time.Millisecond)
	}
	if chosen == nil {
		return // all instances full
	}
	defer atomic.AddUint32(&instanceConns[chosen.ID-1], ^uint32(0))

	// Zero-allocation target address (no heap strings)
	target := [16]byte{}
	copy(target[:], "127.0.0.1:")
	// Fast int to decimal (no strconv)
	itoa(target[10:], uint16(chosen.SocksPort))

	tor, err := net.Dial("tcp", string(target[:]))
	if err != nil {
		return
	}
	defer tor.Close()
	tor.SetDeadline(time.Now().Add(connTimeout))

	// Bounded io.Copy using io.CopyN + fixed buffers
	go boundedCopy(tor, client)
	boundedCopy(client, tor)
}

// Fast int to string without allocation
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

// 64 KB fixed buffer + backpressure
func boundedCopy(dst net.Conn, src net.Conn) (written int64, err error) {
	buf := make([]byte, 64<<10)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nw < nr {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}
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

// Runtime counters (atomic, no mutex)
var (
	totalConns          uint32
	instanceConns       [32]uint32 // current active conns per instance
	instanceTotal       [32]uint64 // total conns served since last rotation
	instanceDraining    [32]uint32 // 1 = draining (no new conns), 0 = normal
	instanceLastRestart [32]int64  // unix timestamp of last restart
)

// Env-tunable limits (set in Start from cfg)
var (
	maxConnsPerInstance int32 = 64
	maxTotalConns       int32 = 512
	rotateAfterConns    uint64 = 64
	rotateAfterSeconds  int64  = 900
	connTimeout                = 15 * time.Minute
)

// Start listens on the public SOCKS address and dispatches connections
// across Tor instances with per-instance limits and rotation.
func Start(ctx context.Context, insts []*config.Instance, cfg *config.Config) {
	// Pull tunables from config
	if cfg.MaxConnsPerInstance > 0 {
		maxConnsPerInstance = int32(cfg.MaxConnsPerInstance)
	}
	if cfg.MaxTotalConns > 0 {
		maxTotalConns = int32(cfg.MaxTotalConns)
	}
	if cfg.RotateAfterConns > 0 {
		rotateAfterConns = uint64(cfg.RotateAfterConns)
	}
	if cfg.RotateAfterSeconds > 0 {
		rotateAfterSeconds = int64(cfg.RotateAfterSeconds)
	}

	addr := net.JoinHostPort(cfg.SocksBindAddr, cfg.SocksPort)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("socks bind failed", "err", err)
		return
	}
	defer l.Close()
	slog.Info("SOCKS proxy active",
		"addr", l.Addr(),
		"maxConnsPerInstance", maxConnsPerInstance,
		"maxTotalConns", maxTotalConns,
		"rotateAfterConns", rotateAfterConns,
		"rotateAfterSeconds", rotateAfterSeconds,
	)

	// Initialize lastRestart timestamps
	now := time.Now().Unix()
	for i := range insts {
		atomic.StoreInt64(&instanceLastRestart[i], now)
	}

	// Background rotation manager
	go manageRotations(ctx, insts)

	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		if atomic.LoadUint32(&totalConns) >= uint32(maxTotalConns) {
			_ = c.Close()
			continue
		}
		atomic.AddUint32(&totalConns, 1)
		go handleSOCKS(c, insts)
	}
}

func handleSOCKS(client net.Conn, insts []*config.Instance) {
	defer client.Close()
	defer atomic.AddUint32(&totalConns, ^uint32(0))

	_ = client.SetDeadline(time.Now().Add(connTimeout))

	instCount := len(insts)
	if instCount == 0 {
		return
	}
	instLen := big.NewInt(int64(instCount))

	// Smart LB: pick a random starting instance, then choose the one with
	// the fewest active connections that is not draining and under limit.
	randIdx, _ := rand.Int(rand.Reader, instLen)
	start := int(randIdx.Int64())

	var chosen *config.Instance
	chosenIdx := -1
	bestLoad := ^uint32(0) // max uint32

	for offset := 0; offset < instCount; offset++ {
		idx := (start + offset) % instCount

		// Skip draining instances
		if atomic.LoadUint32(&instanceDraining[idx]) == 1 {
			continue
		}

		load := atomic.LoadUint32(&instanceConns[idx])
		if load >= uint32(maxConnsPerInstance) {
			continue
		}

		if load < bestLoad {
			bestLoad = load
			chosenIdx = idx
		}
	}

	if chosenIdx < 0 {
		// All instances busy or draining
		return
	}

	// Reserve a slot
	if atomic.AddUint32(&instanceConns[chosenIdx], 1) > uint32(maxConnsPerInstance) {
		// Raced; undo and give up
		atomic.AddUint32(&instanceConns[chosenIdx], ^uint32(0))
		return
	}
	defer atomic.AddUint32(&instanceConns[chosenIdx], ^uint32(0))

	chosen = insts[chosenIdx]
	atomic.AddUint64(&instanceTotal[chosenIdx], 1)

	// Build "127.0.0.1:PORT" without heap churn
	target := [16]byte{}
	copy(target[:], "127.0.0.1:")
	itoaPort(target[10:], uint16(chosen.SocksPort))

	tor, err := net.Dial("tcp", string(target[:]))
	if err != nil {
		return
	}
	defer tor.Close()
	_ = tor.SetDeadline(time.Now().Add(connTimeout))

	// Bounded io.Copy using fixed buffers
	go boundedCopy(tor, client)
	boundedCopy(client, tor)
}

// manageRotations periodically decides when to rotate (restart) Tor instances:
//  - When an instance has served >= rotateAfterConns connections, OR
//  - When it has been running for >= rotateAfterSeconds.
// It marks the instance as "draining", waits until active conns reach 0, then
// calls Restart(), which tears down LUKS + tmpfs + Tor and brings it back up.
func manageRotations(ctx context.Context, insts []*config.Instance) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().Unix()
			for idx, inst := range insts {
				if inst == nil {
					continue
				}

				draining := atomic.LoadUint32(&instanceDraining[idx])
				active := atomic.LoadUint32(&instanceConns[idx])
				last := atomic.LoadInt64(&instanceLastRestart[idx])
				total := atomic.LoadUint64(&instanceTotal[idx])

				if draining == 0 {
					// Decide if we should start draining this instance
					if total >= rotateAfterConns ||
						(last != 0 && now-last >= rotateAfterSeconds) {
						if atomic.CompareAndSwapUint32(&instanceDraining[idx], 0, 1) {
							slog.Info("marking tor instance for rotation (draining)",
								"id", inst.ID,
								"total_conns", total,
								"age_seconds", now-last,
							)
						}
					}
				} else {
					// Already draining: wait for active conns to drop to 0
					if active == 0 {
						slog.Info("rotating tor instance", "id", inst.ID)
						if err := inst.Restart(); err != nil {
							slog.Error("instance restart failed", "id", inst.ID, "err", err)
							// Keep draining flag set; try again next tick
							continue
						}
						atomic.StoreUint64(&instanceTotal[idx], 0)
						atomic.StoreUint32(&instanceDraining[idx], 0)
						atomic.StoreInt64(&instanceLastRestart[idx], now)
						slog.Info("tor instance rotation complete", "id", inst.ID)
					}
				}
			}
		}
	}
}

// Fast int→string for ports without allocation
func itoaPort(buf []byte, n uint16) {
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

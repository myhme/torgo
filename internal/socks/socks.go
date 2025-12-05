package socks

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"math/big"
	"math"
	"net"
	"sync/atomic"
	"time"

	"torgo/internal/config"
)

// per-instance state (supports up to 32 instances)
var (
	totalConns          uint32
	instanceConns       [32]uint32 // active conns
	instanceTotal       [32]uint64 // total conns since last restart
	instanceDraining    [32]uint32 // 1 = draining, 0 = normal
	instanceLastRestart [32]int64  // unix ts

	// per-instance tuning (tier aware)
	instMaxConns    [32]int32
	instRotateConns [32]uint64
	instRotateSecs  [32]int64
	instTier        [32]uint8 // 0 = stable, 1 = paranoid
)

var (
	maxTotalConns int32 = 512
	connTimeout         = 15 * time.Minute
)

// Start binds SOCKS and dispatches connections across a two-tier pool.
func Start(ctx context.Context, insts []*config.Instance, cfg *config.Config) {
	instCount := len(insts)
	if instCount == 0 {
		slog.Error("no instances configured")
		return
	}
	if instCount > 32 {
		instCount = 32
	}

	// Pull globals
	if cfg.MaxTotalConns > 0 {
		maxTotalConns = int32(cfg.MaxTotalConns)
	}

	// Tier layout: first StableInstances are "stable", rest "paranoid"
	stableCount := cfg.StableInstances
	if stableCount > instCount {
		stableCount = instCount
	}
	if stableCount < 0 {
		stableCount = 0
	}

	now := time.Now().Unix()
	for idx := 0; idx < instCount; idx++ {
		isParanoid := idx >= stableCount

		if isParanoid {
			instTier[idx] = 1
			instMaxConns[idx] = int32(cfg.ParanoidMaxConnsPerInstance)
			instRotateConns[idx] = uint64(cfg.ParanoidRotateConns)
			instRotateSecs[idx] = int64(cfg.ParanoidRotateSeconds)
		} else {
			instTier[idx] = 0
			stableMax := cfg.StableMaxConnsPerInstance
			if stableMax > math.MaxInt32 {
				stableMax = math.MaxInt32
			}
			instMaxConns[idx] = int32(stableMax)
			instRotateConns[idx] = uint64(cfg.StableRotateConns)
			instRotateSecs[idx] = int64(cfg.StableRotateSeconds) // ≤ 1 hour, enforced in config
		}
		atomic.StoreInt64(&instanceLastRestart[idx], now)
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
		"maxTotalConns", maxTotalConns,
		"stableCount", stableCount,
		"paranoidCount", instCount-stableCount,
		"paranoidTrafficPercent", cfg.ParanoidTrafficPercent,
		"socksJitterMaxMs", cfg.SocksJitterMaxMs,
	)

	// background rotation manager
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
		go handleSOCKS(c, insts, cfg)
	}
}

func handleSOCKS(client net.Conn, insts []*config.Instance, cfg *config.Config) {
	defer client.Close()
	defer atomic.AddUint32(&totalConns, ^uint32(0))

	// Optional: timing jitter per connection (0..N ms)
	if cfg.SocksJitterMaxMs > 0 {
		jMax := cfg.SocksJitterMaxMs
		if jMax > 5000 {
			jMax = 5000 // sanity cap at 5s
		}
		rnd, _ := rand.Int(rand.Reader, big.NewInt(int64(jMax+1)))
		if j := rnd.Int64(); j > 0 {
			time.Sleep(time.Duration(j) * time.Millisecond)
		}
	}

	_ = client.SetDeadline(time.Now().Add(connTimeout))

	instCount := len(insts)
	if instCount == 0 {
		return
	}
	if instCount > 32 {
		instCount = 32
	}

	// Decide which tier to try first for this connection
	useParanoid := false
	if cfg.ParanoidTrafficPercent > 0 {
		rnd, _ := rand.Int(rand.Reader, big.NewInt(100))
		if rnd.Int64() < int64(cfg.ParanoidTrafficPercent) {
			useParanoid = true
		}
	}

	chosenIdx := pickInstance(instCount, useParanoid)
	if chosenIdx < 0 {
		// fallback: try other tier
		chosenIdx = pickInstance(instCount, !useParanoid)
	}
	if chosenIdx < 0 {
		// all busy / draining
		return
	}

	// reserve slot
	if atomic.AddUint32(&instanceConns[chosenIdx], 1) > uint32(instMaxConns[chosenIdx]) {
		atomic.AddUint32(&instanceConns[chosenIdx], ^uint32(0))
		return
	}
	defer atomic.AddUint32(&instanceConns[chosenIdx], ^uint32(0))

	inst := insts[chosenIdx]
	atomic.AddUint64(&instanceTotal[chosenIdx], 1)

	// "127.0.0.1:PORT" with no heap churn
	target := [16]byte{}
	copy(target[:], "127.0.0.1:")
	itoaPort(target[10:], uint16(inst.SocksPort))

	tor, err := net.Dial("tcp", string(target[:]))
	if err != nil {
		return
	}
	defer tor.Close()
	_ = tor.SetDeadline(time.Now().Add(connTimeout))

	go boundedCopy(tor, client)
	boundedCopy(client, tor)
}

// pickInstance selects the least-loaded instance from the requested tier.
func pickInstance(instCount int, wantParanoid bool) int {
	// random start to avoid deterministic walking
	randIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(instCount)))
	start := int(randIdx.Int64())

	var bestIdx = -1
	var bestLoad uint32 = ^uint32(0)

	for off := 0; off < instCount; off++ {
		idx := (start + off) % instCount

		tier := instTier[idx]
		if wantParanoid && tier != 1 {
			continue
		}
		if !wantParanoid && tier != 0 {
			continue
		}

		if atomic.LoadUint32(&instanceDraining[idx]) == 1 {
			continue
		}

		load := atomic.LoadUint32(&instanceConns[idx])
		limit := uint32(instMaxConns[idx])
		if load >= limit {
			continue
		}
		if load < bestLoad {
			bestLoad = load
			bestIdx = idx
		}
	}
	return bestIdx
}

// Rotation manager: per-instance thresholds from instRotateConns / instRotateSecs.
// For stable tier, instRotateSecs has already been clamped to ≤ 3600s in config,
// so no stable instance can live longer than one hour without being marked for rotation.
// Once draining, as soon as active == 0, we restart — this also handles the
// "when all connections stopped" case.
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
				if idx >= len(insts) || idx >= 32 {
					continue
				}
				if inst == nil {
					continue
				}

				draining := atomic.LoadUint32(&instanceDraining[idx])
				active := atomic.LoadUint32(&instanceConns[idx])
				last := atomic.LoadInt64(&instanceLastRestart[idx])
				total := atomic.LoadUint64(&instanceTotal[idx])

				rotConns := instRotateConns[idx]
				rotSecs := instRotateSecs[idx]

				if draining == 0 {
					// should we start draining?
					if (rotConns > 0 && total >= rotConns) ||
						(rotSecs > 0 && last != 0 && now-last >= rotSecs) {
						if atomic.CompareAndSwapUint32(&instanceDraining[idx], 0, 1) {
							slog.Info("marking tor instance for rotation",
								"id", inst.ID,
								"tier", instTier[idx],
								"total_conns", total,
								"age_seconds", now-last,
							)
						}
					}
				} else {
					// draining: wait until no active conns, then restart
					if active == 0 {
						slog.Info("rotating tor instance", "id", inst.ID, "tier", instTier[idx])
						if err := inst.Restart(); err != nil {
							slog.Error("instance restart failed", "id", inst.ID, "err", err)
							continue
						}
						atomic.StoreUint64(&instanceTotal[idx], 0)
						atomic.StoreUint32(&instanceDraining[idx], 0)
						atomic.StoreInt64(&instanceLastRestart[idx], now)
						slog.Info("tor instance rotation complete", "id", inst.ID, "tier", instTier[idx])
					}
				}
			}
		}
	}
}

// --- helpers ---

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

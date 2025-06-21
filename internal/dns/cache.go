package dns

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"torgo/internal/config"
)

// cacheEntry holds a DNS message and its expiry time.
type cacheEntry struct {
	msg        *dns.Msg
	expiryTime time.Time
}

// DNSCache is a thread-safe in-memory DNS cache.
type DNSCache struct {
	mu        sync.RWMutex
	cache     map[string]*cacheEntry
	appConfig *config.AppConfig
	stopChan  chan struct{}
}

var globalDNSCacheInstance *DNSCache

// NewDNSCache initializes a new DNS cache.
func NewDNSCache(appCfg *config.AppConfig) *DNSCache {
	if !appCfg.DNSCacheEnabled {
		return nil
	}
	dc := &DNSCache{
		cache:     make(map[string]*cacheEntry),
		appConfig: appCfg,
		stopChan:  make(chan struct{}),
	}
	if appCfg.DNSCacheEvictionInterval > 0 {
		go dc.startEvictionManager(appCfg.DNSCacheEvictionInterval)
	}
	log.Println("DNS Cache initialized.")
	return dc
}

// SetGlobalDNSCache sets the global DNS cache instance.
func SetGlobalDNSCache(cache *DNSCache) {
	globalDNSCacheInstance = cache
}

// GetGlobalDNSCache returns the global DNS cache instance.
func GetGlobalDNSCache() *DNSCache {
	return globalDNSCacheInstance
}

// startEvictionManager periodically removes expired entries from the cache.
func (dc *DNSCache) startEvictionManager(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	log.Printf("DNS Cache: Eviction manager started with interval %v", interval)
	for {
		select {
		case <-ticker.C:
			dc.evictExpired()
		case <-dc.stopChan:
			log.Println("DNS Cache: Eviction manager stopping.")
			return
		}
	}
}

// evictExpired removes entries that have passed their expiry time.
func (dc *DNSCache) evictExpired() {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	now := time.Now()
	for key, entry := range dc.cache {
		if now.After(entry.expiryTime) {
			delete(dc.cache, key)
		}
	}
}

// getCacheKey creates a unique key for a DNS query (name + type).
func getCacheKey(q dns.Question) string {
	return strings.ToLower(q.Name) + "_" + dns.TypeToString[q.Qtype]
}

// Get retrieves a DNS message from the cache if it's valid and not expired.
func (dc *DNSCache) Get(question dns.Question) (*dns.Msg, bool) {
	if dc == nil {
		return nil, false
	}

	key := getCacheKey(question)
	dc.mu.RLock()
	entry, found := dc.cache[key]
	dc.mu.RUnlock()

	if !found || time.Now().After(entry.expiryTime) {
		return nil, false
	}

	msgCopy := entry.msg.Copy()
	remainingTTL := uint32(time.Until(entry.expiryTime).Seconds())

	for _, rr := range msgCopy.Answer {
		if rr.Header().Ttl > remainingTTL {
			rr.Header().Ttl = remainingTTL
		}
	}
	for _, rr := range msgCopy.Ns {
		if rr.Header().Ttl > remainingTTL {
			rr.Header().Ttl = remainingTTL
		}
	}

	return msgCopy, true
}

// Set adds a DNS message to the cache.
func (dc *DNSCache) Set(question dns.Question, msg *dns.Msg) {
	if dc == nil || msg.Rcode != dns.RcodeSuccess {
		return
	}

	key := getCacheKey(question)
	minTTL := getMinTTLFromMsg(msg)

	effectiveTTL := minTTL
	if effectiveTTL == 0 && dc.appConfig.DNSCacheDefaultMinTTLSeconds > 0 {
		effectiveTTL = uint32(dc.appConfig.DNSCacheDefaultMinTTLSeconds)
	}
	if dc.appConfig.DNSCacheMinTTLOverrideSeconds > 0 && effectiveTTL < uint32(dc.appConfig.DNSCacheMinTTLOverrideSeconds) {
		effectiveTTL = uint32(dc.appConfig.DNSCacheMinTTLOverrideSeconds)
	}
	if dc.appConfig.DNSCacheMaxTTLOverrideSeconds > 0 && effectiveTTL > uint32(dc.appConfig.DNSCacheMaxTTLOverrideSeconds) {
		effectiveTTL = uint32(dc.appConfig.DNSCacheMaxTTLOverrideSeconds)
	}

	if effectiveTTL == 0 {
		return
	}

	dc.mu.Lock()
	defer dc.mu.Unlock()

	dc.cache[key] = &cacheEntry{
		msg:        msg.Copy(),
		expiryTime: time.Now().Add(time.Duration(effectiveTTL) * time.Second),
	}
}

// getMinTTLFromMsg finds the minimum TTL in a DNS message.
func getMinTTLFromMsg(m *dns.Msg) uint32 {
	var minTTL uint32 = 0
	foundAnyTTL := false

	processSection := func(s []dns.RR) {
		for _, rr := range s {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			ttl := rr.Header().Ttl
			if !foundAnyTTL || ttl < minTTL {
				minTTL = ttl
			}
			foundAnyTTL = true
		}
	}
	processSection(m.Answer)
	processSection(m.Ns)
	return minTTL
}

// Stop gracefully shuts down the DNS cache eviction manager.
func (dc *DNSCache) Stop() {
	if dc != nil && dc.stopChan != nil {
		close(dc.stopChan)
	}
}
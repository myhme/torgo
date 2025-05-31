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
	msg        *dns.Msg  // The cached DNS response
	expiryTime time.Time // When this entry expires
}

// DNSCache is a thread-safe in-memory DNS cache.
type DNSCache struct {
	mu        sync.RWMutex
	cache     map[string]*cacheEntry
	appConfig *config.AppConfig // To access cache config options like TTLs
	stopChan  chan struct{}     // To stop the eviction goroutine
}

var globalDNSCacheInstance *DNSCache // Global instance of the DNS cache

// NewDNSCache initializes a new DNS cache.
func NewDNSCache(appCfg *config.AppConfig) *DNSCache {
	if !appCfg.DNSCacheEnabled {
		return nil // Return nil if cache is globally disabled
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
	evictedCount := 0
	for key, entry := range dc.cache {
		if now.After(entry.expiryTime) {
			delete(dc.cache, key)
			evictedCount++
		}
	}
	if evictedCount > 0 {
		// log.Printf("DNS Cache: Evicted %d expired entries. Cache size: %d", evictedCount, len(dc.cache))
	}
}

// getCacheKey creates a unique key for a DNS query (name + type).
func getCacheKey(q dns.Question) string {
	return strings.ToLower(q.Name) + "_" + dns.TypeToString[q.Qtype]
}

// Get retrieves a DNS message from the cache if it's valid and not expired.
// The caller is responsible for setting the correct ID on the returned message.
func (dc *DNSCache) Get(question dns.Question) (*dns.Msg, bool) {
	if dc == nil || !dc.appConfig.DNSCacheEnabled { // Check if cache itself is nil or disabled
		return nil, false
	}

	key := getCacheKey(question)
	dc.mu.RLock()
	entry, found := dc.cache[key]
	dc.mu.RUnlock()

	if !found {
		return nil, false
	}

	if time.Now().After(entry.expiryTime) {
		return nil, false // Entry is stale
	}

	// Return a copy to ensure the cached message isn't modified by the caller
	msgCopy := entry.msg.Copy()
	// The ID will be set by the caller (handleDNSQuery in proxy.go)

	// Adjust TTLs in the copy to reflect remaining lifetime.
	var remainingTTLSeconds float64
	if expiry := time.Until(entry.expiryTime).Seconds(); expiry > 0 {
		remainingTTLSeconds = expiry
	} else {
		remainingTTLSeconds = 0 // Already expired or very close, effectively 0 TTL
	}
	remainingTTL := uint32(remainingTTLSeconds)


	for _, rr := range msgCopy.Answer {
		if rr.Header().Ttl > remainingTTL {
			rr.Header().Ttl = remainingTTL
		}
	}
	for _, rr := range msgCopy.Ns { // Also adjust for Authority section if present
		if rr.Header().Ttl > remainingTTL {
			rr.Header().Ttl = remainingTTL
		}
	}
	// Note: Extra section often contains OPT records with TTL 0, usually fine to leave as is.

	return msgCopy, true
}

// Set adds a DNS message to the cache.
func (dc *DNSCache) Set(question dns.Question, msg *dns.Msg) {
	if dc == nil || !dc.appConfig.DNSCacheEnabled { // Check if cache itself is nil or disabled
		return
	}
	if msg.Rcode != dns.RcodeSuccess { // Only cache successful responses
		return
	}

	key := getCacheKey(question)
	minTTL := getMinTTLFromMsg(msg) // Get the minimum TTL from the response records

	// Apply configured default/min/max TTLs for caching duration
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

	if effectiveTTL == 0 { // If still zero after all considerations, do not cache.
		return
	}

	dc.mu.Lock()
	defer dc.mu.Unlock()

	// Basic check to prevent unbounded growth - very simplistic.
	// A proper size-limited cache would need LRU or similar.
	if len(dc.cache) > 20000 && dc.appConfig.DNSCacheMaxTTLOverrideSeconds > 600 { // Example arbitrary limit
		log.Println("DNS Cache: Approaching arbitrary item limit (20000), clearing 1/4 for new entries.")
		i := 0
		for k := range dc.cache { // This is not a good way to pick "1/4", just an example
			delete(dc.cache, k)
			i++
			if i >= 5000 { // Clear 5000 items
				break
			}
		}
	}

	dc.cache[key] = &cacheEntry{
		msg:        msg.Copy(), // Store a copy
		expiryTime: time.Now().Add(time.Duration(effectiveTTL) * time.Second),
	}
}

// getMinTTLFromMsg finds the minimum TTL in a DNS message's Answer or Authority sections.
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
	if dc != nil && dc.appConfig.DNSCacheEnabled && dc.stopChan != nil {
		// Use a non-blocking send to signal stop, in case Stop is called multiple times
		// or if the channel is already closed.
		select {
		case dc.stopChan <- struct{}{}:
		default:
		}
	}
}

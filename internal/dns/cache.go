package dns

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"torgo/internal/config"
)

type cacheEntry struct { msg *dns.Msg; expiryTime time.Time }
type DNSCache struct {
	mu sync.RWMutex; cache map[string]*cacheEntry; appConfig *config.AppConfig; stopChan chan struct{}
}
var globalDNSCacheInstance *DNSCache

func NewDNSCache(appCfg *config.AppConfig) *DNSCache {
	if !appCfg.DNSCacheEnabled { return nil }
	dc := &DNSCache{ cache: make(map[string]*cacheEntry), appConfig: appCfg, stopChan: make(chan struct{})}
	if appCfg.DNSCacheEvictionInterval > 0 { go dc.startEvictionManager(appCfg.DNSCacheEvictionInterval) }
	log.Println("DNS Cache initialized.")
	return dc
}
func SetGlobalDNSCache(cache *DNSCache) { globalDNSCacheInstance = cache }
func GetGlobalDNSCache() *DNSCache { return globalDNSCacheInstance }

func (dc *DNSCache) startEvictionManager(interval time.Duration) {
	ticker := time.NewTicker(interval); defer ticker.Stop()
	log.Printf("DNS Cache: Eviction manager started (interval %v)", interval)
	for { select { case <-ticker.C: dc.evictExpired(); case <-dc.stopChan: log.Println("DNS Cache: Eviction manager stopping."); return } }
}
func (dc *DNSCache) evictExpired() {
	dc.mu.Lock(); defer dc.mu.Unlock(); now := time.Now(); evictedCount := 0
	for key, entry := range dc.cache { if now.After(entry.expiryTime) { delete(dc.cache, key); evictedCount++ } }
	// if evictedCount > 0 { log.Printf("DNS Cache: Evicted %d entries. Size: %d", evictedCount, len(dc.cache)) }
}
func getCacheKey(q dns.Question) string { return strings.ToLower(q.Name) + "_" + dns.TypeToString[q.Qtype] }

func (dc *DNSCache) Get(question dns.Question) (*dns.Msg, bool) {
	if dc == nil || !dc.appConfig.DNSCacheEnabled { return nil, false }
	key := getCacheKey(question); dc.mu.RLock(); entry, found := dc.cache[key]; dc.mu.RUnlock()
	if !found || time.Now().After(entry.expiryTime) { return nil, false }
	msgCopy := entry.msg.Copy(); msgCopy.Id = question.Id
	remainingTTL := uint32(0); if expiry := time.Until(entry.expiryTime).Seconds(); expiry > 0 { remainingTTL = uint32(expiry) }
	for _, rr := range msgCopy.Answer { if rr.Header().Ttl > remainingTTL { rr.Header().Ttl = remainingTTL } }
	for _, rr := range msgCopy.Ns { if rr.Header().Ttl > remainingTTL { rr.Header().Ttl = remainingTTL } }
	return msgCopy, true
}
func (dc *DNSCache) Set(question dns.Question, msg *dns.Msg) {
	if dc == nil || !dc.appConfig.DNSCacheEnabled || msg.Rcode != dns.RcodeSuccess { return }
	key := getCacheKey(question); minTTL := getMinTTLFromMsg(msg); effectiveTTL := minTTL
	if effectiveTTL == 0 && dc.appConfig.DNSCacheDefaultMinTTLSeconds > 0 { effectiveTTL = uint32(dc.appConfig.DNSCacheDefaultMinTTLSeconds) }
	if dc.appConfig.DNSCacheMinTTLOverrideSeconds > 0 && effectiveTTL < uint32(dc.appConfig.DNSCacheMinTTLOverrideSeconds) { effectiveTTL = uint32(dc.appConfig.DNSCacheMinTTLOverrideSeconds) }
	if dc.appConfig.DNSCacheMaxTTLOverrideSeconds > 0 && effectiveTTL > uint32(dc.appConfig.DNSCacheMaxTTLOverrideSeconds) { effectiveTTL = uint32(dc.appConfig.DNSCacheMaxTTLOverrideSeconds) }
	if effectiveTTL == 0 { return }
	dc.mu.Lock(); defer dc.mu.Unlock()
	if len(dc.cache) > 20000 { // Simple cap
		log.Println("DNS Cache: At item limit (20000), clearing 1/4."); i := 0
		for k := range dc.cache { delete(dc.cache, k); i++; if i >= 5000 { break } }
	}
	dc.cache[key] = &cacheEntry{ msg: msg.Copy(), expiryTime: time.Now().Add(time.Duration(effectiveTTL) * time.Second)}
}
func getMinTTLFromMsg(m *dns.Msg) uint32 {
	var minTTL uint32 = 0; foundAnyTTL := false
	process := func(s []dns.RR) {
		for _, rr := range s {
			if rr.Header().Rrtype == dns.TypeOPT { continue }
			if !foundAnyTTL || rr.Header().Ttl < minTTL { minTTL = rr.Header().Ttl }; foundAnyTTL = true
		}
	}
	process(m.Answer); process(m.Ns)
	return minTTL
}
func (dc *DNSCache) Stop() {
	if dc != nil && dc.appConfig.DNSCacheEnabled && dc.stopChan != nil {
		select { case dc.stopChan <- struct{}{}: default: } // Non-blocking signal
	}
}

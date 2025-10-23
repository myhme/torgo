package dns

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"log"
	"math"
	"strings"
	"sync"
	"time"

	"torgo/internal/config"

	"github.com/miekg/dns"
)

// cacheEntry holds encrypted DNS message bytes and its expiry time.
type cacheEntry struct {
	ciphertext []byte
	nonce      []byte
	expiryTime time.Time
}

// DNSCache is a thread-safe in-memory DNS cache (encrypted at rest in RAM).
type DNSCache struct {
	mu        sync.RWMutex
	cache     map[string]*cacheEntry
	appConfig *config.AppConfig
	stopChan  chan struct{}

	// encryption state
	aead cipher.AEAD
	key  []byte
}

var globalDNSCacheInstance *DNSCache

// NewDNSCache initializes a new encrypted DNS cache.
func NewDNSCache(appCfg *config.AppConfig) *DNSCache {
	if !appCfg.DNSCacheEnabled {
		return nil
	}
	// Generate per-process random key (AES-256-GCM)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Printf("DNS Cache: Failed to initialize encryption key: %v. Disabling cache.", err)
		return nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("DNS Cache: Failed to create cipher: %v. Disabling cache.", err)
		return nil
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("DNS Cache: Failed to create AEAD: %v. Disabling cache.", err)
		return nil
	}

	dc := &DNSCache{
		cache:     make(map[string]*cacheEntry),
		appConfig: appCfg,
		stopChan:  make(chan struct{}),
		aead:      aead,
		key:       key,
	}
	if appCfg.DNSCacheEvictionInterval > 0 {
		go dc.startEvictionManager(appCfg.DNSCacheEvictionInterval)
	}
	log.Println("DNS Cache initialized (encrypted in memory).")
	return dc
}

// SetGlobalDNSCache sets the global DNS cache instance.
func SetGlobalDNSCache(cache *DNSCache) { globalDNSCacheInstance = cache }

// GetGlobalDNSCache returns the global DNS cache instance.
func GetGlobalDNSCache() *DNSCache { return globalDNSCacheInstance }

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

// evictExpired removes entries that have passed their expiry time and zeroizes data.
func (dc *DNSCache) evictExpired() {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	now := time.Now()
	for key, entry := range dc.cache {
		if now.After(entry.expiryTime) {
			zeroize(entry.ciphertext)
			zeroize(entry.nonce)
			delete(dc.cache, key)
		}
	}
}

// getCacheKey creates a unique key for a DNS query (name + type).
func getCacheKey(q dns.Question) string {
	return strings.ToLower(q.Name) + "_" + dns.TypeToString[q.Qtype]
}

// Get retrieves and decrypts a DNS message from the cache if valid and not expired.
func (dc *DNSCache) Get(question dns.Question) (*dns.Msg, bool) {
	if dc == nil || dc.aead == nil {
		return nil, false
	}
	key := getCacheKey(question)
	dc.mu.RLock()
	entry, found := dc.cache[key]
	dc.mu.RUnlock()
	if !found || time.Now().After(entry.expiryTime) {
		return nil, false
	}
	plain, err := dc.decrypt(entry.nonce, entry.ciphertext)
	if err != nil {
		return nil, false
	}
	var msg dns.Msg
	if err := msg.Unpack(plain); err != nil {
		return nil, false
	}
	// Adjust TTLs to remaining lifetime
	remainingTTL := uint32(time.Until(entry.expiryTime).Seconds())
	for _, rr := range msg.Answer {
		if rr.Header().Ttl > remainingTTL {
			rr.Header().Ttl = remainingTTL
		}
	}
	for _, rr := range msg.Ns {
		if rr.Header().Ttl > remainingTTL {
			rr.Header().Ttl = remainingTTL
		}
	}
	return &msg, true
}

// Set adds and encrypts a DNS message in the cache.
func (dc *DNSCache) Set(question dns.Question, msg *dns.Msg) {
	if dc == nil || dc.aead == nil || msg.Rcode != dns.RcodeSuccess {
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
		if dc.appConfig.DNSCacheMaxTTLOverrideSeconds <= int(math.MaxUint32) {
			effectiveTTL = uint32(dc.appConfig.DNSCacheMaxTTLOverrideSeconds)
		} else {
			log.Printf("DNSCacheMaxTTLOverrideSeconds value (%d) is out of uint32 bounds. Ignoring override.", dc.appConfig.DNSCacheMaxTTLOverrideSeconds)
		}
	}
	if effectiveTTL == 0 {
		return
	}
	packed, err := msg.Pack()
	if err != nil {
		return
	}
	nonce, ciphertext, err := dc.encrypt(packed)
	if err != nil {
		return
	}
	dc.mu.Lock()
	dc.cache[key] = &cacheEntry{ciphertext: ciphertext, nonce: nonce, expiryTime: time.Now().Add(time.Duration(effectiveTTL) * time.Second)}
	dc.mu.Unlock()
}

// getMinTTLFromMsg finds the minimum TTL in a DNS message.
func getMinTTLFromMsg(m *dns.Msg) uint32 {
	var minTTL uint32
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

// Stop gracefully shuts down the DNS cache: zeroize entries and key.
func (dc *DNSCache) Stop() {
	if dc == nil {
		return
	}
	if dc.stopChan != nil {
		close(dc.stopChan)
	}
	dc.mu.Lock()
	for k, entry := range dc.cache {
		zeroize(entry.ciphertext)
		zeroize(entry.nonce)
		delete(dc.cache, k)
	}
	dc.cache = make(map[string]*cacheEntry)
	if dc.key != nil {
		zeroize(dc.key)
	}
	dc.aead = nil
	dc.mu.Unlock()
}

func (dc *DNSCache) encrypt(plain []byte) (nonce []byte, ciphertext []byte, err error) {
	nonce = make([]byte, dc.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = dc.aead.Seal(nil, nonce, plain, nil)
	return nonce, ciphertext, nil
}

func (dc *DNSCache) decrypt(nonce, ciphertext []byte) ([]byte, error) {
	if len(nonce) != dc.aead.NonceSize() {
		return nil, errors.New("dns cache: invalid nonce size")
	}
	return dc.aead.Open(nil, nonce, ciphertext, nil)
}

func zeroize(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}

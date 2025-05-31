package config

import (
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultTorAuthCookiePath = "/var/lib/tor/control_auth_cookie"
	DefaultIPCheckURL        = "https://check.torproject.org/api/ip"
	DefaultHealthCheckInterval = 30 * time.Second
	DefaultSocksTimeout      = 10 * time.Second
	DefaultDNSTimeout        = 5 * time.Second
	DefaultRotationStaggerDelay = 10 * time.Second
	DefaultAPIPort           = "8080"
	DefaultCommonSocksPort   = "9000"
	DefaultCommonDNSPort     = "5300"
	DefaultSocksBasePort     = 9050
	DefaultControlBasePort   = 9160
	DefaultDNSBasePort       = 9200
	DefaultNumTorInstances   = 1
	DefaultIPDiversityCheckInterval        = 5 * time.Minute
	DefaultIPDiversityRotationCooldown     = 15 * time.Minute
	DefaultMinInstancesForIPDiversityCheck = 2
	DefaultAutoRotateCircuitIntervalSeconds = 3600
	DefaultAutoRotateStaggerDelaySeconds    = 30
	DefaultDNSCacheEnabled               = true
	DefaultDNSCacheEvictionIntervalSeconds = 300
	DefaultDNSCacheDefaultMinTTLSeconds  = 60
	DefaultDNSCacheMinTTLOverrideSeconds = 0
	DefaultDNSCacheMaxTTLOverrideSeconds = 86400
)

type AppConfig struct {
	NumTorInstances     int
	SocksBasePort       int
	ControlBasePort     int
	DNSBasePort         int
	CommonSocksPort     string
	CommonDNSPort       string
	APIPort             string
	RotationStaggerDelay time.Duration
	HealthCheckInterval time.Duration
	IPCheckURL          string
	SocksTimeout        time.Duration
	DNSTimeout          time.Duration
	IsGlobalRotationActive int32
	IPDiversityCheckInterval        time.Duration
	IPDiversityRotationCooldown     time.Duration
	MinInstancesForIPDiversityCheck int
	AutoRotateCircuitInterval time.Duration
	AutoRotateStaggerDelay    time.Duration
	IsAutoRotationEnabled     bool
	DNSCacheEnabled               bool
	DNSCacheEvictionInterval      time.Duration
	DNSCacheDefaultMinTTLSeconds  int
	DNSCacheMinTTLOverrideSeconds int
	DNSCacheMaxTTLOverrideSeconds int
}

var GlobalConfig *AppConfig
var once sync.Once

func getIntEnv(key string, defaultValue int) int {
	valStr := os.Getenv(key)
	if valStr == "" { return defaultValue }
	val, err := strconv.Atoi(valStr)
	if err != nil { log.Printf("Warning: Invalid ENV %s ('%s'). Using default %d. Err: %v", key, valStr, defaultValue, err); return defaultValue }
	return val
}
func getBoolEnv(key string, defaultValue bool) bool {
	valStr := os.Getenv(key)
	if valStr == "" { return defaultValue }
	val, err := strconv.ParseBool(valStr)
	if err != nil { log.Printf("Warning: Invalid ENV %s ('%s'). Using default %t. Err: %v", key, valStr, defaultValue, err); return defaultValue }
	return val
}
func getStringEnv(key string, defaultValue string) string {
	valStr := os.Getenv(key); if valStr == "" { return defaultValue }; return valStr
}

func LoadConfig() *AppConfig {
	once.Do(func() {
		cfg := &AppConfig{}
		cfg.NumTorInstances = getIntEnv("TOR_INSTANCES", DefaultNumTorInstances)
		if cfg.NumTorInstances < 1 { cfg.NumTorInstances = 1 }
		cfg.SocksBasePort = getIntEnv("SOCKS_BASE_PORT_CONFIGURED", DefaultSocksBasePort)
		cfg.ControlBasePort = getIntEnv("CONTROL_BASE_PORT_CONFIGURED", DefaultControlBasePort)
		cfg.DNSBasePort = getIntEnv("DNS_BASE_PORT_CONFIGURED", DefaultDNSBasePort)
		cfg.CommonSocksPort = getStringEnv("COMMON_SOCKS_PROXY_PORT", DefaultCommonSocksPort)
		cfg.CommonDNSPort = getStringEnv("COMMON_DNS_PROXY_PORT", DefaultCommonDNSPort)
		cfg.APIPort = getStringEnv("API_PORT", DefaultAPIPort)
		cfg.RotationStaggerDelay = time.Duration(getIntEnv("ROTATION_STAGGER_DELAY_SECONDS", int(DefaultRotationStaggerDelay.Seconds()))) * time.Second
		cfg.HealthCheckInterval = time.Duration(getIntEnv("HEALTH_CHECK_INTERVAL_SECONDS", int(DefaultHealthCheckInterval.Seconds()))) * time.Second
		cfg.IPCheckURL = getStringEnv("IP_CHECK_URL", DefaultIPCheckURL)
		cfg.SocksTimeout = time.Duration(getIntEnv("SOCKS_TIMEOUT_SECONDS", int(DefaultSocksTimeout.Seconds()))) * time.Second
		cfg.DNSTimeout = time.Duration(getIntEnv("DNS_TIMEOUT_SECONDS", int(DefaultDNSTimeout.Seconds()))) * time.Second
		cfg.IPDiversityCheckInterval = time.Duration(getIntEnv("IP_DIVERSITY_CHECK_INTERVAL_SECONDS", int(DefaultIPDiversityCheckInterval.Seconds()))) * time.Second
		cfg.IPDiversityRotationCooldown = time.Duration(getIntEnv("IP_DIVERSITY_ROTATION_COOLDOWN_SECONDS", int(DefaultIPDiversityRotationCooldown.Seconds()))) * time.Second
		cfg.MinInstancesForIPDiversityCheck = getIntEnv("MIN_INSTANCES_FOR_IP_DIVERSITY_CHECK", DefaultMinInstancesForIPDiversityCheck)
		rawAutoRotateIntervalStr := os.Getenv("AUTO_ROTATE_CIRCUIT_INTERVAL_SECONDS")
		trimmedAutoRotateIntervalStr := strings.TrimSpace(rawAutoRotateIntervalStr)
		if trimmedAutoRotateIntervalStr == "0" {
			cfg.IsAutoRotationEnabled = false; cfg.AutoRotateCircuitInterval = 0
		} else {
			autoRotateSec, err := strconv.Atoi(trimmedAutoRotateIntervalStr)
			if err == nil && autoRotateSec > 0 { cfg.AutoRotateCircuitInterval = time.Duration(autoRotateSec) * time.Second; cfg.IsAutoRotationEnabled = true
			} else {
				cfg.AutoRotateCircuitInterval = time.Duration(DefaultAutoRotateCircuitIntervalSeconds) * time.Second; cfg.IsAutoRotationEnabled = true
				if trimmedAutoRotateIntervalStr != "" { log.Printf("Config: Invalid AUTO_ROTATE_CIRCUIT_INTERVAL_SECONDS ('%s'). Defaulting to ENABLED interval %v.", trimmedAutoRotateIntervalStr, cfg.AutoRotateCircuitInterval) }
			}
		}
		cfg.AutoRotateStaggerDelay = time.Duration(getIntEnv("AUTO_ROTATE_STAGGER_DELAY_SECONDS", DefaultAutoRotateStaggerDelaySeconds)) * time.Second
		cfg.DNSCacheEnabled = getBoolEnv("DNS_CACHE_ENABLED", DefaultDNSCacheEnabled)
		cfg.DNSCacheEvictionInterval = time.Duration(getIntEnv("DNS_CACHE_EVICTION_INTERVAL_SECONDS", DefaultDNSCacheEvictionIntervalSeconds)) * time.Second
		cfg.DNSCacheDefaultMinTTLSeconds = getIntEnv("DNS_CACHE_DEFAULT_MIN_TTL_SECONDS", DefaultDNSCacheDefaultMinTTLSeconds)
		cfg.DNSCacheMinTTLOverrideSeconds = getIntEnv("DNS_CACHE_MIN_TTL_OVERRIDE_SECONDS", DefaultDNSCacheMinTTLOverrideSeconds)
		cfg.DNSCacheMaxTTLOverrideSeconds = getIntEnv("DNS_CACHE_MAX_TTL_OVERRIDE_SECONDS", DefaultDNSCacheMaxTTLOverrideSeconds)
		GlobalConfig = cfg
		log.Printf("Configuration loaded: NumInstances=%d, APIPort=%s", cfg.NumTorInstances, cfg.APIPort)
	})
	return GlobalConfig
}

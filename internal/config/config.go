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
	DefaultIPCheckURL        = "https://check.torproject.org/api/ip" // Used for IP diversity and instance's own IP check
	DefaultHealthCheckInterval = 30 * time.Second
	DefaultSocksTimeout      = 10 * time.Second
	DefaultRotationStaggerDelay = 10 * time.Second // For manual "rotate-all-staggered"
	DefaultAPIPort           = "8080"
	DefaultCommonSocksPort   = "9000"
	DefaultCommonDNSPort     = "5300"
	DefaultSocksBasePort     = 9050
	DefaultControlBasePort   = 9160
	DefaultDNSBasePort       = 9200
	DefaultNumTorInstances   = 1

	// Defaults for IP Diversity feature (now part of CircuitManager)
	DefaultIPDiversityCheckInterval        = 5 * time.Minute
	DefaultIPDiversityRotationCooldown     = 15 * time.Minute
	DefaultMinInstancesForIPDiversityCheck = 2

	// Defaults for Automatic Circuit Rotation (now part of CircuitManager)
	DefaultAutoRotateCircuitIntervalSeconds = 3600 // 1 hour
	DefaultAutoRotateStaggerDelaySeconds    = 30   // Stagger between rotations triggered by CircuitManager

	DefaultLoadBalancingStrategy = "random" // Options: "random", "round-robin", "least-connections-proxy"

	// Defaults for Performance Testing (new)
	DefaultPerfTestInterval         = 5 * time.Minute // How often to run performance tests
	DefaultLatencyTestTargetGoogle  = "https://www.google.com/generate_204"
	DefaultLatencyTestTargetCloudflare = "https://1.1.1.1/cdn-cgi/trace" // Small text response
	DefaultSpeedTestTargetCloudflareBytes = 1000000 // 1MB for light speed test from Cloudflare
	DefaultSpeedTestTargetCloudflareURL = "https://speed.cloudflare.com/__down?bytes=" // Append bytes
)

// AppConfig holds the global configuration for the torgo application.
type AppConfig struct {
	NumTorInstances     int
	SocksBasePort       int
	ControlBasePort     int
	DNSBasePort         int
	CommonSocksPort     string
	CommonDNSPort       string
	APIPort             string
	RotationStaggerDelay time.Duration // For manual "rotate-all-staggered" via API
	HealthCheckInterval time.Duration
	IPCheckURL          string // General IP check URL
	SocksTimeout        time.Duration

	IsGlobalRotationActive int32 // For manual "rotate-all-staggered" via API

	// Circuit Manager Settings (combines auto-rotation and IP diversity logic)
	CircuitManagerEnabled             bool
	CircuitMaxAge                     time.Duration // Formerly AutoRotateCircuitInterval
	CircuitRotationStagger            time.Duration // Stagger between rotations triggered by CircuitManager
	IPDiversityCheckEnabled           bool          // Specific toggle for IP diversity part of circuit manager
	IPDiversityMinInstances           int           // Formerly MinInstancesForIPDiversityCheck
	IPDiversitySubnetCheckInterval    time.Duration // How often to check IPs for diversity
	IPDiversityRotationCooldown       time.Duration // Cooldown after an IP diversity-triggered rotation

	LoadBalancingStrategy string

	// Performance Testing Settings
	PerfTestEnabled                 bool
	PerfTestInterval                time.Duration
	LatencyTestTargets              map[string]string // Alias -> URL
	SpeedTestTargetURL              string            // URL for speed test (e.g., Cloudflare with byte param)
	SpeedTestTargetBytes            int               // Bytes to download for speed test
}

var GlobalConfig *AppConfig
var once sync.Once

// GetenvDuration parses an environment variable as seconds into a time.Duration.
func GetenvDuration(key string, defaultValue time.Duration) time.Duration {
	valStr := os.Getenv(key)
	if valStr == "" {
		return defaultValue
	}
	valInt, err := strconv.Atoi(valStr)
	if err != nil || valInt < 0 { // Allow 0 to disable for some settings if applicable
		log.Printf("Config: Invalid duration value for %s: '%s'. Using default: %v", key, valStr, defaultValue)
		return defaultValue
	}
	return time.Duration(valInt) * time.Second
}

// GetenvInt parses an environment variable as an integer.
func GetenvInt(key string, defaultValue int) int {
	valStr := os.Getenv(key)
	if valStr == "" {
		return defaultValue
	}
	valInt, err := strconv.Atoi(valStr)
	if err != nil {
		log.Printf("Config: Invalid integer value for %s: '%s'. Using default: %d", key, valStr, defaultValue)
		return defaultValue
	}
	return valInt
}

// GetenvBool parses an environment variable as a boolean.
// "true", "1", "yes" are true. "false", "0", "no" are false. Otherwise, default.
func GetenvBool(key string, defaultValue bool) bool {
	valStr := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if valStr == "" {
		return defaultValue
	}
	switch valStr {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		log.Printf("Config: Invalid boolean value for %s: '%s'. Using default: %t", key, valStr, defaultValue)
		return defaultValue
	}
}


func LoadConfig() *AppConfig {
	once.Do(func() {
		log.Println("Loading application configuration...")
		cfg := &AppConfig{}

		cfg.NumTorInstances = GetenvInt("TOR_INSTANCES_CONFIGURED", DefaultNumTorInstances)
		if cfg.NumTorInstances < 1 {
			log.Printf("Warning: TOR_INSTANCES_CONFIGURED is %d, must be at least 1. Setting to 1.", cfg.NumTorInstances)
			cfg.NumTorInstances = 1
		}

		cfg.SocksBasePort = GetenvInt("SOCKS_BASE_PORT_CONFIGURED", DefaultSocksBasePort)
		cfg.ControlBasePort = GetenvInt("CONTROL_BASE_PORT_CONFIGURED", DefaultControlBasePort)
		cfg.DNSBasePort = GetenvInt("DNS_BASE_PORT_CONFIGURED", DefaultDNSBasePort)

		cfg.CommonSocksPort = os.Getenv("COMMON_SOCKS_PROXY_PORT")
		if cfg.CommonSocksPort == "" {	cfg.CommonSocksPort = DefaultCommonSocksPort }
		cfg.CommonDNSPort = os.Getenv("COMMON_DNS_PROXY_PORT")
		if cfg.CommonDNSPort == "" { cfg.CommonDNSPort = DefaultCommonDNSPort }
		cfg.APIPort = os.Getenv("API_PORT")
		if cfg.APIPort == "" { cfg.APIPort = DefaultAPIPort }

		cfg.RotationStaggerDelay = GetenvDuration("ROTATION_STAGGER_DELAY_SECONDS", DefaultRotationStaggerDelay)
		cfg.HealthCheckInterval = GetenvDuration("HEALTH_CHECK_INTERVAL_SECONDS", DefaultHealthCheckInterval)
		cfg.SocksTimeout = GetenvDuration("SOCKS_TIMEOUT_SECONDS", DefaultSocksTimeout)
		
		cfg.IPCheckURL = os.Getenv("IP_CHECK_URL")
		if cfg.IPCheckURL == "" { cfg.IPCheckURL = DefaultIPCheckURL }


		// Circuit Manager Settings
		// CIRCUIT_MANAGER_ENABLED: "true" (default) or "false"
		cfg.CircuitManagerEnabled = GetenvBool("CIRCUIT_MANAGER_ENABLED", true)

		// CIRCUIT_MAX_AGE_SECONDS: (default: 1 hour) "0" to disable age-based rotation.
		maxAgeSec := GetenvInt("CIRCUIT_MAX_AGE_SECONDS", DefaultAutoRotateCircuitIntervalSeconds)
		if maxAgeSec > 0 {
			cfg.CircuitMaxAge = time.Duration(maxAgeSec) * time.Second
		} else {
			cfg.CircuitMaxAge = 0 // Explicitly disable if 0 or less
		}
		
		cfg.CircuitRotationStagger = GetenvDuration("CIRCUIT_ROTATION_STAGGER_SECONDS", time.Duration(DefaultAutoRotateStaggerDelaySeconds)*time.Second)

		// IP_DIVERSITY_ENABLED: "true" (default) or "false"
		cfg.IPDiversityCheckEnabled = GetenvBool("IP_DIVERSITY_ENABLED", true)
		cfg.IPDiversityMinInstances = GetenvInt("IP_DIVERSITY_MIN_INSTANCES", DefaultMinInstancesForIPDiversityCheck)
		cfg.IPDiversitySubnetCheckInterval = GetenvDuration("IP_DIVERSITY_SUBNET_CHECK_INTERVAL_SECONDS", DefaultIPDiversityCheckInterval)
		cfg.IPDiversityRotationCooldown = GetenvDuration("IP_DIVERSITY_ROTATION_COOLDOWN_SECONDS", DefaultIPDiversityRotationCooldown)


		// Load Balancing Strategy
		lbStrategy := strings.ToLower(strings.TrimSpace(os.Getenv("LOAD_BALANCING_STRATEGY")))
		switch lbStrategy {
		case "random", "round-robin", "least-connections-proxy":
			cfg.LoadBalancingStrategy = lbStrategy
		default:
			if lbStrategy != "" {
				log.Printf("Config: Invalid LOAD_BALANCING_STRATEGY: '%s'. Defaulting to '%s'.", lbStrategy, DefaultLoadBalancingStrategy)
			}
			cfg.LoadBalancingStrategy = DefaultLoadBalancingStrategy
		}

		// Performance Testing Settings
		cfg.PerfTestEnabled = GetenvBool("PERF_TEST_ENABLED", true)
		cfg.PerfTestInterval = GetenvDuration("PERF_TEST_INTERVAL_SECONDS", DefaultPerfTestInterval)
		
		cfg.LatencyTestTargets = make(map[string]string)
		// Allow overriding default targets via ENV, e.g. LATENCY_TARGET_GOOGLE_URL, LATENCY_TARGET_CLOUDFLARE_URL
		cfg.LatencyTestTargets["google"] = os.Getenv("LATENCY_TARGET_GOOGLE_URL")
		if cfg.LatencyTestTargets["google"] == "" { cfg.LatencyTestTargets["google"] = DefaultLatencyTestTargetGoogle }
		
		cfg.LatencyTestTargets["cloudflare"] = os.Getenv("LATENCY_TARGET_CLOUDFLARE_URL")
		if cfg.LatencyTestTargets["cloudflare"] == "" { cfg.LatencyTestTargets["cloudflare"] = DefaultLatencyTestTargetCloudflare }
		
		// Could add more generic LATENCY_TARGET_ALIAS_URL and parse them
		
		cfg.SpeedTestTargetURL = os.Getenv("SPEED_TEST_TARGET_URL")
		if cfg.SpeedTestTargetURL == "" { cfg.SpeedTestTargetURL = DefaultSpeedTestTargetCloudflareURL }
		cfg.SpeedTestTargetBytes = GetenvInt("SPEED_TEST_TARGET_BYTES", DefaultSpeedTestTargetCloudflareBytes)


		GlobalConfig = cfg
		log.Printf("Configuration loaded: NumInstances=%d, APIPort=%s, LB Strategy=%s",
			cfg.NumTorInstances, cfg.APIPort, cfg.LoadBalancingStrategy)
		if cfg.CircuitManagerEnabled {
			log.Printf("CircuitManager: ENABLED. MaxAge=%v, IPDiversityChecks=%t (MinInst:%d, Interval:%v, Cooldown:%v), Stagger=%v",
				cfg.CircuitMaxAge, cfg.IPDiversityCheckEnabled, cfg.IPDiversityMinInstances, cfg.IPDiversitySubnetCheckInterval, cfg.IPDiversityRotationCooldown, cfg.CircuitRotationStagger)
		} else {
			log.Println("CircuitManager: DISABLED.")
		}
		if cfg.PerfTestEnabled {
			log.Printf("PerfTester: ENABLED. Interval=%v. Latency Targets: %d, Speed Target: %s (%d bytes)",
			cfg.PerfTestInterval, len(cfg.LatencyTestTargets), cfg.SpeedTestTargetURL, cfg.SpeedTestTargetBytes)
		} else {
			log.Println("PerfTester: DISABLED.")
		}
	})
	return GlobalConfig
}

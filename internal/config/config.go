package config

import (
	"log" // Will be replaced by slog, but kept for initial Getenv... functions if they log errors
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"log/slog" // Import slog
)

const (
	DefaultTorAuthCookiePath = "/var/lib/tor/control_auth_cookie"
	DefaultIPCheckURL        = "https://check.torproject.org/api/ip" 
	DefaultHealthCheckInterval = 30 * time.Second
	DefaultSocksTimeout      = 10 * time.Second
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

	DefaultLoadBalancingStrategy = "random" 

	DefaultPerfTestInterval         = 5 * time.Minute 
	DefaultLatencyTestTargetGoogle  = "https://www.google.com/generate_204"
	DefaultLatencyTestTargetCloudflare = "https://1.1.1.1/cdn-cgi/trace" 
	DefaultSpeedTestTargetCloudflareBytes = 1000000 
	DefaultSpeedTestTargetCloudflareURL = "https://speed.cloudflare.com/__down?bytes=" 

	// Logging Defaults
	DefaultLogLevel = "info" // Options: debug, info, warn, error
	DefaultLogFormat = "text" // Options: text, json
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
	RotationStaggerDelay time.Duration 
	HealthCheckInterval time.Duration
	IPCheckURL          string 
	SocksTimeout        time.Duration

	IsGlobalRotationActive int32 

	CircuitManagerEnabled             bool
	CircuitMaxAge                     time.Duration 
	CircuitRotationStagger            time.Duration 
	IPDiversityCheckEnabled           bool          
	IPDiversityMinInstances           int           
	IPDiversitySubnetCheckInterval    time.Duration 
	IPDiversityRotationCooldown       time.Duration 

	LoadBalancingStrategy string

	PerfTestEnabled                 bool
	PerfTestInterval                time.Duration
	LatencyTestTargets              map[string]string 
	SpeedTestTargetURL              string            
	SpeedTestTargetBytes            int               

	// Logging Configuration
	LogLevel slog.Level // Changed from string to slog.Level
	LogFormat string
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
	if err != nil || valInt < 0 { 
		// Use standard log here as slog might not be configured yet during initial config load
		log.Printf("Config (GetenvDuration): Invalid duration value for %s: '%s'. Using default: %v", key, valStr, defaultValue)
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
		log.Printf("Config (GetenvInt): Invalid integer value for %s: '%s'. Using default: %d", key, valStr, defaultValue)
		return defaultValue
	}
	return valInt
}

// GetenvBool parses an environment variable as a boolean.
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
		log.Printf("Config (GetenvBool): Invalid boolean value for %s: '%s'. Using default: %t", key, valStr, defaultValue)
		return defaultValue
	}
}


func LoadConfig() *AppConfig {
	once.Do(func() {
		// Temporary logger for config loading issues before slog is fully set up.
		// This uses the standard log package.
		initialLog := log.New(os.Stderr, "CONFIG_LOADER: ", log.LstdFlags|log.Lshortfile)
		initialLog.Println("Loading application configuration...")
		
		cfg := &AppConfig{}

		cfg.NumTorInstances = GetenvInt("TOR_INSTANCES_CONFIGURED", DefaultNumTorInstances)
		if cfg.NumTorInstances < 1 {
			initialLog.Printf("Warning: TOR_INSTANCES_CONFIGURED is %d, must be at least 1. Setting to 1.", cfg.NumTorInstances)
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

		cfg.CircuitManagerEnabled = GetenvBool("CIRCUIT_MANAGER_ENABLED", true)
		maxAgeSec := GetenvInt("CIRCUIT_MAX_AGE_SECONDS", DefaultAutoRotateCircuitIntervalSeconds)
		if maxAgeSec > 0 {
			cfg.CircuitMaxAge = time.Duration(maxAgeSec) * time.Second
		} else {
			cfg.CircuitMaxAge = 0 
		}
		cfg.CircuitRotationStagger = GetenvDuration("CIRCUIT_ROTATION_STAGGER_SECONDS", time.Duration(DefaultAutoRotateStaggerDelaySeconds)*time.Second)
		cfg.IPDiversityCheckEnabled = GetenvBool("IP_DIVERSITY_ENABLED", true)
		cfg.IPDiversityMinInstances = GetenvInt("IP_DIVERSITY_MIN_INSTANCES", DefaultMinInstancesForIPDiversityCheck)
		cfg.IPDiversitySubnetCheckInterval = GetenvDuration("IP_DIVERSITY_SUBNET_CHECK_INTERVAL_SECONDS", DefaultIPDiversityCheckInterval)
		cfg.IPDiversityRotationCooldown = GetenvDuration("IP_DIVERSITY_ROTATION_COOLDOWN_SECONDS", DefaultIPDiversityRotationCooldown)

		lbStrategy := strings.ToLower(strings.TrimSpace(os.Getenv("LOAD_BALANCING_STRATEGY")))
		switch lbStrategy {
		case "random", "round-robin", "least-connections-proxy":
			cfg.LoadBalancingStrategy = lbStrategy
		default:
			if lbStrategy != "" {
				initialLog.Printf("Invalid LOAD_BALANCING_STRATEGY: '%s'. Defaulting to '%s'.", lbStrategy, DefaultLoadBalancingStrategy)
			}
			cfg.LoadBalancingStrategy = DefaultLoadBalancingStrategy
		}

		cfg.PerfTestEnabled = GetenvBool("PERF_TEST_ENABLED", true)
		cfg.PerfTestInterval = GetenvDuration("PERF_TEST_INTERVAL_SECONDS", DefaultPerfTestInterval)
		cfg.LatencyTestTargets = make(map[string]string)
		cfg.LatencyTestTargets["google"] = os.Getenv("LATENCY_TARGET_GOOGLE_URL")
		if cfg.LatencyTestTargets["google"] == "" { cfg.LatencyTestTargets["google"] = DefaultLatencyTestTargetGoogle }
		cfg.LatencyTestTargets["cloudflare"] = os.Getenv("LATENCY_TARGET_CLOUDFLARE_URL")
		if cfg.LatencyTestTargets["cloudflare"] == "" { cfg.LatencyTestTargets["cloudflare"] = DefaultLatencyTestTargetCloudflare }
		cfg.SpeedTestTargetURL = os.Getenv("SPEED_TEST_TARGET_URL")
		if cfg.SpeedTestTargetURL == "" { cfg.SpeedTestTargetURL = DefaultSpeedTestTargetCloudflareURL }
		cfg.SpeedTestTargetBytes = GetenvInt("SPEED_TEST_TARGET_BYTES", DefaultSpeedTestTargetCloudflareBytes)

		// Logging Configuration
		logLevelStr := strings.ToLower(os.Getenv("LOG_LEVEL"))
		if logLevelStr == "" { logLevelStr = DefaultLogLevel }
		switch logLevelStr {
		case "debug":
			cfg.LogLevel = slog.LevelDebug
		case "info":
			cfg.LogLevel = slog.LevelInfo
		case "warn":
			cfg.LogLevel = slog.LevelWarn
		case "error":
			cfg.LogLevel = slog.LevelError
		default:
			initialLog.Printf("Invalid LOG_LEVEL: '%s'. Defaulting to '%s'.", logLevelStr, DefaultLogLevel)
			cfg.LogLevel = slog.LevelInfo // Default to Info if invalid
		}

		cfg.LogFormat = strings.ToLower(os.Getenv("LOG_FORMAT"))
		if cfg.LogFormat == "" {
			cfg.LogFormat = DefaultLogFormat
		}
		if cfg.LogFormat != "text" && cfg.LogFormat != "json" {
			initialLog.Printf("Invalid LOG_FORMAT: '%s'. Defaulting to '%s'.", cfg.LogFormat, DefaultLogFormat)
			cfg.LogFormat = DefaultLogFormat
		}

		GlobalConfig = cfg
		// After this point, the main application can set up slog with cfg.LogLevel and cfg.LogFormat.
		// The initialLog can be replaced by slog.
		initialLog.Printf("Base configuration loaded: NumInstances=%d, APIPort=%s, LB Strategy=%s, LogLevel=%s, LogFormat=%s",
			cfg.NumTorInstances, cfg.APIPort, cfg.LoadBalancingStrategy, cfg.LogLevel.String(), cfg.LogFormat)
		if cfg.CircuitManagerEnabled {
			initialLog.Printf("CircuitManager: ENABLED. MaxAge=%v, IPDiversityChecks=%t (MinInst:%d, Interval:%v, Cooldown:%v), Stagger=%v",
				cfg.CircuitMaxAge, cfg.IPDiversityCheckEnabled, cfg.IPDiversityMinInstances, cfg.IPDiversitySubnetCheckInterval, cfg.IPDiversityRotationCooldown, cfg.CircuitRotationStagger)
		} else {
			initialLog.Println("CircuitManager: DISABLED.")
		}
		if cfg.PerfTestEnabled {
			initialLog.Printf("PerfTester: ENABLED. Interval=%v. Latency Targets: %d, Speed Target: %s (%d bytes)",
			cfg.PerfTestInterval, len(cfg.LatencyTestTargets), cfg.SpeedTestTargetURL, cfg.SpeedTestTargetBytes)
		} else {
			initialLog.Println("PerfTester: DISABLED.")
		}
	})
	return GlobalConfig
}

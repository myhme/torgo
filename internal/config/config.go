package config

import (
	"log"
	"os"
	"strconv"
	"strings" // Added for TrimSpace
	"sync"
	"time"
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

	// Defaults for IP Diversity feature
	DefaultIPDiversityCheckInterval        = 5 * time.Minute
	DefaultIPDiversityRotationCooldown     = 15 * time.Minute
	DefaultMinInstancesForIPDiversityCheck = 2

	// New defaults for Automatic Circuit Rotation
	DefaultAutoRotateCircuitIntervalSeconds = 3600 // 1 hour
	DefaultAutoRotateStaggerDelaySeconds    = 30   // 30 seconds
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

	IPDiversityCheckInterval        time.Duration
	IPDiversityRotationCooldown     time.Duration
	MinInstancesForIPDiversityCheck int

	AutoRotateCircuitInterval time.Duration
	AutoRotateStaggerDelay    time.Duration
	IsAutoRotationEnabled     bool
}

var GlobalConfig *AppConfig
var once sync.Once

func LoadConfig() *AppConfig {
	once.Do(func() {
		log.Println("Loading application configuration...")
		cfg := &AppConfig{}

		nInstancesStr := os.Getenv("TOR_INSTANCES_CONFIGURED")
		n, err := strconv.Atoi(nInstancesStr)
		if err != nil || n < 1 {
			log.Printf("Invalid or missing TOR_INSTANCES_CONFIGURED: '%s'. Defaulting to %d.", nInstancesStr, DefaultNumTorInstances)
			cfg.NumTorInstances = DefaultNumTorInstances
		} else {
			cfg.NumTorInstances = n
		}

		sBasePortStr := os.Getenv("SOCKS_BASE_PORT_CONFIGURED")
		cfg.SocksBasePort, err = strconv.Atoi(sBasePortStr)
		if err != nil || cfg.SocksBasePort == 0 {
			cfg.SocksBasePort = DefaultSocksBasePort
		}

		cBasePortStr := os.Getenv("CONTROL_BASE_PORT_CONFIGURED")
		cfg.ControlBasePort, err = strconv.Atoi(cBasePortStr)
		if err != nil || cfg.ControlBasePort == 0 {
			cfg.ControlBasePort = DefaultControlBasePort
		}

		dBasePortStr := os.Getenv("DNS_BASE_PORT_CONFIGURED")
		cfg.DNSBasePort, err = strconv.Atoi(dBasePortStr)
		if err != nil || cfg.DNSBasePort == 0 {
			cfg.DNSBasePort = DefaultDNSBasePort
		}

		cfg.CommonSocksPort = os.Getenv("COMMON_SOCKS_PROXY_PORT")
		if cfg.CommonSocksPort == "" {
			cfg.CommonSocksPort = DefaultCommonSocksPort
		}

		cfg.CommonDNSPort = os.Getenv("COMMON_DNS_PROXY_PORT")
		if cfg.CommonDNSPort == "" {
			cfg.CommonDNSPort = DefaultCommonDNSPort
		}

		cfg.APIPort = os.Getenv("API_PORT")
		if cfg.APIPort == "" {
			cfg.APIPort = DefaultAPIPort
		}

		delayStr := os.Getenv("ROTATION_STAGGER_DELAY_SECONDS")
		if delaySec, err := strconv.Atoi(delayStr); err == nil && delaySec > 0 {
			cfg.RotationStaggerDelay = time.Duration(delaySec) * time.Second
		} else {
			cfg.RotationStaggerDelay = DefaultRotationStaggerDelay
		}

		healthIntervalStr := os.Getenv("HEALTH_CHECK_INTERVAL_SECONDS")
		if healthSec, err := strconv.Atoi(healthIntervalStr); err == nil && healthSec > 0 {
			cfg.HealthCheckInterval = time.Duration(healthSec) * time.Second
		} else {
			cfg.HealthCheckInterval = DefaultHealthCheckInterval
		}

		cfg.IPCheckURL = os.Getenv("IP_CHECK_URL")
		if cfg.IPCheckURL == "" {
			cfg.IPCheckURL = DefaultIPCheckURL
		}

		socksTimeoutStr := os.Getenv("SOCKS_TIMEOUT_SECONDS")
		if socksTimeoutSec, err := strconv.Atoi(socksTimeoutStr); err == nil && socksTimeoutSec > 0 {
			cfg.SocksTimeout = time.Duration(socksTimeoutSec) * time.Second
		} else {
			cfg.SocksTimeout = DefaultSocksTimeout
		}

		ipDiversityIntervalStr := os.Getenv("IP_DIVERSITY_CHECK_INTERVAL_SECONDS")
		if ipDiversitySec, err := strconv.Atoi(ipDiversityIntervalStr); err == nil && ipDiversitySec > 0 {
			cfg.IPDiversityCheckInterval = time.Duration(ipDiversitySec) * time.Second
		} else {
			cfg.IPDiversityCheckInterval = DefaultIPDiversityCheckInterval
		}

		ipDiversityCooldownStr := os.Getenv("IP_DIVERSITY_ROTATION_COOLDOWN_SECONDS")
		if ipDiversityCooldownSec, err := strconv.Atoi(ipDiversityCooldownStr); err == nil && ipDiversityCooldownSec > 0 {
			cfg.IPDiversityRotationCooldown = time.Duration(ipDiversityCooldownSec) * time.Second
		} else {
			cfg.IPDiversityRotationCooldown = DefaultIPDiversityRotationCooldown
		}

		minInstancesStr := os.Getenv("MIN_INSTANCES_FOR_IP_DIVERSITY_CHECK")
		if minInst, err := strconv.Atoi(minInstancesStr); err == nil && minInst >= 0 {
			cfg.MinInstancesForIPDiversityCheck = minInst
		} else {
			cfg.MinInstancesForIPDiversityCheck = DefaultMinInstancesForIPDiversityCheck
		}

		// --- Automatic Circuit Rotation Config ---
		rawAutoRotateIntervalStr := os.Getenv("AUTO_ROTATE_CIRCUIT_INTERVAL_SECONDS")
		trimmedAutoRotateIntervalStr := strings.TrimSpace(rawAutoRotateIntervalStr)
		log.Printf("Config: Raw AUTO_ROTATE_CIRCUIT_INTERVAL_SECONDS: '%s', Trimmed: '%s'", rawAutoRotateIntervalStr, trimmedAutoRotateIntervalStr)

		if trimmedAutoRotateIntervalStr == "0" {
			cfg.IsAutoRotationEnabled = false
			cfg.AutoRotateCircuitInterval = 0
			log.Println("Config: Automatic circuit rotation is EXPLICITLY DISABLED via AUTO_ROTATE_CIRCUIT_INTERVAL_SECONDS=0.")
		} else {
			autoRotateSec, err := strconv.Atoi(trimmedAutoRotateIntervalStr)
			if err == nil && autoRotateSec > 0 {
				cfg.AutoRotateCircuitInterval = time.Duration(autoRotateSec) * time.Second
				cfg.IsAutoRotationEnabled = true
				log.Printf("Config: Automatic circuit rotation ENABLED. Interval set to %v from ENV.", cfg.AutoRotateCircuitInterval)
			} else {
				// Not "0" and not a valid positive integer. Default to enabled with default interval.
				cfg.AutoRotateCircuitInterval = time.Duration(DefaultAutoRotateCircuitIntervalSeconds) * time.Second
				cfg.IsAutoRotationEnabled = true // Default to enabled if not explicitly "0"
				if trimmedAutoRotateIntervalStr == "" {
					log.Printf("Config: AUTO_ROTATE_CIRCUIT_INTERVAL_SECONDS not set. Defaulting to ENABLED with interval %v.", cfg.AutoRotateCircuitInterval)
				} else {
					log.Printf("Config: Invalid AUTO_ROTATE_CIRCUIT_INTERVAL_SECONDS ('%s'). Error: %v. Defaulting to ENABLED with interval %v.", trimmedAutoRotateIntervalStr, err, cfg.AutoRotateCircuitInterval)
				}
			}
		}

		autoRotateStaggerStr := os.Getenv("AUTO_ROTATE_STAGGER_DELAY_SECONDS")
		if autoRotateStaggerSec, err := strconv.Atoi(autoRotateStaggerStr); err == nil && autoRotateStaggerSec > 0 {
			cfg.AutoRotateStaggerDelay = time.Duration(autoRotateStaggerSec) * time.Second
		} else {
			cfg.AutoRotateStaggerDelay = time.Duration(DefaultAutoRotateStaggerDelaySeconds) * time.Second
		}
		// --- End Automatic Circuit Rotation Config ---

		GlobalConfig = cfg
		log.Printf("Configuration loaded: NumInstances=%d, APIPort=%s, CommonSOCKS=%s, CommonDNS=%s",
			cfg.NumTorInstances, cfg.APIPort, cfg.CommonSocksPort, cfg.CommonDNSPort)
		log.Printf("IP Diversity: CheckInterval=%v, Cooldown=%v, MinInstances=%d",
			cfg.IPDiversityCheckInterval, cfg.IPDiversityRotationCooldown, cfg.MinInstancesForIPDiversityCheck)
		if cfg.IsAutoRotationEnabled {
			log.Printf("Auto Circuit Rotation: Final Status: ENABLED, Interval=%v, StaggerDelay=%v",
				cfg.AutoRotateCircuitInterval, cfg.AutoRotateStaggerDelay)
		} else {
			log.Println("Auto Circuit Rotation: Final Status: DISABLED.")
		}
	})
	return GlobalConfig
}

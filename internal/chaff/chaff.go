// internal/chaff/chaff.go — FINAL ZERO-TRUST EDITION (DNS NOISE + DEEP SURFING)
package chaff

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/html"
	"golang.org/x/net/proxy"
	"torgo/internal/config"
)

// --- Configuration Constants ---

const (
	minChainDepth = 3   // Visit at least 3 pages per session
	maxChainDepth = 8   // Up to 8 pages for deep surfing
	
	// Text/Article Reading Behavior
	readTimeMean   = 45  // Average 45s reading a page
	readTimeStdDev = 20  // Deviation
	
	// Video Watching Behavior (Cinema Mode)
	// We simulate watching short-form content (3-10 mins)
	watchTimeMean   = 240 // 4 minutes average
	watchTimeStdDev = 120 // +/- 2 minutes
)

// "Low-Data" Video Sites (No Login Required)
var videoDomains = map[string]bool{
	"vimeo.com": true, "www.vimeo.com": true,
	"dailymotion.com": true, "www.dailymotion.com": true,
	"ted.com": true, "www.ted.com": true,
	"twitch.tv": true, "www.twitch.tv": true,
	"archive.org": true, "www.archive.org": true,
}

// Search Engines for Referer Spoofing (Masquerading)
var searchReferers = []string{
	"https://www.google.com/",
	"https://www.bing.com/",
	"https://duckduckgo.com/",
	"https://search.yahoo.com/",
}

var seedSites = []string{
	// Video & Media (Cinema Mode Targets)
	"https://vimeo.com/watch", 
	"https://www.dailymotion.com", 
	"https://www.ted.com/talks",
	"https://archive.org/details/movies",

	// News - Global (Text heavy)
	"https://www.bbc.com", "https://www.cnn.com", "https://www.nytimes.com",
	"https://www.theguardian.com", "https://www.reuters.com", "https://www.aljazeera.com",
	
	// Tech & Dev
	"https://news.ycombinator.com", "https://github.com/explore", "https://stackoverflow.com",
	"https://www.theverge.com", "https://arstechnica.com",

	// Knowledge
	"https://en.wikipedia.org/wiki/Special:Random", "https://www.wikihow.com",
	
	// Shopping (Browsing behavior)
	"https://www.amazon.com", "https://www.ebay.com", "https://www.target.com",
}

func Start(ctx context.Context, cfg *config.Config) {
	if !cfg.ChaffEnabled {
		return
	}

	// Wait for Tor circuits to stabilize before generating noise
	slog.Info("chaff waiting for circuit stabilization...")
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}
	
	slog.Info("chaff zero-trust active", 
		"seeds", len(seedSites), 
		"mode", "circadian-dns-http",
	)

	// 1. Start HTTP Surfer (The main traffic generator)
	go surferLoop(ctx, cfg.SocksPort)

	// 2. Start DNS Noise (UDP/TCP to local Tor DNS port)
	// This generates dummy DNS lookups to mask the timing of any REAL lookups you do.
	go dnsNoiseLoop(ctx, cfg.DNSPort)
}

// --- DNS NOISE GENERATOR ---

func dnsNoiseLoop(ctx context.Context, dnsPort string) {
	// Create a custom resolver that talks to our local Tor DNS port
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial("tcp", "127.0.0.1:"+dnsPort)
		},
	}

	for {
		sleepFactor := getCircadianFactor()
		
		// DNS noise happens even while "sleeping" (devices update in background)
		// but much less frequently.
		var interval time.Duration
		if sleepFactor > 0.8 {
			// Night: Sparse noise (5 to 15 mins)
			interval = randomDuration(300, 900)
		} else {
			// Day: Active noise (20s to 60s)
			interval = randomGaussianDuration(45, 15)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}

		// Pick a random site from our seeds to "resolve"
		target := seedSites[randomInt(len(seedSites))]
		u, _ := url.Parse(target)
		if u == nil { continue }
		
		host := u.Hostname()
		
		// Perform Lookup
		// We use a short timeout because we don't actually care about the result,
		// we just want the traffic to flow to the Guard node.
		ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := resolver.LookupHost(ctxTimeout, host)
		cancel()
		
		if err == nil {
			slog.Debug("chaff dns noise sent", "host", host)
		}
	}
}

// --- HTTP SURFER ENGINE ---

func surferLoop(ctx context.Context, socksPort string) {
	for {
		// 1. Circadian Rhythm Check
		sleepFactor := getCircadianFactor()
		
		// If mostly asleep (late night), 80% chance to skip session entirely
		if sleepFactor > 0.8 && randomInt(100) < 80 {
			slog.Debug("chaff user sleeping (circadian)", "factor", sleepFactor)
			longSleep := randomDuration(600, 3600) // Sleep 10m to 1hr
			select {
			case <-ctx.Done():
				return
			case <-time.After(longSleep):
			}
			continue
		}

		// 2. Perform Session
		performSession(ctx, socksPort)

		// 3. Break Time (Scaled by Circadian Rhythm)
		// Night time = Much longer breaks between bursts
		meanBreak := 120.0 * (1.0 + sleepFactor*2.0) 
		breakDur := randomGaussianDuration(meanBreak, 60)
		
		if breakDur < 15*time.Second {
			breakDur = 15 * time.Second
		}
		
		slog.Debug("chaff user taking a break", "duration", breakDur)
		
		select {
		case <-ctx.Done():
			return
		case <-time.After(breakDur):
		}
	}
}

// getCircadianFactor returns 0.0 (Wide Awake) to 1.0 (Deep Sleep)
func getCircadianFactor() float64 {
	h := time.Now().UTC().Hour()
	switch {
	case h >= 0 && h < 6:
		return 0.9 // Deep sleep (UTC 00-06)
	case h >= 6 && h < 8:
		return 0.5 // Waking up
	case h >= 23:
		return 0.5 // Wind down
	default:
		return 0.1 // Active day
	}
}

func performSession(ctx context.Context, socksPort string) {
	persona := pickPersona()
	
	// Ephemeral CookieJar: Isolate this session from all others
	jar, _ := cookiejar.New(nil)

	client, err := createBrowserClient(socksPort, persona, jar)
	if err != nil {
		slog.Error("chaff client create failed", "err", err)
		return
	}

	currentURL := seedSites[randomInt(len(seedSites))]
	chainDepth := randomIntRange(minChainDepth, maxChainDepth)
	
	// Search Engine Masquerading:
	// 50% chance the first request has a Referer from Google/Bing/DDG
	var referer string
	if randomInt(100) < 50 {
		referer = searchReferers[randomInt(len(searchReferers))]
		slog.Debug("chaff entry via search", "engine", referer)
	}

	slog.Debug("chaff session start", "seed", currentURL, "depth", chainDepth, "persona", persona.Browser)

	for i := 0; i < chainDepth; i++ {
		if ctx.Err() != nil { return }

		// 1. Visit Page (Fetch HTML + Extract Assets)
		body, nextLinks, assets, err := visitPage(client, currentURL, referer, persona)
		if err != nil {
			slog.Debug("chaff visit failed", "url", currentURL, "err", err)
			break 
		}

		// 2. Determine Mode (Video vs Text)
		u, _ := url.Parse(currentURL)
		isVideo := false
		if u != nil {
			domain := strings.TrimPrefix(u.Hostname(), "www.")
			if videoDomains[domain] || videoDomains[u.Hostname()] {
				isVideo = true
			}
		}

		// 3. Emulate Consumption (Active)
		if isVideo {
			// --- CINEMA MODE ---
			if getCircadianFactor() > 0.8 { break } // Don't watch videos at 3AM

			watchDuration := calculateWatchTime()
			slog.Info("chaff watching video", "url", currentURL, "duration", watchDuration)
			
			// Video "Heartbeat" (Frequent pings to mimic buffering)
			simulateActivity(ctx, client, assets, watchDuration, currentURL, persona, true)
		} else {
			// --- READING MODE (Active Scrolling) ---
			readDuration := calculateReadTime(len(body))
			slog.Debug("chaff reading text", "url", currentURL, "duration", readDuration)
			
			// Text "Scrolling" (Sparse pings to mimic lazy loading)
			simulateActivity(ctx, client, assets, readDuration, currentURL, persona, false)
		}

		// 4. Next Link
		if len(nextLinks) == 0 { break }

		referer = currentURL 
		internalBias := 80
		if isVideo { internalBias = 95 }

		currentURL = pickWeightedLink(nextLinks, currentURL, internalBias)
	}
}

// simulateActivity handles both Video Heartbeats and Text Scrolling (Lazy Loading).
// isVideo=true: Frequent pings (20-40s).
// isVideo=false: Sparse pings (1-3 total) delayed randomly.
func simulateActivity(ctx context.Context, client *http.Client, assets []string, duration time.Duration, referer string, p persona, isVideo bool) {
	deadline := time.Now().Add(duration)
	
	if len(assets) == 0 {
		select {
		case <-ctx.Done():
		case <-time.After(duration):
		}
		return
	}

	for time.Now().Before(deadline) {
		var sleepTime time.Duration
		
		if isVideo {
			// Video: Regular heartbeats (20s - 40s)
			sleepTime = randomDuration(20, 40)
		} else {
			// Text: "Scroll" logic
			remaining := time.Until(deadline)
			if remaining < 5*time.Second {
				time.Sleep(remaining)
				return
			}
			sleepTime = randomDuration(10, 25)
		}
		
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleepTime):
		}
		
		if time.Now().After(deadline) { return }

		// Trigger Background Request (Tiny bandwidth)
		target := assets[randomInt(len(assets))]
		
		go func(url string) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			
			// HEAD request is sufficient to trigger traffic activity
			req, _ := http.NewRequestWithContext(ctx, "HEAD", url, nil)
			req.Header.Set("User-Agent", p.UA)
			req.Header.Set("Referer", referer)
			req.Header.Set("Accept", "*/*")
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}(target)

		// For text reading, random chance to stop scrolling early
		if !isVideo && randomInt(100) < 30 {
			remaining := time.Until(deadline)
			if remaining > 0 {
				time.Sleep(remaining)
			}
			return
		}
	}
}

// visitPage fetches content + extracts assets
func visitPage(client *http.Client, target, referer string, p persona) ([]byte, []string, []string, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	req.Header.Set("User-Agent", p.UA)
	req.Header.Set("Accept", p.Accept)
	req.Header.Set("Accept-Language", p.AcceptLang)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	
	if referer == "" {
		req.Header.Set("Sec-Fetch-Site", "none")
	} else {
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Referer", referer)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, nil, nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	// 5MB Limit per page
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, nil, nil, err
	}

	base, _ := url.Parse(target)
	links, assets := extractContent(body, base)

	return body, links, assets, nil
}

// extractContent scans for <a href> (links) and <img/script src> (assets)
func extractContent(body []byte, baseURL *url.URL) ([]string, []string) {
	var links []string
	var assets []string
	
	tokenizer := html.NewTokenizer(bytes.NewReader(body))

	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
		}

		if tokenType == html.StartTagToken || tokenType == html.SelfClosingTagToken {
			token := tokenizer.Token()
			
			// Links
			if token.Data == "a" {
				for _, attr := range token.Attr {
					if attr.Key == "href" {
						if l := resolveURL(attr.Val, baseURL); l != "" && !isInvalidLink(attr.Val) {
							links = append(links, l)
						}
					}
				}
			}
			
			// Assets (Lazy load candidates)
			if token.Data == "img" || token.Data == "script" {
				for _, attr := range token.Attr {
					if attr.Key == "src" {
						if l := resolveURL(attr.Val, baseURL); l != "" {
							assets = append(assets, l)
						}
					}
				}
			}
		}
	}
	return links, assets
}

func resolveURL(val string, baseURL *url.URL) string {
	val = strings.TrimSpace(val)
	if val == "" || strings.HasPrefix(val, "data:") { return "" }
	u, err := url.Parse(val)
	if err != nil { return "" }
	abs := baseURL.ResolveReference(u)
	if abs.Scheme != "http" && abs.Scheme != "https" { return "" }
	return abs.String()
}

func isInvalidLink(val string) bool {
	lower := strings.ToLower(val)
	return strings.HasPrefix(lower, "#") || 
		strings.HasPrefix(lower, "javascript:") || 
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "tel:") ||
		strings.HasSuffix(lower, ".jpg") || 
		strings.HasSuffix(lower, ".png") ||
		strings.HasSuffix(lower, ".pdf") ||
		strings.HasSuffix(lower, ".zip")
}

func pickWeightedLink(links []string, currentURL string, internalBiasPercent int) string {
	if len(links) == 0 { return "" }
	current, _ := url.Parse(currentURL)
	var internalLinks []string
	var externalLinks []string
	
	for _, l := range links {
		u, _ := url.Parse(l)
		if u != nil && current != nil && (u.Host == current.Host || strings.HasSuffix(u.Host, "."+current.Host)) {
			internalLinks = append(internalLinks, l)
		} else {
			externalLinks = append(externalLinks, l)
		}
	}

	if len(internalLinks) > 0 && randomInt(100) < internalBiasPercent {
		return internalLinks[randomInt(len(internalLinks))]
	}
	if len(externalLinks) > 0 {
		return externalLinks[randomInt(len(externalLinks))]
	}
	return links[randomInt(len(links))]
}

// --- Browser Emulation ---

type persona struct {
	Browser    string
	UA         string
	Accept     string
	AcceptLang string
	ID         *utls.ClientHelloID
}

func pickPersona() persona {
	r := randomInt(100)
	if r < 60 {
		return persona{
			Browser:    "chrome",
			UA:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
			Accept:     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			AcceptLang: "en-US,en;q=0.9",
			ID:         &utls.HelloChrome_120,
		}
	} else if r < 85 {
		return persona{
			Browser:    "firefox",
			UA:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
			Accept:     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			AcceptLang: "en-US,en;q=0.5",
			ID:         &utls.HelloFirefox_120,
		}
	} else {
		return persona{
			Browser:    "edge",
			UA:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
			Accept:     "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			AcceptLang: "en-US,en;q=0.9",
			ID:         &utls.HelloChrome_120,
		}
	}
}

func createBrowserClient(socksPort string, p persona, jar *cookiejar.Jar) (*http.Client, error) {
	// Dial local SOCKS5 proxy
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:"+socksPort, nil, proxy.Direct)
	if err != nil { return nil, err }

	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			tcpConn, err := dialer.Dial(network, addr)
			if err != nil { return nil, err }
			
			host, _, _ := net.SplitHostPort(addr)
			// Mimic real browser SNI
			tlsConfig := &utls.Config{ServerName: host, InsecureSkipVerify: true}
			
			uConn := utls.UClient(tcpConn, tlsConfig, *p.ID)
			if err := uConn.Handshake(); err != nil {
				_ = tcpConn.Close()
				return nil, err
			}
			return uConn, nil
		},
		DisableKeepAlives: false,
		MaxIdleConns:      10,
		IdleConnTimeout:   30 * time.Second,
	}

	return &http.Client{
		Transport: tr, 
		Jar: jar, 
		Timeout: 120 * time.Second,
	}, nil
}

// --- Math Helpers ---

func calculateReadTime(contentLength int) time.Duration {
	if contentLength < 1000 { contentLength = 1000 }
	if contentLength > 100000 { contentLength = 100000 }
	baseSeconds := float64(contentLength) / 2500.0
	noise := randomGaussian(0, 10) 
	finalSeconds := baseSeconds + readTimeMean + noise
	if finalSeconds < 5 { finalSeconds = 5 }
	return time.Duration(finalSeconds) * time.Second
}

func calculateWatchTime() time.Duration {
	secs := randomGaussian(watchTimeMean, watchTimeStdDev)
	if secs < 30 { secs = 30 } 
	if secs > 900 { secs = 900 }
	return time.Duration(secs) * time.Second
}

func randomDuration(min, max int) time.Duration {
	return time.Duration(randomIntRange(min, max)) * time.Second
}

func randomInt(max int) int {
	if max <= 0 { return 0 }
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

func randomIntRange(min, max int) int {
	if max <= min { return min }
	return min + randomInt(max-min)
}

func randomGaussian(mean, stdDev float64) float64 {
	u1 := float64(randomInt(1000)) / 1000.0
	u2 := float64(randomInt(1000)) / 1000.0
	z0 := math.Sqrt(-2.0 * math.Log(u1)) * math.Cos(2.0 * math.Pi * u2)
	return z0*stdDev + mean
}

func randomGaussianDuration(meanSec, stdDevSec float64) time.Duration {
	secs := randomGaussian(meanSec, stdDevSec)
	if secs < 1 { secs = 1 }
	return time.Duration(secs) * time.Second
}
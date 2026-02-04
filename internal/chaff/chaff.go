// internal/chaff/chaff.go — DEEP SURFING EDITION
// internal/chaff/chaff.go — LOW-BANDWIDTH CINEMA EDITION
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

// "Low-Data" Video Sites (No Login Required, No huge paywalls)
// We avoid YouTube/Netflix because they require login or CAPTCHAs often.
var videoDomains = map[string]bool{
	"vimeo.com": true, "www.vimeo.com": true,
	"dailymotion.com": true, "www.dailymotion.com": true,
	"ted.com": true, "www.ted.com": true,
	"twitch.tv": true, "www.twitch.tv": true,
	"archive.org": true, "www.archive.org": true,
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
	
	slog.Info("chaff deep-surfer active", 
		"seeds", len(seedSites), 
		"mode", "low-bandwidth-cinema",
	)

	// Launch the surfer
	go surferLoop(ctx, cfg.SocksPort)
}

func surferLoop(ctx context.Context, socksPort string) {
	for {
		// 1. Perform a complete browsing session
		performSession(ctx, socksPort)

		// 2. Variable Break Time (Gaussian distribution)
		// Humans take breaks. Mean 2 mins, but sometimes longer.
		breakDur := randomGaussianDuration(120, 60)
		if breakDur < 15*time.Second {
			breakDur = 15 * time.Second
		}
		
		slog.Debug("chaff user taking a break", "duration", breakDur)
		
		select {
		case <-ctx.Done():
			return
		case <-time.After(breakDur):
			// Continue loop
		}
	}
}

func performSession(ctx context.Context, socksPort string) {
	persona := pickPersona()
	
	// Use an ephemeral CookieJar.
	// This makes us look like a real browser accepting cookies during the session,
	// but because we recreate it every session, we are never tracked long-term.
	jar, _ := cookiejar.New(nil)

	client, err := createBrowserClient(socksPort, persona, jar)
	if err != nil {
		slog.Error("chaff client create failed", "err", err)
		return
	}

	currentURL := seedSites[randomInt(len(seedSites))]
	chainDepth := randomIntRange(minChainDepth, maxChainDepth)
	var referer string

	slog.Debug("chaff session start", "seed", currentURL, "depth", chainDepth, "persona", persona.Browser)

	for i := 0; i < chainDepth; i++ {
		if ctx.Err() != nil { return }

		// 1. Visit Page (Fetch HTML)
		body, nextLinks, assets, err := visitPage(client, currentURL, referer, persona)
		if err != nil {
			slog.Debug("chaff visit failed", "url", currentURL, "err", err)
			break // If page fails, end session naturally
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

		// 3. Emulate Consumption
		if isVideo {
			// --- CINEMA MODE ---
			// We DO NOT download the full video (saves bandwidth).
			// We simulate "watching" by keeping the connection alive and 
			// periodically fetching tiny assets (heartbeats).
			watchDuration := calculateWatchTime()
			slog.Info("chaff watching video (simulated)", "url", currentURL, "duration", watchDuration)
			
			simulateStreaming(ctx, client, assets, watchDuration, currentURL, persona)
		} else {
			// --- READING MODE ---
			readDuration := calculateReadTime(len(body))
			slog.Debug("chaff reading text", "url", currentURL, "duration", readDuration)
			
			select {
			case <-ctx.Done():
				return
			case <-time.After(readDuration):
			}
		}

		// 4. Pick Next Link
		if len(nextLinks) == 0 {
			break
		}

		referer = currentURL 
		
		// If on a video site, we are highly likely (95%) to click another video on the same site.
		// If reading news, we are likely (80%) to click internal, but sometimes external.
		internalBias := 80
		if isVideo { internalBias = 95 }

		currentURL = pickWeightedLink(nextLinks, currentURL, internalBias)
	}
}

// simulateStreaming mimics a user watching a video without downloading it.
// It sends small "Heartbeat" requests (fetching icons/thumbnails) every 20-40 seconds.
// This prevents the connection from looking "dead" and creates a traffic pattern
// that looks like a slow stream or buffering to a metadata observer.
func simulateStreaming(ctx context.Context, client *http.Client, assets []string, duration time.Duration, referer string, p persona) {
	deadline := time.Now().Add(duration)
	
	// If no assets found to ping, just fetch the page URL again with a HEAD request
	if len(assets) == 0 {
		assets = []string{referer}
	}

	for time.Now().Before(deadline) {
		// Interval between "chunks" (Heartbeats)
		// Random 20s - 40s.
		sleepTime := randomDuration(20, 40)
		
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleepTime):
		}

		// Perform Heartbeat (Tiny bandwidth usage)
		target := assets[randomInt(len(assets))]
		
		// Run in background so we don't block the sleep timer
		go func(url string) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			
			req, _ := http.NewRequestWithContext(ctx, "HEAD", url, nil) // HEAD = Headers only!
			req.Header.Set("User-Agent", p.UA)
			req.Header.Set("Referer", referer)
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}(target)
	}
}

// visitPage fetches content and extracts both Links (for navigation) and Assets (for heartbeats).
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

	// 5MB Limit per page to prevent memory DoS or accidental huge downloads
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, nil, nil, err
	}

	base, _ := url.Parse(target)
	links, assets := extractContent(body, base)

	return body, links, assets, nil
}

// extractContent finds navigational Links AND static Assets (images, scripts)
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
			
			// 1. Navigation Links (<a href>)
			if token.Data == "a" {
				for _, attr := range token.Attr {
					if attr.Key == "href" {
						if l := resolveURL(attr.Val, baseURL); l != "" && !isInvalidLink(attr.Val) {
							links = append(links, l)
						}
					}
				}
			}
			
			// 2. Assets (<img src>, <script src>) for Heartbeats
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
	// Only http/s
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
		// Check host match (simple version)
		if u != nil && current != nil && (u.Host == current.Host || strings.HasSuffix(u.Host, "."+current.Host)) {
			internalLinks = append(internalLinks, l)
		} else {
			externalLinks = append(externalLinks, l)
		}
	}

	// Prefer internal links based on bias
	if len(internalLinks) > 0 && randomInt(100) < internalBiasPercent {
		return internalLinks[randomInt(len(internalLinks))]
	}
	
	// Fallback
	if len(externalLinks) > 0 {
		return externalLinks[randomInt(len(externalLinks))]
	}
	return links[randomInt(len(links))]
}

// --- Browser Emulation (TLS + Persona) ---

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
		// Chrome (60% share)
		return persona{
			Browser:    "chrome",
			UA:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
			Accept:     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			AcceptLang: "en-US,en;q=0.9",
			ID:         &utls.HelloChrome_120,
		}
	} else if r < 85 {
		// Firefox (25% share)
		return persona{
			Browser:    "firefox",
			UA:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
			Accept:     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			AcceptLang: "en-US,en;q=0.5",
			ID:         &utls.HelloFirefox_120,
		}
	} else {
		// Edge (15% share)
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
	proxyAddr := "127.0.0.1:" + socksPort
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			tcpConn, err := dialer.Dial(network, addr)
			if err != nil { return nil, err }

			host, _, _ := net.SplitHostPort(addr)
			// Mimic real browser SNI
			tlsConfig := &utls.Config{
				ServerName: host, 
				InsecureSkipVerify: true, // Needed for proxy chains often, but be careful in production
			}
			
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
		Jar:       jar,
		Timeout:   120 * time.Second,
	}, nil
}

// --- Natural Mathematics Helpers ---

func calculateReadTime(contentLength int) time.Duration {
	if contentLength < 1000 { contentLength = 1000 }
	if contentLength > 100000 { contentLength = 100000 }
	
	baseSeconds := float64(contentLength) / 2500.0 // faster reader
	noise := randomGaussian(0, 10) 
	finalSeconds := baseSeconds + readTimeMean + noise
	
	if finalSeconds < 5 { finalSeconds = 5 }
	return time.Duration(finalSeconds) * time.Second
}

func calculateWatchTime() time.Duration {
	secs := randomGaussian(watchTimeMean, watchTimeStdDev)
	if secs < 30 { secs = 30 } 
	if secs > 900 { secs = 900 } // Cap at 15 mins
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
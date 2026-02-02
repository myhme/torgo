// internal/chaff/chaff.go — DEEP SURFING EDITION
package chaff

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
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
	maxChainDepth = 6   // Visit up to 6 pages per session
	readTimeMin   = 15  // Read a page for at least 15s
	readTimeMax   = 120 // Read a page for up to 2m
)

// Real browser User-Agents (Rotated per session)
var userAgents = map[string]string{
	"chrome":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"edge":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
}

// Massive list of benign "Seed" sites to start surfing sessions
var seedSites = []string{
	// News & Media
	"https://www.bbc.com", "https://www.cnn.com", "https://www.nytimes.com",
	"https://www.theguardian.com", "https://www.reuters.com", "https://www.bloomberg.com",
	"https://www.aljazeera.com", "https://www.npr.org", "https://www.wsj.com",
	
	// Tech & Dev
	"https://news.ycombinator.com", "https://github.com/explore", "https://stackoverflow.com",
	"https://www.theverge.com", "https://arstechnica.com", "https://techcrunch.com",
	"https://www.wired.com", "https://dev.to", "https://lobste.rs",

	// Knowledge & Reference
	"https://en.wikipedia.org/wiki/Special:Random", "https://www.imdb.com", 
	"https://www.wikihow.com", "https://www.britannica.com", "https://archive.org",
	
	// Shopping & Lifestyle
	"https://www.amazon.com", "https://www.ebay.com", "https://www.etsy.com",
	"https://www.target.com", "https://www.walmart.com", "https://www.bestbuy.com",
	
	// Social / Aggregators (Read-only)
	"https://www.reddit.com", "https://twitter.com/explore", "https://www.pinterest.com",
	"https://www.quora.com", "https://medium.com", "https://www.tumblr.com",
}

func Start(ctx context.Context, cfg *config.Config) {
	if !cfg.ChaffEnabled {
		return
	}

	// Wait for Tor to stabilize
	time.Sleep(30 * time.Second)
	
	slog.Info("chaff deep-surfer active", 
		"seeds", len(seedSites), 
		"mode", "recursive-browsing",
	)

	// Launch a single "user" thread. 
	// (You could launch more, but one thread looks like one human).
	go surferLoop(ctx, cfg.SocksPort)
}

func surferLoop(ctx context.Context, socksPort string) {
	for {
		// 1. Start a new browsing session
		performSession(ctx, socksPort)

		// 2. Take a break between sessions (Simulate user stepping away)
		// Break: 1 min to 10 mins
		breakDur := randomDuration(60, 600)
		slog.Debug("chaff user taking a break", "duration", breakDur)
		
		select {
		case <-ctx.Done():
			return
		case <-time.After(breakDur):
			// Continue
		}
	}
}

// performSession simulates a user visiting a site and clicking links
func performSession(ctx context.Context, socksPort string) {
	// Pick a random persona for this entire session
	persona := pickPersona()
	
	// Create a client that matches this persona (TLS + Headers)
	client, err := createBrowserClient(socksPort, persona)
	if err != nil {
		slog.Error("chaff client create failed", "err", err)
		return
	}

	// Pick a random start point
	currentURL := seedSites[randomInt(len(seedSites))]
	
	// Determine how many pages to visit in this chain (3-6)
	chainDepth := randomIntRange(minChainDepth, maxChainDepth)

	slog.Debug("chaff session starting", "seed", currentURL, "depth", chainDepth, "persona", persona.Name)

	for i := 0; i < chainDepth; i++ {
		// Check context cancellation
		if ctx.Err() != nil {
			return
		}

		// 1. Visit the page
		htmlContent, nextLinks, err := visitPage(client, currentURL, persona)
		if err != nil {
			slog.Debug("chaff visit failed", "url", currentURL, "err", err)
			break // Stop session if a page fails loading
		}

		// 2. "Read" the page (Sleep)
		// We calculate reading time based on content length slightly (longer page = longer read)
		readBase := readTimeMin
		if len(htmlContent) > 50000 {
			readBase += 10 // Add 10s for large pages
		}
		sleepTime := randomDuration(readBase, readTimeMax)
		
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleepTime):
		}

		// 3. Pick the next link to click
		if len(nextLinks) == 0 {
			slog.Debug("chaff dead end (no links)", "url", currentURL)
			break
		}

		// Filter links to keep them somewhat relevant? 
		// For now, we pick ANY valid http/https link to simulate "surfing the web"
		// Prefer different domain? Or same domain? 
		// Real users do both. Random is fine.
		currentURL = nextLinks[randomInt(len(nextLinks))]
	}
}

// visitPage fetches the URL, returns the body (for size calc) and extracted links
func visitPage(client *http.Client, target string, p persona) ([]byte, []string, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, nil, err
	}

	// Apply Persona Headers
	req.Header.Set("User-Agent", p.UA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none") // "none" for direct navigation, strictly should be "same-origin" for clicks

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	// Limit body read to 2MB to prevent memory DoS on huge pages
	// We need the body to parse links
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, nil, err
	}

	// Extract links from HTML
	base, _ := url.Parse(target)
	links := extractLinks(body, base)

	slog.Debug("chaff visited", "url", target, "links_found", len(links), "size", len(body))
	return body, links, nil
}

// extractLinks parses HTML and returns a list of absolute URLs
func extractLinks(body []byte, baseURL *url.URL) []string {
	var links []string
	tokenizer := html.NewTokenizer(bytes.NewReader(body))

	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
		}

		if tokenType == html.StartTagToken || tokenType == html.SelfClosingTagToken {
			token := tokenizer.Token()
			if token.Data == "a" {
				for _, attr := range token.Attr {
					if attr.Key == "href" {
						val := strings.TrimSpace(attr.Val)
						// Ignore JS, Anchors, Mailto
						if strings.HasPrefix(val, "#") || strings.HasPrefix(val, "javascript:") || strings.HasPrefix(val, "mailto:") {
							continue
						}

						// Resolve relative URLs
						u, err := url.Parse(val)
						if err != nil {
							continue
						}
						absURL := baseURL.ResolveReference(u)

						// Only keep http/https
						if absURL.Scheme == "http" || absURL.Scheme == "https" {
							links = append(links, absURL.String())
						}
					}
				}
			}
		}
	}
	return links
}

// --- Browser Emulation (TLS + Persona) ---

type persona struct {
	Name string
	UA   string
	ID   *utls.ClientHelloID // TLS Fingerprint ID
}

func pickPersona() persona {
	// Weighted random could go here, for now uniform
	r := randomInt(3)
	switch r {
	case 0:
		return persona{"firefox", userAgents["firefox"], &utls.HelloFirefox_120}
	case 1:
		return persona{"edge", userAgents["edge"], &utls.HelloChrome_120} // Edge uses Chrome TLS
	default:
		return persona{"chrome", userAgents["chrome"], &utls.HelloChrome_120}
	}
}

func createBrowserClient(socksPort string, p persona) (*http.Client, error) {
	proxyAddr := "127.0.0.1:" + socksPort
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			tcpConn, err := dialer.Dial(network, addr)
			if err != nil {
				return nil, err
			}

			host, _, _ := net.SplitHostPort(addr)
			tlsConfig := &utls.Config{ServerName: host, InsecureSkipVerify: true} // Mimic browser leniency? No, but keep simple.
			
			// Use the Persona's specific Client Hello ID
			uConn := utls.UClient(tcpConn, tlsConfig, *p.ID)
			if err := uConn.Handshake(); err != nil {
				_ = tcpConn.Close()
				return nil, err
			}
			return uConn, nil
		},
		DisableKeepAlives: false, // Browsers KEEP connections alive
		MaxIdleConns:      10,
		IdleConnTimeout:   30 * time.Second,
	}

	return &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
	}, nil
}

// --- Math Helpers ---

func randomInt(max int) int {
	if max <= 0 { return 0 }
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

func randomIntRange(min, max int) int {
	if max <= min { return min }
	return min + randomInt(max-min)
}

func randomDuration(minSec, maxSec int) time.Duration {
	return time.Duration(randomIntRange(minSec, maxSec)) * time.Second
}
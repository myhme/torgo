package tor // Correct package declaration

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
	"net" // Required for net.Dialer

	"golang.org/x/net/proxy"
)

// HealthCheck checks the status of Tor circuits.
// It takes a snapshot of circuits and returns their health status.
// listenHost is the host where the Tor SOCKS proxies are listening.
func HealthCheck(
	ctx context.Context,
	circuitsToCheck []TorStruct, // Expects a slice of tor.TorStruct
	listenHost string,
) []HealthStatus { // Returns a slice of tor.HealthStatus
	log.Printf("INFO: [healthcheck] Starting health check for %d circuits", len(circuitsToCheck))
	statuses := make([]HealthStatus, 0, len(circuitsToCheck))

	var wg sync.WaitGroup
	resultsChan := make(chan HealthStatus, len(circuitsToCheck))

	for _, circuit := range circuitsToCheck {
		wg.Add(1)
		go func(c TorStruct) { // c is a copy of TorStruct
			defer wg.Done()
			
			status := HealthStatus{ 
				CircuitIdentifier: c.Port, 
				IsHealthy:         true, // Assume healthy initially
				CheckedAt:         time.Now(),
				OriginalPort:      c.Port,
				OriginalIPAddr:    c.IPAddr,
				OriginalCountry:   c.Country,
			}
			
			checkCtx, cancel := context.WithTimeout(ctx, 20*time.Second) 
			defer cancel()

			socksDialer, err := proxy.SOCKS5("tcp", listenHost+":"+c.Port, nil, &net.Dialer{
				Timeout: 10 * time.Second, 
			})
			if err != nil {
				log.Printf("ERROR: [healthcheck] SOCKS5 dialer creation for %s (Port: %s) failed: %v", c.IPAddr, c.Port, err)
				status.IsHealthy = false
				status.Error = err
				resultsChan <- status
				return
			}
			
			tr := &http.Transport{
				DialContext: func(ctxDial context.Context, network, addr string) (net.Conn, error) {
					return socksDialer.Dial(network, addr) 
				},
			}
			httpClient := &http.Client{Transport: tr, Timeout: 10 * time.Second} 

			// CurlWithContext is defined in this 'tor' package (in tor.go)
			_, res, errCurl := CurlWithContext(checkCtx, httpClient, ifconfigURL) 

			if errCurl != nil || res == nil || res.StatusCode != http.StatusOK {
				errMsg := "unknown error"
				statusCode := 0
				if errCurl != nil {
					errMsg = errCurl.Error()
				} else if res == nil {
					errMsg = "nil response"
				} else {
					statusCode = res.StatusCode
					errMsg = fmt.Sprintf("status %d", res.StatusCode)
				}
				
				log.Printf("INFO: [healthcheck] Circuit failed: IP %s, Port %s, Country %s, Error: %s, StatusCode: %d",
					c.IPAddr, c.Port, c.Country, errMsg, statusCode)
				status.IsHealthy = false
				status.Error = fmt.Errorf("circuit %s (Port: %s) failed: %s", c.IPAddr, c.Port, errMsg)
			} else {
				log.Printf("INFO: [healthcheck] Circuit OK: IP %s, Port %s, Country %s", c.IPAddr, c.Port, c.Country)
			}

			if res != nil && res.Body != nil {
				res.Body.Close()
			}
			resultsChan <- status
		}(circuit)
	}

	wg.Wait()
	close(resultsChan)

	for status := range resultsChan {
		statuses = append(statuses, status)
	}
	log.Printf("INFO: [healthcheck] Health check finished. Processed %d circuits.", len(statuses))
	return statuses
}

package test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/kashari/heimdall/router"
	"github.com/stretchr/testify/assert"
)

// Test high concurrency requests
func TestHighConcurrency(t *testing.T) {
	h := router.GjallarHorn()
	h.WithWorkerPool(50) // Enable worker pool

	h.GET("/fast", func(c *router.Context) {
		c.String(http.StatusOK, "OK")
	})

	var wg sync.WaitGroup
	client := &http.Client{Timeout: 2 * time.Second}
	server := httptest.NewServer(h)
	defer server.Close()

	numRequests := 1000
	wg.Add(numRequests)

	start := time.Now()
	for i := 0; i < numRequests; i++ {
		go func() {
			defer wg.Done()
			resp, err := client.Get(server.URL + "/fast")
			if err == nil {
				_, _ = io.ReadAll(resp.Body)
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	duration := time.Since(start)

	t.Logf("Handled %d parallel requests in %v", numRequests, duration)
}

// Test rate limiter under load
func TestRateLimiter(t *testing.T) {
	h := router.GjallarHorn().WithWorkerPool(20)
	h.WithRateLimiter(5, 1*time.Second) // Allow 5 requests per second

	h.GET("/limited", func(c *router.Context) {
		c.String(http.StatusOK, "Allowed")
	})

	client := &http.Client{Timeout: 2 * time.Second}
	server := httptest.NewServer(h)
	defer server.Close()

	allowed := 0
	blocked := 0
	for i := 0; i < 10; i++ {
		resp, err := client.Get(server.URL + "/limited")
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				allowed++
			} else if resp.StatusCode == http.StatusTooManyRequests {
				blocked++
			}
			resp.Body.Close()
		}
	}

	t.Logf("Rate limit test: %d allowed, %d blocked", allowed, blocked)
	assert.LessOrEqual(t, allowed, 5)
	assert.GreaterOrEqual(t, blocked, 5)
}

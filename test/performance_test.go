package test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kashari/heimdall/v2/router"
	"github.com/stretchr/testify/assert"
)

// Generate large JSON payload
func generateLargePayload(size int) []byte {
	return []byte(strings.Repeat("a", size))
}

// Test large payload handling
func TestLargePayload(t *testing.T) {
	h := router.GjallarHorn().WithWorkerPool(2)
	h.POST("/large", func(c *router.Context) {
		body := c.Body()
		c.JSON(http.StatusOK, map[string]int{"received_bytes": len(body)})
	})

	largePayload := generateLargePayload(1000000000) // 100MB JSON
	req := httptest.NewRequest("POST", "/large", bytes.NewReader(largePayload))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(rec, req)
	duration := time.Since(start)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"received_bytes":1000000000`)
	t.Logf("Handled 100MB payload in %v", duration)
}

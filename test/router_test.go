package test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kashari/heimdall/v2/router"
	"github.com/stretchr/testify/assert"
)

// Mock middleware for testing
func mockMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Middleware", "true")
		next(w, r)
	}
}

// Test static route matching
func TestStaticRoute(t *testing.T) {
	h := router.GjallarHorn().WithWorkerPool(10)
	h.GET("/hello", func(c *router.Context) {
		c.JSON(http.StatusOK, map[string]string{"message": "Hello, world!"})
	})

	req := httptest.NewRequest("GET", "/hello", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"message": "Hello, world!"}`, rec.Body.String())
}

// Test dynamic route matching
func TestDynamicRoute(t *testing.T) {
	h := router.GjallarHorn()
	h.GET("/user/:id", func(c *router.Context) {
		id := c.Param("id")
		c.JSON(http.StatusOK, map[string]string{"userID": id})
	})

	req := httptest.NewRequest("GET", "/user/123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"userID": "123"}`, rec.Body.String())
}

// Test middleware execution
func TestMiddlewareExecution(t *testing.T) {
	h := router.GjallarHorn()
	h.Use(mockMiddleware)

	h.GET("/middleware", func(c *router.Context) {
		c.String(http.StatusOK, "Middleware passed")
	})

	req := httptest.NewRequest("GET", "/middleware", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "true", rec.Header().Get("X-Test-Middleware"))
}

// Test query parameters
func TestQueryParams(t *testing.T) {
	h := router.GjallarHorn()
	h.GET("/search", func(c *router.Context) {
		params := c.Query()
		c.JSON(http.StatusOK, params)
	})

	req := httptest.NewRequest("GET", "/search?q=golang&limit=10", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	expected := `{"q":"golang","limit":"10"}`
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, expected, rec.Body.String())
}

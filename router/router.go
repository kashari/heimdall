package router

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-radix"
	"go.uber.org/zap"
)

// Middleware is a function that wraps an HTTP handler.
type Middleware func(http.HandlerFunc) http.HandlerFunc

// ctxKey is an unexported type for context keys within this package.
type ctxKey string

type Context struct {
	Writer  http.ResponseWriter
	Request *http.Request
}

// Param retrieves path variables stored in the request's context.
func (c *Context) Param(key string) string {
	if params, ok := c.Request.Context().Value(ctxKey("params")).(map[string]string); ok {
		return params[key]
	}
	return ""
}

// Query returns all query parameters.
func (c *Context) Query() map[string]interface{} {
	json := make(map[string]interface{})

	for key, vals := range c.Request.URL.Query() {
		if len(vals) > 0 {
			json[key] = vals[0]
		}
	}

	return json
}

func (c *Context) Body() []byte {
	body, _ := io.ReadAll(c.Request.Body)
	return body
}

func (c *Context) JsonBody() map[string]interface{} {
	jsonBody := make(map[string]interface{})
	json.NewDecoder(c.Request.Body).Decode(&jsonBody)
	return jsonBody
}

// QueryParam returns a specific query parameter by key.
func (c *Context) QueryParam(key string) string {
	return c.Request.URL.Query().Get(key)
}

// BindJSON decodes the request body JSON into a provided struct.
func (c *Context) BindJSON(v interface{}) error {
	return json.NewDecoder(c.Request.Body).Decode(v)
}

// JSON sends a JSON response.
func (c *Context) JSON(status int, data interface{}) {
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(status)
	json.NewEncoder(c.Writer).Encode(data)
}

func (c *Context) String(status int, data string) {
	c.Writer.Header().Set("Content-Type", "text/plain")
	c.Writer.WriteHeader(status)
	c.Writer.Write([]byte(data))
}

// paramsKey is the key under which URL parameters are stored in the request context.
const paramsKey ctxKey = "params"

// route represents a registered route.
type route struct {
	method  string
	pattern string // e.g., "/users/:id"
	handler http.HandlerFunc
}

// Router is our high-performance HTTP router.
type Router struct {
	staticRoutes  *radix.Tree  // static routes stored by exact path
	dynamicRoutes []route      // routes with parameters (e.g., ":id")
	middlewares   []Middleware // middleware chain
	logger        *zap.Logger  // high-performance logger
	workerPool    *WorkerPool  // optional concurrent worker pool for handling requests
	rateLimiter   *RateLimiter // optional rate limiter on the critical path
}

// NewRouter initializes and returns a new Router.
func GjallarHorn() *Router {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	return &Router{
		staticRoutes:  radix.New(),
		dynamicRoutes: make([]route, 0),
		middlewares:   []Middleware{},
		logger:        logger,
	}
}

// Use adds a middleware to the chain.
func (r *Router) Use(m Middleware) *Router {
	r.middlewares = append(r.middlewares, m)
	return r
}

// WithWorkerPool configures the router to use a worker pool with the specified number of workers.
func (r *Router) WithWorkerPool(poolSize int) *Router {
	r.workerPool = NewWorkerPool(poolSize)
	return r
}

// WithRateLimiter configures the router to use a rate limiter.
func (r *Router) WithRateLimiter(maxTokens int, refillInterval time.Duration) *Router {
	r.rateLimiter = NewRateLimiter(maxTokens, refillInterval)
	return r
}

// Handle registers a new route with the given HTTP method, pattern, and handler.
// Static routes (without parameters) are stored in the radix tree for fast lookup.
func (r *Router) Handle(method, pattern string, handler http.HandlerFunc) *Router {
	rt := route{
		method:  method,
		pattern: pattern,
		handler: handler,
	}
	if !strings.ContainsAny(pattern, ":*") {
		r.staticRoutes.Insert(pattern, rt)
	} else {
		r.dynamicRoutes = append(r.dynamicRoutes, rt)
	}
	return r
}

func (h *Router) HandleFunc(method, pattern string, handler func(*Context)) *Router {
	// h.Handle(method, pattern, func(w http.ResponseWriter, r *http.Request) {
	// 	ctx := &Context{Writer: w, Request: r}
	// 	handler(ctx)
	// })
	rt := route{
		method:  method,
		pattern: pattern,
		handler: func(w http.ResponseWriter, r *http.Request) {
			ctx := &Context{Writer: w, Request: r}
			handler(ctx)
		},
	}

	if !strings.ContainsAny(pattern, ":*") {
		h.staticRoutes.Insert(pattern, rt)
	} else {
		h.dynamicRoutes = append(h.dynamicRoutes, rt)
	}

	return h
}

func (h *Router) GET(pattern string, handler func(*Context)) *Router {
	return h.HandleFunc("GET", pattern, handler)
}

// POST registers a route for HTTP POST requests.
func (r *Router) POST(pattern string, handler func(*Context)) *Router {
	return r.HandleFunc(http.MethodPost, pattern, handler)
}

// PUT registers a route for HTTP PUT requests.
func (r *Router) PUT(pattern string, handler func(*Context)) *Router {
	return r.HandleFunc(http.MethodPut, pattern, handler)
}

// DELETE registers a route for HTTP DELETE requests.
func (r *Router) DELETE(pattern string, handler func(*Context)) *Router {
	return r.HandleFunc(http.MethodDelete, pattern, handler)
}

// ServeHTTP implements http.Handler. It matches incoming requests to registered routes,
// applies middleware, rate limiting, and optional worker pooling.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	r.logger.Info("Incoming request",
		zap.String("method", req.Method),
		zap.String("url", req.URL.Path))

	// Attempt static (exact) route lookup.
	if val, found := r.staticRoutes.Get(req.URL.Path); found {
		rt := val.(route)
		if rt.method == req.Method {
			r.executeHandler(w, req, rt.handler)
			r.logger.Info("Served static route", zap.Duration("duration", time.Since(start)))
			return
		}
		w.Header().Set("Allow", rt.method)
		http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
		r.logger.Info("Method not allowed (static)", zap.Duration("duration", time.Since(start)))
		return
	}

	// Fallback: iterate over dynamic routes.
	for _, rt := range r.dynamicRoutes {
		if params, ok := matchPattern(rt.pattern, req.URL.Path); ok && rt.method == req.Method {
			ctx := context.WithValue(req.Context(), paramsKey, params)
			r.executeHandler(w, req.WithContext(ctx), rt.handler)
			r.logger.Info("Served dynamic route", zap.Duration("duration", time.Since(start)))
			return
		}
	}

	http.NotFound(w, req)
	r.logger.Info("Route not found", zap.Duration("duration", time.Since(start)))
}

// executeHandler builds the middleware chain, applies rate limiting,
// and dispatches the request either directly or via the worker pool.
// If a worker pool is used, it waits for the handler to finish before returning.
func (r *Router) executeHandler(w http.ResponseWriter, req *http.Request, handler http.HandlerFunc) {
	// Build the final handler by wrapping with middleware.
	finalHandler := handler
	for i := len(r.middlewares) - 1; i >= 0; i-- {
		finalHandler = r.middlewares[i](finalHandler)
	}

	// Check rate limiting.
	if r.rateLimiter != nil && !r.rateLimiter.Allow() {
		http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// If using the worker pool, wait for the handler to complete before returning.
	if r.workerPool != nil {
		var done sync.WaitGroup
		done.Add(1)
		r.workerPool.Submit(func() {
			finalHandler(w, req)
			done.Done()
		})
		done.Wait()
	} else {
		finalHandler(w, req)
	}
}

// Start launches the HTTP server on the specified port with defined timeouts.
func (r *Router) Start(port string) error {
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		IdleTimeout:  90 * time.Second,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	r.logger.Info("Starting server on port " + port)
	return server.ListenAndServe()
}

// matchPattern compares a route pattern (e.g., "/user/:id") with a request path.
// It extracts parameters and returns them if the path matches the pattern.
func matchPattern(pattern, path string) (map[string]string, bool) {
	patternParts := splitPath(pattern)
	pathParts := splitPath(path)
	if len(patternParts) != len(pathParts) {
		return nil, false
	}
	params := make(map[string]string)
	for i, part := range patternParts {
		if len(part) > 0 && part[0] == ':' {
			// Dynamic segment: capture parameter.
			key := part[1:]
			params[key] = pathParts[i]
		} else if part != pathParts[i] {
			return nil, false
		}
	}
	return params, true
}

// splitPath splits a URL path into segments, ignoring empty segments.
func splitPath(path string) []string {
	return strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
}

// WorkerPool manages a pool of worker goroutines to execute tasks concurrently.
type WorkerPool struct {
	tasks chan func()
	wg    sync.WaitGroup
}

// NewWorkerPool creates a new WorkerPool with the specified number of workers.
func NewWorkerPool(size int) *WorkerPool {
	wp := &WorkerPool{
		tasks: make(chan func(), size),
	}
	for i := 0; i < size; i++ {
		go wp.worker()
	}
	return wp
}

// worker is the function run by each worker goroutine.
func (wp *WorkerPool) worker() {
	for task := range wp.tasks {
		task()
		wp.wg.Done()
	}
}

// Submit enqueues a task to be executed by the worker pool.
func (wp *WorkerPool) Submit(task func()) {
	wp.wg.Add(1)
	wp.tasks <- task
}

// Shutdown gracefully shuts down the worker pool by waiting for all tasks to complete
// and then closing the task channel.
func (wp *WorkerPool) Shutdown() {
	wp.wg.Wait()
	close(wp.tasks)
}

// RateLimiter implements a simple token bucket rate limiter.
type RateLimiter struct {
	tokens         int
	maxTokens      int
	mu             sync.Mutex
	refillInterval time.Duration
	quit           chan struct{}
}

// NewRateLimiter creates a new RateLimiter with the specified maximum tokens and refill interval.
func NewRateLimiter(maxTokens int, refillInterval time.Duration) *RateLimiter {
	rl := &RateLimiter{
		tokens:         maxTokens,
		maxTokens:      maxTokens,
		refillInterval: refillInterval,
		quit:           make(chan struct{}),
	}
	go rl.refillTokens()
	return rl
}

// refillTokens periodically refills tokens up to the maximum allowed.
func (rl *RateLimiter) refillTokens() {
	ticker := time.NewTicker(rl.refillInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			if rl.tokens < rl.maxTokens {
				rl.tokens++
			}
			rl.mu.Unlock()
		case <-rl.quit:
			return
		}
	}
}

// Allow checks if a request is allowed under the current rate limit.
// It returns true and decrements a token if available.
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}

// Stop stops the token refill goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.quit)
}

package router

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-radix"
)

// Middleware is a function that wraps an HTTP handler.
type Middleware func(http.HandlerFunc) http.HandlerFunc

// ctxKey is an unexported type for context keys.
type ctxKey string

// Context wraps the http response and request, and provides utility methods.
type Context struct {
	Writer  http.ResponseWriter
	Request *http.Request
}

// Param retrieves a path parameter from the request context.
func (c *Context) Param(key string) string {
	if params, ok := c.Request.Context().Value(ctxKey("params")).(map[string]string); ok {
		return params[key]
	}
	return ""
}

// ParamInt converts the parameter value to an int.
func (c *Context) ParamInt(key string) (int, error) {
	return strconv.Atoi(c.Param(key))
}

// ParamInt64 converts the parameter value to an int64.
func (c *Context) ParamInt64(key string) (int64, error) {
	return strconv.ParseInt(c.Param(key), 10, 64)
}

// ParamFloat64 converts the parameter value to a float64.
func (c *Context) ParamFloat64(key string) (float64, error) {
	return strconv.ParseFloat(c.Param(key), 64)
}

// ParamBool converts the parameter value to a bool.
func (c *Context) ParamBool(key string) (bool, error) {
	return strconv.ParseBool(c.Param(key))
}

// Query returns all query parameters.
func (c *Context) Query() map[string]interface{} {
	q := make(map[string]interface{})
	for key, vals := range c.Request.URL.Query() {
		if len(vals) > 0 {
			q[key] = vals[0]
		}
	}
	return q
}

// Body returns the request body as bytes.
func (c *Context) Body() []byte {
	body, _ := io.ReadAll(c.Request.Body)
	return body
}

// JsonBody decodes the request body into a map.
func (c *Context) JsonBody() map[string]interface{} {
	var body map[string]interface{}
	json.NewDecoder(c.Request.Body).Decode(&body)
	return body
}

// QueryParam returns a single query parameter.
func (c *Context) QueryParam(key string) string {
	return c.Request.URL.Query().Get(key)
}

// BindJSON binds the request JSON to a given struct.
func (c *Context) BindJSON(v interface{}) error {
	return json.NewDecoder(c.Request.Body).Decode(v)
}

// JSON sends a JSON response.
func (c *Context) JSON(status int, data interface{}) {
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(status)
	json.NewEncoder(c.Writer).Encode(data)
}

// String sends a plain text response.
func (c *Context) String(status int, data string) {
	c.Writer.Header().Set("Content-Type", "text/plain")
	c.Writer.WriteHeader(status)
	c.Writer.Write([]byte(data))
}

// paramsKey is the key under which URL parameters are stored.
const paramsKey ctxKey = "params"

// route represents a registered route.
type route struct {
	method  string
	pattern string // e.g., "/users/:id"
	handler http.HandlerFunc
}

// Router is our HTTP router with integrated logging.
type Router struct {
	staticRoutes  *radix.Tree  // static routes stored by exact path
	dynamicRoutes []route      // routes with parameters (e.g., ":id")
	middlewares   []Middleware // middleware chain
	workerPool    *WorkerPool  // optional worker pool for concurrent handling
	rateLimiter   *RateLimiter // optional rate limiter on the critical path
}

// GjallarHorn initializes and returns a new Router with the integrated logger.
// It also prints the HEIMDALL logo and initial startup information.
func GjallarHorn() *Router {
	r := &Router{
		staticRoutes:  radix.New(),
		dynamicRoutes: make([]route, 0),
		middlewares:   []Middleware{},
	}
	r.printStartupInfo()
	return r
}

// Use adds a middleware to the chain.
func (r *Router) Use(m Middleware) *Router {
	r.middlewares = append(r.middlewares, m)
	return r
}

// WithWorkerPool configures the router to use a worker pool.
func (r *Router) WithWorkerPool(poolSize int) *Router {
	r.workerPool = NewWorkerPool(poolSize)
	return r
}

// WithRateLimiter configures the router to use a rate limiter.
func (r *Router) WithRateLimiter(maxTokens int, refillInterval time.Duration) *Router {
	r.rateLimiter = NewRateLimiter(maxTokens, refillInterval)
	return r
}

// WithFileLogging configures the router to log to the specified file in addition to the console.
// If the file cannot be opened, it logs an error and leaves the existing logger intact.
func (r *Router) WithFileLogging(filePath string) *Router {
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		r.Error("Failed to open log file")
		return r
	}

	tee := io.MultiWriter(os.Stdout, f)

	//append the console text to the file using no zap
	log.SetOutput(tee)
	return r
}

// Handle registers a new route.
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

// HandleFunc registers a route using a Context-based handler.
func (r *Router) HandleFunc(method, pattern string, handler func(*Context)) *Router {
	rt := route{
		method:  method,
		pattern: pattern,
		handler: func(w http.ResponseWriter, req *http.Request) {
			ctx := &Context{Writer: w, Request: req}
			handler(ctx)
		},
	}
	if !strings.ContainsAny(pattern, ":*") {
		r.staticRoutes.Insert(pattern, rt)
	} else {
		r.dynamicRoutes = append(r.dynamicRoutes, rt)
	}
	return r
}

func (r *Router) GET(pattern string, handler func(*Context)) *Router {
	return r.HandleFunc("GET", pattern, handler)
}

func (r *Router) POST(pattern string, handler func(*Context)) *Router {
	return r.HandleFunc(http.MethodPost, pattern, handler)
}

func (r *Router) PUT(pattern string, handler func(*Context)) *Router {
	return r.HandleFunc(http.MethodPut, pattern, handler)
}

func (r *Router) DELETE(pattern string, handler func(*Context)) *Router {
	return r.HandleFunc(http.MethodDelete, pattern, handler)
}

// ListRoutes returns a slice of strings describing all registered routes.
func (r *Router) ListRoutes() []string {
	var routes []string
	r.staticRoutes.Walk(func(path string, v interface{}) bool {
		rt := v.(route)
		routes = append(routes, rt.method+" "+rt.pattern)
		return false
	})
	for _, rt := range r.dynamicRoutes {
		routes = append(routes, rt.method+" "+rt.pattern)
	}
	return routes
}

// ServeHTTP implements http.Handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	start := time.Now()

	if val, found := r.staticRoutes.Get(req.URL.Path); found {
		rt := val.(route)
		if rt.method == req.Method {
			r.executeHandler(w, req, rt.handler)
			r.Infof("(STATIC ROUTE) Request: %s %s, from: %s completed in %s", req.Method, req.URL.Path, req.RemoteAddr, time.Since(start))
			return
		}
		w.Header().Set("Allow", rt.method)
		http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
		r.Warnf("Method not allowed (static) %s", time.Since(start).String())
		return
	}

	for _, rt := range r.dynamicRoutes {
		if params, ok := matchPattern(rt.pattern, req.URL.Path); ok && rt.method == req.Method {
			ctx := context.WithValue(req.Context(), paramsKey, params)
			r.executeHandler(w, req.WithContext(ctx), rt.handler)
			r.Infof("(DYNAMIC ROUTE) Request: %s %s, from: %s completed in %s", req.Method, req.URL.Path, req.RemoteAddr, time.Since(start))
			return
		}
	}

	http.NotFound(w, req)
	r.Warnf("Route not found %s", time.Since(start).String())
}

func (r *Router) executeHandler(w http.ResponseWriter, req *http.Request, handler http.HandlerFunc) {
	finalHandler := handler
	for i := len(r.middlewares) - 1; i >= 0; i-- {
		finalHandler = r.middlewares[i](finalHandler)
	}

	if r.rateLimiter != nil && !r.rateLimiter.Allow() {
		http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
		return
	}

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

// Start launches the HTTP server on the specified port after printing full configuration.
func (r *Router) Start(port string) error {
	r.printConfiguration()
	r.Infof("Starting server in port %s", port)
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		IdleTimeout:  90 * time.Second,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	return server.ListenAndServe()
}

// printStartupInfo prints the HEIMDALL logo at router initialization.
func (r *Router) printStartupInfo() {
	// A large, well-formatted HEIMDALL logo.
	logo := `
	.__           .__             .___      .__  .__   
	|  |__   ____ |__| _____    __| _/____  |  | |  |  
	|  |  \_/ __ \|  |/     \  / __ |\__  \ |  | |  |  
	|   Y  \  ___/|  |  Y Y  \/ /_/ | / __ \|  |_|  |__
	|___|  /\___  >__|__|_|  /\____ |(____  /____/____/
		 \/     \/         \/      \/     \/           	

             𝑯𝑬𝑰𝑴𝑫𝑨𝑳𝑳 -> HIGH PERFORMANCE HTTP ROUTER
    `
	log.Printf("%s\n", logo)
}

// printConfiguration logs all startup configuration details.
func (r *Router) printConfiguration() {
	// Log registered routes.
	r.Info("-------------------------- Registered Routes ---------------------------")
	r.Info("--")
	for _, rt := range r.ListRoutes() {
		r.Info("Route " + rt)
	}
	r.Info("--")
	r.Info("-------------------------- Registered Routes ---------------------------")

	// Rate limiter configuration.
	if r.rateLimiter != nil {
		r.Infof("Rate Limiter Configuration MAX_TOKENS: %d REFILL_INTERVAL: %s", r.rateLimiter.maxTokens, r.rateLimiter.refillInterval)
	} else {
		r.Info("Rate Limiter not configured")
	}
	// Worker pool configuration.
	if r.workerPool != nil {
		r.Infof("Worker Pool Configuration SIZE: %d", r.workerPool.size)
	} else {
		r.Infof("Worker Pool not configured")
	}

	if len(r.middlewares) > 0 {
		r.Info("-------------------------- Middleware Chain ---------------------------")
		r.Info("--")
		for i, mw := range r.middlewares {
			r.Infof("Middleware %d: %s", i, getFunctionName(mw))
		}
		r.Info("--")
		r.Info("-------------------------- Middleware Chain ---------------------------")
	}

}

// matchPattern compares a route pattern with a request path.
func matchPattern(pattern, path string) (map[string]string, bool) {
	patternParts := splitPath(pattern)
	pathParts := splitPath(path)
	if len(patternParts) != len(pathParts) {
		return nil, false
	}
	params := make(map[string]string)
	for i, part := range patternParts {
		if len(part) > 0 && part[0] == ':' {
			key := part[1:]
			params[key] = pathParts[i]
		} else if part != pathParts[i] {
			return nil, false
		}
	}
	return params, true
}

// splitPath splits a URL path into non-empty segments.
func splitPath(path string) []string {
	return strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
}

// getFunctionName returns the name of a function (used for middleware identification).
func getFunctionName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

// WorkerPool manages a pool of goroutines.
type WorkerPool struct {
	tasks chan func()
	wg    sync.WaitGroup
	size  int
}

// NewWorkerPool creates a new worker pool with the given size.
func NewWorkerPool(size int) *WorkerPool {
	wp := &WorkerPool{
		tasks: make(chan func(), size),
		size:  size,
	}
	for i := 0; i < size; i++ {
		go wp.worker()
	}
	return wp
}

func (wp *WorkerPool) worker() {
	for task := range wp.tasks {
		task()
		wp.wg.Done()
	}
}

func (wp *WorkerPool) Submit(task func()) {
	wp.wg.Add(1)
	wp.tasks <- task
}

func (wp *WorkerPool) Shutdown() {
	wp.wg.Wait()
	close(wp.tasks)
}

// RateLimiter implements a token bucket rate limiter.
type RateLimiter struct {
	tokens         int
	maxTokens      int
	mu             sync.Mutex
	refillInterval time.Duration
	quit           chan struct{}
}

// NewRateLimiter creates a new rate limiter.
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

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}

func (rl *RateLimiter) Stop() {
	close(rl.quit)
}

func (r *Router) log(level string, message string) {
	switch level {
	case "info":
		log.Println(message)
	case "warn":
		log.Println(message)
	case "error":
		log.Println(message)
	case "debug":
		log.Println(message)
	default:
		log.Println(message)
	}
}

func (r *Router) Info(message string) {
	r.log("info", message)
}

func (r *Router) Warn(message string) {
	r.log("warn", message)
}

func (r *Router) Error(message string) {
	r.log("error", message)
}

func (r *Router) Debug(message string) {
	r.log("debug", message)
}

func (r *Router) Infof(format string, args ...interface{}) {
	r.Info(fmt.Sprintf(format, args...))
}

func (r *Router) Warnf(format string, args ...interface{}) {
	r.Warn(fmt.Sprintf(format, args...))
}

func (r *Router) Errorf(format string, args ...interface{}) {
	r.Error(fmt.Sprintf(format, args...))
}

func (r *Router) Debugf(format string, args ...interface{}) {
	r.Debug(fmt.Sprintf(format, args...))
}

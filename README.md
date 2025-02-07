# Heimdall

Heimdall is a fast and performant HTTP router designed specifically for REST APIs. It supports middleware, dynamic/static routing, an optional worker pool for request processing, and rate limiting.

## Features

- High-performance routing
- Middleware support
- Static and dynamic route matching
- Optional worker pool for concurrent request processing
- Rate limiting

## Installation

To install Heimdall, use `go get`:

```sh
go get github.com/kashari/heimdall
```

## Usage
### Basic Example

```go
package main

import (
    "net/http"
    "github.com/kashari/heimdall/router"
)

func main() {
    r := router.GjallarHorn()

    r.GET("/hello", func(w http.ResponseWriter, r *http.Request) {
        router.JSON(w, http.StatusOK, map[string]string{"message": "Hello, world!"})
    })

    http.ListenAndServe(":8080", r)
}
```

### Middleware

```go
package main

import (
    "net/http"
    "github.com/kashari/heimdall/router"
)

func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Log request details
        next(w, r)
    }
}

func main() {
    r := router.GjallarHorn()
    r.Use(loggingMiddleware)

    r.GET("/hello", func(w http.ResponseWriter, r *http.Request) {
        router.JSON(w, http.StatusOK, map[string]string{"message": "Hello, world!"})
    })

    http.ListenAndServe(":8080", r)
}
```

### Pooled Handling

```go
package main

import (
    "net/http"
    "github.com/kashari/heimdall/router"
)

func main() {
    r := router.GjallarHorn().WithWorkerPool(10)

    r.GET("/hello", func(w http.ResponseWriter, r *http.Request) {
        router.JSON(w, http.StatusOK, map[string]string{"message": "Hello, world!"})
    })

    http.ListenAndServe(":8080", r)
}
```

### Rate Limiting

```go
package main

import (
    "net/http"
    "time"
    "github.com/kashari/heimdall/router"
)

func main() {
    r := router.GjallarHorn().WithRateLimiter(5, 1*time.Second)

    r.GET("/limited", func(w http.ResponseWriter, r *http.Request) {
        router.JSON(w, http.StatusOK, map[string]string{"message": "Allowed"})
    })

    http.ListenAndServe(":8080", r)
}
```


### Tests



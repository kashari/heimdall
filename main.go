package main

import "github.com/kashari/heimdall/router"

func main() {
	heimdall := router.GjallarHorn().WithRateLimiter(100, 1).WithWorkerPool(20).WithFileLogging("heimdall.log")

	heimdall.GET("/ping", func(c *router.Context) {
		resp := map[string]string{"message": "pong"}
		c.JSON(200, resp)
	})

	heimdall.GET("/how-many-seconds-for-this-request/:nanos", func(c *router.Context) {
		nanos, err := c.ParamFloat64("nanos")
		if err != nil {
			c.JSON(400, map[string]string{"error": "nanos must be an integer"})
			return
		}
		resp := map[string]float64{"seconds": nanos / 1e9}
		c.JSON(200, resp)
	})

	heimdall.Start("8080")
}

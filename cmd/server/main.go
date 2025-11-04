package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	service := os.Getenv("SERVICE_NAME")
	if service == "" {
		service = "unknown-service"
	}

	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": service,
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	addr := fmt.Sprintf(":%s", port)
	log.Printf("✅ %s listening on %s", service, addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("❌ %s failed: %v", service, err)
	}
}

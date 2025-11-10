package config

import (
	"log"
	"os"
)

type Config struct {
    Port        string
    DatabaseURL string
    AuthBaseURL string
}

func Get() Config {
    cfg := Config{
        Port:        getenv("PORT", "8080"),
        DatabaseURL: getenv("DATABASE_URL", "postgres://postgres:postgres@postgres:5432/rentacompa?sslmode=disable"),
        AuthBaseURL: getenv("BACKEND_AUTH_URL", "http://rac-auth-service:8080"),
    }
    log.Printf("[user-svc] DB=%s", cfg.DatabaseURL)
    return cfg
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

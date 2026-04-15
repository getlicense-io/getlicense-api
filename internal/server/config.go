package server

import (
	"fmt"
	"os"
	"strings"

	"github.com/getlicense-io/getlicense-api/internal/crypto"
)

// Config holds the server configuration loaded from environment variables.
type Config struct {
	Host           string
	Port           string
	Environment    string
	DatabaseURL    string
	MasterKey      *crypto.MasterKey
	PublicBaseURL  string
	AllowedOrigins []string // F-008: CORS allowlist; required in prod, defaults to "*" in dev
}

// LoadConfig reads configuration from environment variables and validates the master key.
func LoadConfig() (*Config, error) {
	host := os.Getenv("GETLICENSE_HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	port := os.Getenv("GETLICENSE_PORT")
	if port == "" {
		port = "3000"
	}

	env := os.Getenv("GETLICENSE_ENV")
	if env == "" {
		env = "production"
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("server: DATABASE_URL is required")
	}

	masterKeyHex := os.Getenv("GETLICENSE_MASTER_KEY")
	if masterKeyHex == "" {
		return nil, fmt.Errorf("server: GETLICENSE_MASTER_KEY is required")
	}

	mk, err := crypto.NewMasterKey(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("server: invalid GETLICENSE_MASTER_KEY: %w", err)
	}

	publicBaseURL := os.Getenv("GETLICENSE_PUBLIC_BASE_URL")
	if publicBaseURL == "" {
		publicBaseURL = "http://localhost:3000"
	}

	// F-008: CORS allowlist. In development, default to "*" so local
	// dashboards and e2e tools can hit the API from any origin. In
	// production, require GETLICENSE_ALLOWED_ORIGINS to be set
	// explicitly — shipping a wildcard to prod is a misconfig.
	var allowedOrigins []string
	if raw := os.Getenv("GETLICENSE_ALLOWED_ORIGINS"); raw != "" {
		for _, origin := range strings.Split(raw, ",") {
			trimmed := strings.TrimSpace(origin)
			if trimmed != "" {
				allowedOrigins = append(allowedOrigins, trimmed)
			}
		}
	}
	isDev := strings.EqualFold(env, "development")
	if len(allowedOrigins) == 0 {
		if !isDev {
			return nil, fmt.Errorf("server: GETLICENSE_ALLOWED_ORIGINS is required in production — set to a comma-separated allowlist like 'https://dashboard.example.com'")
		}
		allowedOrigins = []string{"*"}
	}

	return &Config{
		Host:           host,
		Port:           port,
		Environment:    env,
		DatabaseURL:    dbURL,
		MasterKey:      mk,
		PublicBaseURL:  publicBaseURL,
		AllowedOrigins: allowedOrigins,
	}, nil
}

// IsDevelopment returns true when the server is running in development mode.
func (c *Config) IsDevelopment() bool {
	return strings.EqualFold(c.Environment, "development")
}

// ListenAddr returns the address the server should listen on (e.g. "0.0.0.0:3000").
func (c *Config) ListenAddr() string {
	return c.Host + ":" + c.Port
}

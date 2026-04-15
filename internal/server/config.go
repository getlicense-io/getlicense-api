package server

import (
	"fmt"
	"os"
	"strings"

	"github.com/getlicense-io/getlicense-api/internal/crypto"
)

// Config holds the server configuration loaded from environment variables.
type Config struct {
	Host          string
	Port          string
	Environment   string
	DatabaseURL   string
	MasterKey     *crypto.MasterKey
	PublicBaseURL string
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

	return &Config{
		Host:          host,
		Port:          port,
		Environment:   env,
		DatabaseURL:   dbURL,
		MasterKey:     mk,
		PublicBaseURL: publicBaseURL,
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

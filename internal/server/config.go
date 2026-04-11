package server

import (
	"fmt"
	"os"
	"strings"

	"github.com/getlicense-io/getlicense-api/internal/crypto"
)

// Config holds the server configuration loaded from environment variables.
type Config struct {
	Host        string
	Port        string
	Environment string
	DatabaseURL string
	MasterKey   *crypto.MasterKey
}

// LoadConfig reads configuration from environment variables and validates the master key.
func LoadConfig() (*Config, error) {
	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = "development"
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("server: DATABASE_URL is required")
	}

	masterKeyHex := os.Getenv("MASTER_KEY")
	if masterKeyHex == "" {
		return nil, fmt.Errorf("server: MASTER_KEY is required")
	}

	mk, err := crypto.NewMasterKey(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("server: invalid MASTER_KEY: %w", err)
	}

	return &Config{
		Host:        host,
		Port:        port,
		Environment: env,
		DatabaseURL: dbURL,
		MasterKey:   mk,
	}, nil
}

// IsDevelopment returns true when the server is running in development mode.
func (c *Config) IsDevelopment() bool {
	return strings.EqualFold(c.Environment, "development")
}

// ListenAddr returns the address the server should listen on (e.g. "0.0.0.0:8080").
func (c *Config) ListenAddr() string {
	return c.Host + ":" + c.Port
}

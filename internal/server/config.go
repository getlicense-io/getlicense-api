package server

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/getlicense-io/getlicense-api/internal/crypto"
)

// Config holds the server configuration loaded from environment variables.
type Config struct {
	Host                    string
	Port                    string
	Environment             string
	DatabaseURL             string
	MasterKey               *crypto.MasterKey
	DefaultValidationTTLSec int // P3 — server default for effective validation_ttl_sec; env var GETLICENSE_DEFAULT_VALIDATION_TTL_SEC
	PublicBaseURL           string
	// DashboardURL is the public origin of the web dashboard used to
	// construct invitation accept URLs. Defaults to http://localhost:3001
	// in development. Production must set GETLICENSE_DASHBOARD_URL.
	DashboardURL   string
	AllowedOrigins []string // F-008: CORS allowlist; required in prod, defaults to "*" in dev
	// EventsCSVMaxRows is the hard cap on rows for a CSV export from
	// GET /v1/events?format=csv. Exceeding it returns 413 export_too_large
	// BEFORE streaming. Default 100_000; range 1_000 <= N <= 1_000_000.
	// Env var: GETLICENSE_EVENTS_CSV_MAX_ROWS.
	EventsCSVMaxRows int
	// MailerKind selects the invitation email backend. Values:
	//   "log"  — DEV ONLY. LogMailer writes the raw accept_url to slog.
	//            Refused in production at startup.
	//   "noop" — Accepts the call without delivery or URL logging.
	//            Production default until a real mailer is wired.
	//
	// Env var: GETLICENSE_MAILER. Defaults: "log" in development, "noop"
	// in production.
	MailerKind string
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

	defaultTTL := 3600
	if raw := os.Getenv("GETLICENSE_DEFAULT_VALIDATION_TTL_SEC"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("server: GETLICENSE_DEFAULT_VALIDATION_TTL_SEC must be an integer: %w", err)
		}
		if n < 60 || n > 2_592_000 {
			return nil, fmt.Errorf("server: GETLICENSE_DEFAULT_VALIDATION_TTL_SEC must be between 60 and 2592000 (got %d)", n)
		}
		defaultTTL = n
	}

	isDev := strings.EqualFold(env, "development")

	publicBaseURL := os.Getenv("GETLICENSE_PUBLIC_BASE_URL")
	if publicBaseURL == "" {
		if !isDev {
			return nil, fmt.Errorf("server: GETLICENSE_PUBLIC_BASE_URL is required in production — set to the public origin clients use, e.g. 'https://api.example.com'")
		}
		publicBaseURL = "http://localhost:3000"
	}
	if !isDev {
		if err := validateProductionURL("GETLICENSE_PUBLIC_BASE_URL", publicBaseURL); err != nil {
			return nil, err
		}
	}

	dashboardURL := os.Getenv("GETLICENSE_DASHBOARD_URL")
	if dashboardURL == "" {
		if !isDev {
			return nil, fmt.Errorf("server: GETLICENSE_DASHBOARD_URL is required in production — set to the dashboard origin used to build invitation accept URLs, e.g. 'https://dashboard.example.com'")
		}
		dashboardURL = "http://localhost:3001"
	}
	if !isDev {
		if err := validateProductionURL("GETLICENSE_DASHBOARD_URL", dashboardURL); err != nil {
			return nil, err
		}
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
	if len(allowedOrigins) == 0 {
		if !isDev {
			return nil, fmt.Errorf("server: GETLICENSE_ALLOWED_ORIGINS is required in production — set to a comma-separated allowlist like 'https://dashboard.example.com'")
		}
		allowedOrigins = []string{"*"}
	}

	eventsCSVMax := 100_000
	if raw := os.Getenv("GETLICENSE_EVENTS_CSV_MAX_ROWS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("server: GETLICENSE_EVENTS_CSV_MAX_ROWS must be an integer: %w", err)
		}
		if n < 1_000 || n > 1_000_000 {
			return nil, fmt.Errorf("server: GETLICENSE_EVENTS_CSV_MAX_ROWS must be between 1000 and 1000000 (got %d)", n)
		}
		eventsCSVMax = n
	}

	mailerKind := os.Getenv("GETLICENSE_MAILER")
	if mailerKind == "" {
		if isDev {
			mailerKind = "log"
		} else {
			mailerKind = "noop"
		}
	}
	switch mailerKind {
	case "log", "noop":
		// ok
	default:
		return nil, fmt.Errorf("server: GETLICENSE_MAILER must be 'log' or 'noop', got %q", mailerKind)
	}
	if mailerKind == "log" && !isDev {
		return nil, fmt.Errorf("server: GETLICENSE_MAILER=log is forbidden in production — it leaks invitation tokens to logs. Use 'noop' until a real mailer is wired")
	}

	return &Config{
		Host:                    host,
		Port:                    port,
		Environment:             env,
		DatabaseURL:             dbURL,
		MasterKey:               mk,
		DefaultValidationTTLSec: defaultTTL,
		PublicBaseURL:           publicBaseURL,
		DashboardURL:            dashboardURL,
		AllowedOrigins:          allowedOrigins,
		EventsCSVMaxRows:        eventsCSVMax,
		MailerKind:              mailerKind,
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

// validateProductionURL enforces the production URL contract for
// GETLICENSE_PUBLIC_BASE_URL and GETLICENSE_DASHBOARD_URL: the value
// MUST parse as a URL, MUST use the https:// scheme, and MUST NOT
// point at localhost / loopback / unspecified addresses. The envName
// is used in error messages to make misconfigurations diagnose-able.
func validateProductionURL(envName, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("server: %s is not a valid URL: %w", envName, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("server: %s must use https:// in production (got %q)", envName, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("server: %s must include a hostname (got %q)", envName, raw)
	}
	lowerHost := strings.ToLower(host)
	switch {
	case lowerHost == "localhost",
		lowerHost == "127.0.0.1",
		lowerHost == "0.0.0.0",
		lowerHost == "::1",
		strings.HasSuffix(lowerHost, ".localhost"):
		return fmt.Errorf("server: %s must not point at localhost in production (got %q)", envName, host)
	}
	return nil
}

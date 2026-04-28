// Package server wires the Fiber HTTP application: route
// registration (split by concern across routes_*.go), middleware
// (RequireAuth dual-mode, ResolveGrant, rate limits, API-key scope),
// thin handler adapters under handler/, the background sweep loop
// (license expiry, lease decay, grant expiry, JWT revocation
// cleanup, webhook fan-out), and the request/response shaping that
// connects HTTP to the service layer.
package server

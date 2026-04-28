// Package auth handles identity authentication: signup, login (with
// optional TOTP step 2), refresh-token rotation, account switching,
// logout, and the API key lifecycle. TOTP verification is delegated
// to internal/identity; this package owns the session/token surface.
package auth

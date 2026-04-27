#!/usr/bin/env sh
set -eu

matches="$(rg -n --pcre2 --glob '*.go' --glob '!internal/db/sqlc/gen/**' --glob '!vendor/**' '^[^/\n]*\.Bind\(\)\.Body\(' . || true)"
if [ -n "$matches" ]; then
  printf '%s\n' "Direct c.Bind().Body() calls are forbidden in JSON write handlers. Use bindStrict instead:"
  printf '%s\n' "$matches"
  exit 1
fi

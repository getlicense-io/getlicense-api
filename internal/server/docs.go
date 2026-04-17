package server

import (
	"github.com/gofiber/contrib/v3/swaggerui"
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/api"
)

// registerDocs mounts Swagger UI at /docs on the given app, serving
// the embedded OpenAPI spec from the api package.
//
// Registration MUST happen before securityHeadersMiddleware in app.go
// so the strict Content-Security-Policy (default-src 'none') applied
// to the JSON API does not reach the docs page, which requires inline
// styles, scripts, and XHR to work. The middleware only matches
// /docs*; every other request falls through to the normal chain with
// CSP intact.
func registerDocs(app *fiber.App) {
	app.Use(swaggerui.New(swaggerui.Config{
		BasePath:    "/",
		Path:        "docs",
		FileContent: api.OpenAPISpec,
		Title:       "GetLicense API",
		CacheAge:    3600,
	}))
}

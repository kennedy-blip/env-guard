# EnvGuard

EnvGuard validates environment-variable bundles against service contracts before deployment. It masks values in API responses, checks required keys and format rules, flags production-inappropriate settings, and produces a readiness verdict.

## Stack
- Go 1.23 standard-library API (Vercel Go Functions)
- Semantic HTML, CSS, and vanilla ES modules in `public/`
- No Node.js, TypeScript, or frontend build step

## Local development
```sh
go run ./cmd/server
``
The small local server is optional; Vercel serves the static frontend and routes API requests through `api/router.go`.

For a quick local API smoke test without the optional server, use:
```sh
go test ./...
go vet ./api/...
``

## Vercel deployment
Import this repository into Vercel. Keep the project root as the Root Directory. The static site is in `public/`; `vercel.json` routes `/api/*` to the Go router function. No build command or Node install is required.

## API
- `GET /api/health`
- `GET /api/templates`
- `POST /api/templates` (in-memory custom contracts; serverless instances are ephemeral)
- `POST /api/validate`

Validation is a safety aid, not a guarantee that a deployment is secure. Never paste production credentials into a browser-based validator. Values are masked in responses, but the request still travels to the server. Use synthetic or rotated test values and keep real secrets in your secret manager.

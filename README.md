# Aegis Http Caddy Module

This module implements the **Zero Trust Aegis Http** protocol directly inside the Caddy Web Server as an HTTP middleware. 
Instead of implementing encryption and authentication individually for GoFiber, PHP, Laravel, or Node.js backends, this Caddy middleware sits in front as a Reverse Proxy. It seamlessly decrypts encrypted E2E requests and transparently encrypts plain HTTP responses using the client's PGP OpenPGP keys.

By using this module, **any programming language or backend framework instantly becomes a Zero Trust endpoint.**

## Prerequisites
- [Go](https://go.dev/) (1.20+)
- [xcaddy](https://github.com/caddyserver/xcaddy) for custom Caddy builds

## Installation & Build
Because Caddy plugins are compiled into Caddy itself, you must create a custom Caddy build:

1. Install `xcaddy`:
   ```bash
   go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
   ```

2. Build Caddy with the Aegis Http Module:
   ```bash
   xcaddy build --with github.com/AegisHttp/caddy-aegis=/path/to/caddy-aegis
   ```
   *(If this repository is pushed to GitHub, you will simply run `xcaddy build --with github.com/AegisHttp/caddy-aegis`)*

3. Verify the module was included:
   ```bash
   ./caddy list-modules | grep aegis_http
   ```

## Configuration (Caddyfile)

```caddyfile
{
    order aegis_http before reverse_proxy
}

:8080 {
    # Aegis HTTP Endpoint
    route {
        aegis_http {
            challenge_path /api/challenge
            login_path /api/login
            decrypt_requests
            encrypt_responses
            require_keyserver
            check_revocation
            tunneling_enabled
            server_email "api@example.com"
            server_passphrase "secret"
            server_private_key_path "/etc/caddy/server_private.asc"
            server_public_key_path "/etc/caddy/server_public.asc"
        }

        # Any Backend
        reverse_proxy localhost:3000
    }
}
```

## Configuration (JSON API)

Caddy natively uses JSON. If you prefer `caddy.json` or you're managing Caddy via its REST API instead of the `Caddyfile`, you can structure your route like this:

```json
{
  "handle": [
    {
      "handler": "headers",
      "response": {
        "set": {
          "Access-Control-Allow-Origin": ["*"],
          "Access-Control-Allow-Methods": ["GET", "POST", "OPTIONS"],
          "Access-Control-Allow-Headers": ["Origin", "Content-Type", "Accept", "x-gpg-id", "x-gpg-session-token", "x-gpg-signature", "x-gpg-encrypted", "x-gpg-tunnel"],
          "Access-Control-Expose-Headers": ["x-gpg-server-id", "x-gpg-support", "x-gpg-encrypted", "x-gpg-session-token"]
        }
      }
    },
    {
      "handler": "aegis_http",
      "challenge_path": "/api/challenge",
      "login_path": "/api/login",
      "decrypt_requests": true,
      "encrypt_responses": true,
      "require_keyserver": true,
      "check_revocation": true,
      "tunneling_enabled": true,
      "server_email": "api@example.com",
      "server_passphrase": "secret",
      "server_private_key_path": "/etc/caddy/server_private.asc",
      "server_public_key_path": "/etc/caddy/server_public.asc"
    },
    {
      "handler": "reverse_proxy",
      "upstreams": [{"dial": "localhost:3000"}]
    }
  ]
}
```
*(A complete payload including correct CORS headers is available in `example/caddy.json`)*

## How It Works

1. **Authentication:** Receives the `/api/challenge` and `/api/login` payload from Aegis Extension, validates signatures through Ubuntu WKD / Keyservers, and trusts the client.
2. **Decryption:** Parses `x-gpg-encrypted` packet blobs, decrypts them with `server_private.asc`, rewrites the Request body and forwards it to `reverse_proxy`. Provides replay attack prevention mechanism.
3. **Encryption:** Intercepts out-going `reverse_proxy` JSON responses, encrypts them using the client's validated PGP Key (`x-gpg-id`), and responds with the armored cipher output to the frontend.
4. **Transparent Tunneling:** Intercepts deeply nested, full HTTP envelopes (URL, Methods, custom Headers like `Authorization`) within single encapsulating `POST /` requests if `x-gpg-tunnel: true` is intercepted. It seamlessly unwraps them internally, allowing backend services like GoFiber/Express to process vanilla traffic organically while preventing network monitoring from scraping request methods or parameter data.

---

## Testing The Example Environment

You can spin up the full 3-step topology (Frontend -> Caddy -> Backend) test environment under `/example`:
1. Build `xcaddy` in `example/` folder keeping the binary name `caddy`.
2. Run `./start-test.sh`.
3. Open `http://localhost:5173` to see robust `Aegis TS SDK` implementations testing plain, encrypted and fully custom headers using `aegis.init({ forceTunneling: true })`.

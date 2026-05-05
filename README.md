# vibe-gateway

A single reverse proxy that adds authentication to all your vibe-coded apps — deploy once, secure everything.

## The problem

Vibe-coded apps are great for shipping fast, but they rarely come with authentication built in. Deploying them publicly means anyone can access them. You could add auth to each app individually, but that's tedious and inconsistent.

## The solution

`vibe-gateway` sits in front of all your apps. Every request passes through it first, and only authenticated users get through. Your apps stay completely private — they never need to handle auth themselves.

```
Internet → vibe-gateway (auth + routing) → your-app-1
                                          → your-app-2
                                          → your-app-3
```

The gateway handles:
- **Authentication** via Auth0 (or any OIDC provider — see below)
- **Routing** — requests to `/<app-name>/...` are proxied to the service named `<app-name>`
- **JWT session management** — users log in once, get a session token, all subsequent requests are verified locally

The gateway forwards the JWT access token to every downstream service in the `Authorization: Bearer <token>` header. Apps can decode this token to read the authenticated user's identity and make their own fine-grained authorization decisions (e.g. "only user X can access this resource") without implementing a login flow themselves.

## Architecture

Built on [Caddy](https://caddyserver.com/) with the [`caddy-security`](https://github.com/greenpau/caddy-security) plugin for OAuth2/OIDC. Deployed as a single Docker container.

The routing rule is simple: a request to `/foo/bar/baz` proxies to the service named `foo` at path `/bar/baz`. Your apps just need to be reachable by name on the internal network.

## Deployment on Render

### The private service model

All your apps deploy as [Render Private Services](https://render.com/docs/private-services) — they have no public URL and are unreachable from the internet. Only `vibe-gateway` is exposed publicly (as a Web Service or Private Service, your choice).

When `vibe-gateway` proxies a request, it resolves `{service-name}:{DOWNSTREAM_PORT}` using Render's internal DNS. Private services are reachable by name within the same Render region, so no extra service discovery is needed.

### Setup

1. **Deploy your apps** as Render Private Services. Note the service name for each one — it becomes the URL prefix.

2. **Create an Auth0 application** (or any OIDC provider — see below). Set the callback URL to:
   ```
   https://<your-gateway-url>/auth/oauth2/auth0
   ```

3. **Deploy vibe-gateway** using the included `render.yaml` (as a Private Service with Tailscale — see below) or as a standard Web Service. Set the following environment variables:

   | Variable | Description |
   |----------|-------------|
   | `AUTH0_CLIENT_ID` | OAuth2 client ID from Auth0 |
   | `AUTH0_CLIENT_SECRET` | OAuth2 client secret from Auth0 |
   | `AUTH0_DOMAIN` | Your Auth0 tenant domain (e.g. `my-tenant.us.auth0.com`) |
   | `AUTH0_JWT_SECRET` | A random secret used to sign session JWTs — generate with `openssl rand -hex 32` |
   | `TAILSCALE_AUTHKEY` | (Optional) Tailscale pre-auth key — only needed if deploying as a Tailscale-protected Private Service |

4. Access your apps at `https://<gateway-url>/<service-name>/`.

## Optional: Tailscale-protected access

By default you'd deploy `vibe-gateway` as a public Render Web Service — anyone on the internet can reach the auth flow and attempt to log in. That's fine for most cases, but if you want an extra layer of network-level access control, you can deploy the gateway itself as a **Private Service that's only reachable over Tailscale**.

With this setup:
- `vibe-gateway` is a Render Private Service (no public URL at all)
- It joins your Tailscale network at startup
- Only devices on your Tailscale network can reach the gateway, let alone authenticate

The `start.sh` script handles this: it starts `tailscaled` in userspace networking mode (no kernel module needed in containers), then calls `tailscale up` with your pre-auth key, and only starts Caddy once the Tailscale connection is established.

To use this mode, just set `TAILSCALE_AUTHKEY` and deploy as a `pserv` (as configured in `render.yaml`). The gateway's Tailscale IP is logged at startup.

You can also optionally set `ADVERTISE_ROUTES` to advertise subnets to the rest of your Tailscale network.

## Swapping out Auth0

Auth0 is just one OIDC provider. The `caddy-security` plugin supports any provider that exposes a standard `/.well-known/openid-configuration` endpoint. To switch providers, update the `Caddyfile`:

```
oauth identity provider <name> {
    realm <name>
    driver generic
    client_id {$CLIENT_ID}
    client_secret {$CLIENT_SECRET}
    metadata_url https://<your-provider>/.well-known/openid-configuration
    scopes openid email profile
}
```

And update the portal and policy blocks to reference the new provider name. Common alternatives:

- **Google** — `accounts.google.com`
- **GitHub** — via a GitHub OAuth app (use a proxy like `dex` for OIDC wrapping)
- **Okta** — `<tenant>.okta.com`
- **Keycloak** — self-hosted, fully open source
- **Authentik** — self-hosted, good UI
- **Cloudflare Access** — if you're already in that ecosystem

Any provider that speaks OIDC will work without changes to the routing or session logic.

## Request flow

```
Request → /caddyhealth          → 200 OK (health check, no auth)
        → /auth/*               → Auth0 OIDC flow (login, callback)
        → /*                    → verify JWT session
                                  ↓ (unauthorized: redirect to /auth/oauth2/auth0)
                                  ↓ (authorized)
                                  rewrite /service/path → /path
                                  proxy → service:10000
```

## Files

| File | Purpose |
|------|---------|
| `Caddyfile` | Caddy config — auth portal, authorization policy, routing |
| `Dockerfile` | Multi-stage build: custom Caddy binary + Tailscale binaries |
| `start.sh` | Entrypoint: starts Tailscale, waits for connection, starts Caddy |
| `render.yaml` | Render Blueprint — deploys as a private service |

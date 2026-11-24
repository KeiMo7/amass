# Engine Control-Plane Authentication

This document describes the authentication and authorization model that
protects the Amass engine control-plane HTTP API and its real-time log
WebSocket.

## Threat model

The control plane exposes the full discovered asset graph and can create and
terminate enumeration sessions. Before this work it authenticated nobody and,
by default, bound every network interface, so any host that could reach the
port had complete read/write access. The model below addresses:

- unauthenticated access to read or write endpoints;
- credentials scoped to only part of the session set;
- expired, revoked and forged credentials;
- read-only credentials attempting mutations;
- brute-force attempts against the control plane;
- credential loss on long-lived log streams;
- starting without any key material;
- credential leakage into logs or error responses.

## Credential file

The engine reads a YAML credential file whose path is supplied with the
`AMASS_ENGINE_CREDENTIALS` environment variable. A complete annotated example
lives at `resources/engine_credentials.example.yaml`.

```yaml
credentials:
  - id: admin
    secret: a-long-random-secret
  - id: viewer
    secret: another-long-random-secret
    readOnly: true
  - id: scoped-team-a
    secret: yet-another-long-random-secret
    expiresAt: 2027-01-01T00:00:00Z
    sessions:
      - 11111111-1111-1111-1111-111111111111
```

| Field       | Meaning                                                                 |
|-------------|-------------------------------------------------------------------------|
| `id`        | Credential identifier, used as the HTTP Basic Auth username.           |
| `secret`    | Shared secret used as the Basic Auth password; minimum 16 bytes.        |
| `expiresAt` | Optional RFC 3339 instant after which the credential is rejected.       |
| `readOnly`  | Optional; permits reads but never create/add/terminate operations.      |
| `sessions`  | Optional allow-list of session UUIDs; omit to reach every session.      |

Secrets are never stored in plaintext. On load each secret is reduced to a
SHA-256 digest and the raw value is discarded. All comparisons use
`crypto/subtle.ConstantTimeCompare`, and an unknown key ID still performs a
real comparison against a random digest so that response timing cannot reveal
whether an identifier exists.

## Transport

Credentials are presented with standard HTTP Basic Authentication
(`Authorization: Basic …`), including on the WebSocket upgrade. Because Basic
Auth carries a reusable secret, production deployments should front the engine
with TLS (reverse proxy or an HTTPS listener); the credential machinery itself
is transport-agnostic.

## Endpoint policy

Only `GET /api/v1/health` is public. It is stateless and returns no session or
asset information. Every other route passes through the authentication
middleware:

- **Missing / forged / expired / revoked credential** → `401 Unauthorized`
  with a generic body. The internal log records the failure *category*
  (missing, forged, expired, revoked), but the external response does not
  distinguish them, so an attacker cannot enumerate valid identifiers.
- **Read-only credential on a write method** → `403 Forbidden`.
- **Session outside the credential's scope** → `404 Not Found`, byte-for-byte
  identical to the response for a session ID that never existed. There is no
  session-existence oracle.
- **Too many failures from one source** → `429 Too Many Requests`.

## Session scoping

A credential with a `sessions` list can only access those sessions. The
constraint is enforced both on per-session routes and on `GET /sessions/list`,
which filters the returned tokens. When a session is terminated its access
rights disappear immediately because the session no longer resolves.

## Throttling

The store tracks consecutive authentication failures per direct peer IP
address (spoofable forwarding headers are ignored). After five failures within
a ten-minute rolling window the source is locked out. A single successful
authentication resets the counter, so a caller holding valid credentials is
never throttled by someone else's guessing, and throttling state is
per-source rather than global.

## WebSocket log streams

`GET /sessions/{id}/ws/logs` authenticates during the HTTP upgrade, before any
frame is exchanged, and applies the same session-scope rules. After upgrade a
watcher goroutine re-validates the principal and:

- closes the connection (close code 1008) as soon as the credential is revoked;
- closes it on the next periodic check once the credential expires;
- closes it (close code 1000) when the underlying session is terminated.

Revocation is broadcast through a generation channel so that open streams react
promptly rather than waiting for a polling tick.

## Startup policy: no key material

The engine refuses to start in an open configuration on a non-loopback
address:

```
refusing to start: no credential material configured and the listen address
is not loopback; provide a credential file or bind 127.0.0.1
```

When the address is loopback (`127.0.0.1` / `::1` / `localhost`) the engine
starts in **open mode** with an explicit `OPEN MODE` warning, trusting only
loopback callers and rejecting every non-loopback request. This preserves the
historic local, credential-free CLI workflow while preventing accidental
public exposure. The listen address is set with `AMASS_ENGINE_ADDR`
(default `:4000`).

## Fail-closed behavior

- Any internal authentication error is treated as a denial, never a pass.
- An empty credential store authenticates nobody.
- The request context is never used to govern an upgraded WebSocket's lifetime
  (it is cancelled when the upgrade handler returns); the long-lived handler
  context is used instead.

## Log redaction

Credentials never appear in access logs, audit records, error responses or log
streams. Successful and failed authentication events reference the principal
only by an irreversible fingerprint (`fp_` + a truncated SHA-256 over the key
ID and secret digest), and the `Authorization` header is never logged.

## Configuration reference

| Variable                   | Purpose                                                        |
|----------------------------|----------------------------------------------------------------|
| `AMASS_ENGINE_ADDR`        | Listen address; default `:4000`.                               |
| `AMASS_ENGINE_CREDENTIALS` | Path to the YAML credential file; enables secured mode.        |
| `AMASS_ENGINE_USER`        | Client-side Basic Auth username (existing client config).      |
| `AMASS_ENGINE_PASSWORD`    | Client-side Basic Auth password (existing client config).      |

The Go client also accepts credentials embedded in a URL
(`http://user:secret@host:4000`), strips the userinfo from the stored URL, and
attaches the resulting Basic Auth header to HTTP calls and WebSocket upgrades.

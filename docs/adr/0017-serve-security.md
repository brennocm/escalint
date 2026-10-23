# 0017 — Security of `escalint serve`

Status: Accepted

## Context

The UI shows who can become administrator in an AWS account. A local web
server is reachable by every process on the machine and, through the
browser, by every web page the user visits (CSRF, DNS rebinding).

## Decision

- **Bind** `127.0.0.1` on a random port by default. Another address needs
  `--listen` *and* `--allow-remote`, and prints a warning.
- **Token:** 32 random bytes (base64url) in the first URL, printed on
  stderr only, accepted **once**. The first request exchanges it for a
  cookie holding a separate random session value (`HttpOnly`,
  `SameSite=Strict`, path `/`, 12 hours, named `escalint_session_<port>` so
  two servers on loopback do not overwrite each other's session) and redirects to `/` so the token
  leaves the address bar and history; a leaked URL opens nothing after
  that (the browser that has the session is simply redirected).
  Comparisons are constant-time. Without a valid cookie every request is
  401. The cookie is not `Secure` because the server speaks plain HTTP on
  loopback. Cookies are not scoped by port, so the browser also sends it
  to other services on `127.0.0.1`; the value is useless to them.
- **Host check:** only `127.0.0.1:<port>`, `localhost:<port>`,
  `[::1]:<port>` (or the explicit listen address: its host name, or every
  interface address for a wildcard such as `0.0.0.0`) are accepted;
  anything else is 421, which defeats DNS rebinding.
- **Read-only:** only `GET`; everything else is 405 with `Allow: GET`.
- **Headers on every response:** a strict CSP
  (`default-src 'none'; script-src 'self'; …; frame-ancestors 'none'`),
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy:
  same-origin`, `X-Frame-Options: DENY`, `Cache-Control: no-store` (hashed
  assets are cacheable).
- Server timeouts and a 16 KiB header limit bound slow clients.

## Consequences

- Handler tests (`httptest`) cover 401, 421, 405, headers and the exact CSP;
  a Playwright test runs the real binary and asserts zero CSP violations
  and zero requests leaving the origin.
- Sharing a running UI with a colleague is deliberately inconvenient: use
  `escalint report --html --redact` instead.

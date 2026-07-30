# QSFT — Security and Usage Audit

**Date:** 2026-07-29
**Commit audited:** `94f3f73` (main, clean tree)
**Method:** full source review of `server/` and `client/src/`, plus dynamic probes against a
locally spawned instance of the real server. Probe artefacts were removed afterwards; the
repository was not modified. All 77 existing tests pass.

---

## Summary

The cryptographic core is solid. STREAM framing, header-in-AAD, counter-in-nonce, hybrid KEX
with a transcript MAC, constant-time comparisons, and a single probed randomness source all
hold up. No flaw was found in the container format or the AEAD composition.

The problems are at the edges: the signalling server, the rate limiting, and one key-derivation
choice that quietly undercuts a guarantee the README makes.

| # | Severity | Finding |
|---|---|---|
| 1 | High | `live:join` has no rate limiting; live code space falls in ~5 minutes |
| 2 | High | Live transfers derive the Argon2id salt from the public 6-digit code |
| 3 | High | `TRUST_PROXY=1` makes the code rate limiter a no-op; the Dockerfile hardcodes it |
| 4 | Medium | Open redirect via `ALIAS_PATHS` when `BASE_PATH` is empty |
| 5 | Medium | `/api/store/init` is unauthenticated and unbounded |
| 6 | Medium | Enumeration incidentally locks out legitimate receivers |
| 7 | Medium | CSP `connect-src` allows any WebSocket host |
| 8 | Low | `/api/health` is publicly readable |
| 9 | Low | Source maps ship to production |
| 10 | Low | ZIP entry names are never sanitized |
| 11 | UX | "Save again" and "Save all as…" are dead after 60 seconds |
| 12 | UX | `appendPart` has no per-record lock |
| 13 | UX | `estimateStrength` over-credits hyphenated junk |

---

## High

### 1. `live:join` has no rate limiting at all — the live code space falls in ~5 minutes

`server/live.js:110` accepts unlimited code guesses. Every HTTP code lookup goes through
`guardCodeLookup`, but the Socket.IO path bypasses it entirely.

Measured against the real server:

```
HTTP /api/resolve:  20 guesses before 429
live:join:        3000 guesses, ZERO throttling, 859ms => ~3492 guesses/sec
                  full 10^6 sweep ≈ 5 minutes on a single socket
```

That was strictly sequential on one socket. Concurrent emits and multiple sockets take it to
seconds.

Compounding it, the WebSocket upgrade has no Origin check even with `NODE_ENV=production`.
`server/index.js:111` leaves `cors: undefined`, which Socket.IO only applies to the polling
transport — WebSocket upgrades are not subject to CORS:

```
cross-origin WS upgrade: ACCEPTED (no Origin check)
```

So any web page can drive this from every visitor's browser. A successful guess takes the
room's single guest slot, which denies the real receiver and yields a passphrase-keyed MAC the
attacker can grind offline — the exact attack the README scopes as requiring an active MITM,
now available to anyone who can guess six digits.

The README's claim that "guessing is rate-limited per IP and per code" is only true of the HTTP
surface.

**Fix:** apply the same `RateLimiter` to `live:join`, keyed on the socket's IP, plus
`allowRequest` on the Socket.IO server to check `Origin` against the deployment's own.

### 2. Live transfers derive the Argon2id salt from the public 6-digit code

`client/src/crypto/kdf.ts:141` — `sessionSalt(code) = SHA256("qsft/v1/session-salt/" + code)`,
used by both `client/src/session/liveSend.ts:58` and `client/src/session/liveReceive.ts:57`.

The salt space is 10⁶ and every value is publicly computable. The README's security table says
"16-byte random salt" — that holds for stored transfers, not live ones.

This matters concretely because the handshake MACs travel in the clear over the signalling
channel, and the README already discloses that a captured MAC is offline-grindable, resting the
mitigation on "Argon2id makes each guess expensive." A predictable salt makes that expense
**precomputable**. The server learns the code the instant it allocates it, so it can start
grinding candidates against that exact salt before the file moves — or precompute a table over
all 10⁶ salts × a candidate list once, and crack any live transfer instantly thereafter. That
is precisely what a salt exists to prevent.

Secondary: the same passphrase plus a recycled code produces an identical inner file key,
leaving only the 56-bit random nonce prefix (AES-GCM path, `client/src/crypto/aead.ts:45`)
standing between two transfers and catastrophic GCM nonce reuse.

**Fix:** have the sender generate a random salt and carry it in HELLO — it already does, via
`hello.salt`. `deriveMasterFor` at `client/src/session/liveReceive.ts:61` already handles a salt
that differs from the guess, so only the pre-derivation optimisation is lost; the Argon2 wait
would follow HELLO instead of overlapping it. If the overlap is worth keeping, send a random
salt in a cheap pre-HELLO signal.

### 3. `TRUST_PROXY=1` makes the code rate limiter a no-op — and the Dockerfile hardcodes it

`server/util.js:30` takes the leftmost `X-Forwarded-For` value unconditionally. That header is
client-supplied. `Dockerfile:41` sets `ENV TRUST_PROXY=1` as an image default, so the documented
deployment path is affected:

```
TRUST_PROXY=1 + spoofed X-Forwarded-For: 500/500 code guesses accepted
                                         (limit is meant to be 20 per 10 min)
```

The per-code limiter does not help: enumeration needs one attempt per code, and the threshold is
ten.

**Fix:** count hops from the right based on a configured trusted-proxy depth rather than taking
the leftmost value. Express's `trust proxy` accepts a hop count or a subnet list — use it and
read `req.ip` instead of parsing the header by hand.

---

## Medium

### 4. Open redirect via `ALIAS_PATHS` when `BASE_PATH` is empty

`server/index.js:55` strips only one leading slash from the captured remainder:

```
/qsft            -> 301 Location: /
/qsft/x          -> 301 Location: /x
/qsft//evil.com  -> 301 Location: //evil.com     ← protocol-relative, off-origin
```

`BASE_PATH` defaults to empty and `ALIAS_PATHS` is independently settable, so this is reachable
on any deployment that configures aliases without a subpath. The README's Coolify recipe sets
both, which happens to make it same-origin there — but that is luck, not a control.

**Fix:** `.replace(/^\/+/, '')`.

### 5. `/api/store/init` is unauthenticated and unbounded

400 reservations were created instantly with no credential and no throttle, each allocating a
code from the registry that live sessions share and writing two files to disk:

```
/api/store/init: 400 uncommitted reservations created unauthenticated (last status 201)
/api/health leaks: {"ok":true,"items":400,"bytesOnDisk":0,"quotaBytes":21474836480}
```

`declaredSize: 0` skips the quota pre-check at `server/store.js:135` entirely. Saturating the
10⁶ registry makes `codes.allocate` return null after 500 attempts, at which point `live:host`
answers "Server is busy" and stored uploads return 503 — a full-service denial, plus inode
pressure. Uncommitted uploads sweep after an hour, so holding the space costs roughly 280 req/s.

**Fix:** rate-limit `/store/init` per IP and cap concurrent uncommitted reservations.

### 6. Enumeration incidentally locks out legitimate receivers

`server/routes.js:28` locks a code for ten minutes after ten failed lookups, and `noteFailure`
fires on every miss. An attacker sweeping the space — free once finding 3 removes the IP limiter
— poisons every code they miss. When the server later allocates a poisoned code to a real
transfer, its receiver is refused with "This code has been guessed at too many times."
`guardCodeLookup` runs before the resolve, so the success refund never applies.

Sustaining this across the whole namespace is expensive (~17k req/s), but a single enumeration
pass leaves a ten-minute dead zone behind it.

**Fix:** key the lockout on codes that are actually allocated, or drop the per-code lock in
favour of a working per-IP one.

### 7. CSP `connect-src` allows any WebSocket host

`server/index.js:29` — `connect-src 'self' ws: wss: blob:`. The bare `ws:`/`wss:` scheme sources
match *any* host, so the policy provides no exfiltration ceiling for the one thing this app most
needs it for. Modern browsers match same-origin `ws://`/`wss://` under `'self'`, so both scheme
sources can be dropped.

---

## Low / information disclosure

### 8. `/api/health` is publicly readable

`server/routes.js:51` returns live item count and bytes on disk — unauthenticated visibility
into how much traffic a privacy tool is carrying. The Docker healthcheck hits it from inside the
container; it does not need to be internet-reachable.

### 9. Source maps ship to production

`vite.config.ts:23` sets `sourcemap: true`. Harmless for MIT code, but the maps are served
`immutable` alongside the bundle and add weight for no user benefit.

### 10. ZIP entry names are never sanitized

`client/src/ui/transferScreen.ts:275` passes `entry.name` straight from the archive's central
directory into `triggerDownload`, while the outer filename goes through `sanitizeFilename`
(`client/src/crypto/format.ts:154`). Browsers do scrub path separators in the `download`
attribute, so this is not a traversal, but the inconsistency is worth closing —
`sanitizeFilename(entry.name)` at the call site.

---

## User-experience bugs

### 11. "Save again" and "Save all as…" are dead after 60 seconds

The clearest functional bug. `client/src/sink.ts:121` revokes the object URL 60s after a
download is triggered:

```js
setTimeout(() => URL.revokeObjectURL(url), 60_000);
```

But `client/src/ui/transferScreen.ts:225` re-uses that same `event.url` for the "Save again"
button, and `client/src/ui/transferScreen.ts:250` for "Save all as …". The auto-download at
line 219 starts the 60-second clock immediately, so a user who comes back to save a second copy
— or who lands on the bundle screen, waits, then hits "Save all" twice — gets a silently failed
download from a revoked URL. Per-entry saves are fine; they mint a fresh URL each click.

**Fix:** keep the Blob rather than the URL and mint a URL per click, or do not revoke a URL that
still has a live button pointing at it.

### 12. `appendPart` has no per-record lock

`server/store.js:174` validates `index === record.nextIndex` synchronously, then `await`s the
append. Two concurrent PUTs with the same index both pass validation and both append, doubling
bytes and corrupting the blob — the receiver sees an AEAD failure with no indication why.

The client uploads strictly sequentially, and the duplicate-index no-op handles the
retry-after-5xx case correctly, so this needs a misbehaving or racing client to trigger. Still
worth a per-record promise chain.

### 13. `estimateStrength` over-credits hyphenated junk

`client/src/util/passphrase.ts:75` — the regex `/^([a-z]+-){3,}[a-z]+$/` treats *any* hyphenated
lowercase string as generated and awards 8 bits per token. `a-a-a-a-a-a` scores 48 bits and is
labelled "Weak" rather than "Too weak". The doc comment says the estimator errs toward calling
things weak; this is the one case where it does not.

**Fix:** cross-check tokens against `WORDS`.

---

## Verified as sound

Worth stating explicitly, since these are the parts most likely to be wrong and are not:

- Header-bound AAD genuinely prevents cipher-suite and KDF downgrade.
- The final-chunk flag is authenticated at both layers, so truncation cannot pass as completion.
- `fromBase64Exact` rejects every malformed handshake field by exact length.
- The small-order X25519 check is present and rejects the all-zero shared secret.
- SAS derives under a label distinct from every traffic key.
- The service worker's `/api/` and `/socket.io/` exclusions hold, including the belt-and-braces
  origin-root variants.
- `sanitizeFilename` correctly strips separators, control characters, and leading dots.
- The CSP is otherwise tight: no `unsafe-inline` on scripts; `object-src`, `base-uri`,
  `form-action`, and `frame-ancestors` are all locked down.

---

## Suggested order of work

1. Rate-limit `live:join` and add an Origin check (finding 1) — largest exposure, smallest diff.
2. Fix `X-Forwarded-For` handling (finding 3) — everything else that relies on rate limiting
   depends on this being real.
3. Random salt for live handshakes (finding 2) — protocol change; needs both ends updated
   together.
4. Alias redirect slash-stripping (finding 4) and the revoked-object-URL bug (finding 11) — both
   one-line fixes.
5. The rest as tidy-up.

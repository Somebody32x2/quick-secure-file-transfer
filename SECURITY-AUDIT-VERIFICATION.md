# QSFT — Independent Verification of SECURITY-AUDIT.md, plus a second-pass audit

**Date:** 2026-07-29
**Commit:** `94f3f73` (main, clean tree)
**Scope:** Medium severity and above.
**Method:** independent source review of `server/` and `client/src/`, then dynamic probes
against the real server spawned on an isolated `DATA_DIR` (`NODE_ENV=production`,
`TRUST_PROXY=1`, `ALIAS_PATHS=/qsft`, `BASE_PATH=""`). Probe artefacts removed; the
repository was not modified apart from this file. All 77 existing tests pass. `npm audit
--omit=dev` reports 0 vulnerabilities.

---

## Verdict on the original audit

Every server-side finding at Medium or above reproduced. Two severities are wrong in the
original — one too high, one too low — and one Medium is really a Low. Six issues at
Medium were not reported at all.

| # | Original | Verified? | My rating | Note |
|---|---|---|---|---|
| 1 | High | **yes** | High | 3,272 guesses/sec measured; cross-origin WS upgrade accepted |
| 2 | High | **yes** | **Medium** | real, but the enabled attack largely pre-exists and the proposed fix is partial |
| 3 | High | **yes** | High | 300/300 spoofed-XFF guesses accepted |
| 4 | Medium | **yes** | Medium | `//evil.example` confirmed |
| 5 | Medium | **yes** | Medium | 400/400 reservations, 400 blob files, one IP |
| 6 | Medium | **yes** | Medium | fresh IP refused on a poisoned code |
| 7 | Medium | **yes** | **Low** | no reachable script-injection primitive to ceiling |
| 12 | "UX" | **yes** | **Medium** | reproduced first try: 8× over-append, silent corruption |
| 13 | "UX" | **yes, worse** | **Medium** | junk scores *"Strong"*, not just "Weak" |
| 8, 9, 10, 11 | Low / UX | yes | agreed | out of scope here; #11 description needs one correction |

New at Medium: **N1**–**N6** below.

---

## Part 1 — Verification of the original findings

### 1. `live:join` unthrottled + no WebSocket Origin check — **confirmed, High**

```
HTTP  /api/resolve:  429 after 20 attempts
live:join:           3000 sequential guesses, 917 ms => 3272 guesses/sec
                     full 10^6 sweep ~= 5.1 min on ONE socket
cross-origin WS upgrade (Origin: https://evil.example, NODE_ENV=production): ACCEPTED
```

Matches [server/live.js:110](server/live.js:110) having no limiter and
[server/index.js:111](server/index.js:111) leaving `cors: undefined` — which Socket.IO
applies to polling only; WebSocket upgrades are not subject to CORS. The original's
numbers and reasoning are correct.

### 2. Deterministic session salt — **confirmed as a fact, but High overstates it**

[client/src/crypto/kdf.ts:141](client/src/crypto/kdf.ts:141) does derive the Argon2id salt
from the public code, and both [liveSend.ts:58](client/src/session/liveSend.ts:58) and
[liveReceive.ts:57](client/src/session/liveReceive.ts:57) use it. The README's "16-byte
random salt" ([README.md:95](README.md:95)) is false for live transfers. That part stands.

Three reasons I rate it Medium rather than High:

- **The attack it enables already exists by design.** The threat is offline grinding of a
  captured handshake MAC, which [kex.ts:22-30](client/src/crypto/kex.ts:22) already
  documents as inherent to authenticating with a low-entropy secret and no PAKE. A
  predictable salt changes *when* the Argon2 work happens, not how much of it there is.
- **Precomputation is not actually cheap.** Measured on this machine, Argon2id at the
  shipped defaults is 759 ms. A table over all 10⁶ salts costs ~8.8 CPU-days *per candidate
  passphrase*; even a 1,000-word candidate list is ~24 CPU-years. The cross-target
  amortisation a salt is meant to prevent is prevented here by Argon2's cost, not by the
  salt.
- **The proposed fix is partial.** Putting a random salt in HELLO defeats a *passive*
  attacker. It does nothing against an active one: the responder derives against whatever
  salt HELLO carries ([handshake.ts:70-73](client/src/session/handshake.ts:70)), before any
  authentication, so a MITM or a hostile server simply forges a HELLO carrying a salt it has
  already precomputed against. Since obtaining a MAC to grind requires completing a
  handshake anyway, the attacker who benefits most is the one the fix does not stop.

What does remain real: the server learns the code at allocation time and can start grinding
before the transfer begins, and the README makes a claim the code does not honour. Both are
worth fixing. The fix is the right one — just fix the README alongside it rather than
treating this as a break.

The "secondary" GCM nonce-reuse concern is weaker still. It needs the same passphrase *and*
a recycled 6-digit code (p ≈ 10⁻⁶ per transfer) *and* a birthday collision in the 56-bit
random prefix (~2²⁸ transfers). Theoretical.

### 3. `TRUST_PROXY=1` + leftmost `X-Forwarded-For` — **confirmed, High**

```
TRUST_PROXY=1, rotating spoofed X-Forwarded-For: 300/300 accepted, 0 throttled
                                                 (limit is 20 per 10 min)
```

[server/util.js:30](server/util.js:30) takes `fwd.split(',')[0]` unconditionally;
[Dockerfile:41](Dockerfile:41) ships `ENV TRUST_PROXY=1` as an image default. Confirmed.

Worth adding: the setting is a genuine dilemma, not a mistake — `README.md:317` correctly
notes that *without* it, behind a proxy every request looks like one IP and one abuser
throttles everybody. The fix must therefore be the hop-counting one (Express `trust proxy`
with a depth or subnet list, then read `req.ip`), not simply defaulting the flag off.

### 4. Open redirect via `ALIAS_PATHS` — **confirmed, Medium**

```
/qsft              -> 301 Location: /
/qsft/x            -> 301 Location: /x
/qsft//evil.example -> 301 Location: //evil.example      <- protocol-relative, off-origin
/qsft///evil.example -> 301 Location: ///evil.example
```

[server/index.js:55](server/index.js:55). `.replace(/^\/+/, '')` is the fix.

### 5. `/api/store/init` unauthenticated and unbounded — **confirmed, Medium**

```
400/400 reservations created from ONE IP in 1785 ms (224/sec), last status 201
health items 0 -> 400; blob files on disk: 400
```

`declaredSize: 0` skips the quota pre-check at [server/store.js:135](server/store.js:135).
Reservations persist for `incompleteUploadTtlSeconds` (1 h), so holding the whole 10⁶
registry needs ~278 req/s sustained — the original's estimate is right, and it is the most
practical registry-exhaustion path because it needs no held connection.

### 6. Code-lockout poisoning — **confirmed, Medium**

```
12 failures on code 424242 from rotating spoofed IPs, then a fresh IP:
  -> 429 "This code has been guessed at too many times and is temporarily locked."
```

`guardCodeLookup` runs before the resolve ([routes.js:19](server/routes.js:19)), so the
`noteSuccess` refund never applies to a poisoned code. Confirmed exactly as described.

### 7. CSP `connect-src ws: wss:` — **confirmed as written, but Low not Medium**

The header is verbatim as reported. But `connect-src` is only an exfiltration ceiling for an
attacker who already has script execution, and I could not find any path to that:
`script-src 'self'` with no `unsafe-inline`, `object-src 'none'`, `base-uri 'none'`,
`form-action 'none'`, and exactly one `innerHTML` in the whole client
([dom.ts:32](client/src/ui/dom.ts:32)) reachable only through an `html:` attribute key that
**no call site in the codebase uses**. Peer-controlled strings (filenames, ZIP entry names)
all go through `textContent`. Tighten it anyway — it costs nothing and `'self'` already
covers same-origin `ws:`/`wss:` in modern browsers — but it is defence in depth, not a live
hole.

### 12. `appendPart` has no per-record lock — **confirmed, and this is Medium, not UX**

Reproduced on the **first** trial (8 raw sockets, heads pre-sent, bodies flushed in one
event-loop batch):

```
8 concurrent PUTs at index=0 of 32768 B
  -> 1 x HTTP 200 returned, 0 reported duplicate
  -> blob on disk = 262144 B (expected 32768 B) — 8x over-append
```

[server/store.js:174-199](server/store.js:174) validates `index === record.nextIndex`
synchronously and only then `await`s the append, so every concurrent handler passes the
check before any of them advances `nextIndex`. The blob is silently corrupted; the receiver
learns about it as an AEAD failure with no explanation. The original's "needs a misbehaving
or racing client" is fair — but any client that retries a slow PUT without waiting for the
first response triggers it, and the window is not narrow.

### 13. `estimateStrength` — **confirmed and materially worse than reported**

The regex `/^([a-z]+-){3,}[a-z]+$/` ([passphrase.ts:75](client/src/util/passphrase.ts:75))
matches any hyphenated lowercase string and awards 8 bits per token with no wordlist check:

```
"a-a-a-a-a-a"                     -> 48 bits -> "Weak"
"correct-horse-battery-staple"    -> 32 bits -> "Weak"
"zz-zz-zz-zz-zz-zz-zz-zz-zz-zz"   -> 80 bits -> "STRONG"
```

The original stopped at "Weak". The estimator will actually label a trivially guessable
string **"Strong. Send it over a different channel than the code."** For the one control the
README calls "the whole ballgame" (`README.md:196`), that is a misleading security
indicator, not a UX nit. Cross-check tokens against `WORDS`; fall through to the character
estimator otherwise.

### 11 — one correction

The described failure is real but the trigger is narrower for bundles than stated. On the
archive path, `showDone` does **not** auto-download ([transferScreen.ts:212](client/src/ui/transferScreen.ts:212)
returns early), so the 60 s clock on `event.url` only starts on the *first* "Save all"
click. Waiting on the bundle screen and then clicking once works fine; it is the *second*
click more than 60 s later that silently fails. The plain-file "Save again" case is exactly
as described, because line 219 starts the clock immediately.

---

## Part 2 — Findings not in the original audit

### N1. `writeMeta` uses a fixed temp filename — concurrent writes crash with an uncaught 500 — **Medium**

Surfaced from the server's own logs while reproducing #12:

```
[error] Error: ENOENT: no such file or directory, rename
  '<DATA_DIR>/tmp/4b90f237...json.tmp' -> '<DATA_DIR>/meta/4b90f237...json'
    at writeMeta (server/store.js:54)
    at appendPart (server/store.js:197)
```

[server/store.js:52](server/store.js:52) builds the temp path as
`` `${record.id}.json.tmp` `` — one fixed name per record, not per write. Two overlapping
`writeMeta` calls for the same record write the same temp file; the first `rename` consumes
it and the second gets ENOENT and rejects into the Express error handler as a 500.

This is a distinct bug from #12 and survives fixing it. `writeMeta` is called from
`appendPart`, `commitUpload`, and `beginRead().finish()` — and `finish()` runs on a
connection-close event, which can overlap an append on the same record with no misbehaving
client at all. Fix: unique temp name per write (`${id}.${randomUUID()}.tmp`), which is also
what makes the rename atomic in the first place.

### N2. Upload bodies are buffered in full *before* the token is checked — **Medium**

```
PUT /api/store/deadbeef-not-a-real-upload/part, no x-upload-token
  -> server read the full 8 MiB before replying "HTTP/1.1 404 Not Found"
```

[routes.js:114](server/routes.js:114) mounts `express.raw({ limit: maxPartBytes + 4096 })`
as route middleware, so the ~8.4 MB body is fully materialised in memory before the handler
runs and `store.appendPart` → `authorised()` rejects it. There is no rate limiter, no
authentication, and no concurrency cap ahead of that buffer, and Node imposes no connection
limit by default — roughly 120 concurrent requests to a nonexistent upload id is 1 GB of
attacker-controlled RSS, from anonymous clients, with no state left behind to sweep.

Fix: check the token and the record before accepting a body — a small `router.param` or a
pre-middleware that resolves `:id` and calls `authorised()` — or stream the body to the blob
instead of buffering it.

### N3. Peer-controlled Argon2 parameters, pre-authentication, with an inline-retry amplifier — **Medium**

`parseKdf` ([kex.ts:150](client/src/crypto/kex.ts:150)) and `decodeHeader`
([format.ts:97](client/src/crypto/format.ts:97)) both accept `m` up to 1 048 576 KiB (1 GiB),
`t` up to 16, `p` up to 16. The receiver derives against those values *before* verifying
anything: [liveReceive.ts:104](client/src/session/liveReceive.ts:104) and
[handshake.ts:72-73](client/src/session/handshake.ts:72) both run on unauthenticated HELLO
content, and for stored transfers the parameters come out of a header the (explicitly
untrusted) server hands over.

Measured cost of the accepted maximum, extrapolated from real runs on a desktop:

```
m=19456  t=2  p=1   ->   0.76 s   (shipped default)
m=262144 t=2  p=1   ->   9.2 s
m=1048576 t=16 p=16 -> ~295 s CPU and ~1 GiB resident   <- accepted by both validators
```

`format.ts:96` says these bounds exist so "a hostile header could otherwise make the
receiver allocate gigabytes or spin for hours" — at the upper bound they do not achieve
that. On a phone the 1 GiB allocation is a tab kill well before any timeout fires.

The amplifier: [kdf.ts:111-120](client/src/crypto/kdf.ts:111) treats the worker's 120-second
timeout as a reason to **retry the identical computation inline on the main thread**. A
hostile peer therefore gets 120 s in a worker followed by a full, uninterruptible main-thread
freeze — the timeout makes things worse rather than bounding them.

Fix: bound `m * t * p` against the shipped default (a small multiple, not 800×), and do not
fall through to inline computation after a *timeout* — only after the worker failed to
start.

### N4. — folded into finding 13 above (severity revised to Medium).

### N5. `live:host` and Socket.IO connections have no per-IP cap — **Medium**

```
300 distinct codes reserved from 300 anonymous sockets in 623 ms (482 codes/sec)
0 refused; no auth; held for LIVE_ROOM_IDLE_MS = 15 min
```

The original covers registry exhaustion only via `/api/store/init` (#5). The socket path is
a second, independent route to the same shared registry in
[server/codes.js](server/codes.js), and it is not rate-limited either. Saturating 10⁶ codes
this way needs ~1,111 sockets/sec sustained *and* ~10⁶ held connections, so it is less
practical than the HTTP path — but there is no cap on concurrent Socket.IO connections at
all, which is also what makes finding #1's guessing attack parallelise for free. Cap
connections per IP and rooms per IP.

### N6. No HSTS on HTTPS deployments — **Low**

[index.js:16-20](server/index.js:16) deliberately omits HSTS so the app works on a plain-http
LAN origin, which is a sound reason. But the documented production path is Traefik on HTTPS,
and there the omission is a downgrade window for no benefit. Set it conditionally on
`req.secure` (which works once finding #3's proxy handling is fixed).

---

## Verified as sound — independently reconfirmed

I agree with the original's "verified as sound" list and add these, checked directly:

- **Dependencies:** `npm audit --omit=dev` — 0 vulnerabilities. All crypto is `@noble/*`,
  no hand-rolled primitives.
- **Upload token:** missing token → 403, wrong token → 403. `safeEqual`
  ([util.js:22](server/util.js:22)) length-checks before `timingSafeEqual`, which is correct
  (the token is fixed-length, so no length oracle).
- **Path traversal:** `POST /api/store/..%2F..%2Fetc%2Fpasswd/commit` → 404. Blob paths are
  built from `record.id` retrieved from an in-memory map, never from the URL parameter.
- **No XSS sink:** one `innerHTML` in the client, reachable only via an `html:` attribute key
  with zero call sites. All peer-controlled strings use `textContent`.
- **`main.ts:426`** — `location.replace(BASE + location.search + location.hash)` is not an
  open redirect; `BASE` is a build-time constant beginning with `/`.
- **Input clamping:** `ttlSeconds: 99999999 → 48 h`, `maxReads: 9999 → 100`.
- **`live:join` validation:** non-numeric and non-string codes both rejected.
- **ZIP parsing:** ZIP64 sentinels refused rather than guessed, `MAX_ENTRIES` capped,
  central-directory bounds checked, malformed input caught and reported as unreadable.
- **Nonce/AAD construction:** counter-in-nonce, final flag authenticated at both the channel
  and container layers, whole header bound into chunk AAD. No flaw found.

---

## Fix status — all of the above are now fixed

Applied and re-probed against a fresh server. Test suite went 77 → 86; typecheck
and build clean.

| Finding | Fix | Verified by |
|---|---|---|
| 1 — `live:join` unthrottled | New `server/guard.js` holds **one** budget for both the HTTP lookup and the socket event, with the same refund-on-success rule | 200 guesses → 0 allowed; a fresh socket does not reset the budget |
| 1 — no WS Origin check | `allowRequest` rejects cross-origin handshakes on **both** transports; `ALLOWED_ORIGINS` escape hatch, refusals logged | `Origin: https://evil.example` → REJECTED |
| 2 — deterministic salt | Sender draws `randomBytes(16)` and carries it in HELLO; `sessionSalt()` deleted outright so it cannot be reintroduced | receiver memoises one derivation across HELLO and the header |
| 3 — leftmost `X-Forwarded-For` | `TRUST_PROXY` is now a **hop count**; `resolveIp` counts from the right, shared by the HTTP and socket paths so they cannot disagree | rotating a forged header bought 20 attempts, not 60; a different real client keeps its own budget |
| 4 — open redirect | `.replace(/^\/+/, '')` | `/qsft//evil.example` → `/evil.example` |
| 5 — unbounded `/store/init` | Per-IP rate limit plus a ceiling on *uncommitted* reservations held | 10/400 created, then 429 |
| 6 — code-lock poisoning | The per-code lock is skipped for codes that are actually allocated | poisoned live code → genuine receiver gets 200 |
| 7 — CSP `connect-src` | Bare `ws:`/`wss:` dropped; `'self'` already covers same-origin sockets | header re-read |
| 8 — `/api/health` | Detail only over loopback, so the container healthcheck still works | remote gets `{"ok":true}` |
| 9 — source maps | `sourcemap: process.env.SOURCEMAP === '1'` | 0 `.map` files in `dist` |
| 10 — ZIP entry names | `sanitizeFilename(entry.name)` at the download call site | — |
| 11 — revoked object URL | `triggerDownload` takes the **Blob** and mints a URL per click; `url` removed from the sink contract and the event entirely | — |
| 12 — `appendPart` race | Per-record promise chain; the index check and the append are now one step | 12 × 8 concurrent same-index PUTs → blob always exactly one chunk |
| 13 — strength estimator | Tokens cross-checked against `WORDS`; unrecognised ones fall through to the character estimate | junk no longer scores "Strong" |
| N1 — `writeMeta` temp collision | Unique temp filename per write, with cleanup on failure | 24-part upload, 0 leftover temp files, no 500s |
| N2 — pre-auth body buffering | `authoriseUpload` middleware runs **before** `express.raw` | answered on headers; 1 MiB in flight vs 8 MiB read |
| N3 — peer-controlled KDF cost | One `assertKdfParams` bounds memory *and* the m×t×p product, used by both the header and handshake validators; a worker **timeout** no longer retries inline | rejects m=1 GiB/t=16/p=16 and the each-field-legal product case |
| N5 — no per-IP socket/room cap | `LIVE_ROOMS_PER_IP` and `MAX_SOCKETS_PER_IP` | 20 rooms from 300 sockets, rest refused |
| N6 — no HSTS | Set when `req.secure`, so the plain-http LAN case is untouched | — |

Nine regression tests were added for the behaviours above, including a raw-socket
test for the `appendPart` race (plain concurrent `fetch` staggers too much to
expose it) and a second server instance configured with `TRUST_PROXY=2` so the
suite can play the appending proxy.

Two things worth knowing:

- **Live transfers now show the Argon2id wait instead of hiding it.** The old
  overlap with ICE gathering was only possible because the salt was predictable.
  It is one wait, once, on the receiver.
- **`TRUST_PROXY` changed meaning**, from a boolean to a count of proxies. The
  Dockerfile's existing `TRUST_PROXY=1` is correct for a single Traefik and needs
  no change — it now means "one hop" rather than "believe the header".

---

## Original suggested order of work (for reference)

1. **#1** — rate-limit `live:join`, add `allowRequest` Origin checking. Largest exposure.
2. **#3** — hop-counted `X-Forwarded-For`. Everything else that claims rate limiting
   depends on it.
3. **N2, #5, N5** — resource limits on the unauthenticated surface: authorise before
   buffering, throttle `/store/init`, cap sockets and rooms per IP. One coherent change.
4. **#12 + N1** — per-record promise chain *and* unique temp filenames. Same file, and N1
   is a live 500 today.
5. **N3** — bound the KDF parameter product; drop the inline retry after a worker timeout.
6. **#13/N4** — cross-check passphrase tokens against `WORDS`. Small diff, and it currently
   tells users junk is "Strong".
7. **#4** and **#11** — one-line fixes.
8. **#2** — random salt in HELLO, *and* correct `README.md:95`, which is the part that is
   unambiguously wrong today.
9. **#7, #6, N6** and the remaining Lows.

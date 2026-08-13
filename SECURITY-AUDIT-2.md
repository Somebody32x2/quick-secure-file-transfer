# QSFT — Security and Usage Audit, round 2

**Date:** 2026-08-13
**Branch audited:** `security-audit-fixes` at `b7d10a7`
**Method:** full source review of `server/` and `client/src/`, dynamic probes against a locally
spawned instance of the real server, and a new end-to-end harness that drives both halves of a
live transfer through the real signalling channel. Probe artefacts were removed afterwards.
Baseline before this round: 89 tests, all passing.

---

## Summary

The thirteen findings from the first audit are genuinely closed — each was re-checked, not taken
on trust, and the fixes hold. `kdf.ts` no longer derives a salt from the room code, `util.js`
counts proxy hops from the right, `live:join` shares one budget with the HTTP lookup, and the
object-URL bug behind "Save again" is gone.

What this round found is a different shape of problem. Two of them are controls that *look*
present and are not: one is defeated by the deployment topology the README recommends, and one
is a byte counter that can be decremented twice for the same blob, which quietly retires the
storage quota. The rest are diagnosis and robustness.

| # | Severity | Finding |
|---|---|---|
| 1 | Medium | `/api/health` leaks storage figures to the internet behind a same-host proxy |
| 2 | Medium | `destroy()` is not idempotent; `bytesOnDisk` under-counts and the quota stops binding |
| 3 | Medium | A busy download spends the guess budget, locking a receiver out of their own code |
| 4 | Low | `bufferOf` can hand WebCrypto a pooled buffer instead of the frame (latent) |
| 5 | UX | A passphrase mismatch is reported to the receiver as "the other device ended the session" |
| 6 | UX | The received-bundle path skipped the completion announcement and left a stale status line |
| 7 | Testing | No end-to-end coverage; `config.ts` could not be loaded outside a Vite bundle |

All seven are fixed. Test count 89 → 102.

---

## Medium

### 1. `/api/health` leaks storage figures behind a same-host reverse proxy

The first audit's finding 8 was closed by gating the detailed readout on `isLocal(req)`, which
read `req.socket.remoteAddress`. That is the address of whatever opened the TCP connection — and
when nginx or Caddy runs on the same host and proxies to `127.0.0.1:8080`, which is the ordinary
way to deploy this, that address is loopback for **every** request, including ones from the
internet.

Measured against the real server with `TRUST_PROXY=1`:

```
remote client, via same-host proxy : {"ok":true,"items":1,"bytesOnDisk":4096,"quotaBytes":21474836480}
LEAKS STATS TO THE INTERNET        : YES
```

So the control reads as present in the source, and is absent in production. That is worse than
not having written it, because nobody goes looking again.

**Fixed** by judging on `clientIp(req)`, which counts proxy hops from the right. A client cannot
reach it by claiming `X-Forwarded-For: 127.0.0.1` — the trusted proxy appends the address it
actually saw, and that is the one read. With no proxy configured the behaviour is unchanged.

### 2. `destroy()` is not idempotent, so `bytesOnDisk` can be decremented twice

`server/store.js`. `beginRead().finish()` clears `record.reading` *before* awaiting its own
`destroy`, and `sweep()` walks a snapshot of the map taken before that. A read that exhausts its
budget while a sweep is in flight is therefore destroyed twice, and the second pass subtracts the
blob's size from `bytesOnDisk` again. `revoke` racing the sweeper does the same.

`byCode` and the code registry were already guarded against a second pass. The byte counter was
not. It only ever drifts downward, so the effect is cumulative and one-directional: the process's
idea of how much it is storing falls below the truth, `createUpload`'s quota check stops binding,
and the disk fills past the ceiling that check exists to enforce.

**Fixed** with an early return on an already-deleted record. A sidecar found on disk still marked
`deleted` at boot is debris from a destroy whose file removal failed; it is now cleaned up
directly rather than handed to `destroy`, and never restored — whatever set that flag was an
expiry or a revocation, and those are meant to stick.

### 3. A busy download spends the guess budget

`server/routes.js`. `store.beginRead(code)` throws 409 when another reader holds the blob, and
that threw straight past `noteSuccess`. The attempt had already been counted by
`guardCodeLookup`, so every collision permanently consumed one of the caller's twenty attempts
for a code they demonstrably already held.

Two people collecting a multi-read transfer at the same time, or one person retrying after a
dropped connection, throttle themselves out of their own transfer. This is the same class of
mistake as the first audit's finding 6 — enumeration defences charging legitimate users — in the
one code path that was not covered by that fix.

**Fixed** by refunding on a real-but-busy code. Regression test asserts twelve collisions against
an 8-attempt limiter leave the transfer collectable.

---

## Low

### 4. `bufferOf` can hand WebCrypto a pooled buffer instead of the frame

`client/src/crypto/aead.ts` normalised a view for `crypto.subtle` via `u8.slice().buffer`. That
relies on `slice` copying — true for a genuine `Uint8Array`, false for a Node `Buffer`, where
`slice` is an alias for `subarray` and returns a view over the same memory. `.buffer` on that view
is the whole pooled allocation:

```
sealed.byteLength     : 48
bufferOf would yield  : 8192 bytes, wanted 48
```

**Browsers are not affected**, so this is latent rather than a live defect — but it is a security
primitive whose stated contract is "an ArrayBuffer of exactly these bytes", and it should not rest
on which flavour of `Uint8Array` the caller happens to hold. It was also load-bearing for the
end-to-end harness below: every relayed frame failed authentication until it was fixed.

**Fixed** by writing the copy out explicitly.

---

## User experience

### 5. A passphrase mismatch is reported to the wrong device

The sender checks the responder's transcript MAC first, fails, and tears the session down. The
receiver — the person who just typed the passphrase — was sitting in `awaitStep('confirm')` and
learned only:

```
Handshake aborted: the other device ended the session
```

True about the event, useless about the cause, and pointing at the wrong device. The one person
who can fix the problem was the one person not told what it was.

**Fixed** with a `kex-abort` signal carrying a fixed reason code. Only the code crosses the wire
and the wording is chosen locally: the signalling channel is reachable by anyone who guesses six
digits, so a free-text reason would be attacker-supplied copy rendered inside our own failure
notice. Only a MAC failure is forwarded — reporting "authentication failed" for a malformed key
would be a lie in the direction that makes people distrust the network.

### 6. The received-bundle path skipped its completion signals

`transferScreen.ts` returned early for a ZIP to open the archive browser, before
`announce('Transfer complete and verified')` and without clearing the status line — so a finished
transfer still read "Receiving..." and a screen reader was never told it had completed.

---

## Testing

### 7. No end-to-end coverage, and `config.ts` could not load outside Vite

Every layer was tested; the seams between them were not. The failures that live there are exactly
the ones no unit test sees — a completion signal losing a race with its own teardown, two devices
disagreeing about the transport, a credit window that stalls, a salt one side derives and the
other does not.

The obstacle was mechanical: `config.ts` read `import.meta.env.BASE_URL` as a bare property, which
throws under plain Node, and every transport module reaches that file transitively. Reading it
through an optional chain makes the session layer loadable headlessly. Because Vite resolves that
expression by pattern-matching it at build time, and getting the shape wrong would break only
subpath deployments and only in production, `test/build.test.ts` now builds for real and asserts
the mount point is baked in — verified to fail if the expression stops being statically
resolvable.

`test/e2e.test.ts` then drives both halves of a live transfer through the real server: real
signalling, real hybrid PQ handshake, real secure channel, real credit-based flow control, real
container. Node has no `RTCPeerConnection`, so both sides fall back to the encrypted relay — the
path where the server sits in the middle of every frame, and the one worth exercising hardest.
It covers byte-exact round trips, SAS agreement across devices, compression, multi-file bundles,
passphrase mismatch, code release on completion, and the store-and-forward flow end to end.

---

## Verified as sound this round

Re-checked rather than assumed, and correct:

- All thirteen first-round fixes hold, including the ones with subtle failure modes: the random
  live salt, hop-counted `X-Forwarded-For`, the shared code-guess budget across HTTP and socket,
  the per-record append lock, and per-click object URLs.
- `roomsByIp`, `socketsByIp` and the code registry balance across every room-teardown path
  (`live:bye`, either side disconnecting, idle timeout, relay congestion).
- The per-code lockout correctly skips allocated codes, so enumeration cannot poison a live
  transfer's own code.
- `MessagePump` drains in-flight frames before reporting a close, which is what lets a sender see
  the receiver's confirmation rather than the teardown behind it — now covered end to end.
- The transcript MAC, the final-chunk flag at both layers, `fromBase64Exact`, the small-order
  X25519 check, and the header-bound AAD all behave as the first audit described.

---

## Fixes in this round

| File | Change |
|---|---|
| `server/routes.js` | health detail judged on the resolved client address; refund a busy 409 |
| `server/store.js` | `destroy` made idempotent; leftover `deleted` sidecars cleaned at boot |
| `client/src/crypto/aead.ts` | `bufferOf` copies explicitly instead of relying on `slice` |
| `client/src/crypto/kex.ts` | `HandshakeError` carries a machine-readable `auth` reason |
| `client/src/session/handshake.ts` | forward a MAC failure to the peer as a fixed reason code |
| `client/src/ui/transferScreen.ts` | bundle path emits the same completion signals as the rest |
| `client/src/config.ts` | loadable outside a Vite bundle; subpath build asserted by test |

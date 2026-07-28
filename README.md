# QSFT — Quantum-Secure File Transfer

Move a file between two devices without trusting the thing in the middle.

Files are encrypted in the browser under a passphrase you choose, before a byte
leaves the device. Live transfers add a second layer keyed by a hybrid
post-quantum key exchange. The server never holds a key, and in live mode never
holds the file.

Built for phones as first-class endpoints, and for hosts you have no reason to
trust — including plain-HTTP LAN addresses where the browser refuses to hand out
WebCrypto at all.

```bash
npm install
npm run build
npm start          # http://localhost:8080
```

For development, `npm run dev` runs the API on `:8080` and Vite on `:5173` with
`--host`, so a phone on the same network can reach it.

```bash
npm test           # 61 tests: crypto, container framing, degraded hosts, server, service worker
npm run icons      # regenerate the PWA icon set
```

It installs as a PWA — "Add to Home Screen" on a phone gives you an app icon and
a standalone window, which is the point when the device is meant to be an
endpoint.

---

## How a transfer works

Pick a file, type a passphrase, and choose how to send it. The other device
enters the 6-digit code and the same passphrase. QSFT works out on its own
whether that code is a live sender or a stored blob.

**Live** — both devices open at once.

1. **Direct peer-to-peer** over a WebRTC data channel. The file never touches
   the server. On a shared network this is also the fastest path by a wide
   margin.
2. **Server relay** if direct fails (symmetric NAT, blocked UDP, a WebView with
   no WebRTC). The server forwards opaque frames between exactly two sockets and
   keeps nothing. Backpressure is credit-based, so in-flight memory stays at a
   couple of megabytes rather than the size of the file.

**Leave on server** — upload now, collect later. The encrypted blob waits under
its code until whichever limit comes first:

- a deadline, capped at 48 hours and settable as low as an hour
- a read budget, down to a single read — collect it once and it is deleted

The sender can also delete it immediately from the result screen.

---

## Security design

### Encrypting the file

Every transfer — live or stored — produces the same container, so a blob
captured off the wire and one sitting on the server are the same object and are
opened by the same code.

```
[64-byte header][sealed 1 KiB metadata][sealed chunk]...[sealed chunk]
```

| Layer | Choice |
|---|---|
| KDF | Argon2id, 19 MiB / t=2 / p=1, 16-byte random salt |
| Cipher | XChaCha20-Poly1305, or AES-256-GCM where WebCrypto exists |
| Chunking | STREAM construction, 1 MiB stored / 64 KiB live |

The chunk counter and a final-chunk flag are bound into every nonce, and the
entire header is bound in as associated data. So reordering chunks, replaying
one, truncating the stream, or editing the header to downgrade the cipher or
weaken the KDF parameters all fail authentication rather than producing
plausible output. There is no separate "wrong password" check to get wrong — a
bad passphrase is just an AEAD failure on chunk 0.

Metadata (filename, size, type) is encrypted as chunk 0 in a fixed 1 KiB block,
so the ciphertext length does not leak how long the filename is.

### Keying a live session

Live transfers wrap the container in a second layer, keyed by a hybrid exchange:

```
X25519  +  ML-KEM-768        (FIPS 203)
      concatenated into one HKDF
```

An attacker must break **both** to recover the session key. The classical half
keeps the exchange at least as strong as X25519 if a lattice weakness turns up;
the ML-KEM half defends against harvest-now-decrypt-later.

An unauthenticated KEM over a server-brokered channel is trivially
machine-in-the-middled by that server, so the transcript is authenticated with
an HMAC keyed by the Argon2id output both devices already share. The server
cannot forge that tag. Both devices then display a **short authentication
string** — four glyphs and six digits derived from the completed transcript. If
the two screens match, nobody substituted keys.

Layers do different jobs, deliberately:

- the **inner** layer protects the file end to end, forever, including from the
  server, and is all a stored transfer has
- the **outer** layer gives the live session forward secrecy and post-quantum
  protection, and hides the container header from the relay

### Running on an untrusted host

On a plain-HTTP origin the browser withholds `crypto.subtle` entirely. QSFT
therefore uses pure-JavaScript primitives (`@noble/*`) for everything and treats
WebCrypto purely as an optional accelerator. Nothing in the transfer path
depends on it.

Randomness is the harder problem. `crypto.getRandomValues` *is* available in
insecure contexts, but some hardened WebViews ship a broken one. QSFT probes it
— including for the "returns all zeros" failure — and falls back to a software
DRBG seeded from timing jitter and device entropy, then says so loudly in the
UI. Every random byte in the app, including ML-KEM key generation and
encapsulation, is drawn through that one probed source.

This is covered by tests that run in a process where `crypto.subtle` genuinely
does not exist (`test/untrusted-host.test.ts`).

### Installing it

The app ships a manifest, a maskable icon set, and a service worker, so it
installs to a home screen and opens without a network round trip. The install
offer appears in-app when the browser says it is possible; on iOS, which never
fires an install event, the app shows the Share → Add to Home Screen route
instead. No dead buttons either way.

A service worker on a cryptography tool is a persistent, privileged thing, so
this one is deliberately narrow:

- **Nothing under `/api/` is ever cached or served from cache.** That path
  carries ciphertext, upload tokens, and code lookups. A cached blob would
  outlive the deletion the server just performed and quietly turn a
  burn-after-read transfer into a stored copy on the device.
- `/socket.io/` is never touched — live payload frames pass through it.
- Only same-origin GETs are considered, and only status-200 basic responses are
  stored.
- A new version does **not** take over silently. It waits, and the app offers a
  reload — swapping cryptographic code out from under a running page is not
  something to do behind the user's back.

Those rules are enforced by tests (`test/service-worker.test.ts`), not just by
comment, and were confirmed against a live install: after an upload, a code
lookup, and a full ciphertext download, the cache held the ten shell entries and
nothing else.

Because hashed asset filenames change every build, an app update propagates
without the worker changing: `index.html` is fetched network-first and the new
asset URLs it names simply miss the cache.

**Installing requires HTTPS or localhost.** Browsers gate service workers on
secure contexts, so on the plain-HTTP LAN origins this app also supports, it
runs normally but cannot be installed. That is a browser rule, not something the
app can opt out of.

---

## What this does not protect against

Stated plainly, because a security tool that oversells itself is worse than one
that doesn't.

**A weak passphrase is the whole ballgame.** Everything else is downstream of
it. An attacker who captures a transfer can grind candidates offline. Argon2id
makes each guess expensive, not impossible. The passphrase field estimates
strength and will generate a 48-bit one for you — use it.

**An active MITM can attack the passphrase offline.** Because the handshake is
authenticated with a passphrase-derived key rather than a PAKE, someone who
completes a handshake in the middle can take the captured MAC away and grind it.
Comparing the short authentication string out of band closes this completely.
A future version should use a real PAKE (CPace or SPAKE2) to remove the exposure
entirely.

**Codes are only 6 digits.** They gate access to ciphertext, not plaintext, and
guessing is rate-limited per IP and per code — but the space is 10⁶. Do not
treat the code as a secret.

**Send the passphrase through a different channel than the code.** Putting both
in the same message defeats the design.

**The server learns metadata.** File size (approximately — compression blurs
it), timing, IP addresses, and who talked to whom. It never learns file
contents, filenames, or keys.

**Compression leaks a coarse entropy signal** through ciphertext length, which
is why it is a per-transfer toggle.

**Deletion is `unlink`, not secure erasure.** On SSDs and journaling filesystems
the bytes may survive physically. Full-disk encryption on the server is the
answer, not a userspace overwrite.

**Stored transfers have no forward secrecy.** They are protected by the
passphrase alone; if it leaks later, a retained copy of the blob is readable.
Live transfers do have forward secrecy via the ephemeral session key.

**The software DRBG is a real downgrade.** It exists so the app degrades to
"probably fine" instead of refusing to run. Don't use it for anything serious.

**This has not been independently audited.** The cryptographic primitives are
well-regarded audited libraries; the protocol composing them is not.

---

## Configuration

All optional, all environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `PORT` / `HOST` | `8080` / `0.0.0.0` | listen address |
| `DATA_DIR` | `./data` | where encrypted blobs live |
| `MAX_TTL_SECONDS` | `172800` | hard retention cap (48h) |
| `DEFAULT_TTL_SECONDS` | `86400` | default retention |
| `STORAGE_QUOTA_BYTES` | `20 GiB` | refuse uploads past this |
| `MAX_FILE_BYTES` | `2 GiB` + slack | per-file ceiling |
| `CODE_ATTEMPTS_PER_IP` | `20` | code lookups per window |
| `CODE_ATTEMPT_WINDOW_MS` | `600000` | that window |
| `ICE_SERVERS` | public STUN | JSON array of ICE servers |
| `TRUST_PROXY` | off | honour `X-Forwarded-For` |

Successful lookups are refunded against the rate limit, so collecting many real
transfers never throttles you — only guessing does.

No TURN server is configured by default. If a NAT defeats direct P2P, QSFT falls
back to its own relay, where the payload is already double-encrypted, rather
than routing it through a third-party TURN operator.

### Serving from a subpath

QSFT can run at the root of a domain or under a path such as
`samuelshuster.com/filetransfer`. Set `BASE_PATH` in **both** places — it is a
build argument for the client (Vite bakes it into asset URLs) and a runtime
variable for the server:

```bash
BASE_PATH=/filetransfer npm run build
BASE_PATH=/filetransfer ALIAS_PATHS=/qsft npm start
```

Everything that constructs a URL follows it: API calls, the Socket.IO endpoint,
the service worker's registration and scope, and the manifest. The manifest uses
relative URLs and the service worker derives its own base from its URL, so
neither needs templating.

`ALIAS_PATHS` is a comma-separated list of paths that **301-redirect** to the
canonical mount point. Redirects rather than second mounts, deliberately:
serving one PWA at two paths on an origin gives it two service worker scopes,
two caches, and two install identities for the same app.

The server also tolerates a reverse proxy that strips the prefix. Path-based
routing may forward `/filetransfer/api/x` intact or strip it to `/api/x`
depending on middleware, so the prefix is removed before Express or Socket.IO
see the request — if the proxy already did it, that is a no-op. Either
configuration works.

### Deploying with Docker / Coolify

```bash
docker build --build-arg BASE_PATH=/filetransfer -t qsft .
docker run -p 8080:8080 -v qsft-data:/data \
  -e BASE_PATH=/filetransfer -e ALIAS_PATHS=/qsft qsft
```

On Coolify, using the Dockerfile build pack:

| Setting | Value |
|---|---|
| Build argument | `BASE_PATH=/filetransfer` |
| Environment | `BASE_PATH=/filetransfer`, `ALIAS_PATHS=/qsft`, `TRUST_PROXY=1` |
| Domain | `https://samuelshuster.com/filetransfer` |
| Extra domain | `https://samuelshuster.com/qsft` (so the redirect is reachable) |
| Persistent volume | `/data` |
| Port | `8080` |

Two things to get right or transfers break:

- **The `/data` volume must persist.** Without it every redeploy silently
  discards stored transfers that have not yet been collected.
- **WebSockets must be allowed through** to `/filetransfer/socket.io`. Without
  them live transfers lose the relay fallback, so any pair of devices that
  cannot reach each other directly will fail rather than degrade.

`TRUST_PROXY=1` matters because the code-guessing rate limiter keys on client
IP; behind a proxy without it, every request looks like it comes from the proxy
and one abuser would throttle everybody.

### Deployment notes

Serve over HTTPS in production. The app is built to survive plain HTTP, but that
is a fallback for LAN and development, not a recommendation — without TLS an
attacker can serve you modified JavaScript, and no in-page cryptography survives
that.

Server state (live rooms, the code registry, rate limiters) is in memory, so
**run a single process**. Behind multiple instances you would need a shared
store for `server/codes.js` and sticky sessions for Socket.IO.

---

## Layout

```
client/
  index.html
  public/      manifest.webmanifest, sw.js, icons/
  src/
    crypto/    env, kdf, aead, format, stream, kex, channel, sas
    transport/ signal (Socket.IO), p2p (WebRTC), link, api
    session/   liveSend, liveReceive, stored, handshake, protocol, pump
    ui/        dom, components, transferScreen
    pwa.ts     install prompt, update handling
server/        index, routes, live, store, codes, config, util
scripts/       dev, test, make-icons
test/          crypto, container, untrusted-host, server, service-worker
```

No UI framework. On a tool whose job is cryptography, a smaller bundle is less
to audit.

## License

MIT

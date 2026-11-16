# Motivation

*Why whatsnative exists, and why it is built the way it is.*

## The problem

Linux users are the only major desktop audience without an official native WhatsApp application. The workarounds that exist fall into a few categories, and each one asks the user to give up something important:

1. **Browser tabs and Electron/Bundled-Chromium wrappers around WhatsApp Web.** They work, but ship a full browser engine: high idle memory, a slow cold start tied to a web session, an online-only message store, and no native desktop calling. Your chat history effectively lives in somebody else's web session, not in a database you own.

2. **System-webview wrappers (`WebKitGTK`, `QtWebEngine`).** Lighter than Electron, but still a web renderer pretending to be a native app. They inherit the web platform's searching, rendering, and calling limitations, and they still depend on WhatsApp Web being reachable.

3. **Chat bridges (for example, a local Matrix bridge + a native Matrix client).** These require running a homeserver and a bridge daemon, map WhatsApp semantics onto another protocol imperfectly, and cannot offer native WhatsApp voice/video calling or screen sharing.

None of these is a *native Linux companion*: a real compiled application that owns a local encrypted database, integrates with the desktop through standard Freedesktop interfaces, starts instantly, searches offline, and can grow into calling without being rewritten.

## Why native, and why now

A native client should deliver, for an ordinary Linux user:

- **Ownership and speed:** local storage you control, with `< 100 ms` startup and `< 100 ms` full-text search across hundreds of thousands of messages — online or offline.
- **Desktop fit:** real GTK4/libadwaita widgets, correct bidirectional text shaping (Arabic, Hebrew, Urdu), CJK input methods, screen-reader accessibility, fractional Wayland scaling, and notifications/background sync/tray via XDG portals rather than bespoke hacks.
- **Calling parity:** the official macOS companion has voice/video calling; Linux should not be structurally unable to follow. That requires a GUI toolkit and media stack capable of zero-copy PipeWire/GStreamer `DMA-BUF` video — which is why GTK4 was chosen up front and why call-signaling states are modeled from the first release.
- **Low footprint:** a background sync worker that idles in tens of megabytes, and a UI shell that releases all GPU resources when its window closes.

## The risk that shaped the architecture

An unofficial native client cannot call a public API — Meta publishes none for personal accounts. It must speak WhatsApp's undocumented Noise-framed socket protocol, binary XML (`WABinary`), and a large set of protobuf schemas. **Isolating protocol code in a module does not hide the resulting wire traffic from Meta's servers.**

That creates a serious, non-abstract risk:

- When Meta changes required client versions, binary dictionaries, or rate thresholds, an outdated binary that blindly reconnects sends stale fingerprints and retries in loops. That pattern is exactly what automated anti-abuse systems use to flag and **ban phone numbers**.
- For a real person, a banned number is not a developer inconvenience. It means losing family chats, work groups, and — increasingly — two-factor login codes for other services.
- Slow-moving distribution channels make this worse: a frozen distro repository can leave users on a ban-inducing protocol version for weeks or months.
- Trademark rules mean an unofficial client cannot simply call itself `"WhatsApp"`-anything on Flathub.

So "zero webview" was never the only goal. The deeper goal is **account safety by design**, plus fast, publisher-controlled delivery. That is the reason for the guardrails throughout this codebase:

- An **Ed25519-signed compatibility manifest** and per-feature kill switches are verified *before* any WhatsApp socket is opened.
- Unrecognized server rejections trip an **automatic circuit breaker** into offline read-only mode instead of retrying.
- Outbound commands pass through a **human-paced token bucket** with jitter, plus per-group retry quarantine, to avoid velocity-based flags.
- Distribution is intended through **fast-updating channels** (Flatpak/AppImage), never frozen distro archives.
- The app has one consistent public name and ID (`whatsnative`, `io.github.rabimba.whatsnative`).

## Why local-first and why so defensive about storage

WhatsApp deletes server-side ciphertext once a companion sends a delivery receipt. If the client discards protobuf fields it does not yet understand, those fields are **gone forever** — including future message types and call logs. So the store commits raw decrypted protobuf bytes (tagged with a `parser_schema_version`) *before* acknowledging the message, allowing future upgrades to re-parse and re-index old rows.

Other data-loss traps drove similar decisions:

- **Rollback corruption:** downgrading a binary must never rewind Signal ratchets or `syncd`/LTHash counters, or MAC failures force logouts and bans. A cryptographic/sync store is kept physically separate from the rebuildable application vault, guarded by an additive-only schema ratchet.
- **`@lid` split-brain:** WhatsApp mixes phone-number JIDs (`@s.whatsapp.net`) with privacy Linked IDs (`@lid`). Keying threads by raw wire IDs splits one conversation into two. All records reference internal canonical IDs backed by an atomic alias table.
- **`HistorySync` storms:** initial pairing can stream 50,000–500,000+ messages that will not be resent. Chunks are staged to disk and committed in single-writer WAL batches, with asynchronous FTS5 indexing and a configurable LRU media cache.

## Why the safety/observability approach is privacy-preserving

Debugging an unofficial client with real chat data is itself a privacy hazard. Therefore:

- there is a **zero-PII** error taxonomy and stack-only, heap-scrubbed crash reporting;
- rotating logs live in `$XDG_STATE_HOME`, never `$XDG_CONFIG_HOME`, and contain no PII;
- the **Export Redacted Diagnostic Bundle** replaces phone numbers/JIDs with salted HMAC hashes;
- a deterministic **`--mock` fixture mode** lets contributors build and test the whole UI without risking a personal number.

## What success looks like

A Linux user links their account once, then gets: instant window startup, fast offline encrypted search, low idle memory across GNOME/KDE/tiling Wayland without needing a tray, automatic safe offline quarantine instead of an account ban when Meta changes the wire protocol, and — in Phase 2 — voice, video, and Wayland screen sharing that attach to the call-signaling state machines built today, with no re-pairing and no UI rewrite.

## Where to go next

- [`architecture.md`](architecture.md) — how the code is structured to deliver on these goals.
- [`security.md`](security.md) — the threat model and guardrails in detail.
- [`roadmap.md`](roadmap.md) — how the work is staged.
- [`../concepts_brief.md`](../concepts_brief.md) — the original concept and risk analysis.

# Architecture

whatsnative is a local-first, hexagonal Rust workspace. The central rule is that **wire-protocol types, database types, D-Bus types, and GTK types never cross into each other's layers**. Everything communicates through the pure contracts in `whatsnative-domain`.

## Workspace map

```
crates/
  domain/          whatsnative-domain        pure contracts + safety gates
  store/           whatsnative-store         encrypted persistence + search + media cache
  platform-xdg/    whatsnative-platform-xdg  XDG layout, portals, keyring, diagnostics, lifecycle
  adapter-wa/      whatsnative-adapter-wa    whatsapp-rust adapter + --mock harness
  ui-gtk4/         whatsnative (binary)      GTK4 / libadwaita application
packaging/         Flatpak manifest, desktop entry, AppStream metainfo
```

Dependencies point inward:

```
ui-gtk4 ──► adapter-wa ──► store ──► domain
   │            │            │         ▲
   └────────────┴────────────┴─────────┘  (platform-xdg also depends on domain)
```

- `whatsnative-domain` has **no** dependency on `whatsapp-rust`, `rusqlite`, `zbus`, or `gtk4`.
- `whatsnative-adapter-wa` exposes **no** `whatsapp_rust` / `wacore` / `waproto` type in its public API.

This is what lets the protocol engine be upgraded (or replaced) without rewriting the UI or migrating user history.

## 1. `whatsnative-domain` — the contract layer

Defines the vocabulary shared by every crate:

- **Canonical identity:** `CanonicalPeerId` and `ConversationId` (UUIDv7) decouple UI/search records from wire-level `@s.whatsapp.net` vs `@lid` JIDs.
- **Timeline model:** `ConversationKind`, `MessageContent`, `TimelineMessage`, `QuotedReplyRef`, `ReactionChip`, `DeliveryState`, `LinkPreviewCard`, `SearchHit`, `HistorySyncStats`.
- **Call seam:** `ActiveCallBanner`, `CallOutcome`, `Phase2MediaSessionHandle` — call signaling is a first-class domain concept even though SRTP media is Phase 2.
- **Safety gates:** `CompatManifest` with Ed25519-verifiable signatures, `CompatDecision`, `FeatureFlags`, `semver_at_least()`.
- **Ports:** `ProtocolEnginePort` (async trait) and the `DomainEvent` / `EngineCommand` bus that the UI and adapter exchange.
- **Lifecycle:** `VaultLifecycleState`, distinguishing `VaultLocked` from `Unpaired` so a locked keyring at boot never looks like a fresh install.

## 2. `whatsnative-store` — local-first persistence

A deliberately split store:

1. **Cryptographic & sync state** — additive-only `crypto_schema_guard.json` plus the `crypto_session.db` path. `CryptoSchemaGuard::verify_or_init()` refuses to let an older binary reader open a newer ratchet store (downgrade safety halt). Physically separate from rebuildable data.
2. **Application vault & search** — `vault.db`, encrypted with SQLCipher (`PRAGMA key`) in WAL mode. Holds:
   - the atomic `@lid` ↔ phone-number peer/conversation alias tables (thread merging),
   - **raw decrypted protobuf bytes** with `PARSER_SCHEMA_VERSION`, committed before network ACKs (`InboundCommitRecord`),
   - staged `HistorySync` chunks and sync statistics,
   - a disposable FTS5 full-text index rebuilt asynchronously from canonical rows.
3. **Encrypted media cache** — `EncryptedMediaCache`, per-file ChaCha20-Poly1305 AEAD with a configurable LRU byte ceiling (default **3 GiB**).

`VaultStore` is the facade used by the rest of the app. `run_data_attribution_audit()` and backup-inspection helpers support the `--inspect-data` mode.

## 3. `whatsnative-platform-xdg` — desktop integration

- **`XdgLayout`** resolves data/state/cache/config roots with `0700` permissions and zero PII in `$XDG_CONFIG_HOME`. `--profile-dir` overrides all roots for isolated testing.
- **`DesktopCapabilities::probe_live()`** uses `zbus` to detect the session type, current desktop, XDG portals (Notification, Background, Secret, ScreenCast), a `StatusNotifierWatcher`, and the secret service. It derives a safe `CloseWindowPolicy`: hide to the Background Portal, hide to a real system tray, or quit cleanly.
- **`KeystoreManager`** implements tiered 256-bit master-key unlocking, separating a locked vault from an unpaired device so boot-time locked keyrings never wipe session state.
- **Notifications & lifecycle:** `send_desktop_notification()`, `request_background_portal_status()`, and `spawn_sleep_wake_listener()` (listens to `org.freedesktop.login1` and re-checks socket liveness after suspend/resume).
- **`RedactedDiagnosticsRing` / `RedactedDiagnosticBundle`** produce salted-HMAC, zero-PII diagnostic exports; `scrub_jids_in_line()` is the primitive that strips identifiers.

## 4. `whatsnative-adapter-wa` — protocol isolation + safety

Wraps `whatsapp-rust 0.7.0` (with the `voip-mlow` feature) behind `ProtocolEnginePort`. No wire type escapes.

Safety components:

- **`OutboundRateGuard`** — a token bucket of ≤ 3 req/s sustained, burst 4, plus 40–180 ms randomized jitter, protecting personal accounts from anti-scraper velocity flags.
- **`GroupRetryQuarantine`** — isolates failing group members so one bad recipient does not cause repeated whole-group retries.
- **Commit-before-ACK hook** (`InboundDurabilityHook`) — persists the message before sending the delivery receipt.
- **Circuit breakers** for `405` / `TemporaryBan` responses and an `AdapterMetrics` counter set that feeds diagnostics.
- **`CompatManifest` verification before connecting**, plus a View-Once companion-privacy enforcement path.
- **Call signaling** — parses `<call>` offer/ring/reject/answered-elsewhere/missed events into `ActiveCallBanner`s and supports call decline.
- **`MockCompanionAdapter`** — a deterministic, zero-account fixture archive powering `--mock`.

`LiveWhatsAppAdapter` is the production implementation. Mapping helpers such as `map_wa_message_to_domain()` / `extract_wa_message_rich()` translate wire messages into domain content.

## 5. `whatsnative` (`ui-gtk4`) — the native shell

- **`main.rs`** — parses CLI, resolves XDG layout, probes capabilities, handles headless `--inspect-data` and `--export-diagnostics` modes, then starts the GTK application on a Tokio runtime.
- **`app.rs`** — the `AdwApplication`, adaptive `AdwNavigationSplitView` (conversation list ↔ thread), composer, reply/edit state, search integration, attachment dialogs, clipboard image paste, and incoming-call banner handling.
- **`qr_widget.rs`** — Cairo-rendered vector QR canvas for companion pairing.
- **`style.rs`** — shared styling; `cli.rs` — flag parsing.

Text is rendered with Pango/HarfBuzz for correct BiDi/RTL/CJK/Emoji shaping.

## Data flow

```
User action (GTK UI)
   │  EngineCommand (queued → sending → sent/quarantined)
   ▼
Outbox in local vault ──► ProtocolEnginePort (adapter-wa)
                              │  rate guard + circuit breaker + compat gate
                              ▼
                         WhatsApp network
                              │  inbound events
                              ▼
InboundDurabilityHook ──► raw protobuf + projection committed to vault ──► receipt sent
                              │
                              ▼
                     DomainEvent ──► UI updates (local-first; UI never reads wire types)
```

## Packaging

`packaging/` contains a Flatpak manifest (`io.github.rabimba.whatsnative.yml`), a `.desktop` entry, and AppStream metainfo. The manifest uses the GNOME 47 platform and the Rust SDK extension, grants only the necessary portal/D-Bus talks, and installs the binary plus desktop metadata. Distribution is intended through fast-updating publisher channels, not frozen distro archives (see [`motivation.md`](motivation.md)).

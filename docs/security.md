# Security & account-safety model

This document describes the threat model behind whatsnative and the concrete guardrails implemented in the code. **Read it before pairing a personal phone number.**

## Threat model

| Threat | Consequence | Mitigation in this codebase |
| :--- | :--- | :--- |
| Unofficial protocol drift (version bumps, dictionary changes) | Stale fingerprints / retry loops → **phone-number ban** | `CompatManifest` verified (Ed25519) before any socket opens; per-feature kill switches; offline read-only quarantine |
| Unknown server rejection (`405`, temporary ban) | Account flags if the client keeps retrying | Circuit breakers halt reconnects and switch to read-only |
| High outbound velocity | Anti-scraper heuristics flag the account | `OutboundRateGuard` token bucket (target ≤ 3 req/s, burst 4, 40–160 ms jitter) + `GroupRetryQuarantine`. Known limitation: concurrent sends can wake together; see the audit notes. |
| Binary downgrade | Rewinding Signal ratchets / LTHash counters → MAC failures, forced logout, ban flags | `CryptoSchemaGuard` additive-only ratchet; cryptographic state physically separate from rebuildable vault |
| Message loss on ACK | Servers delete ciphertext after receipt; unknown fields lost forever | Commit-before-ACK hook stores raw decrypted protobuf with `parser_schema_version`; FTS5 rows are kept consistent through merges and deletes |
| `@lid` vs phone split-brain | Duplicate threads, missed history | Canonical IDs + atomic alias table in the vault |
| `HistorySync` loss / storage blow-up | History gone after re-pair; disk exhaustion | Chunk staging, single-writer WAL commits, async indexing, 3 GiB LRU media cache |
| Local data disclosure | Private chats readable on disk or at the keyring | SQLCipher vault, 0700 XDG dirs, ChaCha20-Poly1305 media cache, zero PII in config |
| Locked keyring at boot misread as unpaired | Session metadata overwritten, history lost | `VaultLocked` distinct from `Unpaired`; tiered key unlock with passphrase fallback |
| Telemetry / diagnostic leakage | JIDs or message content shipped in bug reports | Zero-PII error taxonomy, salted-HMAC redacted bundle export, state-dir logs, `--mock` mode |

## Pre-connect compatibility gate

The `whatsnative-domain` crate defines `CompatManifest`, `CompatDecision`, and `FeatureFlags`. A signed manifest (`compat/compat_manifest.json`) is compiled into the binary. Before any socket, client, or transport work, the adapter verifies its Ed25519 signature against a public key pinned in the source (`COMPAT_VERIFYING_KEY`) and then evaluates the minimum safe client version and any feature kill switches.

Verification fails closed: an unsigned, tampered, or corrupt manifest puts the app in offline read-only quarantine. Updating the manifest requires the project's private signing key; see the comment in `crates/domain/examples/sign_manifest.rs`. The key is deliberately not in this repository.

`--allow-unverified-protocol` deliberately bypasses this gate. It is a **power-user escape hatch**, not a recommended mode: using it forfeits the primary account-safety protection. Never use it on a number you cannot afford to lose.

## Rate limiting and circuit breakers

- `OutboundRateGuard` is a human-paced token bucket targeting ≤ 3 requests/second sustained, burst of 4, plus 40–160 ms randomized jitter. It is not yet applied to every network call, and concurrent callers can wake at the same time.
- `GroupRetryQuarantine` prevents repeated retries against individual failing members from cascading into whole-group velocity spikes.
- `AdapterMetrics` and `DiagnosticCounterSnapshot` count paced commands, quarantined receipts, circuit-breaker trips, and protocol anomalies, so operators can see safety events without seeing message content.

## Encryption and data ownership

- **Vault:** `vault.db` is SQLCipher-encrypted with a 256-bit master key; connections run in WAL mode.
- **Key management:** `KeystoreManager` obtains the master key from a portal-provided secret or the host secret service (`org.freedesktop.secrets`), with a passphrase-wrapped fallback. Vault state is tracked as `VaultLifecycleState` so a locked keyring is never confused with an unpaired device.
- **Media:** `EncryptedMediaCache` applies per-file ChaCha20-Poly1305 AEAD with random nonces and LRU eviction (default 3 GiB).
- **Filesystem:** `XdgLayout` creates all app directories with `0700` permissions. No PII is written to `$XDG_CONFIG_HOME`; rotating logs go to `$XDG_STATE_HOME`.
- **View-Once:** the companion enforces the official companion restriction — View-Once media is not opened or forwarded. This is intentionally stricter than some bridges.

## Redacted diagnostics

`--export-diagnostics <file.json>` produces a `RedactedDiagnosticBundle` using salted HMAC-SHA256 hashes in place of phone numbers/JIDs. `scrub_jids_in_line()` does the stripping; the in-memory `RedactedDiagnosticsRing` is bounded (500 events). The output contains structural counters and error taxonomy only — no message bodies, no contact identifiers. This is the safe artifact to attach to a bug report.

## Lifecycle safety

`DesktopCapabilities::probe_live()` probes the session at runtime. The app only hides to the background or tray when a real XDG Background Portal or `StatusNotifierWatcher` exists; otherwise it quits cleanly. `spawn_sleep_wake_listener()` watches `org.freedesktop.login1` and triggers socket-liveness checks after suspend/resume so half-open TCP sockets do not silently drop messages.

## Disclosure

If you believe you have found a security or account-safety issue, please do **not** open a public issue containing real identifiers or message content. Export a redacted bundle with `--export-diagnostics` and follow the disclosure process in **[`contributing.md`](contributing.md)**.

## Scope limits

whatsnative is an independent project and is not affiliated with WhatsApp LLC or Meta. It does not provide, and will not provide, bypasses of official companion privacy restrictions (for example opening/sending View-Once media), cloud relay services, or telemetry containing personal data.

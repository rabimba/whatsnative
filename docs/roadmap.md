# Roadmap

The work is staged deliberately. Early phases establish safety gates and the call-signaling seams so later phases never require re-pairing, a history migration, or a UI rewrite.

## Phase 0 — Foundation & safety gates ✅ (implemented)

- A consistent public identity (`whatsnative`, `io.github.rabimba.whatsnative`) and the GPL-3.0-or-later license.
- Hexagonal Rust workspace with zero wire types crossing crate boundaries.
- Dual SQLCipher store split: cryptographic/sync state vs. rebuildable application vault, with an additive-only rollback guard.
- Ed25519-verifiable `CompatManifest` + feature kill switches checked before connecting.
- Deterministic `--mock` fixture-replay mode.
- Zero-PII redacted diagnostic bundle exporter.
- XDG layout with `0700` permissions and runtime D-Bus/portal capability probing.

## Phase 1A — Daily-driver E2EE core ✅ (implemented)

- QR and 8-character phone-number companion pairing.
- `HistorySync` chunk staging + canonical `@lid` ↔ phone-thread merging.
- 1:1 and group E2EE text, replies, reactions, edits, deletes, link previews.
- Media attachments, clipboard image paste, XDG file dialogs.
- `< 100 ms` offline FTS5 search with sync-completeness stats.
- Runtime-probed Background Portal, desktop notifications, optional `StatusNotifierItem` tray.
- **Passive call signaling:** incoming-call banners and missed-call timeline logs (real-time media deferred).
- Keyboard shortcuts and BiDi/RTL/CJK/Emoji rendering.

## Phase 1B — Rich desktop messaging (planned)

- Shared PipeWire/GStreamer Opus voice-note recording, waveform rendering, speed-adjusted playback.
- Inline video and sticker rendering.
- Polls and Communities.
- Companion Chat Lock unlock support.

## Phase 1C — Isolated broadcast & MEX surfaces (planned)

- Status (`status@broadcast`) read/write with validated privacy-list encryption fan-out.
- Channels (`@newsletter`) behind a separate schema and a feature-flagged `MEX` circuit breaker.

These are deliberately isolated: Status contact-list fan-out and Channels' frequently rotating GraphQL query IDs are higher-risk surfaces than core Signal messaging, so they ship behind their own kill switches.

## Phase 2 — Real-time calling & screen sharing (planned)

- 1:1 and group voice/video calls using MLow/Opus audio, PipeWire echo cancellation, and hardware H.264 video.
- Wayland desktop/window sharing via `org.freedesktop.portal.ScreenCast` with zero-copy `DMA-BUF` → GStreamer rendering.

The `ActiveCallBanner`, `CallOutcome`, and `Phase2MediaSessionHandle` domain types exist already so Phase 2 attaches to the Phase 1 signaling state machines rather than replacing them.

## Explicit non-goals

- Primary-device registration, SMS verification, or replacing the phone as the root identity.
- Bypassing official companion privacy restrictions (View-Once media, legacy broadcast lists).
- Cloud relays, PII telemetry, or paid LLM features.
- Packaging in slow-updating frozen distro archives.

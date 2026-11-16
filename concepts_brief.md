# Native Linux WhatsApp Companion Client (`whatsnative` Working Codename)

* **Author:** Rabimba Karanjai
* **Date:** 2026-11-09

> **Naming note:** This brief was written before a public name was chosen. The author has since decided to publish the project as **whatsnative**, with app ID `io.github.rabimba.whatsnative`. References below to choosing or replacing a name are historical; the final name is whatsnative. It remains an independent project that is not affiliated with WhatsApp LLC or Meta.

## Overview

Linux desktop users currently lack an official native WhatsApp desktop application. Existing workarounds rely on browser tabs, Electron or system-webview wrappers around WhatsApp Web, or self-hosted chat bridges. Browser wrappers consume hundreds of megabytes of idle memory, depend on active web sessions rather than a fast local search database, and miss native desktop calling capabilities available on macOS.

This concept proposes a compiled native Linux WhatsApp companion application—without Electron or webviews—built on a Linux GUI toolkit and Freedesktop/XDG desktop services for notifications, background synchronization, optional system tray controls, and encrypted secret storage. It aims to match the capabilities of the official macOS companion client across phases: pairing via QR code or 8-character link code, 1:1 and group end-to-end encrypted messaging, media attachments, voice notes, reactions, replies, offline local search, Status, and Channels first, followed by 1:1 and group voice/video calling and Wayland screen sharing in Phase 2 without rewriting the user interface.

---

## Analysis

### Goldfish Multi-Lens Audit Status

All seven isolated, fresh-context Goldfish reviewers evaluated the anchored concept in `BRAINSTORM` mode against the empty greenfield workspace at `/home/rabimba/Documents/GitHub/whatsnative`:

| Reviewer ID | Brainstormer Role Lens | Status |
| :--- | :--- | :--- |
| `egm-design` | Design Critic Brainstormer | `completed` |
| `egm-codebase-details` | Codebase Details Brainstormer | `completed` |
| `egm-zoom-out` | Skeptical Architect Brainstormer | `completed` |
| `egm-comprehension` | UX & Comprehension Brainstormer | `completed` |
| `egm-implementation-readiness` | Implementation Readiness Brainstormer | `completed` |
| `egm-structural` | Structural Architecture Brainstormer | `completed` |
| `egm-inventive-catalyst` | Inventive Catalyst Brainstormer | `completed` |

### Core Risks & Stress-Tested Assumptions

1. **Public Audience ("Everyone") Collides with Unofficial Protocol Ban Risk (Blocker):**
   Meta provides no public personal-account client API. Any non-webview client must speak WhatsApp's undocumented `Noise` encrypted socket framing, binary XML messages (`WABinary`), and protobuf schemas. Isolating protocol code inside a module does not hide wire traffic from Meta's servers. When Meta updates required client version numbers, binary dictionaries, or rate thresholds, older binaries that keep reconnecting in the background send outdated fingerprints or retry loops that trigger automated phone-number bans. For everyday users, losing a personal WhatsApp number cuts off family chats, work groups, and two-factor login codes. In addition, traditional Linux distribution archives (`apt`, `dnf`, LTS channels) delay package updates by weeks or months, stranding users on ban-inducing protocol versions, and Flathub trademark rules restrict app names and icons that borrow WhatsApp branding (a concern raised before the final name was chosen).
   * **Required Guardrails:** Require a plain-language first-run risk consent screen; verify a cryptographically signed remote minimum-safe-version and feature-kill-switch manifest before opening any WhatsApp socket; trip an automatic circuit breaker into offline read-only mode on unrecognized server rejections instead of retrying; enforce human-paced outbound rate limiters (`<= 2-5` requests/second with random jitter, `$0` cloud/LLM cost); distribute only through fast-updating publisher-controlled channels (Flatpak on Flathub, AppImage) rather than frozen distro archives; and choose a trademark-clean public brand name before packaging.

2. **Single-Socket Exclusivity & Unconstrained Stack Traps Across Phase 1 and Phase 2 Calling (Blocker):**
   A linked WhatsApp companion device holds a single encryption identity, one active `Noise` WebSocket connection, and one Signal Double Ratchet and Sender Key store. Two separate engines cannot share one companion session concurrently. Incoming `<call>` signaling messages (offer, ring, reject, answered-elsewhere, missed) arrive over the same socket as text messages during Phase 1. Ignoring `<call>` messages in Phase 1 causes desktop users to miss phone calls silently and forces state-machine and timeline rewrites in Phase 2.
   Furthermore, leaving the native language and GUI toolkit open creates two traps:
   * **Protocol Engine Scarcity & Re-Pairing Loss:** Only two mature open-source WhatsApp multi-device implementations exist: `oxidezap/whatsapp-rust` (Rust, covering multi-device messaging, Status, Channels, and WhatsApp's custom `MLow`/Opus/SRTP voice and H.264 video calling hooks) and `tulir/whatsmeow` (Go, widely used in bridges, which omits calling unless paired with external `purpshell/meowcaller`). Embedding Go into a Rust or C++ UI process via `cgo` mixes two runtimes and garbage collectors, whereas swapping engines in Phase 2 without application-owned credential and history schemas forces every user to unlink, re-pair, and lose older local chat history beyond WhatsApp's initial sync window. Existing native Linux projects (`oxidezap/client` in Rust and `codelif/whatevr` in Go + Qt/Kirigami) also already explore parts of this space and should be evaluated before writing greenfield glue.
   * **Linux GUI & Wayland Video Constraints:** Consumer chat requires bidirectional right-to-left text shaping (Arabic, Hebrew, Urdu), Asian input methods (`IBus`/`Fcitx5`), screen-reader accessibility (`AT-SPI2`), Wayland fractional scaling, and zero-copy GPU video frame rendering (`DMA-BUF` buffers from PipeWire and GStreamer via `org.freedesktop.portal.ScreenCast`) for Phase 2 video calls and screen sharing. Only GTK4 (`libadwaita` + `GstGtk4Paintable`) and Qt6 (`Kirigami` + `QVideoSink`) currently provide all of these on Linux.

3. **Linux Desktop Fragmentation Breaks Naive "Standard Freedesktop/XDG" Assumptions (Blocker):**
   Linux desktops do not share a uniform tray or secret-storage contract:
   * **Missing System Tray on Default GNOME:** No XDG Desktop Portal exists for tray icons. Default GNOME omits `StatusNotifierItem` (`org.kde.StatusNotifierWatcher`) tray support, while minimal Wayland compositors (Sway, Hyprland) often omit Background Portal menus. Hardcoding "close window to tray" leaves GNOME users with an invisible background process they cannot reopen or quit.
   * **Locked Keyrings & Sandbox Transitions:** Flatpak apps receive a single sandbox secret via `org.freedesktop.portal.Secret`, whereas host builds query `org.freedesktop.secrets` (GNOME Keyring, KWallet, KeePassXC). If the app autostarts at login before the keyring is unlocked, naive clients treat missing keys as an unpaired first run and overwrite session metadata. Laptop suspend/resume (`s2idle`/S3) also leaves half-open TCP sockets appearing connected while dropping incoming messages.
   * **Required Guardrails:** Probe D-Bus capabilities at runtime: use XDG Background Portal plus single-instance D-Bus launcher re-activation as the primary lifecycle, enable `StatusNotifierItem` tray controls only when an active host watcher is detected, and quit cleanly on window close when neither exists. Separate `VaultLocked` state from `Unpaired` state, unlock one local `SQLCipher` database using a single 256-bit master key (with passphrase KDF fallback), and listen to `org.freedesktop.login1` sleep/wake signals to verify socket liveness.

4. **Irreversible Ratchet State, Raw Protobuf Loss, `@lid` Split-Brain, and `HistorySync` Storms (Blocker):**
   * **Permanent Server Deletion After ACK:** Once a companion decrypts an incoming message and sends a delivery `<receipt>`, WhatsApp servers delete that ciphertext permanently. Discarding unrecognized protobuf fields in Phase 1 causes irreversible loss of future message types and call logs. Every decrypted `E2E.Message` raw protobuf payload must be saved to local storage with a `parser_schema_version` *before* sending the network receipt so future app upgrades can re-parse and re-index older rows.
   * **Rollback Corruption:** Rolling back an update (`flatpak update --commit`) must never restore an old backup of Signal ratchets or `syncd` (`LTHash` app-state sync) counters after network traffic has occurred, or MAC failures will force logouts and ban flags. Persistence must split physically into an additive-only **Cryptographic & Sync State Store** and a rebuildable **Application Vault & Search Store**.
   * **Phone-Number vs. `@lid` Identity Split:** WhatsApp mixes phone-number IDs (`@s.whatsapp.net`) and privacy Linked IDs (`@lid`). Keying chat tables by raw wire IDs splits single conversations into duplicate threads. All UI and search records must reference an internal canonical peer/conversation ID backed by an atomic `@lid` <-> phone-number alias table.
   * **One-Time `HistorySync` Ingestion & Storage Caps:** Initial pairing streams 50,000–500,000+ historical messages in compressed chunks that WhatsApp will not resend without re-pairing. Raw chunks must stage to disk first and commit in single-writer SQLite `WAL` batches while `FTS5` full-text indexing runs asynchronously in the background, paired with UI sync-completeness indicators and a configurable 3 GB LRU media cache limit (`<= 16 ms` chat switch, `<= 100 ms` `FTS5` search).

5. **Monolithic Phase 1 Scope & Zero-PII Observability Gaps (Major):**
   Bundling Channels (`@newsletter`) and Status (`status@broadcast`) into initial core chat delivery couples Signal messaging to Channels' unencrypted `MEX` GraphQL queries (whose opaque query IDs Meta rotates frequently) and Status's contact-list encryption fan-out (where bugs leak private updates or trip spam heuristics). Official macOS companions also block opening and sending View-Once media; matching official companion restrictions avoids privacy violations and unofficial-client detection.
   For operational debugging without leaking private data, the client needs a zero-PII error taxonomy, stack-only/heap-scrubbed crash reports (`NT_GNU_BUILD_ID` symbolicated), structure-only binary tag captures on schema errors, rotating `0700` logs in `$XDG_STATE_HOME` (never `$XDG_CONFIG_HOME`), a one-click **"Export Redacted Diagnostic Bundle"** using salted HMAC hashes in place of phone numbers, and an offline `--mock` fixture-replay mode so contributors can build and test UI workflows without risking personal phone numbers.

### Inventive Contradictions & Suggested Catalog Patterns

| # | Core Contradiction | Inventive Transform Patterns | Architectural Mechanism & Secondary Trade-offs |
| :--- | :--- | :--- | :--- |
| **C1** | **Packaged Native Binary Stability & macOS Parity** vs. **Zero-Notice Meta Protocol Drift & Account Safety** | **Blessing in Disguise** + **Beforehand Cushioning** + **Dynamics** | Treat unexpected server tags, version warnings, and stream errors as active anti-ban tripwires that halt reconnects and switch into offline read-only quarantine; check an Ed25519-signed protocol compatibility and per-feature kill-switch manifest before connecting; pace outbound requests, Channel fetches, and Status fan-out to active foreground user interaction. *Trade-offs:* Benign server glitches can trigger temporary read-only quarantine; requires hosting a static signed manifest; background hydration is slower than the official macOS app. |
| **C2** | **Phase 1 Delivery Speed & Open Toolkit Choice** vs. **Zero-Rewrite Upgrade to Phase 2 Calling & Screen Sharing** | **Preliminary Action** + **Intermediary** + **Segmentation** | Run a Phase 0 toolkit gate proving PipeWire `DMA-BUF` to GStreamer zero-copy video rendering (`GTK4` or `Qt6`) before building views; route all events through a canonical domain bus that includes `<call>` signaling states (`offer`, `ringing`, `missed`, `handled_elsewhere`) in Phase 1; split Phase 1 vs. Phase 2 along *signaling vs. real-time SRTP media* (showing incoming-call alerts and missed calls in Phase 1 while deferring audio/video codecs and Status publishing). *Trade-offs:* Constrains GUI toolkit choice to GTK4 or Qt6 upfront, adds GStreamer/PipeWire CI setup early, and defers Status publishing out of initial MVP. |
| **C3** | **24/7 Background Sync & Tray Controls** vs. **Low Idle RAM/GPU Footprint & Tray-less Wayland/Flatpak Support** | **Segmentation** + **Cheap Dispensables** + **Dynamics** | Separate a persistent, GPU-less background sync worker (`<= 25-80 MB` RSS, using XDG Background and Notification v2 portals) from a disposable native UI shell (or releasable widget/GPU tree) that frees 100% of GPU textures on window close and cold-starts in `<100 ms` from local SQLite; probe session D-Bus at runtime to expose `StatusNotifierItem` tray controls only when an active host panel exists. *Trade-offs:* `~50-100 ms` window reopen rehydration, local IPC or lifecycle coordination, explicit UI copy distinguishing "Close Window" from "Quit Background Sync," and broader desktop QA coverage. |
| **C4** | **Upstream Protocol Survival Velocity** vs. **Native Linux GUI Safety, Instant Offline Search & Engine Replaceability** | **Extraction (Taking Out)** + **Inversion** | Isolate the WhatsApp protocol worker behind a versioned boundary with zero leaked wire types, and invert control flow into a local-first `SQLCipher` `WAL` + `FTS5` outbox model: the UI reads local projections exclusively and writes queued user actions (`queued` -> `sending` -> `sent`/`quarantined`), while the worker asynchronously syncs network deltas and preserves canonical device credentials across engine upgrades. *Trade-offs:* Eventual-consistency UI state handling and strict schema-version discipline across the worker/vault boundary. |

### Ideal Final Result (IFR)

A Linux user links their WhatsApp account once via QR or phone code and gets `<100 ms` window startup, `<100 ms` offline full-text search across hundreds of thousands of locally encrypted messages, low idle background memory across GNOME, KDE Plasma, and tiling Wayland compositors without requiring a system tray, automatic offline read-only quarantine instead of account bans whenever Meta alters wire schemas, and Phase 2 1:1/group voice, video, and Wayland screen sharing that attach directly to Phase 1's call-signaling state machines and zero-copy PipeWire/GStreamer video widgets without re-pairing or UI refactoring.

---

## Goals vs. Non-Goals

* **In-Scope Goals:**
  * **Phase 0 (Foundation & Safety Gates):** Trademark-clean public app identity; Phase 0 zero-copy Wayland `ScreenCast` -> PipeWire `DMA-BUF` -> GStreamer video sink proof in the chosen native toolkit; dual-database `SQLCipher` storage split (Cryptographic Store vs. Application Vault) unlocked via XDG Secret Portal / Secret Service with passphrase fallback; signed pre-connect compatibility/kill-switch gate; offline `--mock` fixture-replay mode; zero-PII redacted diagnostic exporter.
  * **Phase 1A (Daily-Driver E2EE Core):** QR and 8-character phone-number companion pairing; `HistorySync` chunk staging and `LTHash` app-state sync; canonical `@lid` <-> phone-number identity resolution; 1:1 and group E2EE text, media attachments, clipboard image paste, replies, reactions, edits, deletes; offline `FTS5` search with sync-completeness indicators; runtime-probed XDG Background Portal, Notification v2 inline replies, and optional `StatusNotifierItem` tray; passive `<call>` stanza handling for live incoming-call desktop banners/notifications and missed-call timeline logs; Linux/Freedesktop keyboard shortcuts.
  * **Phase 1B (Rich Desktop Messaging):** Shared PipeWire/GStreamer Opus voice-note recording, waveform rendering, and speed-adjusted playback; inline video/sticker rendering; Polls; Communities; companion Chat Lock unlock support.
  * **Phase 1C (Isolated Broadcast & MEX Surfaces):** Read/write Status (`status@broadcast`) with validated privacy-list encryption fan-out, and Channels (`@newsletter`) isolated behind a separate schema and feature-flagged `MEX` circuit breaker.
  * **Phase 2 (Real-Time Calling & Screen Sharing):** 1:1 and group voice/video calling (`MLow`/Opus audio + PipeWire echo cancellation + hardware H.264 video) and Wayland desktop/window sharing (`org.freedesktop.portal.ScreenCast`).

* **Out-of-Scope Non-Goals:**
  * Primary-device phone number registration, SMS verification, or replacing the user's mobile phone as the root WhatsApp identity.
  * Bypassing official macOS/companion privacy restrictions (specifically opening or sending View-Once photos, videos, and voice notes, or legacy non-companion broadcast lists).
  * Cloud relay servers, server-side push proxies, telemetry collection containing PII/JIDs/plaintext, or paid LLM features (`$0` cloud infrastructure and `0` token budget).
  * Packaging inside slow-updating, frozen Linux distribution repositories (such as Debian Stable or Ubuntu LTS system archives) that cannot deliver protocol fixes within 24–48 hours.

---

## Alternatives Weighed

* **Electron or Bundled Chromium Wrappers around WhatsApp Web:** Rejected by author: Bundles a full browser engine with high idle memory overhead and fails the requirement for an OS-native compiled Linux client with local encrypted database ownership and native desktop calling parity.
* **System WebView Wrappers (`WebKitGTK` / `QtWebEngine`, such as `Karere` or `Whatsie`):** Rejected in current concept hypothesis due to the author's no-webview native OS requirement (flagged by `egm-zoom-out` as the safest pivot if zero account-ban risk for general users outweighs native offline search, `<80 MB` background RAM, and Phase 2 native desktop calling).
* **Local Matrix Bridge + Existing Native Matrix Client (`mautrix-whatsapp` + `Fractal` or `NeoChat`):** Rejected during technical analysis: Requires operating a local or remote Matrix homeserver and bridge daemon, maps WhatsApp features imperfectly onto Matrix room semantics, and cannot provide native WhatsApp 1:1/group calling or screen sharing.
* **Clean-Room WhatsApp Multi-Device Protocol Implementation From Scratch:** Rejected during technical analysis: Writing and maintaining `Noise` handshakes, Signal Double Ratchet/Sender Keys, `WABinary` dictionaries, 100+ protobuf definitions, `LTHash` sync, `@lid` migration, and `MLow`/SRTP VoIP from zero lines of code duplicates existing open-source engines (`oxidezap/whatsapp-rust`, `tulir/whatsmeow`) and delays a usable client by years.
* **Immediate-Mode or Custom GPU Native UI Toolkits (`egui`, `iced`, `Slint`, raw `wgpu`):** Rejected during technical analysis: Lack mature right-to-left script shaping, CJK input-method (`IBus`/`Fcitx5`) support, `AT-SPI2` screen-reader accessibility, and ready-made zero-copy PipeWire/GStreamer `DMA-BUF` video widgets needed for general Linux users and Phase 2 video calling.
* **Frozen Traditional Distro Repository Packaging (`apt`, `dnf` LTS snapshots):** Rejected during technical analysis: Multi-week update lag leaves users running deprecated WhatsApp wire revisions that trigger reconnect loops and automated account bans.

---

## Key Decisions & Staging for Next Steps

Before entering `/egm:egm-draft` to write the formal technical design specification, the following decisions need confirmation or resolution from the author:

1. **Audience Risk Posture vs. No-WebView Constraint:** Confirm that targeting general Linux users via an unofficial native protocol binary includes mandatory first-run account-risk consent, human-paced rate limiting, and a signed remote pre-connect kill-switch/quarantine gate (or decide to pivot to a system-webview wrapper if zero ban risk is strictly required).
2. **Public Brand Identity & License:** *Resolved:* the project is published as `whatsnative` with app ID `io.github.rabimba.whatsnative` under `GPL-3.0-or-later`. The original concern about Flathub naming policy still applies to any future Flathub submission.
3. **Greenfield Build vs. Upstream Reuse & Primary Native Stack:** Decide whether to build greenfield on **Rust + GTK4/`libadwaita` + `oxidezap/whatsapp-rust` + PipeWire/GStreamer** (single-language memory model with built-in Rust VoIP/MLow hooks) versus **Qt6/`Kirigami`** or an **out-of-process `whatsmeow` + `meowcaller` Unix-socket worker**, after checking whether contributing upstream to `oxidezap/client` or `codelif/whatevr` already satisfies the project goals.
4. **Sub-Phased Phase 1 Roadmap (1A -> 1B -> 1C) + Passive Call Alerts in 1A:** Confirm splitting Channels (`@newsletter`) and Status (`status@broadcast`) into Phase 1C behind independent circuit breakers, while pulling passive `<call>` incoming-call notifications and missed-call logs forward into Phase 1A.

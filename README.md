# Kestrel Companion (`whatsnative`)

**A compiled, zero-Electron / zero-WebView native Linux companion client for WhatsApp Multi-Device.**

Built with **Rust 1.94**, **GTK4 4.14**, **libadwaita 1.5**, **SQLCipher**, and **XDG Desktop Portals**.

> **Trademark & affiliation notice:** Kestrel Companion (`io.github.rabimba.kestrel`, binary `whatsnative`) is an independent open-source project. It is **not** affiliated with, authorized, sponsored, or endorsed by WhatsApp LLC or Meta Platforms, Inc. The public brand name was deliberately chosen to comply with third-party trademark policies (no `"Whats*"` branding).

---

## Why this exists (Motivation)

Linux is the one major desktop platform with **no official native WhatsApp client**. The options available today all make the same trade-off: they wrap WhatsApp Web in a browser engine instead of being a real native application.

That trade-off has real costs for everyday users:

| Problem with browser/webview wrappers | How Kestrel Companion approaches it |
| :--- | :--- |
| Hundreds of MB of idle RAM from a bundled browser engine | A compiled GTK4 binary that idles in **tens of MB**, with a GPU-less background worker |
| Messages live in a web session; offline search is slow or absent | A local-first **SQLCipher** vault with **FTS5** full-text search in **< 100 ms** |
| No native desktop calling parity with the official macOS companion | Call-signaling state machines are built in from day one, ready for Phase 2 voice/video |
| Frozen distro packages strand users on outdated protocol versions | Fast-updating, publisher-controlled channels (Flatpak/AppImage) plus a **signed pre-connect safety gate** |
| Opaque binaries that phone home with unknown data | Auditable Rust code, **zero-PII** diagnostics, and all message data stays on your disk |

But "just write a native client" is not enough. An unofficial client speaks WhatsApp's undocumented protocol, so a naive reconnect loop can trip anti-abuse systems and get a **personal phone number banned** — cutting someone off from family chats, work groups, and two-factor login codes. That risk shaped the entire architecture: a signed compatibility manifest is verified *before* any socket opens, outbound traffic is human-paced, unknown server responses trip an automatic read-only circuit breaker, and Signal ratchet state is protected against binary rollbacks.

The result is a local-first, safety-first companion: fast, encrypted, and designed to fail safe rather than fail your account.

For the full problem analysis, risks, and design decisions, see **[`docs/motivation.md`](docs/motivation.md)** and **[`concepts_brief.md`](concepts_brief.md)**.

---

## Highlights

- 🧱 **Hexagonal crate boundaries** — protocol churn never leaks into the UI or database.
- 🔐 **Encrypted at rest** — SQLCipher `vault.db`, ChaCha20-Poly1305 media cache, zero PII in `$XDG_CONFIG_HOME`.
- 🔎 **Local-first** — raw decrypted protobufs committed *before* network ACKs; rebuildable FTS5 index.
- 🛡️ **Account-safety guardrails** — signed `CompatManifest`, circuit breakers, human-paced outbound limiter, per-group retry quarantine.
- 🖥️ **Truly native** — GTK4/libadwaita adaptive split view, BiDi/RTL/CJK/Emoji rendering, Wayland/X11, XDG portals.
- 📞 **Call-aware** — live incoming-call banners and missed-call logs from Phase 1, ready for Phase 2 SRTP media.
- 🧪 `--mock` — a deterministic, zero-account offline demo with 60+ searchable fixture messages.
- 🩺 **Zero-PII diagnostics** — salted-HMAC redacted bundles that can be shared safely.

---

## Architecture at a glance

| Crate | Path | Responsibility |
| :--- | :--- | :--- |
| `whatsnative-domain` | [`crates/domain`](crates/domain) | Pure Rust contracts: `CanonicalPeerId`, `ConversationId`, `TimelineMessage`, `ActiveCallBanner`, Ed25519-verifiable `CompatManifest`. Zero protocol/DB/DBus/UI deps. |
| `whatsnative-store` | [`crates/store`](crates/store) | Rollback-safe crypto guard, encrypted `vault.db` (WAL), atomic `@lid` ↔ phone-thread merge, raw protobuf retention, FTS5 search, encrypted LRU media cache. |
| `whatsnative-platform-xdg` | [`crates/platform-xdg`](crates/platform-xdg) | XDG layout (`0700`), live portal capability probing, secret-service key unlock, `login1` sleep/wake watchdog, redacted diagnostics. |
| `whatsnative-adapter-wa` | [`crates/adapter-wa`](crates/adapter-wa) | Isolated `whatsapp-rust` companion adapter with safety guardrails, call signaling, and the `--mock` fixture harness. |
| `whatsnative` | [`crates/ui-gtk4`](crates/ui-gtk4) | Native GTK4 + libadwaita shell, Cairo QR canvas, link-code flow, Pango text rendering, file dialogs, clipboard paste. |

See **[`docs/architecture.md`](docs/architecture.md)** for the full design and **[`docs/security.md`](docs/security.md)** for the threat model.

---

## Quick start

### System dependencies

```bash
# Ubuntu / Debian
sudo apt install build-essential pkg-config libssl-dev libgtk-4-dev libadwaita-1-dev libdbus-1-dev
```

```bash
# Fedora
sudo dnf install gcc make pkgconf-pkg-config openssl-devel gtk4-devel libadwaita-devel dbus-devel
```

You also need a recent Rust toolchain (`rust-version = 1.94`, edition 2024) — install it from [rustup.rs](https://rustup.rs).

### 1. Try it with zero account (recommended first)

Launch the full native client with pre-seeded 1:1, group, BiDi/RTL/CJK/Emoji, poll, view-once-privacy-stub, channel, and 60+ FTS5-searchable messages — no phone number required:

```bash
cargo run -p whatsnative -- --mock
```

> 💡 Send `/call` in any mock chat (or use **Menu → Simulate Incoming Call**) to exercise the live incoming-call banner and call-decline flow. Press `Ctrl+K` to try the search.

### 2. Pair a real companion device

```bash
# QR-code pairing
cargo run --release -p whatsnative

# Pre-fill an 8-character phone link code
cargo run --release -p whatsnative -- --phone 14155550199
```

> ⚠️ **Account safety:** this is an unofficial client. Read **[`docs/security.md`](docs/security.md)** before pairing a personal number. A first-run risk consent and a signed pre-connect compatibility check protect you; `--allow-unverified-protocol` exists only as a documented power-user escape hatch.

### 3. Export a redacted diagnostic bundle (headless)

```bash
cargo run -p whatsnative -- --mock --export-diagnostics /tmp/kestrel-diag.json
```

---

## Command-line reference

| Flag | Description |
| :--- | :--- |
| `--mock` | Launch the offline, zero-account fixture archive (no phone required). |
| `--profile-dir <DIR>` | Use an isolated XDG data/state/cache/config root (useful for tests). |
| `--passphrase <PASS>` | Unlock or initialize a passphrase-wrapped SQLCipher vault. |
| `--phone <DIGITS>` | Request an 8-character phone-number companion link code. |
| `--pair-code <CODE>` | Supply a custom 8-character link code together with `--phone`. |
| `--export-diagnostics <FILE.json>` | Export a zero-PII salted-HMAC diagnostic bundle and exit. |
| `--inspect-data` | Headless vault integrity / data-attribution audit. |
| `--allow-unverified-protocol` | Power-user override of the `CompatManifest` safety quarantine. |
| `-h`, `--help` | Print usage. |
| `-V`, `--version` | Print version. |

---

## Keyboard shortcuts

| Shortcut | Action |
| :--- | :--- |
| `Ctrl+K` | Focus the global `<100 ms` SQLCipher FTS5 search bar |
| `Enter` | Send message (or save an edit) |
| `Shift+Enter` | Insert a newline in the composer |
| `Ctrl+V` | Paste clipboard text, or send a clipboard screenshot/image directly as PNG |
| `Esc` | Cancel an active Reply or Edit |

---

## Testing

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all -- --check
```

The `--mock` mode is intentionally deterministic so contributors can develop and test the entire UI without ever touching a real phone number.

---

## Project status

Kestrel Companion implements **Phase 0** (safety foundation) and **Phase 1A** (daily-driver E2EE core). Richer messaging, Status/Channels, and real-time calling are staged in later phases so the call-signaling seams exist now without requiring a UI rewrite later. See **[`docs/roadmap.md`](docs/roadmap.md)** for the full staged plan.

---

## Contributing

Contributions are welcome. Start with **[`docs/contributing.md`](docs/contributing.md)** for development setup, crate boundaries, and testing expectations. Please do not open issues that include real phone numbers, JIDs, or message content — use `--export-diagnostics` to produce a safe redacted bundle instead.

---

## License

`GPL-3.0-or-later` — see [`LICENSE`](LICENSE).

# whatsnative

A native Linux companion app for WhatsApp Multi-Device.

It is a real, compiled desktop application. It does **not** bundle a browser. There is no Electron and no WebView. It is written in Rust and uses GTK4, libadwaita, SQLCipher, and the standard Linux desktop services.

> **Independent project.** whatsnative (`io.github.rabimba.whatsnative`) is open source. It is not affiliated with, authorized, sponsored, or endorsed by WhatsApp LLC or Meta Platforms, Inc.

---

## Why we built whatsnative

Linux has no official native WhatsApp desktop app. The apps people use today are web pages wrapped in a browser engine. That works, but it costs you:

- **Memory.** A browser engine uses hundreds of megabytes even when you are not chatting.
- **Your own data.** Your messages live in a web session, not in a database on your computer.
- **Offline search.** Without a local database, finding an old message is slow or impossible.
- **Desktop features.** Browser wrappers cannot offer the calling and desktop integration that a native app can.

A native app should be fast, private, and feel at home on Linux. It should open quickly, search your messages without the internet, keep your history encrypted on your own disk, and use your desktop's notifications and background services.

### The risk that shaped the design

There is another reason to be careful. WhatsApp does not offer a public API for personal accounts. An unofficial app has to speak WhatsApp's private protocol. If it reconnects too often, sends messages too fast, or uses an old protocol version, WhatsApp can ban the phone number. For a real person, that can mean losing family chats, work groups, and two-factor login codes.

So whatsnative is built to **fail safely**:

- It checks a signed compatibility file (bundled in the app and verified against a built-in key) before it opens a connection. If the check fails, it stays offline instead of connecting.
- It slows outgoing messages to a human pace.
- If the server sends something unexpected, it stops reconnecting and switches to read-only mode instead of retrying.
- It saves each message to your local database before it tells the server it arrived.

The result is a local-first, safety-first companion. It is fast, encrypted, and designed to protect your account.

For the full story, read [Why this project exists](docs/motivation.md).

---

## What it can do today

- **Native interface.** A GTK4/libadwaita window that adapts to your screen size. Correct text layout for Arabic, Hebrew, Chinese, Japanese, and emoji.
- **Local, encrypted storage.** A SQLCipher database on your disk. Full-text search usually returns results in under 100 ms, even offline.
- **Chats.** One-to-one and group messages, replies, reactions, edits, deletes, media attachments, and image paste.
- **Safety guardrails.** A signed pre-connect check, rate limiting, and circuit breakers that protect your number.
- **Call alerts.** Incoming call banners and missed-call entries. Real voice and video calls are planned for a later phase.
- **A demo mode.** Run `--mock` to try the whole app without a phone number.
- **Private diagnostics.** Export a bug report with phone numbers and IDs replaced by hashes.

---

## How the code is organized

The project is split into five parts. Each part has one job, and they talk to each other through simple, shared types.

| Part | Folder | What it does |
| :--- | :--- | :--- |
| `whatsnative-domain` | `crates/domain` | The shared vocabulary: chats, messages, call banners, and the safety checks. No network or database code. |
| `whatsnative-store` | `crates/store` | The encrypted database, search index, and media cache. |
| `whatsnative-platform-xdg` | `crates/platform-xdg` | Linux desktop services: notifications, background activity, secret storage, and diagnostics. |
| `whatsnative-adapter-wa` | `crates/adapter-wa` | The WhatsApp protocol code, kept in one place, plus the `--mock` demo data. |
| `whatsnative` | `crates/ui-gtk4` | The GTK4 application you see and use. |

This split means a change to the WhatsApp protocol does not force a rewrite of the interface or the database. Read [the architecture guide](docs/architecture.md) for more.

---

## Get started

### Install the build tools

You need Rust 1.94 or newer, plus the GTK4 and libadwaita development files.

```bash
# Ubuntu / Debian
sudo apt install build-essential pkg-config libssl-dev libgtk-4-dev libadwaita-1-dev libdbus-1-dev

# Fedora
sudo dnf install gcc make pkgconf-pkg-config openssl-devel gtk4-devel libadwaita-devel dbus-devel
```

Install Rust from [rustup.rs](https://rustup.rs) if you do not have it yet.

### Try the demo first

This needs no phone number and changes no real account.

```bash
cargo run -p whatsnative -- --mock
```

Things to try:

- Press `Ctrl+K` to search the demo messages.
- Send `/call` in any chat, or use **Menu → Simulate Incoming Call**, to see a call alert.
- Paste an image with `Ctrl+V` to send it.

To keep the demo separate from your real data:

```bash
cargo run -p whatsnative -- --mock --profile-dir /tmp/whatsnative-demo
```

### Use your own account

```bash
# Pair with a QR code
cargo run --release -p whatsnative

# Or pre-fill an 8-character link code
cargo run --release -p whatsnative -- --phone 14155550199
```

Please read [the security guide](docs/security.md) before you pair a personal number. It explains the safety checks and what you give up if you disable them.

### Export a private bug report

This works without a visible desktop.

```bash
cargo run -p whatsnative -- --mock --export-diagnostics /tmp/whatsnative-diag.json
```

---

## Command line options

| Option | What it does |
| :--- | :--- |
| `--mock` | Start the offline demo. No phone needed. |
| `--profile-dir <DIR>` | Keep all app files in a separate folder. Useful for tests. |
| `--passphrase <PASS>` | Unlock or create a database protected by a passphrase. |
| `--phone <DIGITS>` | Ask for an 8-character link code for this phone number. |
| `--pair-code <CODE>` | Use a specific link code together with `--phone`. |
| `--export-diagnostics <FILE.json>` | Write a private bug report and exit. |
| `--inspect-data` | Check the database for problems and exit. |
| `--allow-unverified-protocol` | Power-user override of the safety check. Not recommended. |
| `-h`, `--help` | Show help. |
| `-V`, `--version` | Show the version. |

---

## Keyboard shortcuts

| Key | Action |
| :--- | :--- |
| `Ctrl+K` | Focus the search bar |
| `Enter` | Send a message, or save an edit |
| `Shift+Enter` | Add a new line in the message box |
| `Ctrl+V` | Paste text, or send an image from the clipboard |
| `Esc` | Cancel a reply or an edit |

---

## Where your files go

whatsnative follows the XDG folder rules. All folders are created with private (`0700`) permissions.

| Purpose | Folder |
| :--- | :--- |
| App data and encrypted database | `$XDG_DATA_HOME/whatsnative/` |
| Logs and diagnostics state | `$XDG_STATE_HOME/whatsnative/logs/` |
| Media cache | `$XDG_CACHE_HOME/whatsnative/media/` |
| Settings (no personal data) | `$XDG_CONFIG_HOME/whatsnative/` |

Use `--profile-dir <DIR>` to put all four folders somewhere else.

---

## Testing and contributing

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all -- --check
```

The demo mode is deterministic, so you can test the interface without a real phone number. See [Contributing](docs/contributing.md) before you open a pull request.

If you find a bug, please do not include real phone numbers or messages in a public issue. Export a redacted report with `--export-diagnostics` instead.

---

## Where the project is going

The safety foundation and the core chat features are done. Voice notes, stickers, polls, Status, Channels, voice and video calls, and screen sharing are planned in later phases. See [the roadmap](docs/roadmap.md).

---

## Further reading

- [Why this project exists](docs/motivation.md)
- [Getting started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Security and account safety](docs/security.md)
- [Roadmap](docs/roadmap.md)
- [Contributing](docs/contributing.md)
- [Original concept brief](concepts_brief.md)

---

## License

`GPL-3.0-or-later`. See [LICENSE](LICENSE).

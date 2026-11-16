# Getting started

This guide covers building, running, and configuring Kestrel Companion (`whatsnative`).

## Prerequisites

- **Rust 1.94 or newer**, edition 2024 support (`rustup toolchain install 1.94` or later; see [rustup.rs](https://rustup.rs)).
- **GTK4 4.14+** and **libadwaita 1.5+** development headers.
- **pkg-config**, **OpenSSL** development headers, and **D-Bus** development headers.
- A Wayland or X11 session (the app probes which one is active).
- `SQLCipher` is built from source via `rusqlite`'s `bundled-sqlcipher` feature — no separate system library is required.

### Install system dependencies

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install build-essential pkg-config libssl-dev libgtk-4-dev libadwaita-1-dev libdbus-1-dev

# Fedora / RHEL
sudo dnf install gcc make pkgconf-pkg-config openssl-devel gtk4-devel libadwaita-devel dbus-devel

# Arch Linux
sudo pacman -S base-devel pkgconf openssl gtk4 libadwaita dbus
```

## Build

```bash
git clone https://github.com/rabimba/whatsnative.git
cd whatsnative
cargo build --release -p whatsnative
```

The resulting binary is `target/release/whatsnative`.

## Run the offline demo (no phone required)

This is the safest way to explore the UI:

```bash
cargo run -p whatsnative -- --mock
```

The mock archive seeds 1:1 chats, groups, BiDi/RTL/CJK/Emoji content, a poll, a view-once privacy stub, a channel, and 60+ searchable messages.

Useful things to try:

- `Ctrl+K` — global FTS5 search across the seeded archive.
- Send `/call` in any chat, or choose **Menu → Simulate Incoming Call** — exercise the live call banner and decline flow.
- Send a reply or edit a message, then press `Esc` to cancel.
- Paste an image with `Ctrl+V` to send it as PNG.

To keep the demo fully isolated from your real profile:

```bash
cargo run -p whatsnative -- --mock --profile-dir /tmp/kestrel-demo
```

## Pair a real device

```bash
# QR-code flow
cargo run --release -p whatsnative

# Optional: pre-fill an 8-character link code for a phone number
cargo run --release -p whatsnative -- --phone 14155550199
# or supply a specific code
cargo run --release -p whatsnative -- --phone 14155550199 --pair-code ABCDEFGH
```

Before you do this, read [`security.md`](security.md). The client verifies a signed compatibility manifest before connecting and trips a read-only circuit breaker on suspicious responses — do not defeat that with `--allow-unverified-protocol` on a number you value.

### Vault passphrase

By default the master key is obtained from an XDG portal secret or the host secret service. To initialize or unlock a passphrase-wrapped vault explicitly:

```bash
cargo run --release -p whatsnative -- --passphrase 'a long, unique passphrase'
```

A locked keyring at boot is treated as `VaultLocked`, never `Unpaired`, so your session metadata is preserved.

## Headless tooling

```bash
# Export a zero-PII diagnostic bundle (works without a display)
cargo run -p whatsnative -- --mock --export-diagnostics /tmp/kestrel-diag.json

# Audit a vault's integrity / data attribution
cargo run -p whatsnative -- --inspect-data --profile-dir /tmp/kestrel-demo
```

## Where files live

Paths follow the XDG Base Directory spec under the `kestrel-companion` slug:

| Purpose | Location |
| :--- | :--- |
| Application data & vault | `$XDG_DATA_HOME/kestrel-companion/` |
| Encrypted logs & diagnostics state | `$XDG_STATE_HOME/kestrel-companion/` |
| Media cache & staged chunks | `$XDG_CACHE_HOME/kestrel-companion/` |
| (No PII) config | `$XDG_CONFIG_HOME/kestrel-companion/` |

All directories are created with `0700` permissions. `--profile-dir <DIR>` overrides all four roots at once, which is ideal for tests and parallel profiles.

## Flatpak build

A Flatpak manifest is provided at `packaging/io.github.rabimba.kestrel.yml` (GNOME 47 platform + Rust SDK extension):

```bash
flatpak-builder --user --install --force-clean build-dir packaging/io.github.rabimba.kestrel.yml
flatpak run io.github.rabimba.kestrel
```

## Troubleshooting

| Symptom | What to check |
| :--- | :--- |
| GTK/libadwaita headers not found | Install the dev packages above; confirm `pkg-config --modversion gtk4`. |
| App reports "VaultLocked" | Unlock your keyring, or pass `--passphrase`. Do not delete the profile. |
| Client stuck in offline read-only mode | The compatibility gate or a circuit breaker tripped. Export diagnostics and check the signed manifest status; do not bypass unless you accept the account risk. |
| Notifications do not appear | Grant notification permission in your desktop settings; the app probes the Notification portal at runtime. |
| No tray icon on GNOME | Expected on default GNOME, which has no `StatusNotifierWatcher`. The app quits cleanly or hides to the Background Portal instead. |

## Next

- [`architecture.md`](architecture.md) — how the code fits together.
- [`security.md`](security.md) — account-safety rules and diagnostics.
- [`contributing.md`](contributing.md) — development workflow.

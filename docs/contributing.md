# Contributing

Thanks for helping build a native, private Linux companion. This document covers the development workflow and the conventions that keep the architecture intact.

## Development setup

1. Install the prerequisites in [`getting-started.md`](getting-started.md).
2. Clone and build:

   ```bash
   git clone https://github.com/rabimba/whatsnative.git
   cd whatsnative
   cargo build --workspace
   ```

3. Always develop against the mock fixture first:

   ```bash
   cargo run -p whatsnative -- --mock --profile-dir /tmp/whatsnative-dev
   ```

   Using `--profile-dir` keeps your work isolated from any real companion profile. **Never test against a personal phone number.**

## Before you open a PR

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
```

All four layers must stay independent. Check the dependency direction in [`architecture.md`](architecture.md).

## Repository layout & conventions

| Area | Rule |
| :--- | :--- |
| `crates/domain` | Pure Rust only. No `whatsapp-rust`, `rusqlite`, `zbus`, or `gtk4` dependencies. Add new shared vocabulary here. |
| `crates/store` | All persistence. Commit raw protobufs before ACKs; keep the crypto/sync store separate from the rebuildable vault. |
| `crates/platform-xdg` | All D-Bus/portals/XDG/filesystem details. Never import GTK or wire types. |
| `crates/adapter-wa` | The **only** crate allowed to import `whatsapp_rust`. Never expose a wire type in its public API — map into `whatsnative-domain` types. |
| `crates/ui-gtk4` | GTK4/libadwaita UI. Read local projections only; send `EngineCommand`s. Never touch wire or SQL directly. |
| `packaging/` | Flatpak/desktop/AppStream metadata. Keep the app ID (`io.github.rabimba.whatsnative`) consistent. |

## Safety rules

- Any change that touches reconnects, retries, or outbound commands must preserve the rate guard, circuit breakers, and commit-before-ACK behavior. Regressions here can get users' phone numbers banned.
- The pre-connect `CompatManifest` gate must not be weakened or bypassed by default.
- Never log JIDs, phone numbers, or message bodies. Use the zero-PII error taxonomy and `RedactedDiagnosticsRing`.
- Do not add telemetry, cloud services, or PII collection.

## Testing expectations

- Unit tests for pure logic live next to the code (see `cli.rs` for an example).
- UI workflows should be reproducible with `--mock` and an isolated `--profile-dir`.
- For persistence changes, verify that FTS5 rows stay consistent through merges, edits, and deletes, and that the rollback guard (`CryptoSchemaGuard`) still blocks downgrades.

## Reporting security or account-safety issues

Do **not** open a public issue with real identifiers or message content. Instead:

```bash
cargo run -p whatsnative -- --mock --export-diagnostics /tmp/whatsnative-diag.json
```

Attach the redacted bundle and contact the maintainer privately through GitHub. See [`security.md`](security.md) for what the bundle contains.

## Design documents

The original concept and risk analysis live in [`../concepts_brief.md`](../concepts_brief.md). Record substantial design work as a dated Markdown document in this `docs/` directory and link it here.

## License

By contributing, you agree that your contributions are licensed under `GPL-3.0-or-later`.

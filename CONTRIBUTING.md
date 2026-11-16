# Contributing to Kestrel Companion

Thanks for your interest! Please read **[`docs/contributing.md`](docs/contributing.md)** for development setup, crate boundaries, testing expectations, and safety rules.

Quick checks before opening a pull request:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
```

Develop against `cargo run -p whatsnative -- --mock --profile-dir /tmp/kestrel-dev`. Never test with a personal phone number, and never include real JIDs or message content in issues — use `--export-diagnostics` to produce a redacted bundle instead.

By contributing, you agree that your contributions are licensed under `GPL-3.0-or-later`.

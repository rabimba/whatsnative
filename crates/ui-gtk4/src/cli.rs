//! Command-line flag parser for `whatsnative`, supporting
//! deterministic `--mock` mode, custom XDG profile roots, headless diagnostic bundle
//! export, and 8-character phone-number pairing flags.

use anyhow::{Result, bail};
use std::path::PathBuf;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliArgs {
    /// Launch against the zero-account deterministic offline fixture (`MockCompanionAdapter`).
    pub mock_mode: bool,
    /// Override XDG base directories with an isolated profile root directory.
    pub profile_dir: Option<PathBuf>,
    /// Optional passphrase to unlock or initialize a passphrase-wrapped SQLCipher vault.
    pub passphrase: Option<String>,
    /// Pre-populate phone number (international digits) for 8-character companion link code.
    pub phone_number: Option<String>,
    /// Optional custom 8-character companion link code.
    pub custom_pair_code: Option<String>,
    /// Export a salted-HMAC redacted diagnostic JSON bundle to `<path>` and exit cleanly.
    pub export_diagnostics: Option<PathBuf>,
    /// Headless data attribution and integrity audit.
    pub inspect_data: bool,
    /// Power-user override bypassing pre-connect `CompatManifest` quarantine.
    pub allow_unverified_protocol: bool,
    /// Print CLI usage and exit.
    pub show_help: bool,
    /// Print version and exit.
    pub show_version: bool,
}

impl CliArgs {
    pub fn parse_from_iter<I, S>(iter: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut args = Self::default();
        let mut it = iter.into_iter().map(Into::into);
        // Skip argv[0]
        let _ = it.next();

        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--mock" => args.mock_mode = true,
                "--inspect-data" => args.inspect_data = true,
                "--allow-unverified-protocol" => args.allow_unverified_protocol = true,
                "-h" | "--help" => args.show_help = true,
                "-V" | "--version" => args.show_version = true,
                "--profile-dir" => {
                    let val = it
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--profile-dir requires a <path> value"))?;
                    args.profile_dir = Some(PathBuf::from(val));
                }
                "--passphrase" => {
                    let val = it
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--passphrase requires a value"))?;
                    args.passphrase = Some(val);
                }
                "--phone" => {
                    let val = it
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--phone requires digits"))?;
                    args.phone_number = Some(val);
                }
                "--pair-code" => {
                    let val = it
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--pair-code requires an 8-char code"))?;
                    args.custom_pair_code = Some(val);
                }
                "--export-diagnostics" => {
                    let val = it.next().ok_or_else(|| {
                        anyhow::anyhow!("--export-diagnostics requires an <output.json> path")
                    })?;
                    args.export_diagnostics = Some(PathBuf::from(val));
                }
                other => {
                    bail!("Unknown flag '{other}'. Run `whatsnative --help` for usage.");
                }
            }
        }
        Ok(args)
    }

    pub fn usage_text() -> &'static str {
        "\
whatsnative — Native Linux Companion Messaging Client
Zero Electron / Zero WebView · GTK4 + libadwaita + SQLCipher + XDG Portals

USAGE:
    whatsnative [OPTIONS]

OPTIONS:
    --mock                           Launch offline zero-account demo archive (no phone required)
    --profile-dir <DIR>              Use an isolated XDG data/state/cache/config root directory
    --passphrase <PASS>              Unlock or initialize passphrase-wrapped SQLCipher vault
    --phone <DIGITS>                 Request 8-character phone-number companion link code
    --pair-code <CODE>               Optional custom 8-character link code (with --phone)
    --export-diagnostics <FILE.json> Export zero-PII salted-HMAC diagnostic bundle and exit
    --allow-unverified-protocol      Power-user override for CompatManifest safety quarantine
    -h, --help                       Print this help message
    -V, --version                    Print version information
"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mock_and_diagnostic_cli_flags() {
        let parsed = CliArgs::parse_from_iter([
            "whatsnative",
            "--mock",
            "--profile-dir",
            "/tmp/whatsnative-prof",
            "--export-diagnostics",
            "/tmp/diag.json",
        ])
        .unwrap();
        assert!(parsed.mock_mode);
        assert_eq!(
            parsed.profile_dir,
            Some(PathBuf::from("/tmp/whatsnative-prof"))
        );
        assert_eq!(
            parsed.export_diagnostics,
            Some(PathBuf::from("/tmp/diag.json"))
        );
    }
}

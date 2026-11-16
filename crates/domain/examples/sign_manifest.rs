//! Signs a compatibility manifest with an Ed25519 signing seed.
//!
//! Usage:
//!   COMPAT_SIGNING_SEED_HEX="$(cat ~/.config/whatsnative/compat-signing-seed.txt)" \
//!     cargo run -p whatsnative-domain --example sign_manifest -- \
//!     compat/manifest.unsigned.json > compat/compat_manifest.json
//!
//! The seed is read from the environment so it never lands in shell history.
//! It is the project's most sensitive release secret: store it in a password
//! manager, never commit it, and use it only to sign updated manifests. The
//! matching public key is pinned in `whatsnative-domain`.

use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signer, SigningKey};
use whatsnative_domain::CompatManifest;

fn main() -> Result<()> {
    let seed_hex = std::env::var("COMPAT_SIGNING_SEED_HEX")
        .context("set COMPAT_SIGNING_SEED_HEX to the 32-byte signing seed")?;
    let manifest_path = std::env::args()
        .nth(1)
        .context("usage: sign_manifest <unsigned-manifest.json>")?;

    let seed_bytes = hex::decode(seed_hex.trim()).context("signing seed must be hex")?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing seed must be exactly 32 bytes"))?;
    if seed == [0u8; 32] {
        bail!("all-zero signing seed is not allowed");
    }
    let signing_key = SigningKey::from_bytes(&seed);

    let raw = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {manifest_path}"))?;
    let mut manifest: CompatManifest =
        serde_json::from_str(&raw).context("parsing unsigned manifest JSON")?;
    let signature = signing_key.sign(&manifest.canonical_signing_bytes());
    manifest.signature_hex = Some(hex::encode(signature.to_bytes()));

    eprintln!(
        "Pinned verifying key: {}",
        hex::encode(signing_key.verifying_key().to_bytes())
    );
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

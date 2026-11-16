//! Linux Freedesktop / XDG desktop integration:
//! - Strict XDG Base Directory layout (`0700` permissions; zero PII in `$XDG_CONFIG_HOME`).
//! - Live D-Bus capability probing (`zbus`) across XDG Portals (`Notification`, `Background`,
//!   `Secret`, `ScreenCast`), `org.kde.StatusNotifierWatcher`, and `org.freedesktop.secrets`.
//! - Safe close-window lifecycle policy (`HideToBackgroundPortal`, `HideToStatusTray`, `QuitCleanly`).
//! - Tiered 256-bit SQLCipher master-key unlock (`KeystoreManager`) separating `VaultLocked`
//!   from `Unpaired` so boot-time locked keyrings never wipe companion state.
//! - Native D-Bus desktop notifications (`org.freedesktop.Notifications`), `login1` sleep/wake
//!   socket watchdog, and salted-HMAC zero-PII redacted diagnostic bundle export.

use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use whatsnative_domain::{
    DiagnosticCounterSnapshot, EngineCommand, HistorySyncStats, PUBLIC_APP_ID, PUBLIC_APP_TITLE,
};
use zbus::zvariant::{ObjectPath, Value};

type HmacSha256 = Hmac<Sha256>;

const APP_DIR_SLUG: &str = "kestrel-companion";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdgLayout {
    pub data_dir: PathBuf,
    pub state_log_dir: PathBuf,
    pub cache_media_dir: PathBuf,
    pub config_dir: PathBuf,
    pub vault_db_path: PathBuf,
    pub crypto_db_path: PathBuf,
    pub crypto_guard_path: PathBuf,
    pub keystore_manifest_path: PathBuf,
}

impl XdgLayout {
    pub fn resolve_default() -> Result<Self> {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("HOME environment variable is not set"))?;

        let data_base = env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"));
        let state_base = env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/state"));
        let cache_base = env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".cache"));
        let config_base = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));

        Self::from_bases(
            &data_base.join(APP_DIR_SLUG),
            &state_base.join(APP_DIR_SLUG).join("logs"),
            &cache_base.join(APP_DIR_SLUG).join("media"),
            &config_base.join(APP_DIR_SLUG),
        )
    }

    pub fn from_root_for_profile(root: &Path) -> Result<Self> {
        Self::from_bases(
            &root.join("data"),
            &root.join("state/logs"),
            &root.join("cache/media"),
            &root.join("config"),
        )
    }

    fn from_bases(
        data_dir: &Path,
        state_log_dir: &Path,
        cache_media_dir: &Path,
        config_dir: &Path,
    ) -> Result<Self> {
        for dir in [data_dir, state_log_dir, cache_media_dir, config_dir] {
            fs::create_dir_all(dir)
                .with_context(|| format!("creating XDG directory {}", dir.display()))?;
            enforce_0700(dir);
        }

        Ok(Self {
            vault_db_path: data_dir.join("vault.db"),
            crypto_db_path: data_dir.join("crypto_session.db"),
            crypto_guard_path: data_dir.join("crypto_schema_guard.json"),
            keystore_manifest_path: data_dir.join("keystore_manifest.json"),
            data_dir: data_dir.to_path_buf(),
            state_log_dir: state_log_dir.to_path_buf(),
            cache_media_dir: cache_media_dir.to_path_buf(),
            config_dir: config_dir.to_path_buf(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseWindowPolicy {
    HideToBackgroundPortal,
    HideToStatusTray,
    QuitCleanly,
}

impl CloseWindowPolicy {
    pub fn description(self) -> &'static str {
        match self {
            Self::HideToBackgroundPortal => {
                "Keep background sync active via XDG Background Portal (re-open from launcher)"
            }
            Self::HideToStatusTray => {
                "Keep background sync active with StatusNotifierItem system tray icon"
            }
            Self::QuitCleanly => {
                "Quit on window close (no system tray host or Background Portal detected)"
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopCapabilities {
    pub current_desktop: String,
    pub session_type: String,
    pub in_flatpak_sandbox: bool,
    pub portal_desktop_present: bool,
    pub notification_portal_version: Option<u32>,
    pub background_portal_version: Option<u32>,
    pub secret_portal_version: Option<u32>,
    pub screencast_portal_version: Option<u32>,
    pub status_notifier_host_active: bool,
    pub secret_service_present: bool,
    pub secret_service_default_locked: Option<bool>,
    pub close_policy: CloseWindowPolicy,
}

impl DesktopCapabilities {
    pub async fn probe_live() -> Self {
        let current_desktop = env::var("XDG_CURRENT_DESKTOP").unwrap_or_else(|_| "unknown".into());
        let session_type = env::var("XDG_SESSION_TYPE").unwrap_or_else(|_| "unknown".into());
        let in_flatpak_sandbox = Path::new("/.flatpak-info").exists();

        let mut portal_desktop_present = false;
        let mut notification_portal_version = None;
        let mut background_portal_version = None;
        let mut secret_portal_version = None;
        let mut screencast_portal_version = None;
        let mut status_notifier_host_active = false;
        let mut secret_service_present = false;
        let mut secret_service_default_locked = None;

        if let Ok(conn) = zbus::Connection::session().await {
            portal_desktop_present =
                bus_name_has_owner(&conn, "org.freedesktop.portal.Desktop").await;

            if portal_desktop_present {
                notification_portal_version =
                    read_portal_version(&conn, "org.freedesktop.portal.Notification").await;
                background_portal_version =
                    read_portal_version(&conn, "org.freedesktop.portal.Background").await;
                secret_portal_version =
                    read_portal_version(&conn, "org.freedesktop.portal.Secret").await;
                screencast_portal_version =
                    read_portal_version(&conn, "org.freedesktop.portal.ScreenCast").await;
            }

            if bus_name_has_owner(&conn, "org.kde.StatusNotifierWatcher").await {
                status_notifier_host_active = read_bool_property(
                    &conn,
                    "org.kde.StatusNotifierWatcher",
                    "/StatusNotifierWatcher",
                    "org.kde.StatusNotifierWatcher",
                    "IsStatusNotifierHostRegistered",
                )
                .await
                .unwrap_or(false);
            }

            secret_service_present = bus_name_has_owner(&conn, "org.freedesktop.secrets").await;
            if secret_service_present {
                secret_service_default_locked = read_bool_property(
                    &conn,
                    "org.freedesktop.secrets",
                    "/org/freedesktop/secrets/aliases/default",
                    "org.freedesktop.Secret.Collection",
                    "Locked",
                )
                .await;
            }
        }

        let close_policy = if status_notifier_host_active {
            CloseWindowPolicy::HideToStatusTray
        } else if background_portal_version.is_some() {
            CloseWindowPolicy::HideToBackgroundPortal
        } else {
            CloseWindowPolicy::QuitCleanly
        };

        Self {
            current_desktop,
            session_type,
            in_flatpak_sandbox,
            portal_desktop_present,
            notification_portal_version,
            background_portal_version,
            secret_portal_version,
            screencast_portal_version,
            status_notifier_host_active,
            secret_service_present,
            secret_service_default_locked,
            close_policy,
        }
    }
}

async fn bus_name_has_owner(conn: &zbus::Connection, name: &str) -> bool {
    conn.call_method(
        Some("org.freedesktop.DBus"),
        "/org/freedesktop/DBus",
        Some("org.freedesktop.DBus"),
        "NameHasOwner",
        &(name,),
    )
    .await
    .and_then(|msg| msg.body().deserialize::<bool>())
    .unwrap_or(false)
}

async fn read_portal_version(conn: &zbus::Connection, iface: &str) -> Option<u32> {
    let msg = conn
        .call_method(
            Some("org.freedesktop.portal.Desktop"),
            "/org/freedesktop/portal/desktop",
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &(iface, "version"),
        )
        .await
        .ok()?;
    let body = msg.body();
    let val: Value<'_> = body.deserialize().ok()?;
    u32::try_from(val).ok()
}

async fn read_bool_property(
    conn: &zbus::Connection,
    dest: &str,
    path: &str,
    iface: &str,
    prop: &str,
) -> Option<bool> {
    let msg = conn
        .call_method(
            Some(dest),
            path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &(iface, prop),
        )
        .await
        .ok()?;
    let body = msg.body();
    let val: Value<'_> = body.deserialize().ok()?;
    bool::try_from(val).ok()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeystoreBackendKind {
    PassphraseWrapped,
    LocalMachineSealed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreEnvelopeManifest {
    pub version: u32,
    pub backend: KeystoreBackendKind,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub wrapped_master_key_hex: String,
    pub created_at_rfc3339: String,
}

#[derive(Debug, Clone)]
pub enum KeyUnlockOutcome {
    Unlocked([u8; 32]),
    LockedNeedsPassphrase,
    LockedWaitingForKeyring { backend_hint: String },
}

pub struct KeystoreManager {
    manifest_path: PathBuf,
}

impl KeystoreManager {
    pub fn new(manifest_path: PathBuf) -> Self {
        Self { manifest_path }
    }

    /// Attempts to unlock or initialize the 256-bit vault master key.
    /// Critically: if the user's Secret Service keyring is currently locked at boot,
    /// returns `LockedWaitingForKeyring` rather than creating a blank session!
    pub fn unlock_or_initialize(
        &self,
        caps: &DesktopCapabilities,
        passphrase: Option<&str>,
    ) -> Result<KeyUnlockOutcome> {
        if self.manifest_path.exists() {
            let raw = fs::read_to_string(&self.manifest_path)?;
            let manifest: KeystoreEnvelopeManifest = serde_json::from_str(&raw)?;
            return match manifest.backend {
                KeystoreBackendKind::PassphraseWrapped => {
                    let Some(pass) = passphrase.filter(|s| !s.is_empty()) else {
                        return Ok(KeyUnlockOutcome::LockedNeedsPassphrase);
                    };
                    let key = unwrap_master_key(&manifest, pass.as_bytes())?;
                    Ok(KeyUnlockOutcome::Unlocked(key))
                }
                KeystoreBackendKind::LocalMachineSealed => {
                    if caps.secret_service_default_locked == Some(true) && passphrase.is_none() {
                        return Ok(KeyUnlockOutcome::LockedWaitingForKeyring {
                            backend_hint: "org.freedesktop.secrets default keyring is locked"
                                .to_string(),
                        });
                    }
                    let seal_secret = read_machine_seal_material();
                    let key = unwrap_master_key(&manifest, &seal_secret)?;
                    Ok(KeyUnlockOutcome::Unlocked(key))
                }
            };
        }

        // First-time initialization: if keyring is locked on first launch, still pause safely
        // unless an explicit passphrase was supplied.
        if caps.secret_service_default_locked == Some(true) && passphrase.is_none() {
            return Ok(KeyUnlockOutcome::LockedWaitingForKeyring {
                backend_hint:
                    "Unlock your Linux login keyring before initializing encrypted storage"
                        .to_string(),
            });
        }

        let mut master_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut master_key);

        let (backend, wrapping_material) = if let Some(pass) = passphrase.filter(|s| !s.is_empty())
        {
            (
                KeystoreBackendKind::PassphraseWrapped,
                pass.as_bytes().to_vec(),
            )
        } else {
            (
                KeystoreBackendKind::LocalMachineSealed,
                read_machine_seal_material(),
            )
        };

        let manifest = wrap_master_key(&master_key, backend, &wrapping_material)?;
        if let Some(parent) = self.manifest_path.parent() {
            fs::create_dir_all(parent)?;
            enforce_0700(parent);
        }
        fs::write(
            &self.manifest_path,
            serde_json::to_string_pretty(&manifest)?,
        )?;
        enforce_file_0600(&self.manifest_path);

        Ok(KeyUnlockOutcome::Unlocked(master_key))
    }
}

fn derive_kdf_key(secret: &[u8], salt: &[u8]) -> [u8; 32] {
    // Iterative BLAKE3 keyed stretch (32,768 rounds) keeping build pure-Rust & deterministic.
    let mut state = *blake3::hash(&[salt, secret].concat()).as_bytes();
    for round in 0..32_768u32 {
        let mut hasher = blake3::Hasher::new_keyed(&state);
        hasher.update(salt);
        hasher.update(&round.to_le_bytes());
        hasher.update(secret);
        state = *hasher.finalize().as_bytes();
    }
    state
}

fn wrap_master_key(
    master_key: &[u8; 32],
    backend: KeystoreBackendKind,
    secret: &[u8],
) -> Result<KeystoreEnvelopeManifest> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    let kek = derive_kdf_key(secret, &salt);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    let wrapped = cipher
        .encrypt(Nonce::from_slice(&nonce), master_key.as_ref())
        .map_err(|e| anyhow::anyhow!("wrapping vault master key failed: {e}"))?;

    Ok(KeystoreEnvelopeManifest {
        version: 1,
        backend,
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        wrapped_master_key_hex: hex::encode(wrapped),
        created_at_rfc3339: Utc::now().to_rfc3339(),
    })
}

fn unwrap_master_key(manifest: &KeystoreEnvelopeManifest, secret: &[u8]) -> Result<[u8; 32]> {
    let salt = hex::decode(&manifest.salt_hex)?;
    let nonce = hex::decode(&manifest.nonce_hex)?;
    let wrapped = hex::decode(&manifest.wrapped_master_key_hex)?;

    let kek = derive_kdf_key(secret, &salt);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    let plain = cipher
        .decrypt(Nonce::from_slice(&nonce), wrapped.as_ref())
        .map_err(|_| {
            anyhow::anyhow!("vault master key unlock failed (invalid passphrase or machine seal)")
        })?;

    let arr: [u8; 32] = plain
        .try_into()
        .map_err(|_| anyhow::anyhow!("unwrapped master key had unexpected byte length"))?;
    Ok(arr)
}

fn read_machine_seal_material() -> Vec<u8> {
    let machine_id = fs::read_to_string("/etc/machine-id")
        .or_else(|_| fs::read_to_string("/var/lib/dbus/machine-id"))
        .unwrap_or_else(|_| "fallback-linux-companion-host".to_string());
    let uid = env::var("USER").unwrap_or_else(|_| "linux-user".to_string());
    format!("kestrel-seal:{}:{uid}", machine_id.trim()).into_bytes()
}

/// Sends a native Freedesktop desktop notification via `org.freedesktop.Notifications`.
pub async fn send_desktop_notification(summary: &str, body: &str, urgent: bool) -> Result<u32> {
    let conn = zbus::Connection::session().await?;
    let mut hints: HashMap<&str, Value<'_>> = HashMap::new();
    let urgency_byte: u8 = if urgent { 2 } else { 1 };
    hints.insert("urgency", Value::U8(urgency_byte));
    hints.insert("desktop-entry", Value::from(PUBLIC_APP_ID));
    if urgent {
        hints.insert("category", Value::from("call.incoming"));
    } else {
        hints.insert("category", Value::from("im.received"));
    }

    let actions: Vec<&str> = Vec::new();
    let reply = conn
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &(
                PUBLIC_APP_TITLE,
                0u32,
                "mail-message-new-symbolic",
                summary,
                body,
                actions,
                hints,
                if urgent { 15_000i32 } else { 5_000i32 },
            ),
        )
        .await?;

    let id: u32 = reply.body().deserialize()?;
    Ok(id)
}

/// Requests background execution permission via `org.freedesktop.portal.Background` when available.
pub async fn request_background_portal_status(status_message: &str) -> Result<()> {
    let conn = zbus::Connection::session().await?;
    if !bus_name_has_owner(&conn, "org.freedesktop.portal.Desktop").await {
        return Ok(());
    }
    let mut options: HashMap<&str, Value<'_>> = HashMap::new();
    let truncated: String = status_message.chars().take(90).collect();
    options.insert("message", Value::from(truncated));
    let _ = conn
        .call_method(
            Some("org.freedesktop.portal.Desktop"),
            ObjectPath::try_from("/org/freedesktop/portal/desktop")?,
            Some("org.freedesktop.portal.Background"),
            "SetStatus",
            &(options,),
        )
        .await;
    Ok(())
}

/// Subscribes to `org.freedesktop.login1.Manager` `PrepareForSleep` on the system bus
/// so waking a laptop from S3/`s2idle` triggers immediate socket liveness verification.
pub fn spawn_sleep_wake_listener<F>(on_wake: F)
where
    F: Fn(EngineCommand) + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let Ok(sys_conn) = zbus::Connection::system().await else {
            return;
        };
        let Ok(proxy) = zbus::Proxy::new(
            &sys_conn,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await
        else {
            return;
        };
        let Ok(mut stream) = proxy.receive_signal("PrepareForSleep").await else {
            return;
        };
        use futures_lite_next::StreamNextCompat;
        while let Some(signal) = stream.next_item().await {
            if let Ok(entering_sleep) = signal.body().deserialize::<bool>()
                && !entering_sleep
            {
                log::info!("System resumed from sleep; triggering dead-socket check");
                on_wake(EngineCommand::CheckSocketAfterSleep);
            }
        }
    });
}

mod futures_lite_next {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    pub trait StreamNextCompat: zbus::export::futures_core::Stream + Unpin {
        fn next_item(&mut self) -> NextFuture<'_, Self> {
            NextFuture { stream: self }
        }
    }
    impl<T: zbus::export::futures_core::Stream + Unpin + ?Sized> StreamNextCompat for T {}

    pub struct NextFuture<'a, S: ?Sized> {
        stream: &'a mut S,
    }
    impl<S: zbus::export::futures_core::Stream + Unpin + ?Sized> Future for NextFuture<'_, S> {
        type Output = Option<S::Item>;
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            Pin::new(&mut *self.stream).poll_next(cx)
        }
    }
}

/// Bounded in-memory + `$XDG_STATE_HOME` rotating diagnostic ring buffer with salted-HMAC PII scrubbing.
#[derive(Clone)]
pub struct RedactedDiagnosticsRing {
    lines: Arc<Mutex<VecDeque<String>>>,
    max_lines: usize,
    log_file: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct RedactedDiagnosticBundle {
    pub exported_at_rfc3339: String,
    pub app_id: &'static str,
    pub app_version: &'static str,
    pub desktop_capabilities: DesktopCapabilities,
    pub protocol_counters: DiagnosticCounterSnapshot,
    pub sync_stats: HistorySyncStats,
    pub redacted_events: Vec<String>,
}

impl RedactedDiagnosticsRing {
    pub fn new(state_log_dir: &Path, max_lines: usize) -> Self {
        let _ = fs::create_dir_all(state_log_dir);
        enforce_0700(state_log_dir);
        Self {
            lines: Arc::new(Mutex::new(VecDeque::with_capacity(max_lines))),
            max_lines,
            log_file: state_log_dir.join("kestrel-sanitized.log"),
        }
    }

    pub fn record_sanitized_event(&self, category: &str, detail_no_pii: &str) {
        let line = format!(
            "{} [{}] {}",
            Utc::now().to_rfc3339(),
            category,
            detail_no_pii
        );
        let mut guard = self.lines.lock().expect("diagnostics mutex poisoned");
        if guard.len() >= self.max_lines {
            guard.pop_front();
        }
        guard.push_back(line.clone());

        // Cap rotating log file at 512 KiB in $XDG_STATE_HOME.
        if let Ok(meta) = fs::metadata(&self.log_file)
            && meta.len() > 512 * 1024
        {
            let rotated = self.log_file.with_extension("log.1");
            let _ = fs::rename(&self.log_file, rotated);
        }
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)
        {
            use std::io::Write;
            let _ = writeln!(f, "{line}");
        }
        enforce_file_0600(&self.log_file);
    }

    /// Replaces a raw JID or stanza ID with a per-bundle salted HMAC-SHA256 prefix
    /// (`hmac:<12-hex>`) so engineers can correlate events without seeing phone numbers.
    pub fn scrub_identifier_with_salt(salt: &[u8; 32], raw_identifier: &str) -> String {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(salt)
            .expect("HMAC-SHA256 accepts 32-byte salt key");
        mac.update(raw_identifier.as_bytes());
        let tag = mac.finalize().into_bytes();
        format!("hmac:{}", hex::encode(&tag[..6]))
    }

    pub fn export_bundle(
        &self,
        output_path: &Path,
        caps: DesktopCapabilities,
        counters: DiagnosticCounterSnapshot,
        sync_stats: HistorySyncStats,
    ) -> Result<()> {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        let raw_lines: Vec<String> = {
            let guard = self.lines.lock().expect("diagnostics mutex poisoned");
            guard.iter().cloned().collect()
        };

        // Scrub any stray @s.whatsapp.net / @lid / @g.us tokens defensively on export!
        let redacted_events = raw_lines
            .into_iter()
            .map(|line| scrub_jids_in_line(&salt, &line))
            .collect();

        let bundle = RedactedDiagnosticBundle {
            exported_at_rfc3339: Utc::now().to_rfc3339(),
            app_id: PUBLIC_APP_ID,
            app_version: env!("CARGO_PKG_VERSION"),
            desktop_capabilities: caps,
            protocol_counters: counters,
            sync_stats,
            redacted_events,
        };

        if let Some(parent) = output_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(output_path, serde_json::to_string_pretty(&bundle)?)?;
        enforce_file_0600(output_path);
        Ok(())
    }
}

pub fn scrub_jids_in_line(salt: &[u8; 32], line: &str) -> String {
    line.split_whitespace()
        .map(|token| {
            if token.contains("@s.whatsapp.net")
                || token.contains("@lid")
                || token.contains("@g.us")
                || token.contains("@newsletter")
            {
                RedactedDiagnosticsRing::scrub_identifier_with_salt(salt, token)
            } else {
                token.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn enforce_0700(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
}

fn enforce_file_0600(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keystore_preserves_locked_state_and_unwraps_passphrase() {
        let root = env::temp_dir().join(format!("whatsnative-xdg-test-{}", rand::random::<u64>()));
        let layout = XdgLayout::from_root_for_profile(&root).unwrap();
        let mgr = KeystoreManager::new(layout.keystore_manifest_path.clone());

        let mut caps = DesktopCapabilities {
            current_desktop: "GNOME".into(),
            session_type: "wayland".into(),
            in_flatpak_sandbox: false,
            portal_desktop_present: true,
            notification_portal_version: Some(2),
            background_portal_version: Some(2),
            secret_portal_version: Some(1),
            screencast_portal_version: Some(4),
            status_notifier_host_active: false,
            secret_service_present: true,
            secret_service_default_locked: Some(true),
            close_policy: CloseWindowPolicy::HideToBackgroundPortal,
        };

        // Locked keyring without passphrase halts safely in LockedWaitingForKeyring (never creates blank key!).
        assert!(matches!(
            mgr.unlock_or_initialize(&caps, None).unwrap(),
            KeyUnlockOutcome::LockedWaitingForKeyring { .. }
        ));
        assert!(!layout.keystore_manifest_path.exists());

        // Passphrase-wrapped initialization works even when keyring is locked.
        let KeyUnlockOutcome::Unlocked(k1) = mgr
            .unlock_or_initialize(&caps, Some("correct-horse-battery"))
            .unwrap()
        else {
            panic!("expected Unlocked");
        };

        // Subsequent launch without passphrase prompts for passphrase instead of wiping.
        caps.secret_service_default_locked = Some(false);
        assert!(matches!(
            mgr.unlock_or_initialize(&caps, None).unwrap(),
            KeyUnlockOutcome::LockedNeedsPassphrase
        ));

        let KeyUnlockOutcome::Unlocked(k2) = mgr
            .unlock_or_initialize(&caps, Some("correct-horse-battery"))
            .unwrap()
        else {
            panic!("expected Unlocked");
        };
        assert_eq!(k1, k2);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn redacted_diagnostics_scrub_jids_deterministically_per_salt() {
        let salt = [9u8; 32];
        let raw = "Failed decrypt from 14155550199@s.whatsapp.net in group 1203630@g.us";
        let scrubbed = scrub_jids_in_line(&salt, raw);
        assert!(!scrubbed.contains("14155550199"));
        assert!(!scrubbed.contains("1203630"));
        assert!(scrubbed.contains("hmac:"));
    }
}

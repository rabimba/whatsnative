//! Pure domain contracts, canonical peer/chat identities, call-signaling seams,
//! and Ed25519-verifiable protocol compatibility gates.
//!
//! Architectural invariant: this crate has zero dependency on `whatsapp-rust`,
//! `rusqlite`, `zbus`, or `gtk4`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use uuid::Uuid;

/// Current parser schema version persisted alongside raw decrypted protobuf bytes.
/// Incrementing this triggers background re-projection of previously unknown fields.
pub const PARSER_SCHEMA_VERSION: i32 = 1;

/// Public display name used in `.desktop` and AppStream metadata to comply with
/// Flathub third-party trademark policy (no `"WhatsApp"` or `"Whats*"` branding).
pub const PUBLIC_APP_TITLE: &str = "whatsnative";
pub const PUBLIC_APP_ID: &str = "io.github.rabimba.whatsnative";

/// Ed25519 public key pinned at build time. Only a manifest signed by the
/// matching private key can authorize a connection or a feature kill switch.
pub const COMPAT_VERIFYING_KEY: [u8; 32] = [
    0x7e, 0xb5, 0xc9, 0x59, 0x6c, 0xad, 0x34, 0xa2, 0x4b, 0x35, 0x34, 0x7b, 0x82, 0x87, 0xe7, 0xef,
    0xe7, 0x42, 0xed, 0xd8, 0x35, 0x55, 0x23, 0xb4, 0x1b, 0xee, 0x4a, 0xb0, 0xaf, 0x47, 0xc5, 0x36,
];

/// Compatibility manifest compiled into the binary, so the safety gate works
/// even when the network is down.
pub const BUNDLED_COMPAT_MANIFEST_JSON: &str = include_str!("../../../compat/compat_manifest.json");

/// Immutable internal identifier for a contact or participant, decoupling all UI
/// and search records from `@s.whatsapp.net` vs. `@lid` wire JIDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanonicalPeerId(pub Uuid);

impl CanonicalPeerId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn parse(s: &str) -> anyhow::Result<Self> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl fmt::Display for CanonicalPeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Immutable internal identifier for a chat thread (1:1, group, status, or channel).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConversationId(pub Uuid);

impl ConversationId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn parse(s: &str) -> anyhow::Result<Self> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl fmt::Display for ConversationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationKind {
    DirectMessage,
    Group,
    StatusBroadcast,
    NewsletterChannel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerIdentityRecord {
    pub peer_id: CanonicalPeerId,
    pub pn_jid: Option<String>,
    pub lid_jid: Option<String>,
    pub display_name: String,
    pub push_name: Option<String>,
    #[serde(default)]
    pub contact_name: Option<String>,
    #[serde(default)]
    pub avatar_cache_key: Option<String>,
    #[serde(default)]
    pub about_status: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationSummary {
    pub id: ConversationId,
    pub kind: ConversationKind,
    pub primary_wire_jid: String,
    pub title: String,
    pub subtitle_preview: String,
    pub last_message_at: Option<DateTime<Utc>>,
    pub unread_count: u32,
    pub is_pinned: bool,
    pub is_muted: bool,
    pub is_archived: bool,
    pub typing_peer: Option<String>,
    #[serde(default)]
    pub avatar_cache_key: Option<String>,
    #[serde(default)]
    pub participant_count: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    Queued,
    Sending,
    Sent,
    Delivered,
    Read,
    DecryptPending,
    Quarantined,
    Failed(String),
    Revoked,
}

impl DeliveryState {
    pub fn badge_label(&self) -> &'static str {
        match self {
            Self::Queued => "Queued",
            Self::Sending => "Sending…",
            Self::Sent => "✓",
            Self::Delivered => "✓✓",
            Self::Read => "✓✓ Read",
            Self::DecryptPending => "Waiting for message…",
            Self::Quarantined => "Quarantined (Offline)",
            Self::Failed(_) => "Send failed",
            Self::Revoked => "Deleted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaKind {
    Image,
    Video,
    VoiceNote,
    Audio,
    Document,
    Sticker,
}

impl MediaKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Image => "Photo",
            Self::Video => "Video",
            Self::VoiceNote => "Voice note",
            Self::Audio => "Audio",
            Self::Document => "Document",
            Self::Sticker => "Sticker",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallOutcome {
    IncomingRinging,
    Missed,
    AcceptedElsewhere,
    DeclinedElsewhere,
    DeclinedOnDesktop,
    Ended,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkPreviewCard {
    pub url: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub thumb_cache_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MessageContent {
    Text {
        body: String,
        #[serde(default)]
        edited_at: Option<DateTime<Utc>>,
        #[serde(default)]
        link_preview: Option<LinkPreviewCard>,
    },
    Media {
        media_kind: MediaKind,
        #[serde(default)]
        caption: Option<String>,
        mime_type: String,
        #[serde(default)]
        file_name: Option<String>,
        byte_len: u64,
        /// Pre-allocated pixel dimensions (`width`, `height`) from media protobuf metadata
        /// so virtualized list items reserve exact bubble geometry before download.
        #[serde(default)]
        dimensions: Option<(u32, u32)>,
        #[serde(default)]
        cache_key: Option<String>,
        #[serde(default)]
        thumb_cache_key: Option<String>,
        #[serde(default)]
        duration_secs: Option<u32>,
        #[serde(default)]
        waveform: Option<Vec<u8>>,
    },
    Poll {
        question: String,
        options: Vec<String>,
    },
    Location {
        latitude: f64,
        longitude: f64,
        #[serde(default)]
        label: Option<String>,
        #[serde(default)]
        thumb_cache_key: Option<String>,
    },
    /// Mirrors official macOS companion behavior: View-Once media is never decrypted
    /// or rendered on desktop to preserve sender privacy and avoid ban fingerprints.
    ViewOnceCompanionStub { media_label: String },
    CallTimelineItem {
        call_id: String,
        is_video: bool,
        outcome: CallOutcome,
        duration_secs: Option<u32>,
    },
    UnknownPlaceholder {
        schema_version: i32,
        summary: String,
    },
}

impl MessageContent {
    pub fn preview_text(&self) -> String {
        match self {
            Self::Text { body, .. } => body.lines().next().unwrap_or("").to_string(),
            Self::Media {
                media_kind,
                caption,
                file_name,
                ..
            } => {
                if let Some(cap) = caption.as_deref().filter(|s| !s.is_empty()) {
                    format!("[{}] {}", media_kind.label(), cap)
                } else if let Some(name) = file_name.as_deref().filter(|s| !s.is_empty()) {
                    format!("[{}] {}", media_kind.label(), name)
                } else {
                    format!("[{}]", media_kind.label())
                }
            }
            Self::Poll { question, .. } => format!("[Poll] {question}"),
            Self::Location { label, .. } => {
                format!("[Location] {}", label.as_deref().unwrap_or("Shared pin"))
            }
            Self::ViewOnceCompanionStub { media_label } => {
                format!("View-once {media_label} (open on primary phone)")
            }
            Self::CallTimelineItem {
                is_video, outcome, ..
            } => {
                let kind = if *is_video {
                    "Video call"
                } else {
                    "Voice call"
                };
                match outcome {
                    CallOutcome::IncomingRinging => format!("{kind} ringing…"),
                    CallOutcome::Missed => format!("Missed {}", kind.to_lowercase()),
                    CallOutcome::AcceptedElsewhere => format!("{kind} answered on another device"),
                    CallOutcome::DeclinedElsewhere => format!("{kind} declined on another device"),
                    CallOutcome::DeclinedOnDesktop => format!("{kind} declined"),
                    CallOutcome::Ended => format!("{kind} ended"),
                }
            }
            Self::UnknownPlaceholder { summary, .. } => summary.clone(),
        }
    }

    pub fn searchable_text(&self) -> String {
        match self {
            Self::Text {
                body, link_preview, ..
            } => {
                if let Some(lp) = link_preview {
                    format!(
                        "{} {} {}",
                        body,
                        lp.title.as_deref().unwrap_or(""),
                        lp.description.as_deref().unwrap_or("")
                    )
                    .trim()
                    .to_string()
                } else {
                    body.clone()
                }
            }
            Self::Media {
                caption, file_name, ..
            } => format!(
                "{} {}",
                caption.as_deref().unwrap_or(""),
                file_name.as_deref().unwrap_or("")
            )
            .trim()
            .to_string(),
            Self::Poll { question, options } => format!("{} {}", question, options.join(" ")),
            Self::Location { label, .. } => label.clone().unwrap_or_default(),
            Self::ViewOnceCompanionStub { .. }
            | Self::CallTimelineItem { .. }
            | Self::UnknownPlaceholder { .. } => String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotedReplyRef {
    pub target_stanza_id: String,
    pub sender_label: String,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionChip {
    pub emoji: String,
    pub count: usize,
    pub reacted_by_me: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineMessage {
    pub local_id: String,
    pub stanza_id: String,
    pub conversation_id: ConversationId,
    pub sender_id: CanonicalPeerId,
    pub sender_display: String,
    #[serde(default)]
    pub sender_avatar_cache_key: Option<String>,
    pub is_from_me: bool,
    pub timestamp: DateTime<Utc>,
    pub sort_key: i64,
    pub delivery: DeliveryState,
    pub content: MessageContent,
    pub quoted: Option<QuotedReplyRef>,
    pub reactions: Vec<ReactionChip>,
}

/// Day-1 `<call>` signaling model surfaced to the native UI and XDG notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveCallBanner {
    pub call_id: String,
    pub peer_wire_jid: String,
    pub creator_wire_jid: String,
    pub caller_display: String,
    pub is_video: bool,
    pub is_group: bool,
    pub started_at: DateTime<Utc>,
}

/// Phase 2 OS media handles (PipeWire node IDs and XDG `ScreenCast` portal session tokens)
/// kept separate from byte-buffer messaging traits so real-time media attaches cleanly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Phase2MediaSessionHandle {
    pub pipewire_audio_source_node: Option<u32>,
    pub pipewire_audio_sink_node: Option<u32>,
    pub pipewire_video_node: Option<u32>,
    pub screencast_restore_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub conversation_id: ConversationId,
    pub conversation_title: String,
    pub stanza_id: String,
    pub sender_display: String,
    pub snippet: String,
    pub timestamp: DateTime<Utc>,
    pub sort_key: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistorySyncStats {
    pub chunks_staged: u64,
    pub messages_committed: u64,
    pub progress_pct: u8,
    pub in_progress: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum VaultLifecycleState {
    VaultLocked {
        backend_hint: String,
    },
    ConsentRequired,
    Quarantined {
        reason: String,
    },
    Unpaired,
    Pairing {
        qr_payload: Option<String>,
        pair_code: Option<String>,
        expires_in_secs: u64,
    },
    Connecting,
    Connected {
        account_jid: String,
        push_name: String,
    },
    OfflineReadOnly {
        reason: String,
    },
}

impl VaultLifecycleState {
    /// A short, PII-free label for diagnostics and logs.
    ///
    /// Never include account JIDs, push names, pairing codes, QR payloads or
    /// quarantine reasons here: these strings are written to the on-disk
    /// "sanitized" diagnostic log.
    pub fn redacted_summary(&self) -> &'static str {
        match self {
            Self::VaultLocked { .. } => "vault_locked",
            Self::ConsentRequired => "consent_required",
            Self::Quarantined { .. } => "quarantined",
            Self::Unpaired => "unpaired",
            Self::Pairing { .. } => "pairing",
            Self::Connecting => "connecting",
            Self::Connected { .. } => "connected",
            Self::OfflineReadOnly { .. } => "offline_read_only",
        }
    }
}

/// Per-subsystem feature flags controlled by `CompatManifest` so broken `MEX` Channels
/// or Status schemas can be disabled independently without interrupting 1:1/group E2EE chat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlags {
    pub core_messaging: bool,
    pub voice_notes: bool,
    pub status_broadcast: bool,
    pub channels_mex: bool,
    pub voip_calling: bool,
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            core_messaging: true,
            voice_notes: true,
            status_broadcast: true,
            channels_mex: true,
            voip_calling: false,
        }
    }
}

/// Cryptographically verifiable pre-connect compatibility manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatManifest {
    pub epoch: u64,
    pub min_safe_app_version: String,
    pub min_safe_wa_rust_version: String,
    pub issued_at: DateTime<Utc>,
    pub features: FeatureFlags,
    pub kill_switch_active: bool,
    pub kill_switch_reason: Option<String>,
    pub signature_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompatDecision {
    Allowed,
    Quarantine { reason: String },
}

impl CompatManifest {
    pub fn default_local() -> Self {
        Self {
            epoch: 1,
            min_safe_app_version: "0.1.0".to_string(),
            min_safe_wa_rust_version: "0.7.0".to_string(),
            issued_at: Utc::now(),
            features: FeatureFlags::default(),
            kill_switch_active: false,
            kill_switch_reason: None,
            signature_hex: None,
        }
    }

    /// Canonical payload bytes covered by the Ed25519 signature.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        format!(
            "epoch={};min_app={};min_wa_rust={};kill={};reason={};core={};vn={};status={};mex={};voip={}",
            self.epoch,
            self.min_safe_app_version,
            self.min_safe_wa_rust_version,
            self.kill_switch_active,
            self.kill_switch_reason.as_deref().unwrap_or(""),
            self.features.core_messaging,
            self.features.voice_notes,
            self.features.status_broadcast,
            self.features.channels_mex,
            self.features.voip_calling,
        )
        .into_bytes()
    }

    pub fn verify_ed25519(&self, verifying_key_bytes: &[u8; 32]) -> anyhow::Result<()> {
        let sig_hex = self
            .signature_hex
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("compatibility manifest is missing signature_hex"))?;
        let sig_bytes = hex::decode(sig_hex)?;
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Ed25519 signature must be exactly 64 bytes"))?;
        let signature = Signature::from_bytes(&sig_array);
        let vk = VerifyingKey::from_bytes(verifying_key_bytes)?;
        vk.verify(&self.canonical_signing_bytes(), &signature)
            .map_err(|e| anyhow::anyhow!("CompatManifest Ed25519 signature check failed: {e}"))
    }

    pub fn evaluate(&self, app_version: &str, wa_rust_version: &str) -> CompatDecision {
        if self.kill_switch_active {
            let reason = self.kill_switch_reason.clone().unwrap_or_else(|| {
                "Remote safety kill-switch active due to upstream WhatsApp protocol rotation."
                    .to_string()
            });
            return CompatDecision::Quarantine { reason };
        }
        if !semver_at_least(app_version, &self.min_safe_app_version) {
            return CompatDecision::Quarantine {
                reason: format!(
                    "App version {app_version} is older than minimum safe version {}; running in offline read-only mode to protect your account.",
                    self.min_safe_app_version
                ),
            };
        }
        if !semver_at_least(wa_rust_version, &self.min_safe_wa_rust_version) {
            return CompatDecision::Quarantine {
                reason: format!(
                    "Protocol adapter {wa_rust_version} is older than minimum safe version {}; update required before reconnecting.",
                    self.min_safe_wa_rust_version
                ),
            };
        }
        CompatDecision::Allowed
    }
}

/// Loads the signed manifest bundled into the binary. A corrupt artifact fails
/// closed: the returned manifest keeps the app in offline read-only mode.
pub fn bundled_compat_manifest() -> CompatManifest {
    match serde_json::from_str::<CompatManifest>(BUNDLED_COMPAT_MANIFEST_JSON) {
        Ok(manifest) => manifest,
        Err(_) => CompatManifest {
            kill_switch_active: true,
            kill_switch_reason: Some(
                "Bundled compatibility manifest is corrupt; refusing to connect".to_string(),
            ),
            ..CompatManifest::default_local()
        },
    }
}

/// Outcome of checking a manifest's authenticity before connecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompatVerification {
    Verified,
    /// Only returned when the caller explicitly opted out of verification.
    Overridden {
        reason: String,
    },
}

/// Authenticates the compatibility manifest before any network work is done.
/// An invalid signature is fatal unless the user explicitly opted out with
/// `--allow-unverified-protocol`.
pub fn verify_compat_manifest(
    manifest: &CompatManifest,
    allow_unverified: bool,
) -> anyhow::Result<CompatVerification> {
    match manifest.verify_ed25519(&COMPAT_VERIFYING_KEY) {
        Ok(()) => Ok(CompatVerification::Verified),
        Err(err) if allow_unverified => Ok(CompatVerification::Overridden {
            reason: err.to_string(),
        }),
        Err(err) => Err(anyhow::anyhow!(
            "Compatibility manifest signature check failed; refusing to open a WhatsApp socket: {err}"
        )),
    }
}

pub fn semver_at_least(actual: &str, minimum: &str) -> bool {
    let parse_tuple = |s: &str| -> (u64, u64, u64) {
        let core = s.split('-').next().unwrap_or(s);
        let mut parts = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
        (
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
        )
    };
    parse_tuple(actual) >= parse_tuple(minimum)
}

/// Zero-PII structured protocol/desktop diagnostic event category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticCounterSnapshot {
    pub messages_persisted: u64,
    pub retry_receipts_quarantined: u64,
    pub history_chunks_staged: u64,
    pub outbound_commands_paced: u64,
    pub call_signals_observed: u64,
    pub circuit_breaker_trips: u64,
    pub last_protocol_anomaly: Option<String>,
}

/// Events emitted from the protocol/domain runtime up to the native UI and XDG notifier.
#[derive(Debug, Clone)]
pub enum DomainEvent {
    LifecycleChanged(VaultLifecycleState),
    ConversationsUpdated(Vec<ConversationSummary>),
    ContactsUpdated(Vec<PeerIdentityRecord>),
    AvatarUpdated {
        jid: String,
        cache_key: String,
    },
    MediaUpdated {
        conversation_id: ConversationId,
        stanza_id: String,
    },
    MessagesUpdated {
        conversation_id: ConversationId,
    },
    IncomingNotification {
        conversation_id: ConversationId,
        title: String,
        body: String,
    },
    HistorySyncUpdated(HistorySyncStats),
    CallBannerUpdated(Option<ActiveCallBanner>),
    TypingUpdated {
        conversation_id: ConversationId,
        peer_label: Option<String>,
    },
    ToastMessage(String),
}

#[derive(Debug, Clone)]
pub enum EngineCommand {
    StartSession {
        phone_number_for_code: Option<String>,
        custom_pair_code: Option<String>,
    },
    OpenOrCreateDirectChat {
        wire_jid: String,
        display_hint: Option<String>,
    },
    DownloadMessageMedia {
        conversation_id: ConversationId,
        stanza_id: String,
    },
    RefreshContactsAndAvatars,
    SendText {
        conversation_id: ConversationId,
        local_id: String,
        text: String,
        reply_to_stanza_id: Option<String>,
    },
    SendAttachment {
        conversation_id: ConversationId,
        local_id: String,
        file_path: PathBuf,
        mime_type: String,
        media_kind: MediaKind,
        caption: Option<String>,
    },
    SendReaction {
        conversation_id: ConversationId,
        target_stanza_id: String,
        emoji: String,
    },
    EditMessage {
        conversation_id: ConversationId,
        target_stanza_id: String,
        new_text: String,
    },
    RevokeMessage {
        conversation_id: ConversationId,
        target_stanza_id: String,
    },
    DeclineCall {
        call_id: String,
        peer_wire_jid: String,
        creator_wire_jid: String,
    },
    CheckSocketAfterSleep,
    Disconnect,
    Logout,
}

#[async_trait]
pub trait ProtocolEnginePort: Send + Sync {
    async fn submit(&self, cmd: EngineCommand) -> anyhow::Result<()>;
    fn diagnostics(&self) -> DiagnosticCounterSnapshot;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn compat_manifest_ed25519_verification_and_quarantine_gate() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_bytes = signing_key.verifying_key().to_bytes();

        let mut manifest = CompatManifest::default_local();
        manifest.min_safe_app_version = "0.2.0".to_string();
        let sig = signing_key.sign(&manifest.canonical_signing_bytes());
        manifest.signature_hex = Some(hex::encode(sig.to_bytes()));

        manifest
            .verify_ed25519(&verifying_bytes)
            .expect("valid Ed25519 signature must pass");

        // Stale app version triggers read-only quarantine instead of risking a ban.
        assert!(matches!(
            manifest.evaluate("0.1.0", "0.7.0"),
            CompatDecision::Quarantine { .. }
        ));
        assert_eq!(manifest.evaluate("0.2.0", "0.7.0"), CompatDecision::Allowed);
        assert_eq!(manifest.evaluate("0.3.1", "0.7.2"), CompatDecision::Allowed);

        // Tampering invalidates Ed25519 verification.
        manifest.min_safe_app_version = "0.0.1".to_string();
        assert!(manifest.verify_ed25519(&verifying_bytes).is_err());
    }

    #[test]
    fn legacy_message_content_json_deserializes_cleanly() {
        let legacy_text = r#"{"type":"text","body":"Hello world","edited_at":null}"#;
        let parsed_text: MessageContent = serde_json::from_str(legacy_text).unwrap();
        assert!(matches!(
            parsed_text,
            MessageContent::Text {
                ref body,
                link_preview: None,
                ..
            } if body == "Hello world"
        ));

        let legacy_media = r#"{"type":"media","media_kind":"image","caption":null,"mime_type":"image/jpeg","file_name":null,"byte_len":4096,"dimensions":[640,480],"cache_key":null,"duration_secs":null}"#;
        let parsed_media: MessageContent = serde_json::from_str(legacy_media).unwrap();
        assert!(matches!(
            parsed_media,
            MessageContent::Media {
                media_kind: MediaKind::Image,
                thumb_cache_key: None,
                waveform: None,
                ..
            }
        ));
    }

    #[test]
    fn lifecycle_redacted_summary_never_exposes_account_or_pairing_pii() {
        let jid = "14155550199@s.whatsapp.net";
        let name = "Rabimba Karanjai";
        let qr = "2-ABCDEF@ABCDEFGH";
        let code = "ABCDEF12";

        let connected = VaultLifecycleState::Connected {
            account_jid: jid.to_string(),
            push_name: name.to_string(),
        }
        .redacted_summary();
        let pairing = VaultLifecycleState::Pairing {
            qr_payload: Some(qr.to_string()),
            pair_code: Some(code.to_string()),
            expires_in_secs: 60,
        }
        .redacted_summary();

        for summary in [connected, pairing] {
            assert!(!summary.contains(jid));
            assert!(!summary.contains(name));
            assert!(!summary.contains(qr));
            assert!(!summary.contains(code));
        }
        assert!(connected.contains("connected"));
        assert!(pairing.contains("pairing"));
    }

    #[test]
    fn bundled_compat_manifest_verifies_against_the_pinned_key() {
        let manifest = bundled_compat_manifest();
        manifest
            .verify_ed25519(&COMPAT_VERIFYING_KEY)
            .expect("the bundled manifest must be signed by the pinned key");
        assert_eq!(
            manifest.evaluate(env!("CARGO_PKG_VERSION"), "0.7.0"),
            CompatDecision::Allowed
        );
    }

    #[test]
    fn tampered_manifest_is_rejected_unless_explicitly_overridden() {
        let mut manifest = bundled_compat_manifest();
        manifest.min_safe_app_version = "9.9.9".to_string();

        assert!(verify_compat_manifest(&manifest, false).is_err());
        assert!(matches!(
            verify_compat_manifest(&manifest, true),
            Ok(CompatVerification::Overridden { .. })
        ));
    }
}

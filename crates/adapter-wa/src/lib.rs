//! Isolated WhatsApp Multi-Device protocol adapter (`whatsapp-rust 0.7.0`) and
//! deterministic zero-account offline `--mock` harness.
//!
//! Architectural invariant: zero `whatsapp_rust` / `wacore` / `waproto` types cross
//! this crate's public API; everything above speaks pure `whatsnative_domain` contracts.

#![recursion_limit = "512"]

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use rand::Rng;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use whatsapp_rust::buffa::Message as BuffaMessage;
use whatsapp_rust::http::HttpRequest;
use whatsapp_rust::pair_code::PairCodeOptions;
use whatsapp_rust::prelude::*;
use whatsapp_rust::wacore::appstate::hash::HashState;
use whatsapp_rust::wacore::download::MediaType;
use whatsapp_rust::wacore::store::traits::{AppSyncStore, DeviceStore, ProtocolStore};
use whatsapp_rust::wacore::types::call::{CallAction, ElsewhereOutcome};
use whatsapp_rust::wacore::types::events::UnavailableType;
use whatsapp_rust::wacore::types::presence::{ChatPresence, ReceiptType};
use whatsapp_rust::wacore_binary::JidExt;
use whatsapp_rust::{InboundDurabilityHook, RetryAdmission, RevokeType, UploadOptions};
use whatsnative_domain::{
    ActiveCallBanner, CallOutcome, CompatDecision, CompatManifest, ConversationId,
    ConversationKind, DeliveryState, DiagnosticCounterSnapshot, DomainEvent, EngineCommand,
    HistorySyncStats, LinkPreviewCard, MediaKind, MessageContent, PARSER_SCHEMA_VERSION,
    ProtocolEnginePort, QuotedReplyRef, VaultLifecycleState, verify_compat_manifest,
};

/// Authenticates the manifest and evaluates the kill-switch gate. This runs
/// before any socket, store, or network work in `start_live_session`.
pub(crate) fn compat_gate_decision(
    compat: &CompatManifest,
    allow_unverified: bool,
) -> CompatDecision {
    if let Err(err) = verify_compat_manifest(compat, allow_unverified) {
        return CompatDecision::Quarantine {
            reason: err.to_string(),
        };
    }
    if allow_unverified {
        return CompatDecision::Allowed;
    }
    compat.evaluate(env!("CARGO_PKG_VERSION"), "0.7.0")
}
use whatsnative_store::{
    CURRENT_CRYPTO_READER_VERSION, CryptoSchemaGuard, InboundCommitRecord, VaultStore,
};

/// Human-paced outbound token bucket (`<= 3 req/s` sustained, burst `4`, plus `40-180 ms`
/// randomized jitter) protecting personal accounts from anti-scraper velocity flags.
pub struct OutboundRateGuard {
    inner: AsyncMutex<RateState>,
    paced_total: AtomicU64,
}

struct RateState {
    tokens: f64,
    last_refill: Instant,
}

impl OutboundRateGuard {
    pub fn new() -> Self {
        Self {
            inner: AsyncMutex::new(RateState {
                tokens: 4.0,
                last_refill: Instant::now(),
            }),
            paced_total: AtomicU64::new(0),
        }
    }

    pub async fn acquire_human_paced(&self) {
        let wait_dur = {
            let mut st = self.inner.lock().await;
            let now = Instant::now();
            let elapsed = now.saturating_duration_since(st.last_refill).as_secs_f64();
            st.tokens = (st.tokens + elapsed * 3.0).min(4.0);
            st.last_refill = now;
            if st.tokens >= 1.0 {
                st.tokens -= 1.0;
                Duration::ZERO
            } else {
                let deficit = 1.0 - st.tokens;
                st.tokens = 0.0;
                Duration::from_secs_f64(deficit / 3.0)
            }
        };
        let jitter_ms = rand::thread_rng().gen_range(40..=160);
        tokio::time::sleep(wait_dur + Duration::from_millis(jitter_ms)).await;
        self.paced_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn paced_count(&self) -> u64 {
        self.paced_total.load(Ordering::Relaxed)
    }
}

impl Default for OutboundRateGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-`(chat, requester)` retry-receipt quarantine (`burst = 2`, `refill = 2/day`)
/// preventing broken group participant sessions from triggering sender-key retry storms.
pub struct GroupRetryQuarantine {
    buckets: Mutex<HashMap<(String, String), (f64, Instant)>>,
    burst: f64,
    refill_per_sec: f64,
    max_pairs: usize,
    quarantined_total: AtomicU64,
}

impl GroupRetryQuarantine {
    pub fn new(burst: u32, refill_per_day: u32, max_pairs: usize) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            burst: f64::from(burst),
            refill_per_sec: f64::from(refill_per_day) / 86_400.0,
            max_pairs,
            quarantined_total: AtomicU64::new(0),
        }
    }

    pub fn quarantined_total(&self) -> u64 {
        self.quarantined_total.load(Ordering::Relaxed)
    }
}

impl RetryAdmission for GroupRetryQuarantine {
    fn admit(&self, chat: &Jid, requester: &Jid, _retry_count: u8) -> bool {
        let now = Instant::now();
        let key = (chat.user.to_string(), requester.user.to_string());
        let mut map = self.buckets.lock().expect("quarantine lock poisoned");
        if !map.contains_key(&key) && map.len() >= self.max_pairs {
            return true;
        }
        let (tokens, last) = map.entry(key).or_insert((self.burst, now));
        let elapsed = now.saturating_duration_since(*last).as_secs_f64();
        *tokens = (*tokens + elapsed * self.refill_per_sec).min(self.burst);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            self.quarantined_total.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

#[derive(Default)]
pub struct AdapterMetrics {
    pub messages_persisted: AtomicU64,
    pub history_chunks_staged: AtomicU64,
    pub call_signals_observed: AtomicU64,
    pub circuit_breaker_trips: AtomicU64,
    pub last_anomaly: Mutex<Option<String>>,
}

impl AdapterMetrics {
    fn record_anomaly(&self, reason: impl Into<String>) {
        self.circuit_breaker_trips.fetch_add(1, Ordering::Relaxed);
        *self.last_anomaly.lock().expect("anomaly mutex poisoned") = Some(reason.into());
    }
}

#[derive(Default)]
struct UiRefreshCoalescer {
    running: AtomicBool,
    pending_convs: AtomicBool,
    pending_contacts: AtomicBool,
}

impl UiRefreshCoalescer {
    fn schedule_conversations(
        self: &Arc<Self>,
        vault: VaultStore,
        event_tx: async_channel::Sender<DomainEvent>,
    ) {
        self.pending_convs.store(true, Ordering::SeqCst);
        self.trigger(vault, event_tx);
    }

    fn schedule_contacts(
        self: &Arc<Self>,
        vault: VaultStore,
        event_tx: async_channel::Sender<DomainEvent>,
    ) {
        self.pending_contacts.store(true, Ordering::SeqCst);
        self.trigger(vault, event_tx);
    }

    fn schedule(self: &Arc<Self>, vault: VaultStore, event_tx: async_channel::Sender<DomainEvent>) {
        self.pending_convs.store(true, Ordering::SeqCst);
        self.pending_contacts.store(true, Ordering::SeqCst);
        self.trigger(vault, event_tx);
    }

    fn trigger(self: &Arc<Self>, vault: VaultStore, event_tx: async_channel::Sender<DomainEvent>) {
        if self
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let this = self.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    let fetch_convs = this.pending_convs.swap(false, Ordering::SeqCst);
                    let fetch_contacts = this.pending_contacts.swap(false, Ordering::SeqCst);

                    if fetch_convs || fetch_contacts {
                        let v = vault.clone();
                        let res = tokio::task::spawn_blocking(move || {
                            let convs = if fetch_convs {
                                v.list_conversations().ok()
                            } else {
                                None
                            };
                            let contacts = if fetch_contacts {
                                v.list_contacts().ok()
                            } else {
                                None
                            };
                            (convs, contacts)
                        })
                        .await;

                        if let Ok((maybe_convs, maybe_contacts)) = res {
                            if let Some(contacts) = maybe_contacts {
                                let _ = event_tx.send(DomainEvent::ContactsUpdated(contacts)).await;
                            }
                            if let Some(convs) = maybe_convs {
                                let _ = event_tx
                                    .send(DomainEvent::ConversationsUpdated(convs))
                                    .await;
                            }
                        }
                    }

                    if !this.pending_convs.load(Ordering::SeqCst)
                        && !this.pending_contacts.load(Ordering::SeqCst)
                    {
                        this.running.store(false, Ordering::SeqCst);
                        if !this.pending_convs.load(Ordering::SeqCst)
                            && !this.pending_contacts.load(Ordering::SeqCst)
                        {
                            break;
                        }
                        if this
                            .running
                            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            });
        }
    }
}

/// Commits raw decrypted protobuf envelopes + canonical `@lid` <-> `@s.whatsapp.net`
/// projections into `VaultStore` BEFORE `whatsapp-rust` sends delivery `<receipt>` ACKs.
struct VaultDurabilityHook {
    vault: VaultStore,
    event_tx: async_channel::Sender<DomainEvent>,
    metrics: Arc<AdapterMetrics>,
    compat: CompatManifest,
    media_sem: Arc<Semaphore>,
}

#[async_trait]
impl InboundDurabilityHook for VaultDurabilityHook {
    async fn on_messages(
        &self,
        client: Arc<Client>,
        batch: &[InboundMessage],
    ) -> anyhow::Result<()> {
        process_inbound_message_slice(
            &client,
            batch,
            &self.vault,
            &self.event_tx,
            &self.metrics,
            &self.compat,
            &self.media_sem,
        )
        .await
    }
}

async fn process_inbound_message_slice(
    client: &Arc<Client>,
    batch: &[InboundMessage],
    vault_ref: &VaultStore,
    event_tx_ref: &async_channel::Sender<DomainEvent>,
    metrics_ref: &Arc<AdapterMetrics>,
    compat: &CompatManifest,
    media_sem: &Arc<Semaphore>,
) -> anyhow::Result<()> {
    let mut pre_items = Vec::with_capacity(batch.len());
    let mut reaction_ops = Vec::new();
    let mut edit_ops = Vec::new();
    let mut revoke_ops = Vec::new();

    for item in batch {
        let chat_jid = item.info.source.chat.to_string();
        let kind = classify_conversation_kind(&item.info.source.chat);
        if kind == ConversationKind::NewsletterChannel && !compat.features.channels_mex {
            continue;
        }
        if kind == ConversationKind::StatusBroadcast && !compat.features.status_broadcast {
            continue;
        }

        let sender_jid = item.info.source.sender.to_string();
        let sender_alt = item
            .info
            .source
            .sender_alt
            .as_ref()
            .map(ToString::to_string);
        let is_self_chat = item.info.source.chat == item.info.source.sender;
        let chat_alt = if item.info.source.is_from_me {
            if is_self_chat {
                item.info
                    .source
                    .recipient_alt
                    .as_ref()
                    .or(item.info.source.sender_alt.as_ref())
            } else {
                item.info.source.recipient_alt.as_ref()
            }
        } else {
            item.info.source.sender_alt.as_ref()
        }
        .map(ToString::to_string)
        .filter(|_| kind == ConversationKind::DirectMessage);

        let push_name = (!item.info.push_name.is_empty()).then(|| item.info.push_name.clone());
        let base = item.message.get_base_message();

        // Reaction update
        if let Some(react) = base.reaction_message.as_option() {
            if let Some(target_id) = react.key.as_option().and_then(|k| k.id.clone()) {
                let emoji = react.text.clone().unwrap_or_default();
                reaction_ops.push((
                    chat_jid,
                    chat_alt,
                    kind,
                    sender_jid,
                    sender_alt,
                    push_name,
                    target_id,
                    emoji,
                    item.info.source.is_from_me,
                ));
            }
            continue;
        }

        // Protocol revoke / edit
        if let Some(pm) = base.protocol_message.as_option() {
            use whatsapp_rust::waproto::whatsapp::message::protocol_message::Type as ProtoType;
            if pm.r#type == Some(ProtoType::REVOKE) {
                if let Some(target_id) = pm.key.as_option().and_then(|k| k.id.clone()) {
                    revoke_ops.push((chat_jid, chat_alt, kind, target_id));
                }
                continue;
            }
            if let Some(edited) = pm.edited_message.as_option()
                && let Some(target_id) = pm.key.as_option().and_then(|k| k.id.clone())
                && let Some(new_txt) = edited.text_content()
            {
                edit_ops.push((chat_jid, chat_alt, kind, target_id, new_txt.to_string()));
                continue;
            }
        }

        pre_items.push((
            chat_jid,
            chat_alt,
            kind,
            sender_jid,
            sender_alt,
            push_name,
            item.info.id.clone(),
            item.info.source.is_from_me,
            item.info.timestamp.timestamp_millis(),
            (*item.message).clone(),
        ));
    }

    let vault = vault_ref.clone();
    let event_tx = event_tx_ref.clone();
    let metrics = metrics_ref.clone();

    type CommitBatchOutcome = (
        Vec<(ConversationId, Option<(String, String)>)>,
        Vec<(ConversationId, String, wa::Message)>,
    );

    let (touched, media_jobs) =
        tokio::task::spawn_blocking(move || -> anyhow::Result<CommitBatchOutcome> {
            let mut records = Vec::with_capacity(pre_items.len());
            let mut pending_downloads = Vec::new();

            for (
                chat_jid,
                chat_alt,
                kind,
                sender_jid,
                sender_alt,
                push_name,
                stanza_id,
                is_from_me,
                ts_ms,
                wa_msg,
            ) in pre_items
            {
                let (content, quoted) = extract_wa_message_rich(&wa_msg, &stanza_id, Some(&vault));
                let raw_proto = wa_msg.encode_to_vec();
                if should_auto_download_media(&wa_msg) {
                    pending_downloads.push((
                        chat_jid.clone(),
                        chat_alt.clone(),
                        kind,
                        stanza_id.clone(),
                        wa_msg,
                    ));
                }
                records.push(InboundCommitRecord {
                    chat_wire_jid: chat_jid,
                    chat_alt_jid: chat_alt,
                    chat_kind: kind,
                    chat_title_hint: if kind == ConversationKind::DirectMessage {
                        if is_from_me { None } else { push_name.clone() }
                    } else {
                        None
                    },
                    sender_wire_jid: sender_jid,
                    sender_alt_jid: sender_alt,
                    sender_push_name: if is_from_me { None } else { push_name },
                    stanza_id,
                    is_from_me,
                    timestamp_ms: ts_ms,
                    delivery: DeliveryState::Delivered,
                    content,
                    quoted,
                    raw_decrypted_proto: raw_proto,
                    defer_fts: false,
                });
            }

            let mut notify_list = Vec::new();
            let committed_convs = vault.commit_inbound_batch(&records)?;
            metrics
                .messages_persisted
                .fetch_add(records.len() as u64, Ordering::Relaxed);

            for cid in committed_convs {
                let notif = records.last().and_then(|r| {
                    if !r.is_from_me {
                        let title = r
                            .sender_push_name
                            .clone()
                            .unwrap_or_else(|| r.sender_wire_jid.clone());
                        Some((title, r.content.preview_text()))
                    } else {
                        None
                    }
                });
                notify_list.push((cid, notif));
            }

            let mut resolved_downloads = Vec::new();
            for (chat_jid, chat_alt, kind, stanza_id, wa_msg) in pending_downloads {
                if let Ok(cid) =
                    vault.ensure_conversation(&chat_jid, chat_alt.as_deref(), kind, None)
                {
                    resolved_downloads.push((cid, stanza_id, wa_msg));
                }
            }

            for (
                chat_jid,
                chat_alt,
                kind,
                sender_jid,
                sender_alt,
                push,
                target_id,
                emoji,
                from_me,
            ) in reaction_ops
            {
                let conv_id =
                    vault.ensure_conversation(&chat_jid, chat_alt.as_deref(), kind, None)?;
                let peer_id = vault.resolve_or_merge_peer(
                    &sender_jid,
                    sender_alt.as_deref(),
                    push.as_deref(),
                )?;
                vault.upsert_reaction(conv_id, &target_id, peer_id, &emoji, from_me)?;
                notify_list.push((conv_id, None));
            }

            for (chat_jid, chat_alt, kind, target_id, new_txt) in edit_ops {
                let conv_id =
                    vault.ensure_conversation(&chat_jid, chat_alt.as_deref(), kind, None)?;
                vault.apply_message_edit(conv_id, &target_id, &new_txt)?;
                notify_list.push((conv_id, None));
            }

            for (chat_jid, chat_alt, kind, target_id) in revoke_ops {
                let conv_id =
                    vault.ensure_conversation(&chat_jid, chat_alt.as_deref(), kind, None)?;
                vault.apply_message_revoke(conv_id, &target_id)?;
                notify_list.push((conv_id, None));
            }

            Ok((notify_list, resolved_downloads))
        })
        .await
        .context("inbound durability commit join error")??;

    if !touched.is_empty() {
        if let Ok(convs) = vault_ref.list_conversations() {
            let _ = event_tx
                .send(DomainEvent::ConversationsUpdated(convs))
                .await;
        }
        for (cid, notif) in touched {
            let _ = event_tx
                .send(DomainEvent::MessagesUpdated {
                    conversation_id: cid,
                })
                .await;
            if let Some((title, body)) = notif {
                let _ = event_tx
                    .send(DomainEvent::IncomingNotification {
                        conversation_id: cid,
                        title,
                        body,
                    })
                    .await;
            }
        }
    }

    for (cid, stanza_id, wa_msg) in media_jobs {
        spawn_message_media_download(
            client.clone(),
            vault_ref.clone(),
            event_tx_ref.clone(),
            media_sem.clone(),
            cid,
            stanza_id,
            wa_msg,
        );
    }

    Ok(())
}

fn maybe_store_inline_thumb(
    vault: Option<&VaultStore>,
    key_suffix: &str,
    raw_bytes: Option<&[u8]>,
) -> Option<String> {
    let v = vault?;
    let bytes = raw_bytes.filter(|b| !b.is_empty())?;
    let key = format!("thumb:{key_suffix}");
    v.store_encrypted_media(&key, bytes).ok()?;
    Some(key)
}

pub fn map_wa_message_to_domain(msg: &wa::Message) -> (MessageContent, Option<QuotedReplyRef>) {
    extract_wa_message_rich(msg, "stateless", None)
}

pub fn extract_wa_message_rich(
    msg: &wa::Message,
    stanza_id: &str,
    vault: Option<&VaultStore>,
) -> (MessageContent, Option<QuotedReplyRef>) {
    // Enforce official macOS companion View-Once restriction first!
    if msg.is_view_once() {
        let base = msg.get_base_message();
        let label = if base.image_message.is_set() {
            "photo"
        } else if base.video_message.is_set() {
            "video"
        } else if base.audio_message.is_set() {
            "voice note"
        } else {
            "media"
        };
        return (
            MessageContent::ViewOnceCompanionStub {
                media_label: label.to_string(),
            },
            None,
        );
    }

    let base = msg.get_base_message();
    let quoted = extract_quoted_ref(base);

    if let Some(ext) = base.extended_text_message.as_option()
        && let Some(body) = ext.text.as_deref().filter(|s| !s.is_empty())
    {
        let matched_url = ext
            .matched_text
            .as_deref()
            .filter(|u| u.starts_with("http://") || u.starts_with("https://"))
            .or_else(|| {
                body.split_whitespace()
                    .find(|w| w.starts_with("http://") || w.starts_with("https://"))
            });

        let link_preview = matched_url.map(|url| LinkPreviewCard {
            url: url.trim().to_string(),
            title: ext.title.clone().filter(|s| !s.trim().is_empty()),
            description: ext.description.clone().filter(|s| !s.trim().is_empty()),
            thumb_cache_key: maybe_store_inline_thumb(
                vault,
                &format!("lp-{stanza_id}"),
                ext.jpeg_thumbnail.as_deref(),
            ),
        });

        return (
            MessageContent::Text {
                body: body.to_string(),
                edited_at: None,
                link_preview,
            },
            quoted,
        );
    }

    if let Some(text) = msg.text_content() {
        let inline_url = text
            .split_whitespace()
            .find(|w| w.starts_with("http://") || w.starts_with("https://"))
            .map(|u| LinkPreviewCard {
                url: u.trim().to_string(),
                title: None,
                description: None,
                thumb_cache_key: None,
            });
        return (
            MessageContent::Text {
                body: text.to_string(),
                edited_at: None,
                link_preview: inline_url,
            },
            quoted,
        );
    }

    if let Some(img) = base.image_message.as_option() {
        let dims = match (img.width, img.height) {
            (Some(w), Some(h)) if w > 0 && h > 0 => Some((w, h)),
            _ => None,
        };
        let thumb_cache_key =
            maybe_store_inline_thumb(vault, stanza_id, img.jpeg_thumbnail.as_deref());
        return (
            MessageContent::Media {
                media_kind: MediaKind::Image,
                caption: img.caption.clone(),
                mime_type: img
                    .mimetype
                    .clone()
                    .unwrap_or_else(|| "image/jpeg".to_string()),
                file_name: None,
                byte_len: img.file_length.unwrap_or(0),
                dimensions: dims,
                cache_key: None,
                thumb_cache_key,
                duration_secs: None,
                waveform: None,
            },
            quoted,
        );
    }

    if let Some(vid) = base.video_message.as_option() {
        let dims = match (vid.width, vid.height) {
            (Some(w), Some(h)) if w > 0 && h > 0 => Some((w, h)),
            _ => None,
        };
        let thumb_cache_key =
            maybe_store_inline_thumb(vault, stanza_id, vid.jpeg_thumbnail.as_deref());
        return (
            MessageContent::Media {
                media_kind: MediaKind::Video,
                caption: vid.caption.clone(),
                mime_type: vid
                    .mimetype
                    .clone()
                    .unwrap_or_else(|| "video/mp4".to_string()),
                file_name: None,
                byte_len: vid.file_length.unwrap_or(0),
                dimensions: dims,
                cache_key: None,
                thumb_cache_key,
                duration_secs: vid.seconds,
                waveform: None,
            },
            quoted,
        );
    }

    if let Some(aud) = base.audio_message.as_option() {
        let is_ptt = aud.ptt.unwrap_or(false);
        return (
            MessageContent::Media {
                media_kind: if is_ptt {
                    MediaKind::VoiceNote
                } else {
                    MediaKind::Audio
                },
                caption: None,
                mime_type: aud
                    .mimetype
                    .clone()
                    .unwrap_or_else(|| "audio/ogg; codecs=opus".to_string()),
                file_name: None,
                byte_len: aud.file_length.unwrap_or(0),
                dimensions: None,
                cache_key: None,
                thumb_cache_key: None,
                duration_secs: aud.seconds,
                waveform: aud.waveform.clone().filter(|w| !w.is_empty()),
            },
            quoted,
        );
    }

    if let Some(doc) = base.document_message.as_option() {
        let thumb_cache_key =
            maybe_store_inline_thumb(vault, stanza_id, doc.jpeg_thumbnail.as_deref());
        return (
            MessageContent::Media {
                media_kind: MediaKind::Document,
                caption: doc.caption.clone(),
                mime_type: doc
                    .mimetype
                    .clone()
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
                file_name: doc.file_name.clone().or_else(|| doc.title.clone()),
                byte_len: doc.file_length.unwrap_or(0),
                dimensions: None,
                cache_key: None,
                thumb_cache_key,
                duration_secs: None,
                waveform: None,
            },
            quoted,
        );
    }

    if let Some(stk) = base.sticker_message.as_option() {
        let dims = match (stk.width, stk.height) {
            (Some(w), Some(h)) if w > 0 && h > 0 => Some((w, h)),
            _ => Some((160, 160)),
        };
        let thumb_cache_key =
            maybe_store_inline_thumb(vault, stanza_id, stk.png_thumbnail.as_deref());
        return (
            MessageContent::Media {
                media_kind: MediaKind::Sticker,
                caption: None,
                mime_type: stk
                    .mimetype
                    .clone()
                    .unwrap_or_else(|| "image/webp".to_string()),
                file_name: None,
                byte_len: stk.file_length.unwrap_or(0),
                dimensions: dims,
                cache_key: None,
                thumb_cache_key,
                duration_secs: None,
                waveform: None,
            },
            quoted,
        );
    }

    if let Some(poll) = base
        .poll_creation_message
        .as_option()
        .or_else(|| base.poll_creation_message_v2.as_option())
        .or_else(|| base.poll_creation_message_v3.as_option())
    {
        let opts = poll
            .options
            .iter()
            .filter_map(|o| o.option_name.clone())
            .collect();
        return (
            MessageContent::Poll {
                question: poll.name.clone().unwrap_or_else(|| "Poll".to_string()),
                options: opts,
            },
            quoted,
        );
    }

    if let Some(loc) = base.location_message.as_option() {
        let thumb_cache_key =
            maybe_store_inline_thumb(vault, stanza_id, loc.jpeg_thumbnail.as_deref());
        return (
            MessageContent::Location {
                latitude: loc.degrees_latitude.unwrap_or(0.0),
                longitude: loc.degrees_longitude.unwrap_or(0.0),
                label: loc.name.clone().or_else(|| loc.address.clone()),
                thumb_cache_key,
            },
            quoted,
        );
    }

    (
        MessageContent::UnknownPlaceholder {
            schema_version: PARSER_SCHEMA_VERSION,
            summary: "Message saved; update client to view rich format".to_string(),
        },
        quoted,
    )
}

fn should_auto_download_media(msg: &wa::Message) -> bool {
    if msg.is_view_once() {
        return false;
    }
    let base = msg.get_base_message();
    if let Some(img) = base.image_message.as_option() {
        return img.file_length.unwrap_or(0) <= 24 * 1024 * 1024;
    }
    if base.sticker_message.is_set() {
        return true;
    }
    if let Some(aud) = base.audio_message.as_option() {
        return aud.file_length.unwrap_or(0) <= 16 * 1024 * 1024;
    }
    if let Some(vid) = base.video_message.as_option() {
        let len = vid.file_length.unwrap_or(0);
        return len > 0 && len <= 10 * 1024 * 1024;
    }
    if let Some(doc) = base.document_message.as_option() {
        let len = doc.file_length.unwrap_or(0);
        return len > 0 && len <= 8 * 1024 * 1024;
    }
    false
}

async fn download_wa_media_bytes(client: &Client, msg: &wa::Message) -> Result<Option<Vec<u8>>> {
    if msg.is_view_once() {
        return Ok(None);
    }
    let base = msg.get_base_message();
    if let Some(img) = base.image_message.as_option() {
        return Ok(Some(client.download(img).await?));
    }
    if let Some(stk) = base.sticker_message.as_option() {
        return Ok(Some(client.download(stk).await?));
    }
    if let Some(aud) = base.audio_message.as_option() {
        return Ok(Some(client.download(aud).await?));
    }
    if let Some(vid) = base.video_message.as_option() {
        return Ok(Some(client.download(vid).await?));
    }
    if let Some(doc) = base.document_message.as_option() {
        return Ok(Some(client.download(doc).await?));
    }
    Ok(None)
}

fn spawn_message_media_download(
    client: Arc<Client>,
    vault: VaultStore,
    event_tx: async_channel::Sender<DomainEvent>,
    sem: Arc<Semaphore>,
    conversation_id: ConversationId,
    stanza_id: String,
    wa_msg: wa::Message,
) {
    tokio::spawn(async move {
        let Ok(_permit) = sem.acquire_owned().await else {
            return;
        };
        if let Ok(Some(bytes)) = download_wa_media_bytes(&client, &wa_msg).await
            && !bytes.is_empty()
        {
            let full_key = format!("media:{stanza_id}");
            let v = vault.clone();
            let sid = stanza_id.clone();
            let fk = full_key.clone();
            let saved = tokio::task::spawn_blocking(move || -> Result<bool> {
                v.store_encrypted_media(&fk, &bytes)?;
                v.update_message_media_keys(conversation_id, &sid, Some(&fk), None, None, None)
            })
            .await;
            if matches!(saved, Ok(Ok(_))) {
                let _ = event_tx
                    .send(DomainEvent::MediaUpdated {
                        conversation_id,
                        stanza_id,
                    })
                    .await;
            }
        }
    });
}

fn extract_quoted_ref(base: &wa::Message) -> Option<QuotedReplyRef> {
    let ctx = base
        .extended_text_message
        .as_option()
        .and_then(|m| m.context_info.as_option())
        .or_else(|| {
            base.image_message
                .as_option()
                .and_then(|m| m.context_info.as_option())
        })
        .or_else(|| {
            base.video_message
                .as_option()
                .and_then(|m| m.context_info.as_option())
        })
        .or_else(|| {
            base.document_message
                .as_option()
                .and_then(|m| m.context_info.as_option())
        })?;

    let stanza_id = ctx.stanza_id.clone()?;
    let sender_label = ctx
        .participant
        .as_deref()
        .map(|p| p.split('@').next().unwrap_or(p).to_string())
        .unwrap_or_else(|| "Quoted".to_string());
    let snippet = ctx
        .quoted_message
        .as_option()
        .and_then(|q| q.text_content().map(str::to_string))
        .unwrap_or_else(|| "Media / attachment".to_string());

    Some(QuotedReplyRef {
        target_stanza_id: stanza_id,
        sender_label,
        snippet,
    })
}

fn classify_conversation_kind(jid: &Jid) -> ConversationKind {
    if jid.is_status_broadcast() {
        ConversationKind::StatusBroadcast
    } else if jid.is_newsletter() {
        ConversationKind::NewsletterChannel
    } else if jid.is_group() {
        ConversationKind::Group
    } else {
        ConversationKind::DirectMessage
    }
}

fn ensure_jid_domain(raw: &str, default_domain: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        String::new()
    } else if trimmed.contains('@') {
        trimmed.to_string()
    } else {
        format!("{trimmed}{default_domain}")
    }
}

#[derive(Default)]
struct HydrationCoordinator {
    running: AtomicBool,
    rerun_requested: AtomicBool,
}

async fn fetch_and_store_avatar(
    client: &Arc<Client>,
    vault: &VaultStore,
    event_tx: &async_channel::Sender<DomainEvent>,
    jid: &Jid,
) -> bool {
    if jid.is_status_broadcast() || jid.user.is_empty() {
        return false;
    }
    let jid_str = jid.to_string();
    match client.contacts().get_profile_picture(jid, true).await {
        Ok(Some(pic)) if !pic.url.is_empty() => {
            if let Ok(resp) = client.http_client.execute(HttpRequest::get(&pic.url)).await
                && resp.status_code == 200
                && !resp.body.is_empty()
            {
                let v = vault.clone();
                let js = jid_str.clone();
                let body = resp.body;
                if let Ok(Ok(cache_key)) =
                    tokio::task::spawn_blocking(move || v.store_avatar_for_jid(&js, &body)).await
                {
                    let _ = event_tx
                        .send(DomainEvent::AvatarUpdated {
                            jid: jid_str,
                            cache_key,
                        })
                        .await;
                    return true;
                }
            }
            false
        }
        Ok(_) => {
            if !jid_str.ends_with("@lid") {
                let v = vault.clone();
                let js = jid_str;
                let _ =
                    tokio::task::spawn_blocking(move || v.mark_avatar_absent_for_jid(&js)).await;
            }
            false
        }
        Err(_) => false,
    }
}

fn spawn_local_inline_media_backfill(
    vault: VaultStore,
    event_tx: async_channel::Sender<DomainEvent>,
) {
    tokio::spawn(async move {
        let updated =
            tokio::task::spawn_blocking(move || -> Result<(usize, Vec<ConversationId>)> {
                let candidates = vault.list_messages_needing_media_backfill(500)?;
                let mut count = 0usize;
                let mut touched_convs = Vec::new();
                for (cid, stanza_id, _old_content, raw_proto) in candidates {
                    if let Ok(wa_msg) = wa::Message::decode_from_slice(&raw_proto) {
                        let (rich_content, _) =
                            extract_wa_message_rich(&wa_msg, &stanza_id, Some(&vault));
                        let changed = match &rich_content {
                            MessageContent::Media {
                                thumb_cache_key,
                                waveform,
                                ..
                            } => vault.update_message_media_keys(
                                cid,
                                &stanza_id,
                                None,
                                thumb_cache_key.as_deref(),
                                waveform.as_deref(),
                                None,
                            )?,
                            MessageContent::Text { link_preview, .. } => vault
                                .update_message_media_keys(
                                    cid,
                                    &stanza_id,
                                    None,
                                    None,
                                    None,
                                    link_preview.as_ref(),
                                )?,
                            MessageContent::Location {
                                thumb_cache_key, ..
                            } => vault.update_message_media_keys(
                                cid,
                                &stanza_id,
                                None,
                                thumb_cache_key.as_deref(),
                                None,
                                None,
                            )?,
                            _ => false,
                        };
                        if changed {
                            count += 1;
                            if !touched_convs.contains(&cid) {
                                touched_convs.push(cid);
                            }
                        }
                    }
                }
                Ok((count, touched_convs))
            })
            .await;

        if let Ok(Ok((count, convs))) = updated
            && count > 0
        {
            for cid in convs {
                let _ = event_tx
                    .send(DomainEvent::MessagesUpdated {
                        conversation_id: cid,
                    })
                    .await;
            }
        }
    });
}

fn trigger_live_hydration(
    coord: Arc<HydrationCoordinator>,
    client: Arc<Client>,
    vault: VaultStore,
    event_tx: async_channel::Sender<DomainEvent>,
    media_sem: Arc<Semaphore>,
    ui_coalescer: Arc<UiRefreshCoalescer>,
) {
    if coord
        .running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        coord.rerun_requested.store(true, Ordering::SeqCst);
        return;
    }

    tokio::spawn(async move {
        loop {
            coord.rerun_requested.store(false, Ordering::SeqCst);

            // 1. Sync any newly discovered LID <-> PN mappings from whatsapp-rust's protocol store.
            if let Ok(mappings) = client
                .persistence_manager()
                .backend()
                .get_all_lid_mappings()
                .await
                && !mappings.is_empty()
            {
                let v = vault.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    for m in mappings {
                        let pn = ensure_jid_domain(&m.phone_number, "@s.whatsapp.net");
                        let lid = ensure_jid_domain(&m.lid, "@lid");
                        if !pn.is_empty() && !lid.is_empty() {
                            let _ = v.upsert_contact(Some(&pn), Some(&lid), None, None);
                        }
                    }
                })
                .await;
                ui_coalescer.schedule_contacts(vault.clone(), event_tx.clone());
            }

            // 2. Fetch participating group subjects & participant LID <-> PN mappings.
            if client.is_connected()
                && let Ok(groups) = client.groups().get_participating().await
                && !groups.is_empty()
            {
                let v = vault.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    for (gid, meta) in groups {
                        for p in &meta.participants {
                            let pn_s =
                                p.phone_number
                                    .as_ref()
                                    .map(ToString::to_string)
                                    .or_else(|| {
                                        let j = p.jid.to_string();
                                        j.ends_with("@s.whatsapp.net").then_some(j)
                                    });
                            let lid_s = p.lid.as_ref().map(ToString::to_string).or_else(|| {
                                let j = p.jid.to_string();
                                j.ends_with("@lid").then_some(j)
                            });
                            if pn_s.is_some() && lid_s.is_some() {
                                let _ =
                                    v.upsert_contact(pn_s.as_deref(), lid_s.as_deref(), None, None);
                            }
                        }
                        let p_count = meta.size.or(Some(meta.participants.len() as u32));
                        let _ = v.update_group_metadata(&gid.to_string(), &meta.subject, p_count);
                    }
                })
                .await;
                ui_coalescer.schedule(vault.clone(), event_tx.clone());
            }

            // 3. Backfill full-res CDN downloads for recent media messages in `vault.db`.
            if client.is_connected() {
                let v = vault.clone();
                if let Ok(Ok(candidates)) =
                    tokio::task::spawn_blocking(move || v.list_messages_needing_media_backfill(80))
                        .await
                {
                    for (cid, stanza_id, content, raw_proto) in candidates {
                        let missing_full = matches!(
                            content,
                            MessageContent::Media {
                                cache_key: None,
                                ..
                            }
                        );
                        if missing_full
                            && let Ok(wa_msg) = wa::Message::decode_from_slice(&raw_proto)
                            && should_auto_download_media(&wa_msg)
                        {
                            spawn_message_media_download(
                                client.clone(),
                                vault.clone(),
                                event_tx.clone(),
                                media_sem.clone(),
                                cid,
                                stanza_id,
                                wa_msg,
                            );
                        }
                    }
                }
            }

            // 4. Paced profile picture hydration for conversations & contacts missing avatars.
            if client.is_connected() {
                let v = vault.clone();
                if let Ok(Ok(missing_jids)) =
                    tokio::task::spawn_blocking(move || v.jids_missing_avatars(90)).await
                {
                    for raw_jid in missing_jids {
                        if !client.is_connected() {
                            break;
                        }
                        if let Ok(jid) = raw_jid.parse::<Jid>() {
                            let _ = fetch_and_store_avatar(&client, &vault, &event_tx, &jid).await;
                            tokio::time::sleep(Duration::from_millis(120)).await;
                        }
                    }
                }
            }

            if !coord.rerun_requested.swap(false, Ordering::SeqCst) || !client.is_connected() {
                break;
            }
        }
        coord.running.store(false, Ordering::SeqCst);
    });
}

pub struct LiveWhatsAppAdapter {
    vault: VaultStore,
    crypto_db_path: PathBuf,
    crypto_guard_path: PathBuf,
    compat: CompatManifest,
    allow_unverified_override: bool,
    event_tx: async_channel::Sender<DomainEvent>,
    rate_guard: Arc<OutboundRateGuard>,
    quarantine: Arc<GroupRetryQuarantine>,
    metrics: Arc<AdapterMetrics>,
    active_client: Arc<AsyncMutex<Option<Arc<Client>>>>,
    media_sem: Arc<Semaphore>,
    hydration_coord: Arc<HydrationCoordinator>,
    ui_coalescer: Arc<UiRefreshCoalescer>,
}

impl LiveWhatsAppAdapter {
    pub fn new(
        vault: VaultStore,
        crypto_db_path: PathBuf,
        crypto_guard_path: PathBuf,
        compat: CompatManifest,
        allow_unverified_override: bool,
        event_tx: async_channel::Sender<DomainEvent>,
    ) -> Self {
        Self {
            vault,
            crypto_db_path,
            crypto_guard_path,
            compat,
            allow_unverified_override,
            event_tx,
            rate_guard: Arc::new(OutboundRateGuard::new()),
            quarantine: Arc::new(GroupRetryQuarantine::new(2, 2, 32_768)),
            metrics: Arc::new(AdapterMetrics::default()),
            active_client: Arc::new(AsyncMutex::new(None)),
            media_sem: Arc::new(Semaphore::new(3)),
            hydration_coord: Arc::new(HydrationCoordinator::default()),
            ui_coalescer: Arc::new(UiRefreshCoalescer::default()),
        }
    }

    async fn start_live_session(
        &self,
        phone_number_for_code: Option<String>,
        custom_pair_code: Option<String>,
    ) -> Result<()> {
        // 1. Verify crypto downgrade guard BEFORE opening `crypto_session.db`.
        let mut crypto_guard = CryptoSchemaGuard::verify_or_init(
            &self.crypto_guard_path,
            CURRENT_CRYPTO_READER_VERSION,
        )?;

        // 2. Pre-connect Compatibility & Kill-Switch Gate. The Ed25519
        // signature is verified here, before any client or transport work.
        let decision = compat_gate_decision(&self.compat, self.allow_unverified_override);
        if let CompatDecision::Quarantine { reason } = decision {
            self.metrics.record_anomaly(&reason);
            let _ = self
                .event_tx
                .send(DomainEvent::LifecycleChanged(
                    VaultLifecycleState::Quarantined { reason },
                ))
                .await;
            return Ok(());
        }

        // Disconnect any prior running client cleanly first.
        if let Some(prev) = self.active_client.lock().await.take() {
            prev.disconnect().await;
        }

        // Immediately hydrate inline thumbnails/waveforms/link-previews from existing `vault.db` rows
        // and emit cached contacts before network handshake even finishes!
        if let Ok(contacts) = self.vault.list_contacts() {
            let _ = self
                .event_tx
                .send(DomainEvent::ContactsUpdated(contacts))
                .await;
        }
        spawn_local_inline_media_backfill(self.vault.clone(), self.event_tx.clone());

        let _ = self
            .event_tx
            .send(DomainEvent::LifecycleChanged(
                VaultLifecycleState::Connecting,
            ))
            .await;

        let crypto_path_str = self
            .crypto_db_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("crypto_session.db path is not valid UTF-8"))?
            .to_string();
        let sqlite_store = SqliteStore::new(&crypto_path_str)
            .await
            .context("initializing whatsapp-rust SqliteStore")?;

        // Pull all existing @lid <-> @s.whatsapp.net mappings out of `crypto_session.db` immediately!
        if let Ok(mappings) = sqlite_store.get_all_lid_mappings().await
            && !mappings.is_empty()
        {
            let v = self.vault.clone();
            let _ = tokio::task::spawn_blocking(move || {
                for m in mappings {
                    let pn = ensure_jid_domain(&m.phone_number, "@s.whatsapp.net");
                    let lid = ensure_jid_domain(&m.lid, "@lid");
                    if !pn.is_empty() && !lid.is_empty() {
                        let _ = v.upsert_contact(Some(&pn), Some(&lid), None, None);
                    }
                }
            })
            .await;
            self.ui_coalescer
                .schedule_contacts(self.vault.clone(), self.event_tx.clone());
        }

        // One-time AppState Contacts & Chat-Settings Backfill for ALREADY-PAIRED companion sessions!
        // Resets AppState collection versions once so `whatsapp-rust` replays CriticalUnblockLow + Regular*
        // snapshots and emits `Event::ContactUpdate` for the user's entire address book without re-pairing!
        let contacts_backfilled = self
            .vault
            .get_kv("contacts_appstate_backfilled_v1")?
            .as_deref()
            == Some("true");
        if !contacts_backfilled && sqlite_store.exists().await.unwrap_or(false) {
            for col in [
                "critical_block",
                "critical_unblock_low",
                "regular_low",
                "regular_high",
                "regular",
            ] {
                let _ = sqlite_store.set_version(col, HashState::default()).await;
                let _ = sqlite_store.clear_mutation_macs(col).await;
            }
            if let Ok(Some(mut dev)) = sqlite_store.load().await
                && !dev.push_name.is_empty()
            {
                let _ = self.vault.set_kv("saved_self_push_name", &dev.push_name);
                dev.push_name.clear();
                let _ = sqlite_store.save(&dev).await;
            }
        }

        crypto_guard.mark_network_io_active(&self.crypto_guard_path)?;

        let hook = VaultDurabilityHook {
            vault: self.vault.clone(),
            event_tx: self.event_tx.clone(),
            metrics: self.metrics.clone(),
            compat: self.compat.clone(),
            media_sem: self.media_sem.clone(),
        };

        let tx_qr = self.event_tx.clone();
        let tx_code = self.event_tx.clone();
        let mut builder = Bot::builder()
            .with_backend(sqlite_store)
            .with_inbound_durability_hook(hook)
            .on_qr_code(move |qr, timeout| {
                let tx = tx_qr.clone();
                async move {
                    let _ = tx
                        .send(DomainEvent::LifecycleChanged(
                            VaultLifecycleState::Pairing {
                                qr_payload: Some(qr),
                                pair_code: None,
                                expires_in_secs: timeout.as_secs(),
                            },
                        ))
                        .await;
                }
            })
            .on_pair_code(move |code, timeout| {
                let tx = tx_code.clone();
                async move {
                    let _ = tx
                        .send(DomainEvent::LifecycleChanged(
                            VaultLifecycleState::Pairing {
                                qr_payload: None,
                                pair_code: Some(code),
                                expires_in_secs: timeout.as_secs(),
                            },
                        ))
                        .await;
                }
            });

        if let Some(phone) = phone_number_for_code.filter(|s| !s.trim().is_empty()) {
            let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
            builder = builder.with_pair_code(PairCodeOptions {
                phone_number: digits,
                custom_code: custom_pair_code.filter(|s| !s.trim().is_empty()),
                ..Default::default()
            });
        }

        let bot = builder
            .build()
            .await
            .context("building whatsapp-rust Bot")?;
        let client = bot.client();
        let _ = client.set_retry_admission(self.quarantine.clone());

        let (handler, event_rx) = ChannelEventHandler::new();
        let subscription = client.subscribe_handler(handler);

        *self.active_client.lock().await = Some(client.clone());

        let vault = self.vault.clone();
        let event_tx = self.event_tx.clone();
        let metrics = self.metrics.clone();
        let compat = self.compat.clone();
        let media_sem = self.media_sem.clone();
        let hydration_coord = self.hydration_coord.clone();
        let ui_coalescer = self.ui_coalescer.clone();

        tokio::spawn(async move {
            let _keep_sub = subscription;
            let _bot_handle = bot.spawn();

            while let Ok(ev) = event_rx.recv().await {
                handle_live_wa_event(
                    &ev,
                    &client,
                    &vault,
                    &event_tx,
                    &metrics,
                    &compat,
                    &media_sem,
                    &hydration_coord,
                    &ui_coalescer,
                )
                .await;
            }
        });

        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_live_wa_event(
    ev: &Event,
    client: &Arc<Client>,
    vault: &VaultStore,
    event_tx: &async_channel::Sender<DomainEvent>,
    metrics: &Arc<AdapterMetrics>,
    compat: &CompatManifest,
    media_sem: &Arc<Semaphore>,
    hydration_coord: &Arc<HydrationCoordinator>,
    ui_coalescer: &Arc<UiRefreshCoalescer>,
) {
    match ev {
        Event::Connected(_) => {
            let account_pn = client.pn().map(|j| j.to_string());
            let account_lid = client.lid().map(|j| j.to_string());
            if let Some(ref pn) = account_pn {
                let _ = vault.set_kv("account_pn", pn);
            }
            if let Some(ref lid) = account_lid {
                let _ = vault.set_kv("account_lid", lid);
            }
            let account_jid = account_pn
                .clone()
                .or_else(|| account_lid.clone())
                .unwrap_or_else(|| "Linked Companion".to_string());
            let live_push = client.push_name();
            let push_name = if !live_push.is_empty() {
                let _ = vault.set_kv("push_name", &live_push);
                live_push
            } else {
                vault
                    .get_kv("saved_self_push_name")
                    .ok()
                    .flatten()
                    .or_else(|| vault.get_kv("push_name").ok().flatten())
                    .unwrap_or_default()
            };
            let _ = vault.set_kv("account_jid", &account_jid);
            let _ = event_tx
                .send(DomainEvent::LifecycleChanged(
                    VaultLifecycleState::Connected {
                        account_jid,
                        push_name,
                    },
                ))
                .await;
            ui_coalescer.schedule(vault.clone(), event_tx.clone());
            trigger_live_hydration(
                hydration_coord.clone(),
                client.clone(),
                vault.clone(),
                event_tx.clone(),
                media_sem.clone(),
                ui_coalescer.clone(),
            );
        }
        Event::OfflineSyncCompleted(_) => {
            let _ = vault.set_kv("contacts_appstate_backfilled_v1", "true");
            trigger_live_hydration(
                hydration_coord.clone(),
                client.clone(),
                vault.clone(),
                event_tx.clone(),
                media_sem.clone(),
                ui_coalescer.clone(),
            );
        }
        Event::Messages(batch) if !batch.hook_committed => {
            // Commits newsletter / Channel messages and PDO-recovered placeholder messages
            // that bypassed `InboundDurabilityHook`.
            let _ = process_inbound_message_slice(
                client,
                &batch.messages,
                vault,
                event_tx,
                metrics,
                compat,
                media_sem,
            )
            .await;
        }
        Event::ContactUpdate(cu) => {
            let jid_str = cu.jid.to_string();
            let pn_jid = cu
                .action
                .pn_jid
                .clone()
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    jid_str
                        .ends_with("@s.whatsapp.net")
                        .then(|| jid_str.clone())
                });
            let lid_jid = cu
                .action
                .lid_jid
                .clone()
                .filter(|s| !s.is_empty())
                .or_else(|| jid_str.ends_with("@lid").then_some(jid_str));
            let contact_name = cu
                .action
                .full_name
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| {
                    cu.action
                        .first_name
                        .clone()
                        .filter(|s| !s.trim().is_empty())
                });
            let username = cu.action.username.clone().filter(|s| !s.trim().is_empty());

            let v = vault.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let _ = v.set_kv("contacts_appstate_backfilled_v1", "true");
                let _ = v.upsert_contact(
                    pn_jid.as_deref(),
                    lid_jid.as_deref(),
                    contact_name.as_deref(),
                    username.as_deref(),
                );
            })
            .await;
            ui_coalescer.schedule_contacts(vault.clone(), event_tx.clone());
        }
        Event::ContactUpdated(cu) => {
            let c = client.clone();
            let v = vault.clone();
            let tx = event_tx.clone();
            let jid = cu.jid.clone();
            tokio::spawn(async move {
                let _ = fetch_and_store_avatar(&c, &v, &tx, &jid).await;
            });
        }
        Event::ContactNumberChanged(cnc) => {
            let new_pn = cnc.new_jid.to_string();
            let new_lid = cnc.new_lid.as_ref().map(ToString::to_string);
            let v = vault.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let _ = v.upsert_contact(Some(&new_pn), new_lid.as_deref(), None, None);
            })
            .await;
            ui_coalescer.schedule_contacts(vault.clone(), event_tx.clone());
        }
        Event::PushNameUpdate(pu) => {
            let jid_s = pu.jid.to_string();
            let new_push = pu.new_push_name.clone();
            let v = vault.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let _ = v.upsert_contact(Some(&jid_s), None, None, Some(&new_push));
            })
            .await;
            ui_coalescer.schedule_contacts(vault.clone(), event_tx.clone());
        }
        Event::UserAboutUpdate(ua) => {
            let jid_s = ua.jid.to_string();
            let status = ua.status.clone();
            let v = vault.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let _ = v.set_peer_about(&jid_s, &status);
            })
            .await;
            ui_coalescer.schedule_contacts(vault.clone(), event_tx.clone());
        }
        Event::PictureUpdate(pic) => {
            let jid = pic.jid.clone();
            if pic.removed {
                let v = vault.clone();
                let js = jid.to_string();
                let _ = tokio::task::spawn_blocking(move || v.clear_avatar_for_jid(&js)).await;
                ui_coalescer.schedule(vault.clone(), event_tx.clone());
            } else {
                let c = client.clone();
                let v = vault.clone();
                let tx = event_tx.clone();
                tokio::spawn(async move {
                    let _ = fetch_and_store_avatar(&c, &v, &tx, &jid).await;
                });
            }
        }
        Event::GroupUpdate(gu) => {
            let c = client.clone();
            let v = vault.clone();
            let tx = event_tx.clone();
            let gid = gu.group_jid.clone();
            let coalescer = ui_coalescer.clone();
            tokio::spawn(async move {
                if let Ok(meta) = c.groups().get_metadata(&gid).await {
                    let p_count = meta.size.or(Some(meta.participants.len() as u32));
                    let v_inner = v.clone();
                    let gid_s = gid.to_string();
                    let subj = meta.subject;
                    let _ = tokio::task::spawn_blocking(move || {
                        v_inner.update_group_metadata(&gid_s, &subj, p_count)
                    })
                    .await;
                    coalescer.schedule_conversations(v, tx);
                }
            });
        }
        Event::PinUpdate(p) => {
            let js = p.jid.to_string();
            let pinned = p.action.pinned;
            let v = vault.clone();
            let _ = tokio::task::spawn_blocking(move || {
                v.set_conversation_flags(&js, pinned, None, None, None)
            })
            .await;
            ui_coalescer.schedule_conversations(vault.clone(), event_tx.clone());
        }
        Event::MuteUpdate(m) => {
            let js = m.jid.to_string();
            let muted = m.action.muted;
            let v = vault.clone();
            let _ = tokio::task::spawn_blocking(move || {
                v.set_conversation_flags(&js, None, muted, None, None)
            })
            .await;
            ui_coalescer.schedule_conversations(vault.clone(), event_tx.clone());
        }
        Event::ArchiveUpdate(a) => {
            let js = a.jid.to_string();
            let archived = a.action.archived;
            let v = vault.clone();
            let _ = tokio::task::spawn_blocking(move || {
                v.set_conversation_flags(&js, None, None, archived, None)
            })
            .await;
            ui_coalescer.schedule_conversations(vault.clone(), event_tx.clone());
        }
        Event::MarkChatAsReadUpdate(r) => {
            let js = r.jid.to_string();
            let read = r.action.read;
            let v = vault.clone();
            let _ = tokio::task::spawn_blocking(move || {
                v.set_conversation_flags(&js, None, None, None, read)
            })
            .await;
            ui_coalescer.schedule_conversations(vault.clone(), event_tx.clone());
        }
        Event::ClientOutdated(_) => {
            // Anti-Ban Tripwire #1: halt socket immediately rather than looping outdated handshakes!
            let reason = "WhatsApp server reported ClientOutdated (405). Socket halted in offline read-only quarantine to prevent account flags; please update the application.".to_string();
            metrics.record_anomaly("ClientOutdated(405)");
            client.disconnect().await;
            let _ = event_tx
                .send(DomainEvent::LifecycleChanged(
                    VaultLifecycleState::Quarantined { reason },
                ))
                .await;
        }
        Event::TemporaryBan(ban) => {
            // Anti-Ban Tripwire #2: halt immediately on TemporaryBan!
            let reason = format!(
                "WhatsApp reported temporary restriction ({}). Reconnects halted for {}m; local search and history remain available.",
                ban.code,
                ban.expire.num_minutes()
            );
            metrics.record_anomaly(format!("TemporaryBan({})", ban.code.code()));
            client.disconnect().await;
            let _ = event_tx
                .send(DomainEvent::LifecycleChanged(
                    VaultLifecycleState::Quarantined { reason },
                ))
                .await;
        }
        Event::ConnectFailure(fail) => {
            if !fail.reason.should_reconnect() {
                let reason = format!(
                    "Connection rejected by server ({:?}). Auto-reconnect paused to protect your account.",
                    fail.reason
                );
                metrics.record_anomaly(format!("ConnectFailure({:?})", fail.reason));
                client.disconnect().await;
                let _ = event_tx
                    .send(DomainEvent::LifecycleChanged(
                        VaultLifecycleState::OfflineReadOnly { reason },
                    ))
                    .await;
            }
        }
        Event::LoggedOut(lo) => {
            let reason = format!("Companion session unlinked ({:?}).", lo.reason);
            let _ = event_tx.send(DomainEvent::ToastMessage(reason)).await;
            let _ = event_tx
                .send(DomainEvent::LifecycleChanged(VaultLifecycleState::Unpaired))
                .await;
        }
        Event::Disconnected(_) => {
            let _ = event_tx
                .send(DomainEvent::LifecycleChanged(
                    VaultLifecycleState::OfflineReadOnly {
                        reason: "Network disconnected — browsing locally encrypted archive"
                            .to_string(),
                    },
                ))
                .await;
        }
        Event::Receipt(rcpt) => {
            let new_state = match rcpt.r#type {
                ReceiptType::Read | ReceiptType::ReadSelf | ReceiptType::Played => {
                    Some(DeliveryState::Read)
                }
                ReceiptType::Delivered => Some(DeliveryState::Delivered),
                ReceiptType::Sent | ReceiptType::Sender => Some(DeliveryState::Sent),
                _ => None,
            };
            if let Some(state) = new_state {
                let chat_jid = rcpt.source.chat.to_string();
                for msg_id in &rcpt.message_ids {
                    if let Ok(Some(cid)) =
                        vault.update_delivery_by_stanza(&chat_jid, msg_id, state.clone())
                    {
                        let _ = event_tx
                            .send(DomainEvent::MessagesUpdated {
                                conversation_id: cid,
                            })
                            .await;
                    }
                }
            }
        }
        Event::UndecryptableMessage(undec) => {
            let chat_jid = undec.info.source.chat.to_string();
            let kind = classify_conversation_kind(&undec.info.source.chat);
            let content = if undec.unavailable_type == UnavailableType::ViewOnce {
                MessageContent::ViewOnceCompanionStub {
                    media_label: "media".to_string(),
                }
            } else {
                MessageContent::Text {
                    body: "Waiting for this message. Keep your phone online to sync.".to_string(),
                    edited_at: None,
                    link_preview: None,
                }
            };
            let rec = InboundCommitRecord {
                chat_wire_jid: chat_jid,
                chat_alt_jid: None,
                chat_kind: kind,
                chat_title_hint: None,
                sender_wire_jid: undec.info.source.sender.to_string(),
                sender_alt_jid: undec
                    .info
                    .source
                    .sender_alt
                    .as_ref()
                    .map(ToString::to_string),
                sender_push_name: None,
                stanza_id: undec.info.id.clone(),
                is_from_me: undec.info.source.is_from_me,
                timestamp_ms: undec.info.timestamp.timestamp_millis(),
                delivery: DeliveryState::DecryptPending,
                content,
                quoted: None,
                raw_decrypted_proto: Vec::new(),
                defer_fts: true,
            };
            if let Ok(convs) = vault.commit_inbound_batch(&[rec]) {
                for cid in convs {
                    let _ = event_tx
                        .send(DomainEvent::MessagesUpdated {
                            conversation_id: cid,
                        })
                        .await;
                }
            }
        }
        Event::HistorySync(lazy_hs) => {
            metrics
                .history_chunks_staged
                .fetch_add(1, Ordering::Relaxed);
            let compressed = lazy_hs.compressed_bytes().clone();
            let sync_type = lazy_hs.sync_type();
            let chunk_order = lazy_hs.chunk_order();
            let progress = lazy_hs.progress();
            let lazy_clone = (**lazy_hs).clone();
            let vault_bg = vault.clone();
            let vault_after = vault.clone();
            let tx_bg = event_tx.clone();
            let metrics_bg = metrics.clone();
            let client_bg = client.clone();
            let media_sem_bg = media_sem.clone();
            let coord_bg = hydration_coord.clone();
            let coalescer_bg = ui_coalescer.clone();

            tokio::spawn(async move {
                let staged =
                    tokio::task::spawn_blocking(move || -> anyhow::Result<HistorySyncStats> {
                        let chunk_hash = vault_bg.stage_history_sync_chunk(
                            sync_type,
                            chunk_order,
                            progress,
                            &compressed,
                        )?;

                        if let Some(decoded) = lazy_clone.get() {
                            // 1. Ingest LID <-> phone number mappings first so split threads never form.
                            for m in &decoded.phone_number_to_lid_mappings {
                                let _ = vault_bg.upsert_contact(
                                    m.pn_jid.as_deref(),
                                    m.lid_jid.as_deref(),
                                    None,
                                    None,
                                );
                            }

                            // 2. Ingest address-book inline contacts (`full_name` / `first_name` / `username`).
                            for ic in &decoded.inline_contacts {
                                let cname = ic
                                    .full_name
                                    .as_deref()
                                    .filter(|s| !s.trim().is_empty())
                                    .or_else(|| {
                                        ic.first_name.as_deref().filter(|s| !s.trim().is_empty())
                                    });
                                let _ = vault_bg.upsert_contact(
                                    ic.pn_jid.as_deref(),
                                    ic.lid_jid.as_deref(),
                                    cname,
                                    ic.username.as_deref(),
                                );
                            }

                            // 3. Ingest pushnames table.
                            for pn in &decoded.pushnames {
                                let _ = vault_bg.upsert_contact(
                                    pn.id.as_deref(),
                                    None,
                                    None,
                                    pn.pushname.as_deref(),
                                );
                            }

                            let self_jid = vault_bg
                                .get_kv("account_pn")
                                .ok()
                                .flatten()
                                .or_else(|| vault_bg.get_kv("account_jid").ok().flatten())
                                .unwrap_or_else(|| "self".to_string());

                            let mut batch = Vec::new();
                            for conv in &decoded.conversations {
                                if conv.id.is_empty() {
                                    continue;
                                }
                                let kind = if conv.id.ends_with("@g.us") {
                                    ConversationKind::Group
                                } else if conv.id.ends_with("@newsletter") {
                                    ConversationKind::NewsletterChannel
                                } else if conv.id == "status@broadcast" {
                                    ConversationKind::StatusBroadcast
                                } else {
                                    ConversationKind::DirectMessage
                                };
                                let title_hint = conv
                                    .name
                                    .clone()
                                    .or_else(|| conv.display_name.clone())
                                    .filter(|s| !s.is_empty());
                                let alt_jid = conv
                                    .pn_jid
                                    .clone()
                                    .or_else(|| conv.lid_jid.clone())
                                    .filter(|s| !s.is_empty() && s != &conv.id);

                                let _ = vault_bg.ensure_conversation(
                                    &conv.id,
                                    alt_jid.as_deref(),
                                    kind,
                                    title_hint.as_deref(),
                                );
                                if kind == ConversationKind::Group
                                    && let Some(ref subj) = title_hint
                                {
                                    let _ = vault_bg.update_group_metadata(
                                        &conv.id,
                                        subj,
                                        (!conv.participant.is_empty())
                                            .then_some(conv.participant.len() as u32),
                                    );
                                }
                                if conv.pinned.unwrap_or(0) > 0 || conv.archived == Some(true) {
                                    let _ = vault_bg.set_conversation_flags(
                                        &conv.id,
                                        (conv.pinned.unwrap_or(0) > 0).then_some(true),
                                        None,
                                        conv.archived,
                                        None,
                                    );
                                }

                                for hs_msg in &conv.messages {
                                    let Some(wmi) = hs_msg.message.as_option() else {
                                        continue;
                                    };
                                    let Some(key) = wmi.key.as_option() else {
                                        continue;
                                    };
                                    let Some(stanza_id) = key.id.clone() else {
                                        continue;
                                    };
                                    let Some(inner_msg) = wmi.message.as_option() else {
                                        continue;
                                    };
                                    let from_me = key.from_me.unwrap_or(false);
                                    let explicit_sender =
                                        key.participant.clone().or_else(|| wmi.participant.clone());
                                    let sender_wire = if from_me {
                                        explicit_sender.unwrap_or_else(|| self_jid.clone())
                                    } else {
                                        explicit_sender.unwrap_or_else(|| conv.id.clone())
                                    };
                                    let ts_sec = wmi.message_timestamp.unwrap_or(0) as i64;
                                    let (content, quoted) = extract_wa_message_rich(
                                        inner_msg,
                                        &stanza_id,
                                        Some(&vault_bg),
                                    );
                                    batch.push(InboundCommitRecord {
                                        chat_wire_jid: conv.id.clone(),
                                        chat_alt_jid: alt_jid.clone(),
                                        chat_kind: kind,
                                        chat_title_hint: if kind == ConversationKind::DirectMessage
                                            && from_me
                                        {
                                            None
                                        } else {
                                            title_hint.clone()
                                        },
                                        sender_wire_jid: sender_wire,
                                        sender_alt_jid: None,
                                        sender_push_name: if from_me {
                                            None
                                        } else {
                                            wmi.push_name.clone()
                                        },
                                        stanza_id,
                                        is_from_me: from_me,
                                        timestamp_ms: ts_sec.saturating_mul(1000),
                                        delivery: DeliveryState::Read,
                                        content,
                                        quoted,
                                        raw_decrypted_proto: inner_msg.encode_to_vec(),
                                        defer_fts: true,
                                    });
                                }
                            }

                            for chunk in batch.chunks(500) {
                                let _ = vault_bg.commit_inbound_batch(chunk)?;
                                metrics_bg
                                    .messages_persisted
                                    .fetch_add(chunk.len() as u64, Ordering::Relaxed);
                            }
                        }

                        vault_bg.mark_history_chunk_ingested(&chunk_hash)?;
                        // Index deferred FTS5 rows incrementally so search comes online rapidly without stalling WAL.
                        while vault_bg.flush_pending_fts_batch(300)? > 0 {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        vault_bg.sync_stats()
                    })
                    .await;

                if let Ok(Ok(stats)) = staged {
                    let _ = tx_bg.send(DomainEvent::HistorySyncUpdated(stats)).await;
                    coalescer_bg.schedule_conversations(vault_after.clone(), tx_bg.clone());
                    trigger_live_hydration(
                        coord_bg,
                        client_bg,
                        vault_after,
                        tx_bg,
                        media_sem_bg,
                        coalescer_bg,
                    );
                }
            });
        }
        Event::IncomingCall(inc) => {
            metrics
                .call_signals_observed
                .fetch_add(1, Ordering::Relaxed);
            match &inc.action {
                CallAction::Offer {
                    call_id,
                    call_creator,
                    caller_pn,
                    is_video,
                    group_jid,
                    ..
                } => {
                    let caller_display = inc
                        .notify
                        .clone()
                        .or_else(|| caller_pn.as_ref().map(ToString::to_string))
                        .unwrap_or_else(|| inc.from.to_string());
                    let banner = ActiveCallBanner {
                        call_id: call_id.clone(),
                        peer_wire_jid: inc.from.to_string(),
                        creator_wire_jid: call_creator.to_string(),
                        caller_display: caller_display.clone(),
                        is_video: *is_video,
                        is_group: group_jid.is_some(),
                        started_at: inc.timestamp,
                    };
                    let _ = event_tx
                        .send(DomainEvent::CallBannerUpdated(Some(banner)))
                        .await;
                    let _ = event_tx
                        .send(DomainEvent::IncomingNotification {
                            conversation_id: ConversationId::new_v7(),
                            title: format!(
                                "Incoming {} call from {}",
                                if *is_video { "video" } else { "voice" },
                                caller_display
                            ),
                            body: "Answer on your phone or decline from desktop banner."
                                .to_string(),
                        })
                        .await;
                }
                CallAction::Terminate { .. } | CallAction::Reject { .. } => {
                    let _ = event_tx.send(DomainEvent::CallBannerUpdated(None)).await;
                }
                _ => {}
            }
        }
        Event::MissedCall(missed) => {
            metrics
                .call_signals_observed
                .fetch_add(1, Ordering::Relaxed);
            let _ = event_tx.send(DomainEvent::CallBannerUpdated(None)).await;
            record_call_timeline_event(
                vault,
                event_tx,
                &missed.from.to_string(),
                &missed.call_id,
                CallOutcome::Missed,
                missed.timestamp.timestamp_millis(),
            )
            .await;
        }
        Event::CallEndedElsewhere(ended) => {
            metrics
                .call_signals_observed
                .fetch_add(1, Ordering::Relaxed);
            let _ = event_tx.send(DomainEvent::CallBannerUpdated(None)).await;
            let outcome = match ended.outcome {
                ElsewhereOutcome::Accepted => CallOutcome::AcceptedElsewhere,
                _ => CallOutcome::DeclinedElsewhere,
            };
            record_call_timeline_event(
                vault,
                event_tx,
                &ended.from.to_string(),
                &ended.call_id,
                outcome,
                ended.timestamp.timestamp_millis(),
            )
            .await;
        }
        Event::ChatPresence(cp) => {
            let chat_str = cp.source.chat.to_string();
            let kind = classify_conversation_kind(&cp.source.chat);
            if let Ok(cid) = vault.ensure_conversation(&chat_str, None, kind, None) {
                let label = if cp.state == ChatPresence::Composing {
                    Some("typing…".to_string())
                } else {
                    None
                };
                let _ = event_tx
                    .send(DomainEvent::TypingUpdated {
                        conversation_id: cid,
                        peer_label: label,
                    })
                    .await;
            }
        }
        _ => {}
    }
}

async fn record_call_timeline_event(
    vault: &VaultStore,
    event_tx: &async_channel::Sender<DomainEvent>,
    peer_jid: &str,
    call_id: &str,
    outcome: CallOutcome,
    timestamp_ms: i64,
) {
    let rec = InboundCommitRecord {
        chat_wire_jid: peer_jid.to_string(),
        chat_alt_jid: None,
        chat_kind: if peer_jid.ends_with("@g.us") {
            ConversationKind::Group
        } else {
            ConversationKind::DirectMessage
        },
        chat_title_hint: None,
        sender_wire_jid: peer_jid.to_string(),
        sender_alt_jid: None,
        sender_push_name: None,
        stanza_id: format!("call-{call_id}-{outcome:?}"),
        is_from_me: false,
        timestamp_ms,
        delivery: DeliveryState::Delivered,
        content: MessageContent::CallTimelineItem {
            call_id: call_id.to_string(),
            is_video: false,
            outcome,
            duration_secs: None,
        },
        quoted: None,
        raw_decrypted_proto: Vec::new(),
        defer_fts: true,
    };
    if let Ok(touched) = vault.commit_inbound_batch(&[rec]) {
        if let Ok(convs) = vault.list_conversations() {
            let _ = event_tx
                .send(DomainEvent::ConversationsUpdated(convs))
                .await;
        }
        for cid in touched {
            let _ = event_tx
                .send(DomainEvent::MessagesUpdated {
                    conversation_id: cid,
                })
                .await;
        }
    }
}

#[async_trait]
impl ProtocolEnginePort for LiveWhatsAppAdapter {
    async fn submit(&self, cmd: EngineCommand) -> Result<()> {
        match cmd {
            EngineCommand::StartSession {
                phone_number_for_code,
                custom_pair_code,
            } => {
                self.start_live_session(phone_number_for_code, custom_pair_code)
                    .await?;
            }
            EngineCommand::OpenOrCreateDirectChat {
                wire_jid,
                display_hint,
            } => {
                let v = self.vault.clone();
                let jid_s = wire_jid.clone();
                let hint = display_hint.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    v.ensure_conversation(
                        &jid_s,
                        None,
                        ConversationKind::DirectMessage,
                        hint.as_deref(),
                    )
                })
                .await??;

                if let Ok(convs) = self.vault.list_conversations() {
                    let _ = self
                        .event_tx
                        .send(DomainEvent::ConversationsUpdated(convs))
                        .await;
                }
                if let Some(client) = self.active_client.lock().await.clone()
                    && let Ok(parsed_jid) = wire_jid.parse::<Jid>()
                {
                    let v2 = self.vault.clone();
                    let tx2 = self.event_tx.clone();
                    tokio::spawn(async move {
                        let _ = fetch_and_store_avatar(&client, &v2, &tx2, &parsed_jid).await;
                    });
                }
            }
            EngineCommand::DownloadMessageMedia {
                conversation_id,
                stanza_id,
            } => {
                let Some(client) = self.active_client.lock().await.clone() else {
                    let _ = self
                        .event_tx
                        .send(DomainEvent::ToastMessage(
                            "Connect companion session to download full-resolution media"
                                .to_string(),
                        ))
                        .await;
                    return Ok(());
                };
                let v = self.vault.clone();
                let sid = stanza_id.clone();
                let raw_opt = tokio::task::spawn_blocking(move || {
                    v.load_raw_message_proto(conversation_id, &sid)
                })
                .await??;
                let Some(raw_proto) = raw_opt else {
                    let _ = self
                        .event_tx
                        .send(DomainEvent::ToastMessage(
                            "Encrypted media metadata unavailable for this message".to_string(),
                        ))
                        .await;
                    return Ok(());
                };
                let wa_msg = wa::Message::decode_from_slice(&raw_proto)
                    .context("decoding stored media protobuf")?;

                let tx = self.event_tx.clone();
                let vault_dl = self.vault.clone();
                let sem = self.media_sem.clone();
                tokio::spawn(async move {
                    let Ok(_permit) = sem.acquire_owned().await else {
                        return;
                    };
                    match download_wa_media_bytes(&client, &wa_msg).await {
                        Ok(Some(bytes)) if !bytes.is_empty() => {
                            let full_key = format!("media:{stanza_id}");
                            let fk = full_key.clone();
                            let sid_inner = stanza_id.clone();
                            let v_save = vault_dl.clone();
                            let res = tokio::task::spawn_blocking(move || -> Result<bool> {
                                v_save.store_encrypted_media(&fk, &bytes)?;
                                v_save.update_message_media_keys(
                                    conversation_id,
                                    &sid_inner,
                                    Some(&fk),
                                    None,
                                    None,
                                    None,
                                )
                            })
                            .await;
                            if matches!(res, Ok(Ok(_))) {
                                let _ = tx
                                    .send(DomainEvent::MediaUpdated {
                                        conversation_id,
                                        stanza_id,
                                    })
                                    .await;
                            }
                        }
                        Ok(_) => {
                            let _ = tx
                                .send(DomainEvent::ToastMessage(
                                    "No downloadable media payload attached".to_string(),
                                ))
                                .await;
                        }
                        Err(e) => {
                            let _ = tx
                                .send(DomainEvent::ToastMessage(format!(
                                    "Media download failed: {e}"
                                )))
                                .await;
                        }
                    }
                });
            }
            EngineCommand::RefreshContactsAndAvatars => {
                spawn_local_inline_media_backfill(self.vault.clone(), self.event_tx.clone());
                self.ui_coalescer
                    .schedule(self.vault.clone(), self.event_tx.clone());
                if let Some(client) = self.active_client.lock().await.clone() {
                    trigger_live_hydration(
                        self.hydration_coord.clone(),
                        client,
                        self.vault.clone(),
                        self.event_tx.clone(),
                        self.media_sem.clone(),
                        self.ui_coalescer.clone(),
                    );
                }
            }
            EngineCommand::SendText {
                conversation_id,
                local_id,
                text,
                reply_to_stanza_id,
            } => {
                let target_str = self.vault.conversation_primary_jid(conversation_id)?;
                let target_jid: Jid = target_str.parse()?;
                self.rate_guard.acquire_human_paced().await;

                let maybe_client = self.active_client.lock().await.clone();
                let Some(client) = maybe_client else {
                    self.vault.update_outbound_sent(
                        &local_id,
                        &local_id,
                        DeliveryState::Failed("Not connected".to_string()),
                    )?;
                    let _ = self
                        .event_tx
                        .send(DomainEvent::MessagesUpdated { conversation_id })
                        .await;
                    return Ok(());
                };

                let proto_msg = if let Some(stanza_id) = reply_to_stanza_id {
                    wa::Message::text_with_context(
                        text,
                        wa::ContextInfo {
                            stanza_id: Some(stanza_id),
                            ..Default::default()
                        },
                    )
                } else {
                    wa::Message::text(text)
                };

                match client.send_message(target_jid, proto_msg).await {
                    Ok(sent) => {
                        self.vault.update_outbound_sent(
                            &local_id,
                            &sent.message_id,
                            DeliveryState::Sent,
                        )?;
                    }
                    Err(e) => {
                        self.vault.update_outbound_sent(
                            &local_id,
                            &local_id,
                            DeliveryState::Failed(e.to_string()),
                        )?;
                    }
                }
                let _ = self
                    .event_tx
                    .send(DomainEvent::MessagesUpdated { conversation_id })
                    .await;
                if let Ok(convs) = self.vault.list_conversations() {
                    let _ = self
                        .event_tx
                        .send(DomainEvent::ConversationsUpdated(convs))
                        .await;
                }
            }
            EngineCommand::SendAttachment {
                conversation_id,
                local_id,
                file_path,
                mime_type,
                media_kind,
                caption,
            } => {
                let target_str = self.vault.conversation_primary_jid(conversation_id)?;
                let target_jid: Jid = target_str.parse()?;
                let bytes = tokio::fs::read(&file_path).await?;
                let file_name = file_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(str::to_string);

                let _ = self.vault.store_encrypted_media(&local_id, &bytes);
                self.rate_guard.acquire_human_paced().await;

                let Some(client) = self.active_client.lock().await.clone() else {
                    self.vault.update_outbound_sent(
                        &local_id,
                        &local_id,
                        DeliveryState::Failed("Not connected".to_string()),
                    )?;
                    return Ok(());
                };

                let wa_media_type = match media_kind {
                    MediaKind::Image => MediaType::Image,
                    MediaKind::Video => MediaType::Video,
                    MediaKind::VoiceNote | MediaKind::Audio => MediaType::Audio,
                    MediaKind::Sticker => MediaType::Sticker,
                    MediaKind::Document => MediaType::Document,
                };

                let uploaded = client
                    .upload(bytes.clone(), wa_media_type, UploadOptions::new())
                    .await?;

                let proto_msg = match media_kind {
                    MediaKind::Image => wa::Message {
                        image_message: MessageField::some(wa::message::ImageMessage {
                            url: Some(uploaded.url),
                            direct_path: Some(uploaded.direct_path),
                            media_key: Some(uploaded.media_key.to_vec()),
                            file_sha256: Some(uploaded.file_sha256.to_vec()),
                            file_enc_sha256: Some(uploaded.file_enc_sha256.to_vec()),
                            file_length: Some(uploaded.file_length),
                            mimetype: Some(mime_type),
                            caption,
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    MediaKind::Video => wa::Message {
                        video_message: MessageField::some(wa::message::VideoMessage {
                            url: Some(uploaded.url),
                            direct_path: Some(uploaded.direct_path),
                            media_key: Some(uploaded.media_key.to_vec()),
                            file_sha256: Some(uploaded.file_sha256.to_vec()),
                            file_enc_sha256: Some(uploaded.file_enc_sha256.to_vec()),
                            file_length: Some(uploaded.file_length),
                            mimetype: Some(mime_type),
                            caption,
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    MediaKind::VoiceNote | MediaKind::Audio => wa::Message {
                        audio_message: MessageField::some(wa::message::AudioMessage {
                            url: Some(uploaded.url),
                            direct_path: Some(uploaded.direct_path),
                            media_key: Some(uploaded.media_key.to_vec()),
                            file_sha256: Some(uploaded.file_sha256.to_vec()),
                            file_enc_sha256: Some(uploaded.file_enc_sha256.to_vec()),
                            file_length: Some(uploaded.file_length),
                            mimetype: Some(mime_type),
                            ptt: Some(media_kind == MediaKind::VoiceNote),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    _ => wa::Message {
                        document_message: MessageField::some(wa::message::DocumentMessage {
                            url: Some(uploaded.url),
                            direct_path: Some(uploaded.direct_path),
                            media_key: Some(uploaded.media_key.to_vec()),
                            file_sha256: Some(uploaded.file_sha256.to_vec()),
                            file_enc_sha256: Some(uploaded.file_enc_sha256.to_vec()),
                            file_length: Some(uploaded.file_length),
                            mimetype: Some(mime_type),
                            file_name,
                            caption,
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                };

                match client.send_message(target_jid, proto_msg).await {
                    Ok(sent) => {
                        self.vault.update_outbound_sent(
                            &local_id,
                            &sent.message_id,
                            DeliveryState::Sent,
                        )?;
                    }
                    Err(e) => {
                        self.vault.update_outbound_sent(
                            &local_id,
                            &local_id,
                            DeliveryState::Failed(e.to_string()),
                        )?;
                    }
                }
                let _ = self
                    .event_tx
                    .send(DomainEvent::MessagesUpdated { conversation_id })
                    .await;
            }
            EngineCommand::SendReaction {
                conversation_id,
                target_stanza_id,
                emoji,
            } => {
                let self_peer = self
                    .vault
                    .resolve_or_merge_peer("self", None, Some("You"))?;
                self.vault.upsert_reaction(
                    conversation_id,
                    &target_stanza_id,
                    self_peer,
                    &emoji,
                    true,
                )?;
                let _ = self
                    .event_tx
                    .send(DomainEvent::MessagesUpdated { conversation_id })
                    .await;

                if let Some(client) = self.active_client.lock().await.clone() {
                    let target_str = self.vault.conversation_primary_jid(conversation_id)?;
                    let target_jid: Jid = target_str.parse()?;
                    self.rate_guard.acquire_human_paced().await;
                    let key = wa::MessageKey {
                        remote_jid: Some(target_str),
                        id: Some(target_stanza_id),
                        ..Default::default()
                    };
                    let _ = client.send_reaction(target_jid, key, &emoji).await;
                }
            }
            EngineCommand::EditMessage {
                conversation_id,
                target_stanza_id,
                new_text,
            } => {
                self.vault
                    .apply_message_edit(conversation_id, &target_stanza_id, &new_text)?;
                let _ = self
                    .event_tx
                    .send(DomainEvent::MessagesUpdated { conversation_id })
                    .await;
                if let Some(client) = self.active_client.lock().await.clone() {
                    let target_str = self.vault.conversation_primary_jid(conversation_id)?;
                    let target_jid: Jid = target_str.parse()?;
                    self.rate_guard.acquire_human_paced().await;
                    let _ = client
                        .edit_message(target_jid, target_stanza_id, wa::Message::text(new_text))
                        .await;
                }
            }
            EngineCommand::RevokeMessage {
                conversation_id,
                target_stanza_id,
            } => {
                self.vault
                    .apply_message_revoke(conversation_id, &target_stanza_id)?;
                let _ = self
                    .event_tx
                    .send(DomainEvent::MessagesUpdated { conversation_id })
                    .await;
                if let Some(client) = self.active_client.lock().await.clone() {
                    let target_str = self.vault.conversation_primary_jid(conversation_id)?;
                    let target_jid: Jid = target_str.parse()?;
                    self.rate_guard.acquire_human_paced().await;
                    let _ = client
                        .revoke_message(target_jid, target_stanza_id, RevokeType::Sender)
                        .await;
                }
            }
            EngineCommand::DeclineCall {
                call_id,
                peer_wire_jid,
                creator_wire_jid,
            } => {
                let _ = self
                    .event_tx
                    .send(DomainEvent::CallBannerUpdated(None))
                    .await;
                if let Some(client) = self.active_client.lock().await.clone()
                    && let (Ok(peer), Ok(creator)) = (
                        peer_wire_jid.parse::<Jid>(),
                        creator_wire_jid.parse::<Jid>(),
                    )
                {
                    let _ = client.voip().reject_call(&call_id, &peer, &creator).await;
                }
                record_call_timeline_event(
                    &self.vault,
                    &self.event_tx,
                    &peer_wire_jid,
                    &call_id,
                    CallOutcome::DeclinedOnDesktop,
                    Utc::now().timestamp_millis(),
                )
                .await;
            }
            EngineCommand::CheckSocketAfterSleep => {
                if let Some(client) = self.active_client.lock().await.clone()
                    && !client.is_connected()
                {
                    client.reconnect().await;
                }
            }
            EngineCommand::Disconnect => {
                if let Some(client) = self.active_client.lock().await.take() {
                    client.disconnect().await;
                }
                let _ = self
                    .event_tx
                    .send(DomainEvent::LifecycleChanged(
                        VaultLifecycleState::OfflineReadOnly {
                            reason: "Disconnected by user — reading encrypted local archive"
                                .to_string(),
                        },
                    ))
                    .await;
            }
            EngineCommand::Logout => {
                if let Some(client) = self.active_client.lock().await.take() {
                    client.logout().await;
                }
                let _ = self
                    .event_tx
                    .send(DomainEvent::LifecycleChanged(VaultLifecycleState::Unpaired))
                    .await;
            }
        }
        Ok(())
    }

    fn diagnostics(&self) -> DiagnosticCounterSnapshot {
        DiagnosticCounterSnapshot {
            messages_persisted: self.metrics.messages_persisted.load(Ordering::Relaxed),
            retry_receipts_quarantined: self.quarantine.quarantined_total(),
            history_chunks_staged: self.metrics.history_chunks_staged.load(Ordering::Relaxed),
            outbound_commands_paced: self.rate_guard.paced_count(),
            call_signals_observed: self.metrics.call_signals_observed.load(Ordering::Relaxed),
            circuit_breaker_trips: self.metrics.circuit_breaker_trips.load(Ordering::Relaxed),
            last_protocol_anomaly: self
                .metrics
                .last_anomaly
                .lock()
                .expect("anomaly lock")
                .clone(),
        }
    }
}

/// Encodes raw `width * height * 4` RGBA pixels into a valid standard PNG image using
/// zero external image crates (stored DEFLATE blocks + Adler-32 + IEEE CRC-32).
fn encode_rgba_png(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
    fn crc32(tag: &[u8], data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in tag.iter().chain(data.iter()) {
            crc ^= u32::from(b);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
    }

    fn write_chunk(out: &mut Vec<u8>, tag: &[u8; 4], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(tag);
        out.extend_from_slice(data);
        out.extend_from_slice(&crc32(tag, data).to_be_bytes());
    }

    let row_bytes = (width as usize) * 4;
    let mut scanlines = Vec::with_capacity((row_bytes + 1) * (height as usize));
    for y in 0..(height as usize) {
        scanlines.push(0u8); // Filter type 0 (None)
        let start = y * row_bytes;
        scanlines.extend_from_slice(&rgba[start..start + row_bytes]);
    }

    let mut zlib = Vec::with_capacity(scanlines.len() + 64);
    zlib.extend_from_slice(&[0x78, 0x01]); // zlib header (no compression / low)
    let chunks: Vec<&[u8]> = if scanlines.is_empty() {
        vec![&[]]
    } else {
        scanlines.chunks(65_535).collect()
    };
    for (idx, block) in chunks.iter().enumerate() {
        let bfinal = u8::from(idx + 1 == chunks.len());
        zlib.push(bfinal);
        let len = block.len() as u16;
        zlib.extend_from_slice(&len.to_le_bytes());
        zlib.extend_from_slice(&(!len).to_le_bytes());
        zlib.extend_from_slice(block);
    }

    // Adler-32 checksum over uncompressed scanlines
    let (mut s1, mut s2) = (1u32, 0u32);
    for &b in &scanlines {
        s1 = (s1 + u32::from(b)) % 65_521;
        s2 = (s2 + s1) % 65_521;
    }
    zlib.extend_from_slice(&((s2 << 16) | s1).to_be_bytes());

    let mut out = Vec::with_capacity(zlib.len() + 64);
    out.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]); // PNG magic
    let mut ihdr = [0u8; 13];
    ihdr[0..4].copy_from_slice(&width.to_be_bytes());
    ihdr[4..8].copy_from_slice(&height.to_be_bytes());
    ihdr[8] = 8; // 8-bit depth
    ihdr[9] = 6; // RGBA color type
    write_chunk(&mut out, b"IHDR", &ihdr);
    write_chunk(&mut out, b"IDAT", &zlib);
    write_chunk(&mut out, b"IEND", &[]);
    out
}

fn synth_avatar_png(c1: [u8; 3], c2: [u8; 3]) -> Vec<u8> {
    let (w, h) = (64u32, 64u32);
    let mut rgba = vec![0u8; (w * h * 4) as usize];
    for y in 0..h {
        for x in 0..w {
            let tx = x as f32 / (w - 1) as f32;
            let ty = y as f32 / (h - 1) as f32;
            let t = (tx * 0.55 + ty * 0.45).clamp(0.0, 1.0);
            let dx = x as f32 - 31.5;
            let dy = y as f32 - 31.5;
            let dist = (dx * dx + dy * dy).sqrt();
            let ring = (dist > 22.0 && dist < 25.0) as u8 as f32 * 0.28;
            let idx = ((y * w + x) * 4) as usize;
            for ch in 0..3 {
                let base = c1[ch] as f32 * (1.0 - t) + c2[ch] as f32 * t;
                rgba[idx + ch] = (base + ring * 255.0).clamp(0.0, 255.0) as u8;
            }
            rgba[idx + 3] = 255;
        }
    }
    encode_rgba_png(w, h, &rgba)
}

fn synth_landscape_photo_png(w: u32, h: u32) -> Vec<u8> {
    let mut rgba = vec![0u8; (w * h * 4) as usize];
    for y in 0..h {
        let fy = y as f32 / h as f32;
        for x in 0..w {
            let fx = x as f32 / w as f32;
            // Dusk sky gradient
            let mut r = (32.0 + fy * 185.0) as u8;
            let mut g = (48.0 + fy * 105.0) as u8;
            let mut b = (112.0 + (1.0 - fy) * 90.0) as u8;

            // Sun disc
            let sdx = fx - 0.72;
            let sdy = (fy - 0.34) * (h as f32 / w as f32);
            if sdx * sdx + sdy * sdy < 0.0085 {
                r = 255;
                g = 222;
                b = 132;
            }

            // Layered mountain ridges
            let ridge1 = 0.56 + 0.11 * (fx * 7.5).sin() + 0.05 * (fx * 17.0).cos();
            let ridge2 = 0.68 + 0.09 * (fx * 5.2 + 1.4).sin() + 0.04 * (fx * 13.0).sin();
            if fy > ridge2 {
                r = 22;
                g = 34;
                b = 56;
            } else if fy > ridge1 {
                r = 44;
                g = 62;
                b = 96;
            }

            let idx = ((y * w + x) * 4) as usize;
            rgba[idx] = r;
            rgba[idx + 1] = g;
            rgba[idx + 2] = b;
            rgba[idx + 3] = 255;
        }
    }
    encode_rgba_png(w, h, &rgba)
}

fn synth_sticker_png() -> Vec<u8> {
    let (w, h) = (144u32, 144u32);
    let mut rgba = vec![0u8; (w * h * 4) as usize];
    for y in 0..h {
        for x in 0..w {
            let dx = x as f32 - 71.5;
            let dy = y as f32 - 71.5;
            let dist = (dx * dx + dy * dy).sqrt();
            let idx = ((y * w + x) * 4) as usize;
            if dist <= 62.0 {
                let edge = dist > 56.0;
                rgba[idx] = if edge { 255 } else { 46 };
                rgba[idx + 1] = if edge { 255 } else { 194 };
                rgba[idx + 2] = if edge { 255 } else { 126 };
                rgba[idx + 3] = 255;
                // Friendly geometric eyes & smile
                let le = ((dx + 20.0).powi(2) + (dy + 12.0).powi(2)).sqrt() < 7.0;
                let re = ((dx - 20.0).powi(2) + (dy + 12.0).powi(2)).sqrt() < 7.0;
                let smile = dy > 4.0 && (dist - 28.0).abs() < 4.2 && dx.abs() < 26.0;
                if le || re || smile {
                    rgba[idx] = 20;
                    rgba[idx + 1] = 36;
                    rgba[idx + 2] = 44;
                }
            }
        }
    }
    encode_rgba_png(w, h, &rgba)
}

/// Deterministic zero-account offline companion engine (`whatsnative --mock`) allowing
/// contributors and users to test pairing, encrypted FTS5 search, BiDi/RTL/CJK shaping,
/// `@lid` merges, contacts, avatars, inline photos, waveforms, link previews, View-Once
/// privacy stubs, and incoming-call banners without risking a live phone number.
pub struct MockCompanionAdapter {
    vault: VaultStore,
    event_tx: async_channel::Sender<DomainEvent>,
    metrics: Arc<AdapterMetrics>,
}

impl MockCompanionAdapter {
    pub fn new(vault: VaultStore, event_tx: async_channel::Sender<DomainEvent>) -> Self {
        Self {
            vault,
            event_tx,
            metrics: Arc::new(AdapterMetrics::default()),
        }
    }

    pub fn seed_fixture_archive(&self) -> Result<()> {
        if !self.vault.list_conversations()?.is_empty() {
            return Ok(());
        }

        // 1. Seed address-book contacts + about statuses + vibrant encrypted avatars!
        let contacts_seed = [
            (
                "14155550101@s.whatsapp.net",
                Some("8800112233@lid"),
                "Linus Torvalds",
                "Linus",
                "Maintainer · Kernel & Git",
                [28, 113, 216],
                [53, 132, 228],
            ),
            (
                "14155550188@s.whatsapp.net",
                Some("8800112288@lid"),
                "Amira Hassan",
                "Amira",
                "Wayland color management & HDR",
                [192, 97, 203],
                [237, 51, 59],
            ),
            (
                "14155550199@s.whatsapp.net",
                Some("8800112299@lid"),
                "Kenji Takahashi",
                "Kenji",
                "PipeWire low-latency audio graph",
                [46, 194, 126],
                [38, 162, 105],
            ),
            (
                "14155550177@s.whatsapp.net",
                Some("8800112277@lid"),
                "Dr. Barbara Liskov",
                "Barbara",
                "Distributed systems & consensus",
                [230, 97, 0],
                [245, 194, 17],
            ),
            (
                "14155550144@s.whatsapp.net",
                None,
                "Radia Perlman",
                "Radia",
                "Spanning trees & zero-config routing",
                [129, 61, 156],
                [53, 132, 228],
            ),
            (
                "14155550155@s.whatsapp.net",
                None,
                "Alan Cox",
                "Alan",
                "TTY subsystem & retro computing",
                [51, 209, 122],
                [28, 113, 216],
            ),
        ];

        for (pn, lid, full_name, push, about, c1, c2) in contacts_seed {
            let _ = self
                .vault
                .upsert_contact(Some(pn), lid, Some(full_name), Some(push))?;
            let _ = self.vault.set_peer_about(pn, about);
            let avatar_png = synth_avatar_png(c1, c2);
            let _ = self.vault.store_avatar_for_jid(pn, &avatar_png);
        }

        // Seed encrypted group & channel avatars + media blobs
        let _ = self.vault.store_avatar_for_jid(
            "1203630445566@g.us",
            &synth_avatar_png([38, 162, 105], [28, 113, 216]),
        );
        let _ = self.vault.store_avatar_for_jid(
            "120363999888@newsletter",
            &synth_avatar_png([245, 194, 17], [224, 27, 36]),
        );

        let photo_png = synth_landscape_photo_png(480, 280);
        let photo_len = photo_png.len() as u64;
        self.vault
            .store_encrypted_media("media:MOCK-PHOTO-1", &photo_png)?;

        let sticker_png = synth_sticker_png();
        let sticker_len = sticker_png.len() as u64;
        self.vault
            .store_encrypted_media("media:MOCK-STICKER-1", &sticker_png)?;

        let lp_thumb = synth_landscape_photo_png(240, 135);
        self.vault
            .store_encrypted_media("thumb:lp-MOCK-LINK-1", &lp_thumb)?;

        let waveform_bars: Vec<u8> = (0..48)
            .map(|i| {
                let f = i as f32 * 0.37;
                ((f.sin().abs() * 0.65 + (f * 2.3).cos().abs() * 0.35) * 92.0 + 8.0) as u8
            })
            .collect();

        let base_ts = Utc::now().timestamp_millis() - 3_600_000;
        let mut records = vec![
            InboundCommitRecord {
                chat_wire_jid: "14155550101@s.whatsapp.net".into(),
                chat_alt_jid: Some("8800112233@lid".into()),
                chat_kind: ConversationKind::DirectMessage,
                chat_title_hint: Some("Linus Torvalds".into()),
                sender_wire_jid: "14155550101@s.whatsapp.net".into(),
                sender_alt_jid: Some("8800112233@lid".into()),
                sender_push_name: Some("Linus".into()),
                stanza_id: "MOCK-1".into(),
                is_from_me: false,
                timestamp_ms: base_ts,
                delivery: DeliveryState::Read,
                content: MessageContent::Text {
                    body: "Welcome to whatsnative (--mock offline mode)! Zero WebView, native GTK4 + libadwaita + SQLCipher FTS5.".into(),
                    edited_at: None,
                    link_preview: None,
                },
                quoted: None,
                raw_decrypted_proto: b"mock-proto-1".to_vec(),
                defer_fts: false,
            },
            InboundCommitRecord {
                chat_wire_jid: "14155550101@s.whatsapp.net".into(),
                chat_alt_jid: Some("8800112233@lid".into()),
                chat_kind: ConversationKind::DirectMessage,
                chat_title_hint: Some("Linus Torvalds".into()),
                sender_wire_jid: "14155550101@s.whatsapp.net".into(),
                sender_alt_jid: Some("8800112233@lid".into()),
                sender_push_name: Some("Linus".into()),
                stanza_id: "MOCK-PHOTO-1".into(),
                is_from_me: false,
                timestamp_ms: base_ts + 15_000,
                delivery: DeliveryState::Read,
                content: MessageContent::Media {
                    media_kind: MediaKind::Image,
                    caption: Some(" Dusk over the Pacific Northwest — rendered via native gdk::Texture + AEAD cache (click to open full-size lightbox!).".into()),
                    mime_type: "image/png".into(),
                    file_name: Some("pnw-dusk.png".into()),
                    byte_len: photo_len,
                    dimensions: Some((480, 280)),
                    cache_key: Some("media:MOCK-PHOTO-1".into()),
                    thumb_cache_key: Some("media:MOCK-PHOTO-1".into()),
                    duration_secs: None,
                    waveform: None,
                },
                quoted: None,
                raw_decrypted_proto: Vec::new(),
                defer_fts: false,
            },
            InboundCommitRecord {
                chat_wire_jid: "14155550101@s.whatsapp.net".into(),
                chat_alt_jid: Some("8800112233@lid".into()),
                chat_kind: ConversationKind::DirectMessage,
                chat_title_hint: Some("Linus Torvalds".into()),
                sender_wire_jid: "14155550101@s.whatsapp.net".into(),
                sender_alt_jid: Some("8800112233@lid".into()),
                sender_push_name: Some("Linus".into()),
                stanza_id: "MOCK-VOICE-1".into(),
                is_from_me: false,
                timestamp_ms: base_ts + 22_000,
                delivery: DeliveryState::Read,
                content: MessageContent::Media {
                    media_kind: MediaKind::VoiceNote,
                    caption: None,
                    mime_type: "audio/ogg; codecs=opus".into(),
                    file_name: None,
                    byte_len: 38_400,
                    dimensions: None,
                    cache_key: None,
                    thumb_cache_key: None,
                    duration_secs: Some(19),
                    waveform: Some(waveform_bars),
                },
                quoted: None,
                raw_decrypted_proto: Vec::new(),
                defer_fts: false,
            },
            InboundCommitRecord {
                chat_wire_jid: "14155550101@s.whatsapp.net".into(),
                chat_alt_jid: Some("8800112233@lid".into()),
                chat_kind: ConversationKind::DirectMessage,
                chat_title_hint: Some("Linus Torvalds".into()),
                sender_wire_jid: "14155550101@s.whatsapp.net".into(),
                sender_alt_jid: Some("8800112233@lid".into()),
                sender_push_name: Some("Linus".into()),
                stanza_id: "MOCK-LINK-1".into(),
                is_from_me: false,
                timestamp_ms: base_ts + 26_000,
                delivery: DeliveryState::Read,
                content: MessageContent::Text {
                    body: "Check out the Wayland fractional-scaling & DMA-BUF release notes: https://wayland.freedesktop.org".into(),
                    edited_at: None,
                    link_preview: Some(LinkPreviewCard {
                        url: "https://wayland.freedesktop.org".into(),
                        title: Some("Wayland Compositor Protocol & Linux Graphics".into()),
                        description: Some("Zero-copy DMA-BUF presentation, tearing control, and color management protocols.".into()),
                        thumb_cache_key: Some("thumb:lp-MOCK-LINK-1".into()),
                    }),
                },
                quoted: None,
                raw_decrypted_proto: Vec::new(),
                defer_fts: false,
            },
            InboundCommitRecord {
                chat_wire_jid: "8800112233@lid".into(),
                chat_alt_jid: Some("14155550101@s.whatsapp.net".into()),
                chat_kind: ConversationKind::DirectMessage,
                chat_title_hint: Some("Linus Torvalds".into()),
                sender_wire_jid: "8800112233@lid".into(),
                sender_alt_jid: Some("14155550101@s.whatsapp.net".into()),
                sender_push_name: Some("Linus".into()),
                stanza_id: "MOCK-2".into(),
                is_from_me: false,
                timestamp_ms: base_ts + 30_000,
                delivery: DeliveryState::Read,
                content: MessageContent::ViewOnceCompanionStub {
                    media_label: "photo".into(),
                },
                quoted: None,
                raw_decrypted_proto: Vec::new(),
                defer_fts: false,
            },
            InboundCommitRecord {
                chat_wire_jid: "1203630445566@g.us".into(),
                chat_alt_jid: None,
                chat_kind: ConversationKind::Group,
                chat_title_hint: Some("Linux Desktop Wayland WG".into()),
                sender_wire_jid: "14155550188@s.whatsapp.net".into(),
                sender_alt_jid: None,
                sender_push_name: Some("Amira".into()),
                stanza_id: "MOCK-RTL-1".into(),
                is_from_me: false,
                timestamp_ms: base_ts + 90_000,
                delivery: DeliveryState::Read,
                content: MessageContent::Text {
                    body: "مرحباً! Bidirectional RTL shaping, 日本語 IME, हिन्दी, and emoji 👨‍👩‍👧‍👦 render natively via Pango/HarfBuzz.".into(),
                    edited_at: None,
                    link_preview: None,
                },
                quoted: None,
                raw_decrypted_proto: b"mock-rtl".to_vec(),
                defer_fts: false,
            },
            InboundCommitRecord {
                chat_wire_jid: "1203630445566@g.us".into(),
                chat_alt_jid: None,
                chat_kind: ConversationKind::Group,
                chat_title_hint: Some("Linux Desktop Wayland WG".into()),
                sender_wire_jid: "14155550188@s.whatsapp.net".into(),
                sender_alt_jid: None,
                sender_push_name: Some("Amira".into()),
                stanza_id: "MOCK-STICKER-1".into(),
                is_from_me: false,
                timestamp_ms: base_ts + 105_000,
                delivery: DeliveryState::Read,
                content: MessageContent::Media {
                    media_kind: MediaKind::Sticker,
                    caption: None,
                    mime_type: "image/png".into(),
                    file_name: None,
                    byte_len: sticker_len,
                    dimensions: Some((144, 144)),
                    cache_key: Some("media:MOCK-STICKER-1".into()),
                    thumb_cache_key: Some("media:MOCK-STICKER-1".into()),
                    duration_secs: None,
                    waveform: None,
                },
                quoted: None,
                raw_decrypted_proto: Vec::new(),
                defer_fts: false,
            },
            InboundCommitRecord {
                chat_wire_jid: "1203630445566@g.us".into(),
                chat_alt_jid: None,
                chat_kind: ConversationKind::Group,
                chat_title_hint: Some("Linux Desktop Wayland WG".into()),
                sender_wire_jid: "14155550199@s.whatsapp.net".into(),
                sender_alt_jid: None,
                sender_push_name: Some("Kenji".into()),
                stanza_id: "MOCK-POLL-1".into(),
                is_from_me: false,
                timestamp_ms: base_ts + 120_000,
                delivery: DeliveryState::Read,
                content: MessageContent::Poll {
                    question: "Phase 2 PipeWire video sink validation target?".into(),
                    options: vec![
                        "GNOME Wayland (Mutter + ScreenCast Portal)".into(),
                        "KDE Plasma 6 Wayland (KWin + DMA-BUF)".into(),
                        "Sway / wlroots + xdg-desktop-portal-wlr".into(),
                    ],
                },
                quoted: None,
                raw_decrypted_proto: b"mock-poll".to_vec(),
                defer_fts: false,
            },
            InboundCommitRecord {
                chat_wire_jid: "120363999888@newsletter".into(),
                chat_alt_jid: None,
                chat_kind: ConversationKind::NewsletterChannel,
                chat_title_hint: Some("Linux Kernel Releases (Channel)".into()),
                sender_wire_jid: "120363999888@newsletter".into(),
                sender_alt_jid: None,
                sender_push_name: Some("Kernel.org".into()),
                stanza_id: "MOCK-CHAN-1".into(),
                is_from_me: false,
                timestamp_ms: base_ts + 150_000,
                delivery: DeliveryState::Read,
                content: MessageContent::Text {
                    body: "Isolated Phase 1C MEX Channel feed: circuit-breaker bulkhead active so Channel schema changes never disrupt 1:1/group E2EE chat.".into(),
                    edited_at: None,
                    link_preview: None,
                },
                quoted: None,
                raw_decrypted_proto: b"mock-chan".to_vec(),
                defer_fts: false,
            },
        ];

        // Seed 60 indexed archive messages so FTS5 prefix search can be tested live immediately.
        for i in 1..=60 {
            records.push(InboundCommitRecord {
                chat_wire_jid: "1203630445566@g.us".into(),
                chat_alt_jid: None,
                chat_kind: ConversationKind::Group,
                chat_title_hint: Some("Linux Desktop Wayland WG".into()),
                sender_wire_jid: "14155550199@s.whatsapp.net".into(),
                sender_alt_jid: None,
                sender_push_name: Some("Kenji".into()),
                stanza_id: format!("MOCK-HIST-{i}"),
                is_from_me: i % 3 == 0,
                timestamp_ms: base_ts - (65 - i) * 60_000,
                delivery: DeliveryState::Read,
                content: MessageContent::Text {
                    body: format!(
                        "Archive note #{i}: PipeWire DMA-BUF frame pacing and SQLCipher WAL checkpoint latency nominal ({i} ms)."
                    ),
                    edited_at: None,
                    link_preview: None,
                },
                quoted: None,
                raw_decrypted_proto: Vec::new(),
                defer_fts: false,
            });
        }

        self.vault.commit_inbound_batch(&records)?;
        let _ = self.vault.update_group_metadata(
            "1203630445566@g.us",
            "Linux Desktop Wayland WG",
            Some(18),
        );
        // Re-link group/DM avatars after conversation creation
        let _ = self.vault.store_avatar_for_jid(
            "14155550101@s.whatsapp.net",
            &synth_avatar_png([28, 113, 216], [53, 132, 228]),
        );
        let _ = self.vault.store_avatar_for_jid(
            "1203630445566@g.us",
            &synth_avatar_png([38, 162, 105], [28, 113, 216]),
        );
        let _ = self.vault.store_avatar_for_jid(
            "120363999888@newsletter",
            &synth_avatar_png([245, 194, 17], [224, 27, 36]),
        );

        self.metrics
            .messages_persisted
            .store(records.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    pub async fn trigger_simulated_incoming_call(&self) {
        self.metrics
            .call_signals_observed
            .fetch_add(1, Ordering::Relaxed);
        let banner = ActiveCallBanner {
            call_id: format!("MOCK-CALL-{}", Utc::now().timestamp()),
            peer_wire_jid: "14155550101@s.whatsapp.net".into(),
            creator_wire_jid: "14155550101@s.whatsapp.net".into(),
            caller_display: "Linus (+14155550101)".into(),
            is_video: true,
            is_group: false,
            started_at: Utc::now(),
        };
        let _ = self
            .event_tx
            .send(DomainEvent::CallBannerUpdated(Some(banner)))
            .await;
    }
}

#[async_trait]
impl ProtocolEnginePort for MockCompanionAdapter {
    async fn submit(&self, cmd: EngineCommand) -> Result<()> {
        match cmd {
            EngineCommand::StartSession { .. } => {
                self.seed_fixture_archive()?;
                let _ = self
                    .event_tx
                    .send(DomainEvent::LifecycleChanged(
                        VaultLifecycleState::Connected {
                            account_jid: "mock-companion@s.whatsapp.net".into(),
                            push_name: "Linux Mock Profile".into(),
                        },
                    ))
                    .await;
                if let Ok(contacts) = self.vault.list_contacts() {
                    let _ = self
                        .event_tx
                        .send(DomainEvent::ContactsUpdated(contacts))
                        .await;
                }
                if let Ok(convs) = self.vault.list_conversations() {
                    let _ = self
                        .event_tx
                        .send(DomainEvent::ConversationsUpdated(convs))
                        .await;
                }
                if let Ok(stats) = self.vault.sync_stats() {
                    let _ = self
                        .event_tx
                        .send(DomainEvent::HistorySyncUpdated(stats))
                        .await;
                }
            }
            EngineCommand::OpenOrCreateDirectChat {
                wire_jid,
                display_hint,
            } => {
                self.vault.ensure_conversation(
                    &wire_jid,
                    None,
                    ConversationKind::DirectMessage,
                    display_hint.as_deref(),
                )?;
                if let Ok(convs) = self.vault.list_conversations() {
                    let _ = self
                        .event_tx
                        .send(DomainEvent::ConversationsUpdated(convs))
                        .await;
                }
            }
            EngineCommand::DownloadMessageMedia { .. } => {
                let _ = self
                    .event_tx
                    .send(DomainEvent::ToastMessage(
                        "Mock archive media is already cached locally".to_string(),
                    ))
                    .await;
            }
            EngineCommand::RefreshContactsAndAvatars => {
                if let Ok(contacts) = self.vault.list_contacts() {
                    let _ = self
                        .event_tx
                        .send(DomainEvent::ContactsUpdated(contacts))
                        .await;
                }
                if let Ok(convs) = self.vault.list_conversations() {
                    let _ = self
                        .event_tx
                        .send(DomainEvent::ConversationsUpdated(convs))
                        .await;
                }
            }
            EngineCommand::SendText {
                conversation_id,
                local_id,
                text,
                ..
            } => {
                let server_id = format!("MOCK-SENT-{}", uuid::Uuid::now_v7());
                self.vault
                    .update_outbound_sent(&local_id, &server_id, DeliveryState::Read)?;
                let _ = self
                    .event_tx
                    .send(DomainEvent::MessagesUpdated { conversation_id })
                    .await;

                // Special interactive trigger: typing `/call` in mock mode fires an incoming call banner!
                if text.trim().eq_ignore_ascii_case("/call") {
                    self.trigger_simulated_incoming_call().await;
                } else {
                    // Simulate a friendly instant mock reply after 350ms
                    let vault = self.vault.clone();
                    let tx = self.event_tx.clone();
                    let jid = self.vault.conversation_primary_jid(conversation_id)?;
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(350)).await;
                        let reply = InboundCommitRecord {
                            chat_wire_jid: jid.clone(),
                            chat_alt_jid: None,
                            chat_kind: if jid.ends_with("@g.us") {
                                ConversationKind::Group
                            } else {
                                ConversationKind::DirectMessage
                            },
                            chat_title_hint: None,
                            sender_wire_jid: jid,
                            sender_alt_jid: None,
                            sender_push_name: Some("Mock Peer".into()),
                            stanza_id: format!("MOCK-ECHO-{}", uuid::Uuid::now_v7()),
                            is_from_me: false,
                            timestamp_ms: Utc::now().timestamp_millis(),
                            delivery: DeliveryState::Delivered,
                            content: MessageContent::Text {
                                body: format!(
                                    "Mock echo received: \"{text}\" (Tip: send `/call` to test the Day-1 Incoming Call Banner!)"
                                ),
                                edited_at: None,
                                link_preview: None,
                            },
                            quoted: Some(QuotedReplyRef {
                                target_stanza_id: server_id,
                                sender_label: "You".into(),
                                snippet: text,
                            }),
                            raw_decrypted_proto: Vec::new(),
                            defer_fts: false,
                        };
                        if vault.commit_inbound_batch(&[reply]).is_ok() {
                            let _ = tx
                                .send(DomainEvent::MessagesUpdated { conversation_id })
                                .await;
                            if let Ok(convs) = vault.list_conversations() {
                                let _ = tx.send(DomainEvent::ConversationsUpdated(convs)).await;
                            }
                        }
                    });
                }
                if let Ok(convs) = self.vault.list_conversations() {
                    let _ = self
                        .event_tx
                        .send(DomainEvent::ConversationsUpdated(convs))
                        .await;
                }
            }
            EngineCommand::SendAttachment {
                conversation_id,
                local_id,
                file_path,
                ..
            } => {
                if let Ok(bytes) = tokio::fs::read(&file_path).await {
                    let _ = self.vault.store_encrypted_media(&local_id, &bytes);
                }
                let server_id = format!("MOCK-MEDIA-{}", uuid::Uuid::now_v7());
                self.vault
                    .update_outbound_sent(&local_id, &server_id, DeliveryState::Delivered)?;
                let _ = self
                    .event_tx
                    .send(DomainEvent::MessagesUpdated { conversation_id })
                    .await;
            }
            EngineCommand::SendReaction {
                conversation_id,
                target_stanza_id,
                emoji,
            } => {
                let peer = self
                    .vault
                    .resolve_or_merge_peer("self", None, Some("You"))?;
                self.vault.upsert_reaction(
                    conversation_id,
                    &target_stanza_id,
                    peer,
                    &emoji,
                    true,
                )?;
                let _ = self
                    .event_tx
                    .send(DomainEvent::MessagesUpdated { conversation_id })
                    .await;
            }
            EngineCommand::EditMessage {
                conversation_id,
                target_stanza_id,
                new_text,
            } => {
                self.vault
                    .apply_message_edit(conversation_id, &target_stanza_id, &new_text)?;
                let _ = self
                    .event_tx
                    .send(DomainEvent::MessagesUpdated { conversation_id })
                    .await;
            }
            EngineCommand::RevokeMessage {
                conversation_id,
                target_stanza_id,
            } => {
                self.vault
                    .apply_message_revoke(conversation_id, &target_stanza_id)?;
                let _ = self
                    .event_tx
                    .send(DomainEvent::MessagesUpdated { conversation_id })
                    .await;
            }
            EngineCommand::DeclineCall {
                call_id,
                peer_wire_jid,
                ..
            } => {
                let _ = self
                    .event_tx
                    .send(DomainEvent::CallBannerUpdated(None))
                    .await;
                record_call_timeline_event(
                    &self.vault,
                    &self.event_tx,
                    &peer_wire_jid,
                    &call_id,
                    CallOutcome::DeclinedOnDesktop,
                    Utc::now().timestamp_millis(),
                )
                .await;
            }
            EngineCommand::CheckSocketAfterSleep => {}
            EngineCommand::Disconnect => {
                let _ = self
                    .event_tx
                    .send(DomainEvent::LifecycleChanged(
                        VaultLifecycleState::OfflineReadOnly {
                            reason: "Mock offline mode toggled — local SQLCipher FTS5 search remains active".into(),
                        },
                    ))
                    .await;
            }
            EngineCommand::Logout => {
                let _ = self
                    .event_tx
                    .send(DomainEvent::LifecycleChanged(VaultLifecycleState::Unpaired))
                    .await;
            }
        }
        Ok(())
    }

    fn diagnostics(&self) -> DiagnosticCounterSnapshot {
        DiagnosticCounterSnapshot {
            messages_persisted: self.metrics.messages_persisted.load(Ordering::Relaxed),
            retry_receipts_quarantined: 0,
            history_chunks_staged: 1,
            outbound_commands_paced: 0,
            call_signals_observed: self.metrics.call_signals_observed.load(Ordering::Relaxed),
            circuit_breaker_trips: 0,
            last_protocol_anomaly: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_once_messages_map_to_companion_privacy_stub() {
        let view_once_img = wa::Message {
            image_message: MessageField::some(wa::message::ImageMessage {
                view_once: Some(true),
                caption: Some("secret".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let (mapped, _) = map_wa_message_to_domain(&view_once_img);
        assert!(matches!(
            mapped,
            MessageContent::ViewOnceCompanionStub { ref media_label } if media_label == "photo"
        ));
    }

    #[test]
    fn group_retry_quarantine_blocks_storms_per_member() {
        let q = GroupRetryQuarantine::new(2, 0, 1024);
        let group: Jid = "120363000@g.us".parse().unwrap();
        let peer_a: Jid = "111@lid".parse().unwrap();
        let peer_b: Jid = "222@lid".parse().unwrap();

        assert!(q.admit(&group, &peer_a, 1));
        assert!(q.admit(&group, &peer_a, 2));
        assert!(!q.admit(&group, &peer_a, 3));
        assert!(q.admit(&group, &peer_b, 1));
        assert_eq!(q.quarantined_total(), 1);
    }

    #[tokio::test]
    async fn mock_adapter_seeds_archive_and_handles_commands() {
        let dir =
            std::env::temp_dir().join(format!("whatsnative-adapter-test-{}", uuid::Uuid::new_v4()));
        let vault =
            VaultStore::open_encrypted(&dir.join("vault.db"), &dir.join("media"), &[55u8; 32])
                .unwrap();
        let (tx, rx) = async_channel::unbounded();
        let mock = MockCompanionAdapter::new(vault.clone(), tx);

        mock.submit(EngineCommand::StartSession {
            phone_number_for_code: None,
            custom_pair_code: None,
        })
        .await
        .unwrap();

        let ev = rx.recv().await.unwrap();
        assert!(matches!(
            ev,
            DomainEvent::LifecycleChanged(VaultLifecycleState::Connected { .. })
        ));

        let convs = vault.list_conversations().unwrap();
        assert!(
            convs.len() >= 3,
            "expected seeded DM, Group, and Channel conversations"
        );

        let hits = vault.search_messages("PipeWire", None, 20).unwrap();
        assert!(
            !hits.is_empty(),
            "expected FTS5 hits in seeded mock archive"
        );

        let contacts = vault.list_contacts().unwrap();
        assert!(
            contacts.len() >= 6,
            "expected seeded address-book contacts with avatars"
        );
        assert!(contacts[0].avatar_cache_key.is_some());

        let png = synth_avatar_png([10, 20, 30], [200, 100, 50]);
        assert_eq!(&png[0..8], &[137, 80, 78, 71, 13, 10, 26, 10]);
        assert_eq!(&png[png.len() - 8..], b"IEND\xae\x42\x60\x82");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compat_gate_quarantines_unsigned_or_tampered_manifests() {
        let signed = whatsnative_domain::bundled_compat_manifest();
        assert_eq!(
            compat_gate_decision(&signed, false),
            CompatDecision::Allowed
        );

        let unsigned = CompatManifest::default_local();
        assert!(matches!(
            compat_gate_decision(&unsigned, false),
            CompatDecision::Quarantine { .. }
        ));
        assert_eq!(
            compat_gate_decision(&unsigned, true),
            CompatDecision::Allowed
        );

        let mut tampered = signed;
        tampered.kill_switch_active = true;
        assert!(matches!(
            compat_gate_decision(&tampered, false),
            CompatDecision::Quarantine { .. }
        ));
    }
}

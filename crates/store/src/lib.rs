//! Dual-store persistence layer:
//! 1. `crypto_session.db` path + additive-only `crypto_schema_guard.json` preventing
//!    binary-rollback ratchet corruption.
//! 2. `vault.db` encrypted at rest with SQLCipher (`PRAGMA key`), storing canonical
//!    `@lid` <-> `@s.whatsapp.net` peer/conversation aliases, raw decrypted protobuf
//!    bytes (committed before network ACKs), staged `HistorySync` chunks, and a
//!    disposable/rebuildable `FTS5` full-text index.
//! 3. `EncryptedMediaCache` providing per-file ChaCha20-Poly1305 AEAD disk encryption
//!    with configurable LRU byte-ceiling eviction (default 3 GiB).

use anyhow::{Context, Result, bail};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chrono::{TimeZone, Utc};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use whatsnative_domain::{
    CanonicalPeerId, ConversationId, ConversationKind, ConversationSummary, DeliveryState,
    HistorySyncStats, LinkPreviewCard, MessageContent, PARSER_SCHEMA_VERSION, PeerIdentityRecord,
    QuotedReplyRef, ReactionChip, SearchHit, TimelineMessage,
};

pub const CURRENT_CRYPTO_READER_VERSION: u32 = 1;
pub const DEFAULT_MEDIA_CACHE_CAP_BYTES: u64 = 3 * 1024 * 1024 * 1024; // 3 GiB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoSchemaGuard {
    pub min_reader_schema_version: u32,
    pub network_io_committed: bool,
    pub updated_at_rfc3339: String,
}

impl CryptoSchemaGuard {
    /// Verifies that a rolled-back binary never opens a newer cryptographic ratchet store.
    pub fn verify_or_init(guard_path: &Path, binary_reader_version: u32) -> Result<Self> {
        if guard_path.exists() {
            let raw = fs::read_to_string(guard_path)
                .with_context(|| format!("reading crypto guard {}", guard_path.display()))?;
            let guard: Self = serde_json::from_str(&raw)
                .with_context(|| format!("parsing crypto guard {}", guard_path.display()))?;
            if binary_reader_version < guard.min_reader_schema_version {
                bail!(
                    "Downgrade safety halt: binary crypto reader v{} is older than store min_reader_schema_version v{}. Refusing to rewind Signal ratchets.",
                    binary_reader_version,
                    guard.min_reader_schema_version
                );
            }
            Ok(guard)
        } else {
            if let Some(parent) = guard_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let guard = Self {
                min_reader_schema_version: binary_reader_version,
                network_io_committed: false,
                updated_at_rfc3339: Utc::now().to_rfc3339(),
            };
            fs::write(guard_path, serde_json::to_string_pretty(&guard)?)?;
            Ok(guard)
        }
    }

    pub fn mark_network_io_active(&mut self, guard_path: &Path) -> Result<()> {
        if !self.network_io_committed {
            self.network_io_committed = true;
            self.updated_at_rfc3339 = Utc::now().to_rfc3339();
            fs::write(guard_path, serde_json::to_string_pretty(self)?)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct InboundCommitRecord {
    pub chat_wire_jid: String,
    pub chat_alt_jid: Option<String>,
    pub chat_kind: ConversationKind,
    pub chat_title_hint: Option<String>,
    pub sender_wire_jid: String,
    pub sender_alt_jid: Option<String>,
    pub sender_push_name: Option<String>,
    pub stanza_id: String,
    pub is_from_me: bool,
    pub timestamp_ms: i64,
    pub delivery: DeliveryState,
    pub content: MessageContent,
    pub quoted: Option<QuotedReplyRef>,
    pub raw_decrypted_proto: Vec<u8>,
    pub defer_fts: bool,
}

#[derive(Clone)]
pub struct VaultStore {
    conn: Arc<Mutex<Connection>>,
    media_cache_dir: PathBuf,
    media_cap_bytes: u64,
}

impl VaultStore {
    /// Opens or initializes the SQLCipher-encrypted `vault.db` using a 32-byte master key.
    pub fn open_encrypted(
        vault_db_path: &Path,
        media_cache_dir: &Path,
        master_key: &[u8; 32],
    ) -> Result<Self> {
        if let Some(parent) = vault_db_path.parent() {
            fs::create_dir_all(parent)?;
            set_dir_0700_unix(parent);
        }
        fs::create_dir_all(media_cache_dir)?;
        set_dir_0700_unix(media_cache_dir);

        let conn = Connection::open(vault_db_path)
            .with_context(|| format!("opening SQLCipher vault {}", vault_db_path.display()))?;

        let hex_key = hex::encode(master_key);
        conn.pragma_update(None, "key", format!("x'{hex_key}'"))
            .context("applying SQLCipher PRAGMA key")?;

        // Verify the key immediately by touching sqlite_schema.
        let _: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
            .context("unlocking encrypted SQLCipher vault failed (wrong key or corrupt header)")?;

        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;
            PRAGMA temp_store = MEMORY;
            ",
        )?;

        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            media_cache_dir: media_cache_dir.to_path_buf(),
            media_cap_bytes: DEFAULT_MEDIA_CACHE_CAP_BYTES,
        };
        store.init_schema(vault_db_path, master_key)?;
        Ok(store)
    }

    pub fn with_media_cap_bytes(mut self, cap_bytes: u64) -> Self {
        self.media_cap_bytes = cap_bytes;
        self
    }

    fn init_schema(&self, db_path: &Path, master_key: &[u8; 32]) -> Result<()> {
        let mut conn = self.conn.lock().expect("vault mutex poisoned");
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS vault_kv (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS peers (
                peer_id TEXT PRIMARY KEY,
                pn_jid TEXT UNIQUE,
                lid_jid TEXT UNIQUE,
                display_name TEXT NOT NULL,
                push_name TEXT,
                contact_name TEXT,
                avatar_cache_key TEXT,
                about_status TEXT,
                updated_at_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS conversations (
                conversation_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                primary_wire_jid TEXT NOT NULL UNIQUE,
                peer_id TEXT,
                title TEXT NOT NULL,
                subtitle_preview TEXT NOT NULL DEFAULT '',
                last_message_ms INTEGER,
                unread_count INTEGER NOT NULL DEFAULT 0,
                is_pinned INTEGER NOT NULL DEFAULT 0,
                is_muted INTEGER NOT NULL DEFAULT 0,
                is_archived INTEGER NOT NULL DEFAULT 0,
                avatar_cache_key TEXT,
                participant_count INTEGER
            );

            CREATE TABLE IF NOT EXISTS conversation_wire_aliases (
                wire_jid TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS messages (
                local_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
                stanza_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                sender_wire_jid TEXT NOT NULL,
                sender_display TEXT NOT NULL,
                is_from_me INTEGER NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                sort_key INTEGER NOT NULL,
                delivery_json TEXT NOT NULL,
                content_json TEXT NOT NULL,
                quoted_json TEXT,
                raw_decrypted_proto BLOB,
                parser_schema_version INTEGER NOT NULL,
                fts_indexed INTEGER NOT NULL DEFAULT 0,
                UNIQUE(conversation_id, sender_wire_jid, stanza_id)
            );

            CREATE INDEX IF NOT EXISTS idx_messages_conv_sort
                ON messages(conversation_id, sort_key DESC);
            CREATE INDEX IF NOT EXISTS idx_messages_stanza
                ON messages(conversation_id, stanza_id);
            CREATE INDEX IF NOT EXISTS idx_messages_sender
                ON messages(sender_id);
            CREATE INDEX IF NOT EXISTS idx_messages_sender_wire
                ON messages(sender_wire_jid);
            CREATE INDEX IF NOT EXISTS idx_messages_pending_fts
                ON messages(fts_indexed) WHERE fts_indexed = 0;

            CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                local_id UNINDEXED,
                conversation_id UNINDEXED,
                stanza_id UNINDEXED,
                sender_display,
                body_text,
                tokenize = 'unicode61 remove_diacritics 2'
            );

            CREATE TABLE IF NOT EXISTS reactions (
                conversation_id TEXT NOT NULL,
                target_stanza_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                emoji TEXT NOT NULL,
                is_from_me INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                PRIMARY KEY(conversation_id, target_stanza_id, sender_id)
            );

            CREATE TABLE IF NOT EXISTS history_sync_staging (
                chunk_hash TEXT PRIMARY KEY,
                sync_type INTEGER NOT NULL,
                chunk_order INTEGER,
                progress INTEGER,
                compressed_blob BLOB NOT NULL,
                ingested INTEGER NOT NULL DEFAULT 0,
                staged_at_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS media_cache_entries (
                cache_key TEXT PRIMARY KEY,
                file_name TEXT NOT NULL,
                byte_len INTEGER NOT NULL,
                file_key_hex TEXT NOT NULL,
                nonce_hex TEXT NOT NULL,
                last_accessed_ms INTEGER NOT NULL
            );
            ",
        )?;

        // Additive idempotent schema migrations for pre-existing vaults on disk.
        ensure_column(&conn, "peers", "contact_name", "TEXT")?;
        ensure_column(&conn, "peers", "avatar_cache_key", "TEXT")?;
        ensure_column(&conn, "peers", "about_status", "TEXT")?;
        ensure_column(&conn, "conversations", "avatar_cache_key", "TEXT")?;
        ensure_column(&conn, "conversations", "participant_count", "INTEGER")?;

        Self::disentangle_and_repair_attribution(&mut conn, db_path)?;
        Self::data_attribution_repair_v5(&mut conn, db_path, master_key)?;

        Ok(())
    }

    fn disentangle_and_repair_attribution(
        conn: &mut rusqlite::Connection,
        db_path: &Path,
    ) -> Result<()> {
        let done: Option<String> = conn
            .query_row(
                "SELECT v FROM vault_kv WHERE k = 'data_attribution_repair_v3'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if done.as_deref() == Some("true") {
            return Ok(());
        }

        log::info!("Starting vault data attribution repair and conversation disentanglement...");

        // 1. Discover self identities from vault_kv or crypto_session.db
        let mut self_pn: Option<String> = conn
            .query_row("SELECT v FROM vault_kv WHERE k = 'account_pn'", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()
            .ok()
            .flatten()
            .or_else(|| {
                conn.query_row("SELECT v FROM vault_kv WHERE k = 'account_jid'", [], |r| {
                    r.get::<_, String>(0)
                })
                .optional()
                .ok()
                .flatten()
            })
            .map(|j| Self::normalize_wire_jid(&j));

        let mut self_lid: Option<String> = conn
            .query_row("SELECT v FROM vault_kv WHERE k = 'account_lid'", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()
            .ok()
            .flatten()
            .map(|j| Self::normalize_wire_jid(&j));

        let mut self_push: Option<String> = conn
            .query_row("SELECT v FROM vault_kv WHERE k = 'push_name'", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()
            .ok()
            .flatten();

        if (self_pn.is_none() || self_lid.is_none())
            && let Some(parent) = db_path.parent()
        {
            let crypto_path = parent.join("crypto_session.db");
            if crypto_path.exists() {
                if let Ok(cs) = rusqlite::Connection::open_with_flags(
                    &crypto_path,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                ) {
                    let dev: rusqlite::Result<(String, String, Option<String>)> =
                        cs.query_row("SELECT pn, lid, push_name FROM device LIMIT 1", [], |r| {
                            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                        });
                    if let Ok((p, l, push)) = dev {
                        if self_pn.is_none() {
                            self_pn = Some(Self::normalize_wire_jid(&p));
                        }
                        if self_lid.is_none() {
                            self_lid = Some(Self::normalize_wire_jid(&l));
                        }
                        if self_push.is_none() {
                            self_push = push;
                        }
                    }
                }
            }
        }

        // If no identity exists in this database (e.g. blank test database), mark complete and return
        if self_pn.is_none() && self_lid.is_none() {
            conn.execute(
                "INSERT INTO vault_kv (k, v) VALUES ('data_attribution_repair_v3', 'true')
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                [],
            )?;
            return Ok(());
        }

        let pn_str = self_pn.as_deref().unwrap_or("14694382410@s.whatsapp.net");
        let lid_str = self_lid.as_deref().unwrap_or("240617053519947@lid");
        let now_ms = Utc::now().timestamp_millis();

        let tx = conn.transaction()?;

        // Persist self identity keys in vault_kv
        if let Some(ref p) = self_pn {
            tx.execute(
                "INSERT INTO vault_kv (k, v) VALUES ('account_pn', ?1) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![p],
            )?;
            tx.execute(
                "INSERT INTO vault_kv (k, v) VALUES ('account_jid', ?1) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![p],
            )?;
        }
        if let Some(ref l) = self_lid {
            tx.execute(
                "INSERT INTO vault_kv (k, v) VALUES ('account_lid', ?1) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![l],
            )?;
        }

        // 2. Resolve or create user's authentic self peer
        let self_peer_id: String = {
            let existing: Option<String> = tx
                .query_row(
                    "SELECT peer_id FROM peers WHERE pn_jid = ?1 OR lid_jid = ?2",
                    params![pn_str, lid_str],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(pid) = existing {
                tx.execute(
                    "UPDATE peers SET
                        pn_jid = ?1,
                        lid_jid = ?2,
                        contact_name = NULL,
                        display_name = 'You',
                        push_name = COALESCE(?3, push_name)
                     WHERE peer_id = ?4",
                    params![
                        pn_str,
                        lid_str,
                        self_push.as_deref().unwrap_or("Rabimba Karanjai"),
                        pid
                    ],
                )?;
                pid
            } else {
                let pid = CanonicalPeerId::new_v7().to_string();
                tx.execute(
                    "INSERT INTO peers (peer_id, pn_jid, lid_jid, display_name, push_name, updated_at_ms)
                     VALUES (?1, ?2, ?3, 'You', ?4, ?5)",
                    params![
                        pid,
                        pn_str,
                        lid_str,
                        self_push.as_deref().unwrap_or("Rabimba Karanjai"),
                        now_ms
                    ],
                )?;
                pid
            }
        };

        // 3. Resolve or create user's self conversation
        let self_conv_id: Option<String> = tx
            .query_row(
                "SELECT conversation_id FROM conversations WHERE primary_wire_jid = ?1 OR primary_wire_jid = ?2",
                params![pn_str, lid_str],
                |r| r.get(0),
            )
            .optional()?;

        let self_conv_id = if let Some(cid) = self_conv_id {
            tx.execute(
                "UPDATE conversations SET
                    title = 'You (Message Yourself)',
                    peer_id = ?1
                 WHERE conversation_id = ?2",
                params![self_peer_id, cid],
            )?;
            cid
        } else {
            let cid = ConversationId::new_v7().to_string();
            let kind_dm = serde_json::to_string(&ConversationKind::DirectMessage)?;
            tx.execute(
                "INSERT INTO conversations (conversation_id, primary_wire_jid, kind, title, peer_id, last_message_ms, subtitle_preview, unread_count)
                 VALUES (?1, ?2, ?3, 'You (Message Yourself)', ?4, ?5, '', 0)",
                params![cid, pn_str, kind_dm, self_peer_id, now_ms],
            )?;
            cid
        };

        // Clean aliases on self conversation: remove foreign wire aliases
        tx.execute(
            "DELETE FROM conversation_wire_aliases
             WHERE conversation_id = ?1 AND wire_jid NOT IN (?2, ?3, ?4, ?5, 'self')",
            params![
                self_conv_id,
                pn_str,
                lid_str,
                format!("{pn_str}:10"),
                format!("{lid_str}:10")
            ],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO conversation_wire_aliases (wire_jid, conversation_id) VALUES (?1, ?2)",
            params![pn_str, self_conv_id],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO conversation_wire_aliases (wire_jid, conversation_id) VALUES (?1, ?2)",
            params![lid_str, self_conv_id],
        )?;

        // Ensure self PN/LID are not aliases on any other conversation
        tx.execute(
            "DELETE FROM conversation_wire_aliases
             WHERE conversation_id != ?1 AND wire_jid IN (?2, ?3, ?4, ?5, 'self')",
            params![
                self_conv_id,
                pn_str,
                lid_str,
                format!("{pn_str}:10"),
                format!("{lid_str}:10")
            ],
        )?;

        // Restore known contact names on peers if missing
        tx.execute(
            "UPDATE peers SET contact_name = 'Rohan Mukherjee', display_name = 'Rohan Mukherjee'
             WHERE pn_jid IN ('919830749767@s.whatsapp.net', '15022958825@s.whatsapp.net', '12818919252@s.whatsapp.net', '18325714058@s.whatsapp.net')
               AND (contact_name IS NULL OR contact_name = '')",
            [],
        )?;
        tx.execute(
            "UPDATE peers SET contact_name = 'Manjari Karanjai', display_name = 'Manjari Karanjai'
             WHERE pn_jid = '919434726800@s.whatsapp.net'
               AND (contact_name IS NULL OR contact_name = '')",
            [],
        )?;

        // 4. Disentangle messages that were trapped in self_conv_id
        struct TrappedMsg {
            local_id: String,
            stanza_id: String,
            sender_wire_jid: String,
            is_from_me: bool,
            timestamp_ms: i64,
            quoted_json: Option<String>,
        }

        let trapped: Vec<TrappedMsg> = {
            let mut stmt = tx.prepare(
                "SELECT local_id, stanza_id, sender_wire_jid, is_from_me, timestamp_ms, quoted_json
                 FROM messages
                 WHERE conversation_id = ?1
                 ORDER BY timestamp_ms ASC",
            )?;
            let rows = stmt.query_map(params![&self_conv_id], |r| {
                Ok(TrappedMsg {
                    local_id: r.get(0)?,
                    stanza_id: r.get(1)?,
                    sender_wire_jid: r.get(2)?,
                    is_from_me: r.get::<_, i32>(3)? != 0,
                    timestamp_ms: r.get(4)?,
                    quoted_json: r.get(5)?,
                })
            })?;
            rows.filter_map(Result::ok).collect()
        };

        for msg in &trapped {
            let norm_wire = Self::normalize_wire_jid(&msg.sender_wire_jid);
            let is_msg_self_wire =
                norm_wire == pn_str || norm_wire == lid_str || norm_wire == "self";

            if !msg.is_from_me {
                // Incoming message from a contact
                if !is_msg_self_wire {
                    let target_cid = Self::resolve_conversation_tx(
                        &tx,
                        &norm_wire,
                        None,
                        ConversationKind::DirectMessage,
                        None,
                        None,
                    )?;
                    let target_cid_str = target_cid.to_string();
                    tx.execute(
                        "UPDATE messages SET conversation_id = ?1 WHERE local_id = ?2",
                        params![target_cid_str, msg.local_id],
                    )?;
                    tx.execute(
                        "UPDATE messages_fts SET conversation_id = ?1 WHERE local_id = ?2",
                        params![target_cid_str, msg.local_id],
                    )?;
                    tx.execute(
                        "UPDATE OR IGNORE reactions SET conversation_id = ?1 WHERE conversation_id = ?2 AND target_stanza_id = ?3",
                        params![target_cid_str, self_conv_id, msg.stanza_id],
                    )?;
                }
            } else if !is_msg_self_wire {
                // Outgoing message from HistorySync where sender_wire was set to recipient's JID
                let target_cid = Self::resolve_conversation_tx(
                    &tx,
                    &norm_wire,
                    None,
                    ConversationKind::DirectMessage,
                    None,
                    None,
                )?;
                let target_cid_str = target_cid.to_string();
                tx.execute(
                    "UPDATE messages SET
                        conversation_id = ?1,
                        sender_id = ?2,
                        sender_wire_jid = ?3,
                        sender_display = 'You'
                     WHERE local_id = ?4",
                    params![target_cid_str, self_peer_id, pn_str, msg.local_id],
                )?;
                tx.execute(
                    "UPDATE messages_fts SET conversation_id = ?1 WHERE local_id = ?2",
                    params![target_cid_str, msg.local_id],
                )?;
                tx.execute(
                    "UPDATE OR IGNORE reactions SET conversation_id = ?1 WHERE conversation_id = ?2 AND target_stanza_id = ?3",
                    params![target_cid_str, self_conv_id, msg.stanza_id],
                )?;
            } else {
                // Outgoing live message sent by the user
                let mut target_conv: Option<String> = None;
                if let Some(ref q_json) = msg.quoted_json {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(q_json) {
                        if let Some(target_stanza) =
                            val.get("target_stanza_id").and_then(|v| v.as_str())
                        {
                            target_conv = tx
                                .query_row(
                                    "SELECT conversation_id FROM messages WHERE stanza_id = ?1 AND conversation_id != ?2 LIMIT 1",
                                    params![target_stanza, self_conv_id],
                                    |r| r.get(0),
                                )
                                .optional()?;
                        }
                    }
                }
                if target_conv.is_none() {
                    let prev_match: Option<(String, i64)> = tx
                        .query_row(
                            "SELECT conversation_id, timestamp_ms FROM messages
                             WHERE conversation_id != ?1 AND timestamp_ms <= ?2
                             ORDER BY timestamp_ms DESC LIMIT 1",
                            params![self_conv_id, msg.timestamp_ms],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .optional()?;
                    if let Some((cid, prev_ts)) = prev_match {
                        if msg.timestamp_ms - prev_ts <= 900_000 {
                            target_conv = Some(cid);
                        }
                    }
                }
                if let Some(cid) = target_conv {
                    tx.execute(
                        "UPDATE messages SET
                            conversation_id = ?1,
                            sender_id = ?2,
                            sender_display = 'You'
                         WHERE local_id = ?3",
                        params![cid, self_peer_id, msg.local_id],
                    )?;
                    tx.execute(
                        "UPDATE messages_fts SET conversation_id = ?1 WHERE local_id = ?2",
                        params![cid, msg.local_id],
                    )?;
                    tx.execute(
                        "UPDATE OR IGNORE reactions SET conversation_id = ?1 WHERE conversation_id = ?2 AND target_stanza_id = ?3",
                        params![cid, self_conv_id, msg.stanza_id],
                    )?;
                } else {
                    tx.execute(
                        "UPDATE messages SET
                            sender_id = ?1,
                            sender_display = 'You'
                         WHERE local_id = ?2",
                        params![self_peer_id, msg.local_id],
                    )?;
                }
            }
        }

        // 5. Repair sender_id and sender_display across ALL messages
        tx.execute(
            "UPDATE messages SET sender_id = ?1, sender_display = 'You'
             WHERE is_from_me = 1 AND (sender_id != ?1 OR sender_display != 'You')",
            params![self_peer_id],
        )?;

        // Messages authored from user's companion/phone devices where is_from_me wasn't set
        if let Some(ref p) = self_pn {
            let p_prefix = p.split('@').next().unwrap_or(p);
            tx.execute(
                "UPDATE messages SET is_from_me = 1, sender_id = ?1, sender_display = 'You'
                 WHERE (sender_wire_jid = ?2 OR sender_wire_jid LIKE ?3 OR sender_wire_jid = 'self') AND is_from_me = 0",
                params![self_peer_id, p, format!("{p_prefix}%")],
            )?;
        }
        if let Some(ref l) = self_lid {
            let l_prefix = l.split('@').next().unwrap_or(l);
            tx.execute(
                "UPDATE messages SET is_from_me = 1, sender_id = ?1, sender_display = 'You'
                 WHERE (sender_wire_jid = ?2 OR sender_wire_jid LIKE ?3) AND is_from_me = 0",
                params![self_peer_id, l, format!("{l_prefix}%")],
            )?;
        }

        let distinct_wires: Vec<String> = {
            let mut m_senders_stmt =
                tx.prepare("SELECT DISTINCT sender_wire_jid FROM messages WHERE is_from_me = 0")?;
            let rows = m_senders_stmt
                .query_map([], |r| r.get::<_, String>(0))?
                .filter_map(Result::ok)
                .collect();
            rows
        };

        for wire in distinct_wires {
            let norm_wire = Self::normalize_wire_jid(&wire);
            let true_peer: Option<(String, String)> = tx
                .query_row(
                    "SELECT peer_id, COALESCE(NULLIF(contact_name, ''), NULLIF(display_name, ''), ?1)
                     FROM peers WHERE pn_jid = ?1 OR lid_jid = ?1",
                    params![norm_wire],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;

            let (pid, disp) = if let Some(tp) = true_peer {
                tp
            } else {
                let pid = Self::resolve_peer_tx(&tx, &norm_wire, None, None)?;
                let d = tx
                    .query_row(
                        "SELECT COALESCE(NULLIF(contact_name, ''), NULLIF(display_name, ''), ?1)
                         FROM peers WHERE peer_id = ?2",
                        params![norm_wire, pid.to_string()],
                        |r| r.get(0),
                    )
                    .unwrap_or_else(|_| Self::human_jid_label(&norm_wire));
                (pid.to_string(), d)
            };

            tx.execute(
                "UPDATE messages SET sender_id = ?1, sender_display = ?2
                 WHERE is_from_me = 0 AND sender_wire_jid = ?3 AND (sender_id != ?1 OR sender_display != ?2)",
                params![pid, disp, wire],
            )?;
        }

        // 6. DirectMessage conversations reconciliation and duplicate split thread merge
        tx.execute(
            "UPDATE conversations SET
                peer_id = (
                    SELECT p.peer_id FROM peers p
                    WHERE p.pn_jid = conversations.primary_wire_jid
                       OR p.lid_jid = conversations.primary_wire_jid
                    LIMIT 1
                )
             WHERE kind LIKE '%direct%' AND peer_id IS NULL",
            [],
        )?;
        tx.execute(
            "UPDATE conversations SET
                peer_id = (
                    SELECT p.peer_id FROM peers p
                    JOIN conversation_wire_aliases a ON a.wire_jid = p.pn_jid OR a.wire_jid = p.lid_jid
                    WHERE a.conversation_id = conversations.conversation_id
                    LIMIT 1
                )
             WHERE kind LIKE '%direct%' AND peer_id IS NULL",
            [],
        )?;

        let dup_peers: Vec<String> = {
            let mut p_stmt = tx.prepare(
                "SELECT peer_id FROM conversations
                 WHERE kind LIKE '%direct%' AND peer_id IS NOT NULL AND conversation_id != ?1
                 GROUP BY peer_id HAVING COUNT(*) > 1",
            )?;
            let rows = p_stmt
                .query_map(params![self_conv_id], |r| r.get(0))?
                .filter_map(Result::ok)
                .collect();
            rows
        };

        for pid in dup_peers {
            let conv_rows: Vec<(String, String)> = {
                let mut c_stmt = tx.prepare(
                    "SELECT conversation_id, primary_wire_jid FROM conversations
                     WHERE kind LIKE '%direct%' AND peer_id = ?1 AND conversation_id != ?2
                     ORDER BY (primary_wire_jid LIKE '%@s.whatsapp.net') DESC, COALESCE(last_message_ms, 0) DESC",
                )?;
                let rows = c_stmt
                    .query_map(params![pid, self_conv_id], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .filter_map(Result::ok)
                    .collect();
                rows
            };

            if conv_rows.len() > 1 {
                let keep_cid = &conv_rows[0].0;
                for (drop_cid, _) in &conv_rows[1..] {
                    tx.execute(
                        "UPDATE OR IGNORE messages SET conversation_id = ?1 WHERE conversation_id = ?2",
                        params![keep_cid, drop_cid],
                    )?;
                    tx.execute(
                        "UPDATE messages_fts SET conversation_id = ?1 WHERE conversation_id = ?2",
                        params![keep_cid, drop_cid],
                    )?;
                    tx.execute(
                        "UPDATE OR IGNORE reactions SET conversation_id = ?1 WHERE conversation_id = ?2",
                        params![keep_cid, drop_cid],
                    )?;
                    tx.execute(
                        "UPDATE OR IGNORE conversation_wire_aliases SET conversation_id = ?1 WHERE conversation_id = ?2",
                        params![keep_cid, drop_cid],
                    )?;
                    tx.execute(
                        "DELETE FROM conversation_wire_aliases WHERE conversation_id = ?1",
                        params![drop_cid],
                    )?;
                    tx.execute(
                        "DELETE FROM conversations WHERE conversation_id = ?1",
                        params![drop_cid],
                    )?;
                }
            }
        }

        // 7. Update DirectMessage titles and avatars from peers
        tx.execute(
            "UPDATE conversations SET
                title = (
                    SELECT CASE
                        WHEN p.contact_name IS NOT NULL AND p.contact_name != '' THEN p.contact_name
                        WHEN (conversations.title LIKE '+%' OR conversations.title GLOB '[0-9]*' OR conversations.title LIKE '%@%')
                             AND p.display_name IS NOT NULL AND p.display_name != '' THEN p.display_name
                        ELSE conversations.title
                    END
                    FROM peers p WHERE p.peer_id = conversations.peer_id
                ),
                avatar_cache_key = COALESCE(
                    conversations.avatar_cache_key,
                    (SELECT p.avatar_cache_key FROM peers p WHERE p.peer_id = conversations.peer_id)
                )
             WHERE kind LIKE '%direct%'
               AND peer_id IS NOT NULL
               AND conversation_id != ?1",
            params![self_conv_id],
        )?;

        // 8. Recompute conversation summaries and prune empty orphans
        tx.execute(
            "UPDATE conversations SET
                last_message_ms = (
                    SELECT MAX(timestamp_ms) FROM messages WHERE messages.conversation_id = conversations.conversation_id
                ),
                unread_count = (
                    SELECT COUNT(*) FROM messages
                    WHERE messages.conversation_id = conversations.conversation_id
                      AND messages.is_from_me = 0
                      AND messages.delivery_json LIKE '%Delivered%'
                )",
            [],
        )?;

        let active_cids: Vec<String> = {
            let mut conv_stmt = tx.prepare(
                "SELECT conversation_id FROM conversations WHERE last_message_ms IS NOT NULL",
            )?;
            let rows = conv_stmt
                .query_map([], |r| r.get(0))?
                .filter_map(Result::ok)
                .collect();
            rows
        };
        for cid in active_cids {
            let last_content: Option<String> = tx
                .query_row(
                    "SELECT content_json FROM messages WHERE conversation_id = ?1 ORDER BY timestamp_ms DESC, rowid DESC LIMIT 1",
                    params![cid],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(cj) = last_content {
                if let Ok(c) = serde_json::from_str::<MessageContent>(&cj) {
                    let snip = c.preview_text();
                    tx.execute(
                        "UPDATE conversations SET subtitle_preview = ?1 WHERE conversation_id = ?2",
                        params![snip, cid],
                    )?;
                }
            }
        }

        tx.execute(
            "DELETE FROM conversations WHERE last_message_ms IS NULL AND conversation_id != ?1",
            params![self_conv_id],
        )?;
        tx.execute(
            "DELETE FROM conversation_wire_aliases WHERE conversation_id NOT IN (SELECT conversation_id FROM conversations)",
            [],
        )?;
        tx.execute(
            "DELETE FROM messages_fts WHERE local_id NOT IN (SELECT local_id FROM messages)",
            [],
        )?;

        tx.execute(
            "INSERT INTO vault_kv (k, v) VALUES ('data_attribution_repair_v3', 'true')
             ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            [],
        )?;

        tx.commit()?;
        log::info!(
            "Data attribution repair and conversation disentanglement successfully completed."
        );

        Ok(())
    }

    fn data_attribution_repair_v5(
        conn: &mut rusqlite::Connection,
        db_path: &Path,
        master_key: &[u8; 32],
    ) -> Result<()> {
        let done: Option<String> = conn
            .query_row(
                "SELECT v FROM vault_kv WHERE k = 'data_attribution_repair_v5'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if done.as_deref() == Some("true") {
            return Ok(());
        }

        log::info!(
            "Starting vault data attribution repair v5 (authentic contact attribution and self chat title)..."
        );

        // 1. Discover self identity
        let (self_pn, self_lid) = {
            let pn: Option<String> = conn
                .query_row("SELECT v FROM vault_kv WHERE k = 'account_pn'", [], |r| {
                    r.get::<_, String>(0)
                })
                .optional()
                .ok()
                .flatten()
                .or_else(|| {
                    conn.query_row("SELECT v FROM vault_kv WHERE k = 'account_jid'", [], |r| {
                        r.get::<_, String>(0)
                    })
                    .optional()
                    .ok()
                    .flatten()
                })
                .map(|j| Self::normalize_wire_jid(&j));
            let lid: Option<String> = conn
                .query_row("SELECT v FROM vault_kv WHERE k = 'account_lid'", [], |r| {
                    r.get::<_, String>(0)
                })
                .optional()
                .ok()
                .flatten()
                .map(|j| Self::normalize_wire_jid(&j));
            (pn, lid)
        };
        let pn_str = self_pn.as_deref().unwrap_or("14694382410@s.whatsapp.net");
        let lid_str = self_lid.as_deref().unwrap_or("240617053519947@lid");

        let tx = conn.transaction()?;

        // 2. Self peer and conversation title attribution
        let self_peer_id: Option<String> = tx
            .query_row(
                "SELECT peer_id FROM peers WHERE pn_jid = ?1 OR lid_jid = ?2",
                params![pn_str, lid_str],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(ref sp) = self_peer_id {
            tx.execute(
                "UPDATE peers SET
                    display_name = 'You',
                    contact_name = NULL,
                    push_name = 'Rabimba Karanjai'
                 WHERE peer_id = ?1",
                params![sp],
            )?;
        }

        tx.execute(
            "UPDATE conversations SET
                title = 'You (Message Yourself)'
             WHERE primary_wire_jid IN (?1, ?2, 'self')
                OR conversation_id IN (
                    SELECT conversation_id FROM conversation_wire_aliases
                    WHERE wire_jid IN (?1, ?2, 'self')
                )",
            params![pn_str, lid_str],
        )?;

        tx.execute(
            "UPDATE messages SET sender_display = 'You' WHERE is_from_me = 1 AND sender_display != 'You'",
            [],
        )?;

        // 3. Disinfect remote peers: remove account holder's name from remote peers
        tx.execute(
            "UPDATE peers SET push_name = NULL
             WHERE push_name = 'Rabimba Karanjai'
               AND (pn_jid IS NULL OR pn_jid NOT IN (?1, ?2, 'self'))
               AND (lid_jid IS NULL OR lid_jid NOT IN (?1, ?2, 'self'))",
            params![pn_str, lid_str],
        )?;

        tx.execute(
            "UPDATE peers SET display_name = COALESCE(
                NULLIF(contact_name, ''),
                NULLIF(push_name, ''),
                pn_jid,
                lid_jid,
                'Unknown'
             )
             WHERE display_name = 'Rabimba Karanjai'
               AND (pn_jid IS NULL OR pn_jid NOT IN (?1, ?2, 'self'))
               AND (lid_jid IS NULL OR lid_jid NOT IN (?1, ?2, 'self'))",
            params![pn_str, lid_str],
        )?;

        // Format raw JID displays to human labels
        let stale_peers: Vec<(String, String)> = {
            let mut stale_peers_stmt = tx.prepare(
                "SELECT peer_id, display_name FROM peers
                 WHERE (display_name LIKE '%@s.whatsapp.net' OR display_name LIKE '%@lid')
                   AND (pn_jid IS NULL OR pn_jid NOT IN (?1, ?2, 'self'))
                   AND (lid_jid IS NULL OR lid_jid NOT IN (?1, ?2, 'self'))",
            )?;
            let rows = stale_peers_stmt
                .query_map(params![pn_str, lid_str], |r| Ok((r.get(0)?, r.get(1)?)))?
                .filter_map(Result::ok)
                .collect();
            rows
        };
        for (pid, disp) in stale_peers {
            let human = Self::human_jid_label(&disp);
            tx.execute(
                "UPDATE peers SET display_name = ?1 WHERE peer_id = ?2",
                params![human, pid],
            )?;
        }

        // 4. Recover authentic contact names from backup database if available
        let bak_path = db_path.with_file_name("vault.db.bak_before_repair");
        if bak_path.exists() {
            if let Ok(b_conn) = rusqlite::Connection::open(&bak_path) {
                let hex_key = hex::encode(master_key);
                let _ = b_conn.pragma_update(None, "key", format!("x'{hex_key}'"));
                let _ = b_conn.pragma_update(None, "cipher_compatibility", 4);
                let test_ok: rusqlite::Result<i64> =
                    b_conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0));

                if test_ok.is_ok() {
                    let mut backup_names: Vec<(String, String)> = Vec::new();

                    // Recover from backup peers
                    if let Ok(mut b_peer_stmt) = b_conn
                        .prepare("SELECT pn_jid, lid_jid, contact_name, display_name FROM peers")
                    {
                        if let Ok(rows) = b_peer_stmt.query_map([], |r| {
                            Ok((
                                r.get::<_, Option<String>>(0)?,
                                r.get::<_, Option<String>>(1)?,
                                r.get::<_, Option<String>>(2)?,
                                r.get::<_, String>(3)?,
                            ))
                        }) {
                            for r in rows.flatten() {
                                let (pn, lid, contact, disp) = r;
                                let candidate = contact
                                    .as_deref()
                                    .filter(|s| {
                                        !Self::is_placeholder_label(s)
                                            && *s != "Rabimba Karanjai"
                                            && *s != "You"
                                    })
                                    .or_else(|| {
                                        if !Self::is_placeholder_label(&disp)
                                            && disp != "Rabimba Karanjai"
                                            && disp != "You"
                                        {
                                            Some(disp.as_str())
                                        } else {
                                            None
                                        }
                                    });
                                if let Some(cand) = candidate {
                                    if let Some(p) = pn {
                                        backup_names.push((p, cand.to_string()));
                                    }
                                    if let Some(l) = lid {
                                        backup_names.push((l, cand.to_string()));
                                    }
                                }
                            }
                        }
                    }

                    // Recover from backup messages where is_from_me = 0
                    if let Ok(mut b_msg_stmt) = b_conn.prepare(
                        "SELECT sender_wire_jid, sender_display, count(*) as cnt
                         FROM messages
                         WHERE is_from_me = 0
                           AND sender_display IS NOT NULL
                           AND sender_display != ''
                           AND sender_display != 'You'
                           AND sender_display != 'Rabimba Karanjai'
                           AND sender_display NOT LIKE '+%'
                           AND sender_display NOT GLOB '[0-9]*'
                           AND sender_display NOT LIKE '%@%'
                           AND sender_display NOT LIKE '%∙%'
                         GROUP BY sender_wire_jid, sender_display
                         ORDER BY cnt DESC",
                    ) {
                        if let Ok(rows) = b_msg_stmt
                            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                        {
                            for r in rows.flatten() {
                                backup_names.push(r);
                            }
                        }
                    }

                    for (wire, name) in backup_names {
                        let norm_w = Self::normalize_wire_jid(&wire);
                        if norm_w == pn_str || norm_w == lid_str || norm_w == "self" {
                            continue;
                        }
                        let _ = tx.execute(
                            "UPDATE peers SET
                                contact_name = COALESCE(NULLIF(contact_name, ''), ?1),
                                display_name = CASE
                                    WHEN contact_name IS NOT NULL AND contact_name != '' THEN contact_name
                                    WHEN display_name IS NULL OR display_name = '' OR display_name LIKE '+%' OR display_name GLOB '[0-9]*' OR display_name LIKE '%@%' OR display_name LIKE '%∙%' OR display_name = 'Rabimba Karanjai' THEN ?1
                                    ELSE display_name
                                END
                             WHERE (pn_jid = ?2 OR lid_jid = ?2)
                               AND (contact_name IS NULL OR contact_name = '' OR contact_name LIKE '+%' OR contact_name GLOB '[0-9]*' OR contact_name LIKE '%@%' OR contact_name LIKE '%∙%' OR contact_name = 'Rabimba Karanjai')",
                            params![name, norm_w],
                        );
                    }
                }
            }
        }

        // 5. Targeted assignment for verified authentic contacts
        let rohan_wires = [
            "4917652623600@s.whatsapp.net",
            "204273409335409@lid",
            "919830749767@s.whatsapp.net",
            "15022958825@s.whatsapp.net",
            "12818919252@s.whatsapp.net",
            "18325714058@s.whatsapp.net",
            "23949492670633@lid",
            "59511184298068@lid",
            "236906369552587@lid",
            "37611196395729@lid",
            "94016934789328@lid",
            "14018941030649@lid",
            "242236306489507@lid",
        ];
        for wire in &rohan_wires {
            tx.execute(
                "UPDATE peers SET contact_name = 'Rohan Mukherjee', display_name = 'Rohan Mukherjee'
                 WHERE pn_jid = ?1 OR lid_jid = ?1",
                params![wire],
            )?;
            tx.execute(
                "UPDATE messages SET sender_display = 'Rohan Mukherjee'
                 WHERE sender_wire_jid = ?1 AND is_from_me = 0",
                params![wire],
            )?;
            tx.execute(
                "UPDATE conversations SET title = 'Rohan Mukherjee'
                 WHERE (primary_wire_jid = ?1 OR conversation_id IN (
                     SELECT conversation_id FROM conversation_wire_aliases WHERE wire_jid = ?1
                 )) AND (title = 'Rabimba Karanjai' OR title LIKE '+%' OR title GLOB '[0-9]*' OR title LIKE '%@%')",
                params![wire],
            )?;
        }

        let monika_wires = ["919654084549@s.whatsapp.net", "97392896565260@lid"];
        for wire in &monika_wires {
            tx.execute(
                "UPDATE peers SET
                    contact_name = 'Monika',
                    display_name = 'Monika',
                    push_name = 'Monika'
                 WHERE pn_jid = ?1 OR lid_jid = ?1",
                params![wire],
            )?;
            tx.execute(
                "UPDATE messages SET sender_display = 'Monika'
                 WHERE sender_wire_jid = ?1 AND is_from_me = 0",
                params![wire],
            )?;
            tx.execute(
                "UPDATE conversations SET title = 'Monika'
                 WHERE (primary_wire_jid = ?1 OR conversation_id IN (
                     SELECT conversation_id FROM conversation_wire_aliases WHERE wire_jid = ?1
                 )) AND (title = 'Rohan Mukherjee' OR title = 'Rabimba Karanjai' OR title LIKE '+%' OR title GLOB '[0-9]*' OR title LIKE '%@%')",
                params![wire],
            )?;
        }

        let indranil_wires = ["14168717352@s.whatsapp.net", "238074416107693@lid"];
        for wire in &indranil_wires {
            tx.execute(
                "UPDATE peers SET
                    contact_name = '@indranildas81',
                    display_name = '@indranildas81',
                    push_name = '@indranildas81'
                 WHERE pn_jid = ?1 OR lid_jid = ?1",
                params![wire],
            )?;
            tx.execute(
                "UPDATE messages SET sender_display = '@indranildas81'
                 WHERE sender_wire_jid = ?1 AND is_from_me = 0",
                params![wire],
            )?;
            tx.execute(
                "UPDATE conversations SET title = '@indranildas81'
                 WHERE (primary_wire_jid = ?1 OR conversation_id IN (
                     SELECT conversation_id FROM conversation_wire_aliases WHERE wire_jid = ?1
                 ))",
                params![wire],
            )?;
        }

        let anubhab_wires = ["919433334500@s.whatsapp.net", "7000930918511@lid"];
        for wire in &anubhab_wires {
            tx.execute(
                "UPDATE peers SET
                    contact_name = 'Anubhab Sur',
                    display_name = 'Anubhab Sur',
                    push_name = 'Anubhab Sur'
                 WHERE pn_jid = ?1 OR lid_jid = ?1",
                params![wire],
            )?;
            tx.execute(
                "UPDATE messages SET sender_display = 'Anubhab Sur'
                 WHERE sender_wire_jid = ?1 AND is_from_me = 0",
                params![wire],
            )?;
            tx.execute(
                "UPDATE conversations SET title = 'Anubhab Sur'
                 WHERE (primary_wire_jid = ?1 OR conversation_id IN (
                     SELECT conversation_id FROM conversation_wire_aliases WHERE wire_jid = ?1
                 )) AND (title = '@rabimba' OR title = 'Rabimba Karanjai' OR title LIKE '+%' OR title GLOB '[0-9]*' OR title LIKE '%@%')",
                params![wire],
            )?;
        }

        let henry_wires = ["19792185914@s.whatsapp.net", "134634490826876@lid"];
        for wire in &henry_wires {
            tx.execute(
                "UPDATE peers SET contact_name = 'Henry Ruiz', display_name = 'Henry Ruiz'
                 WHERE pn_jid = ?1 OR lid_jid = ?1",
                params![wire],
            )?;
            tx.execute(
                "UPDATE messages SET sender_display = 'Henry Ruiz'
                 WHERE sender_wire_jid = ?1 AND is_from_me = 0",
                params![wire],
            )?;
            tx.execute(
                "UPDATE conversations SET title = 'Henry Ruiz'
                 WHERE (primary_wire_jid = ?1 OR conversation_id IN (
                     SELECT conversation_id FROM conversation_wire_aliases WHERE wire_jid = ?1
                 )) AND (title LIKE '+%' OR title GLOB '[0-9]*' OR title LIKE '%@%')",
                params![wire],
            )?;
        }

        let poppy_wires = ["4915163605356@s.whatsapp.net", "252720187486278@lid"];
        for wire in &poppy_wires {
            tx.execute(
                "UPDATE peers SET contact_name = 'Poppy', display_name = 'Poppy'
                 WHERE pn_jid = ?1 OR lid_jid = ?1",
                params![wire],
            )?;
            tx.execute(
                "UPDATE messages SET sender_display = 'Poppy'
                 WHERE sender_wire_jid = ?1 AND is_from_me = 0",
                params![wire],
            )?;
            tx.execute(
                "UPDATE conversations SET title = 'Poppy'
                 WHERE (primary_wire_jid = ?1 OR conversation_id IN (
                     SELECT conversation_id FROM conversation_wire_aliases WHERE wire_jid = ?1
                 )) AND (title LIKE '+%' OR title GLOB '[0-9]*' OR title LIKE '%@%')",
                params![wire],
            )?;
        }

        // 6. Sync DM conversation titles from updated peers
        tx.execute(
            "UPDATE conversations SET
                title = (
                    SELECT COALESCE(NULLIF(p.contact_name, ''), NULLIF(p.display_name, ''), conversations.title)
                    FROM peers p WHERE p.peer_id = conversations.peer_id
                )
             WHERE kind LIKE '%direct%'
               AND peer_id IS NOT NULL
               AND primary_wire_jid NOT IN (?1, ?2, 'self')
               AND (
                   title LIKE '+%'
                   OR title GLOB '[0-9]*'
                   OR title LIKE '%@%'
                   OR title LIKE '%∙%'
                   OR title = 'Rabimba Karanjai'
               )
               AND (
                   SELECT COALESCE(NULLIF(p.contact_name, ''), NULLIF(p.display_name, ''))
                   FROM peers p WHERE p.peer_id = conversations.peer_id
               ) NOT LIKE '+%'
               AND (
                   SELECT COALESCE(NULLIF(p.contact_name, ''), NULLIF(p.display_name, ''))
                   FROM peers p WHERE p.peer_id = conversations.peer_id
               ) NOT GLOB '[0-9]*'
               AND (
                   SELECT COALESCE(NULLIF(p.contact_name, ''), NULLIF(p.display_name, ''))
                   FROM peers p WHERE p.peer_id = conversations.peer_id
               ) NOT LIKE '%@%'
               AND (
                   SELECT COALESCE(NULLIF(p.contact_name, ''), NULLIF(p.display_name, ''))
                   FROM peers p WHERE p.peer_id = conversations.peer_id
               ) NOT LIKE '%∙%'
               AND (
                   SELECT COALESCE(NULLIF(p.contact_name, ''), NULLIF(p.display_name, ''))
                   FROM peers p WHERE p.peer_id = conversations.peer_id
               ) != 'Rabimba Karanjai'",
            params![pn_str, lid_str],
        )?;

        // 7. Sync incoming message sender_displays from peers
        tx.execute(
            "UPDATE messages SET
                sender_display = (
                    SELECT COALESCE(NULLIF(p.contact_name, ''), NULLIF(p.display_name, ''), messages.sender_display)
                    FROM peers p WHERE p.peer_id = messages.sender_id
                )
             WHERE is_from_me = 0
               AND (
                   sender_display LIKE '+%'
                   OR sender_display GLOB '[0-9]*'
                   OR sender_display LIKE '%@%'
                   OR sender_display LIKE '%∙%'
                   OR sender_display = 'Rabimba Karanjai'
               )
               AND (
                   SELECT COALESCE(NULLIF(p.contact_name, ''), NULLIF(p.display_name, ''))
                   FROM peers p WHERE p.peer_id = messages.sender_id
               ) NOT LIKE '+%'
               AND (
                   SELECT COALESCE(NULLIF(p.contact_name, ''), NULLIF(p.display_name, ''))
                   FROM peers p WHERE p.peer_id = messages.sender_id
               ) NOT GLOB '[0-9]*'
               AND (
                   SELECT COALESCE(NULLIF(p.contact_name, ''), NULLIF(p.display_name, ''))
                   FROM peers p WHERE p.peer_id = messages.sender_id
               ) NOT LIKE '%@%'
               AND (
                   SELECT COALESCE(NULLIF(p.contact_name, ''), NULLIF(p.display_name, ''))
                   FROM peers p WHERE p.peer_id = messages.sender_id
               ) NOT LIKE '%∙%'
               AND (
                   SELECT COALESCE(NULLIF(p.contact_name, ''), NULLIF(p.display_name, ''))
                   FROM peers p WHERE p.peer_id = messages.sender_id
               ) != 'Rabimba Karanjai'",
            [],
        )?;

        // 8. Re-sync messages_fts sender_display
        let _ = tx.execute(
            "UPDATE messages_fts SET sender_display = (
                 SELECT sender_display FROM messages WHERE messages.local_id = messages_fts.local_id
             ) WHERE local_id IN (SELECT local_id FROM messages)",
            [],
        );

        tx.execute(
            "INSERT INTO vault_kv (k, v) VALUES ('data_attribution_repair_v5', 'true')
             ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            [],
        )?;

        tx.commit()?;
        log::info!("Data attribution repair v5 successfully completed.");

        Ok(())
    }

    pub fn get_kv(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let val = conn
            .query_row("SELECT v FROM vault_kv WHERE k = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(val)
    }

    pub fn set_kv(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        conn.execute(
            "INSERT INTO vault_kv (k, v) VALUES (?1, ?2)
             ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_raw_protos_for_sender(
        &self,
        sender_wire: &str,
        limit: usize,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT stanza_id, raw_decrypted_proto FROM messages
             WHERE sender_wire_jid = ?1 AND raw_decrypted_proto IS NOT NULL
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![sender_wire, limit as i64], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    pub fn is_risk_consent_accepted(&self) -> Result<bool> {
        Ok(self.get_kv("risk_consent_accepted")?.as_deref() == Some("true"))
    }

    pub fn set_risk_consent_accepted(&self, accepted: bool) -> Result<()> {
        self.set_kv(
            "risk_consent_accepted",
            if accepted { "true" } else { "false" },
        )
    }

    /// Resolves `(wire_jid, alt_jid)` into an immutable `CanonicalPeerId`, merging split
    /// `@lid` and `@s.whatsapp.net` records atomically if they were previously discovered separately.
    pub fn resolve_or_merge_peer(
        &self,
        wire_jid: &str,
        alt_jid: Option<&str>,
        push_name: Option<&str>,
    ) -> Result<CanonicalPeerId> {
        let mut conn = self.conn.lock().expect("vault mutex poisoned");
        let tx = conn.transaction()?;
        let id = Self::resolve_peer_tx(&tx, wire_jid, alt_jid, push_name)?;
        tx.commit()?;
        Ok(id)
    }

    /// Normalizes a WhatsApp JID by stripping any `:device` companion suffix (`user:12@server` -> `user@server`).
    pub fn normalize_wire_jid(raw: &str) -> String {
        let trimmed = raw.trim();
        if let Some((user_dev, server)) = trimmed.split_once('@') {
            let user = user_dev.split(':').next().unwrap_or(user_dev);
            format!("{user}@{server}")
        } else {
            trimmed.to_string()
        }
    }

    fn classify_pn_lid(a: Option<&str>, b: Option<&str>) -> (Option<String>, Option<String>) {
        let mut pn = None;
        let mut lid = None;
        for candidate in [a, b].into_iter().flatten() {
            let norm = Self::normalize_wire_jid(candidate);
            if norm.is_empty() {
                continue;
            }
            if norm.ends_with("@lid") {
                lid = Some(norm);
            } else if norm.ends_with("@s.whatsapp.net") {
                pn = Some(norm);
            } else if norm.chars().all(|c| c.is_ascii_digit()) {
                pn = Some(format!("{norm}@s.whatsapp.net"));
            }
        }
        (pn, lid)
    }

    fn human_jid_label(jid: &str) -> String {
        let user = jid.split('@').next().unwrap_or(jid);
        let user = user.split(':').next().unwrap_or(user);
        if jid.ends_with("@s.whatsapp.net")
            && !user.is_empty()
            && user.chars().all(|c| c.is_ascii_digit())
        {
            format!("+{user}")
        } else {
            user.to_string()
        }
    }

    fn is_placeholder_label(s: &str) -> bool {
        let trimmed = s.trim();
        trimmed.is_empty()
            || trimmed.starts_with('+')
            || trimmed.contains('@')
            || trimmed.contains('∙')
            || trimmed.chars().all(|c| c.is_ascii_digit())
    }

    fn get_self_identifiers_tx(tx: &rusqlite::Transaction<'_>) -> (Option<String>, Option<String>) {
        let pn: Option<String> = tx
            .query_row("SELECT v FROM vault_kv WHERE k = 'account_pn'", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()
            .ok()
            .flatten()
            .or_else(|| {
                tx.query_row("SELECT v FROM vault_kv WHERE k = 'account_jid'", [], |r| {
                    r.get::<_, String>(0)
                })
                .optional()
                .ok()
                .flatten()
            })
            .map(|j| Self::normalize_wire_jid(&j));

        let lid: Option<String> = tx
            .query_row("SELECT v FROM vault_kv WHERE k = 'account_lid'", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()
            .ok()
            .flatten()
            .map(|j| Self::normalize_wire_jid(&j));

        (pn, lid)
    }

    fn resolve_peer_tx(
        tx: &rusqlite::Transaction<'_>,
        wire_jid: &str,
        alt_jid: Option<&str>,
        push_name: Option<&str>,
    ) -> Result<CanonicalPeerId> {
        let now_ms = Utc::now().timestamp_millis();
        let norm_wire = Self::normalize_wire_jid(wire_jid);

        let (self_pn, self_lid) = Self::get_self_identifiers_tx(tx);
        let is_wire_self = self_pn.as_deref() == Some(&norm_wire)
            || self_lid.as_deref() == Some(&norm_wire)
            || norm_wire == "self";

        let clean_alt = alt_jid.and_then(|a| {
            let norm_a = Self::normalize_wire_jid(a);
            let is_alt_self = self_pn.as_deref() == Some(&norm_a)
                || self_lid.as_deref() == Some(&norm_a)
                || norm_a == "self";
            if !is_wire_self && is_alt_self {
                None // Drop poisoned self-alt on remote peer
            } else if is_wire_self && !is_alt_self {
                None // Drop remote-alt on self peer
            } else {
                Some(a)
            }
        });

        let (pn_opt, lid_opt) = Self::classify_pn_lid(Some(&norm_wire), clean_alt);
        let mut clean_push = push_name.map(str::trim).filter(|s| !s.is_empty());

        if !is_wire_self {
            let self_push: Option<String> = tx
                .query_row("SELECT v FROM vault_kv WHERE k = 'push_name'", [], |r| {
                    r.get(0)
                })
                .optional()
                .ok()
                .flatten();
            if let Some(ref p) = clean_push {
                if *p == "Rabimba Karanjai" || *p == "You" || self_push.as_deref() == Some(*p) {
                    clean_push = None;
                }
            }
        }

        let by_pn: Option<String> = if let Some(ref pn) = pn_opt {
            tx.query_row(
                "SELECT peer_id FROM peers WHERE pn_jid = ?1",
                params![pn],
                |r| r.get(0),
            )
            .optional()?
        } else {
            None
        };

        let by_lid: Option<String> = if let Some(ref lid) = lid_opt {
            tx.query_row(
                "SELECT peer_id FROM peers WHERE lid_jid = ?1",
                params![lid],
                |r| r.get(0),
            )
            .optional()?
        } else {
            None
        };

        // Fallback for group/newsletter/self JIDs that are neither @lid nor @s.whatsapp.net
        if pn_opt.is_none() && lid_opt.is_none() {
            let existing: Option<String> = tx
                .query_row(
                    "SELECT peer_id FROM peers WHERE pn_jid = ?1",
                    params![norm_wire],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(pid) = existing {
                if let Some(name) = clean_push {
                    tx.execute(
                        "UPDATE peers SET
                            push_name = ?1,
                            display_name = COALESCE(NULLIF(contact_name, ''), ?1),
                            updated_at_ms = ?2
                         WHERE peer_id = ?3",
                        params![name, now_ms, pid],
                    )?;
                }
                return CanonicalPeerId::parse(&pid);
            }
            let pid = CanonicalPeerId::new_v7();
            let label = clean_push
                .map(str::to_string)
                .unwrap_or_else(|| Self::human_jid_label(&norm_wire));
            tx.execute(
                "INSERT INTO peers (peer_id, pn_jid, lid_jid, display_name, push_name, updated_at_ms)
                 VALUES (?1, ?2, NULL, ?3, ?4, ?5)",
                params![pid.to_string(), norm_wire, label, clean_push, now_ms],
            )?;
            return Ok(pid);
        }

        match (by_pn, by_lid) {
            (Some(pn_peer), Some(lid_peer)) if pn_peer != lid_peer => {
                let is_pn_peer_self = tx
                    .query_row(
                        "SELECT 1 FROM peers WHERE peer_id = ?1 AND (pn_jid = ?2 OR lid_jid = ?3)",
                        params![
                            pn_peer,
                            self_pn.as_deref().unwrap_or(""),
                            self_lid.as_deref().unwrap_or("")
                        ],
                        |_| Ok(true),
                    )
                    .optional()?
                    .unwrap_or(false);
                let is_lid_peer_self = tx
                    .query_row(
                        "SELECT 1 FROM peers WHERE peer_id = ?1 AND (pn_jid = ?2 OR lid_jid = ?3)",
                        params![
                            lid_peer,
                            self_pn.as_deref().unwrap_or(""),
                            self_lid.as_deref().unwrap_or("")
                        ],
                        |_| Ok(true),
                    )
                    .optional()?
                    .unwrap_or(false);
                if is_pn_peer_self != is_lid_peer_self {
                    return CanonicalPeerId::parse(if is_wire_self {
                        if is_pn_peer_self { &pn_peer } else { &lid_peer }
                    } else {
                        if !is_pn_peer_self {
                            &pn_peer
                        } else {
                            &lid_peer
                        }
                    });
                }

                // Check for conflict: does lid_peer already have a different pn_jid?
                let lid_existing_pn: Option<String> = tx
                    .query_row(
                        "SELECT pn_jid FROM peers WHERE peer_id = ?1",
                        params![lid_peer],
                        |r| r.get(0),
                    )
                    .optional()?
                    .flatten();
                if let (Some(existing_pn), Some(new_pn)) =
                    (lid_existing_pn.as_deref(), pn_opt.as_deref())
                {
                    if existing_pn != new_pn {
                        return CanonicalPeerId::parse(if norm_wire.ends_with("@s.whatsapp.net") {
                            &pn_peer
                        } else {
                            &lid_peer
                        });
                    }
                }

                // Check for conflict: does pn_peer already have a different lid_jid?
                let pn_existing_lid: Option<String> = tx
                    .query_row(
                        "SELECT lid_jid FROM peers WHERE peer_id = ?1",
                        params![pn_peer],
                        |r| r.get(0),
                    )
                    .optional()?
                    .flatten();
                if let (Some(existing_lid), Some(new_lid)) =
                    (pn_existing_lid.as_deref(), lid_opt.as_deref())
                {
                    if existing_lid != new_lid {
                        return CanonicalPeerId::parse(if norm_wire.ends_with("@s.whatsapp.net") {
                            &pn_peer
                        } else {
                            &lid_peer
                        });
                    }
                }

                // Late @lid <-> @s.whatsapp.net discovery! Preserve contact_name, avatar, and about_status from lid_peer.
                let (lid_contact, lid_push, lid_avatar, lid_about): (
                    Option<String>,
                    Option<String>,
                    Option<String>,
                    Option<String>,
                ) = tx.query_row(
                    "SELECT contact_name, push_name, avatar_cache_key, about_status FROM peers WHERE peer_id = ?1",
                    params![lid_peer],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )?;

                tx.execute("DELETE FROM peers WHERE peer_id = ?1", params![lid_peer])?;
                tx.execute(
                    "UPDATE peers SET
                        lid_jid = COALESCE(?1, lid_jid),
                        contact_name = COALESCE(NULLIF(contact_name, ''), NULLIF(?2, '')),
                        push_name = COALESCE(NULLIF(?3, ''), NULLIF(push_name, ''), NULLIF(?4, '')),
                        avatar_cache_key = COALESCE(avatar_cache_key, ?5),
                        about_status = COALESCE(about_status, ?6),
                        display_name = CASE
                            WHEN ?10 = 1 THEN 'You'
                            ELSE COALESCE(
                                NULLIF(contact_name, ''),
                                NULLIF(?2, ''),
                                NULLIF(?3, ''),
                                NULLIF(push_name, ''),
                                NULLIF(?4, ''),
                                ?7,
                                display_name
                            )
                        END,
                        updated_at_ms = ?8
                     WHERE peer_id = ?9",
                    params![
                        lid_opt,
                        lid_contact,
                        clean_push,
                        lid_push,
                        lid_avatar,
                        lid_about,
                        pn_opt.as_deref().map(Self::human_jid_label),
                        now_ms,
                        pn_peer,
                        i32::from(is_wire_self)
                    ],
                )?;
                tx.execute(
                    "UPDATE messages SET sender_id = ?1 WHERE sender_id = ?2",
                    params![pn_peer, lid_peer],
                )?;
                tx.execute(
                    "UPDATE conversations SET peer_id = ?1 WHERE peer_id = ?2",
                    params![pn_peer, lid_peer],
                )?;
                tx.execute(
                    "UPDATE OR IGNORE reactions SET sender_id = ?1 WHERE sender_id = ?2",
                    params![pn_peer, lid_peer],
                )?;
                CanonicalPeerId::parse(&pn_peer)
            }
            (Some(existing), _) | (None, Some(existing)) => {
                tx.execute(
                    "UPDATE peers SET
                        pn_jid = COALESCE(?1, pn_jid),
                        lid_jid = COALESCE(?2, lid_jid),
                        push_name = COALESCE(?3, push_name),
                        display_name = CASE
                            WHEN ?7 = 1 THEN 'You'
                            ELSE COALESCE(
                                NULLIF(contact_name, ''),
                                NULLIF(?3, ''),
                                NULLIF(push_name, ''),
                                ?4,
                                display_name
                            )
                        END,
                        updated_at_ms = ?5
                     WHERE peer_id = ?6",
                    params![
                        pn_opt,
                        lid_opt,
                        clean_push,
                        pn_opt.as_deref().map(Self::human_jid_label),
                        now_ms,
                        existing,
                        i32::from(is_wire_self)
                    ],
                )?;
                CanonicalPeerId::parse(&existing)
            }
            (None, None) => {
                let pid = CanonicalPeerId::new_v7();
                let preferred_jid = pn_opt
                    .as_deref()
                    .or(lid_opt.as_deref())
                    .unwrap_or(&norm_wire);
                let display = if is_wire_self {
                    "You".to_string()
                } else {
                    clean_push
                        .map(str::to_string)
                        .unwrap_or_else(|| Self::human_jid_label(preferred_jid))
                };
                tx.execute(
                    "INSERT INTO peers (peer_id, pn_jid, lid_jid, display_name, push_name, updated_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        pid.to_string(),
                        pn_opt,
                        lid_opt,
                        display,
                        clean_push,
                        now_ms
                    ],
                )?;
                Ok(pid)
            }
        }
    }

    fn resolve_conversation_tx(
        tx: &rusqlite::Transaction<'_>,
        chat_wire_jid: &str,
        chat_alt_jid: Option<&str>,
        kind: ConversationKind,
        peer_id: Option<CanonicalPeerId>,
        title_hint: Option<&str>,
    ) -> Result<ConversationId> {
        let norm_chat = Self::normalize_wire_jid(chat_wire_jid);

        let (self_pn, self_lid) = Self::get_self_identifiers_tx(tx);
        let is_chat_self = self_pn.as_deref() == Some(&norm_chat)
            || self_lid.as_deref() == Some(&norm_chat)
            || norm_chat == "self";

        let clean_alt = chat_alt_jid.and_then(|a| {
            let norm_a = Self::normalize_wire_jid(a);
            let is_alt_self = self_pn.as_deref() == Some(&norm_a)
                || self_lid.as_deref() == Some(&norm_a)
                || norm_a == "self";
            if !is_chat_self && is_alt_self {
                None // Drop poisoned self-alt on remote conversation
            } else if is_chat_self && !is_alt_self {
                None // Drop remote-alt on self conversation
            } else {
                Some(a)
            }
        });

        let norm_alt = clean_alt
            .map(Self::normalize_wire_jid)
            .filter(|s| !s.is_empty() && s != &norm_chat);

        let peer_id = if kind == ConversationKind::DirectMessage {
            peer_id
                .or_else(|| Self::resolve_peer_tx(tx, &norm_chat, norm_alt.as_deref(), None).ok())
        } else {
            None
        };

        let find_alias = |jid: &str| -> Result<Option<String>> {
            Ok(tx
                .query_row(
                    "SELECT conversation_id FROM conversation_wire_aliases WHERE wire_jid = ?1",
                    params![jid],
                    |r| r.get(0),
                )
                .optional()?)
        };

        // Also check peer's known aliases so a DM arriving on @lid immediately finds an existing @s.whatsapp.net thread!
        let (peer_pn, peer_lid, peer_best_name, peer_avatar): (
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = if let Some(pid) = peer_id {
            tx.query_row(
                "SELECT pn_jid, lid_jid, COALESCE(NULLIF(contact_name, ''), NULLIF(display_name, '')), avatar_cache_key
                 FROM peers WHERE peer_id = ?1",
                params![pid.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
            .unwrap_or((None, None, None, None))
        } else {
            (None, None, None, None)
        };

        let effective_alt = norm_alt
            .or_else(|| {
                if is_chat_self {
                    if norm_chat.ends_with("@lid") {
                        self_pn.clone()
                    } else {
                        self_lid.clone()
                    }
                } else if norm_chat.ends_with("@lid") {
                    peer_pn.clone()
                } else if norm_chat.ends_with("@s.whatsapp.net") {
                    peer_lid.clone()
                } else {
                    None
                }
            })
            .filter(|alt| {
                let is_alt_self = self_pn.as_deref() == Some(alt.as_str())
                    || self_lid.as_deref() == Some(alt.as_str())
                    || alt == "self";
                if !is_chat_self && is_alt_self {
                    false
                } else if is_chat_self && !is_alt_self {
                    false
                } else {
                    true
                }
            });

        let conv_a = find_alias(&norm_chat)?.or(find_alias(chat_wire_jid)?);
        let conv_b = match effective_alt.as_deref() {
            Some(alt) => find_alias(alt)?,
            None => None,
        };

        let kind_str = serde_json::to_string(&kind)?;
        let preferred_wire = if let Some(ref alt) = effective_alt
            && alt.ends_with("@s.whatsapp.net")
        {
            alt.as_str()
        } else {
            norm_chat.as_str()
        };

        // Prefer saved contact/peer name over raw push_name hint on DMs!
        let resolved_title_hint: Option<String> = if kind == ConversationKind::DirectMessage {
            if is_chat_self {
                Some("You (Message Yourself)".to_string())
            } else {
                match (&peer_best_name, title_hint.filter(|s| !s.trim().is_empty())) {
                    (Some(p_name), _) if !Self::is_placeholder_label(p_name) => {
                        Some(p_name.clone())
                    }
                    (_, Some(h)) if !Self::is_placeholder_label(h) => Some(h.trim().to_string()),
                    (Some(p_name), _) => Some(p_name.clone()),
                    (_, Some(h)) => Some(h.trim().to_string()),
                    (None, None) => None,
                }
            }
        } else {
            title_hint
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };

        let insert_alias_safe = |tx: &rusqlite::Transaction<'_>,
                                 wire: &str,
                                 target_cid: &str|
         -> Result<()> {
            let is_wire_self = self_pn.as_deref() == Some(wire)
                || self_lid.as_deref() == Some(wire)
                || wire == "self";
            if is_chat_self != is_wire_self {
                return Ok(()); // Reject alias mismatch
            }
            tx.execute(
                    "INSERT OR IGNORE INTO conversation_wire_aliases (wire_jid, conversation_id) VALUES (?1, ?2)",
                    params![wire, target_cid],
                )?;
            Ok(())
        };

        match (conv_a, conv_b) {
            (Some(ca), Some(cb)) if ca != cb => {
                let primary_ca: String = tx.query_row(
                    "SELECT primary_wire_jid FROM conversations WHERE conversation_id = ?1",
                    params![ca],
                    |r| r.get(0),
                )?;
                let primary_cb: String = tx.query_row(
                    "SELECT primary_wire_jid FROM conversations WHERE conversation_id = ?1",
                    params![cb],
                    |r| r.get(0),
                )?;

                let is_ca_self = self_pn.as_deref() == Some(&primary_ca)
                    || self_lid.as_deref() == Some(&primary_ca)
                    || primary_ca == "self";
                let is_cb_self = self_pn.as_deref() == Some(&primary_cb)
                    || self_lid.as_deref() == Some(&primary_cb)
                    || primary_cb == "self";

                // Self conversation isolation: Never merge self and remote!
                if is_ca_self != is_cb_self {
                    return Ok(ConversationId::parse(if is_chat_self {
                        if is_ca_self { &ca } else { &cb }
                    } else if !is_ca_self {
                        &ca
                    } else {
                        &cb
                    })?);
                }

                // Phone number isolation: Never merge two different @s.whatsapp.net conversations!
                if primary_ca.ends_with("@s.whatsapp.net")
                    && primary_cb.ends_with("@s.whatsapp.net")
                    && primary_ca != primary_cb
                {
                    return Ok(ConversationId::parse(&ca)?);
                }

                // Keep whichever conversation is anchored to @s.whatsapp.net, merging the @lid thread into it!
                let (keep, drop_conv) = if norm_chat.ends_with("@s.whatsapp.net") {
                    (ca, cb)
                } else {
                    (cb, ca)
                };
                let (drop_last_ms, drop_sub, drop_unread, drop_avatar): (
                    Option<i64>,
                    String,
                    i64,
                    Option<String>,
                ) = tx.query_row(
                    "SELECT last_message_ms, subtitle_preview, unread_count, avatar_cache_key
                     FROM conversations WHERE conversation_id = ?1",
                    params![drop_conv],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )?;

                // A message can arrive under both a phone JID and a @lid with the
                // same sender + stanza id. UPDATE OR IGNORE would leave that copy in
                // the dropped thread, where ON DELETE CASCADE would silently delete
                // a real message. Deduplicate explicitly before moving anything.
                tx.execute(
                    "DELETE FROM messages WHERE conversation_id = ?1 AND EXISTS (
                        SELECT 1 FROM messages k
                         WHERE k.conversation_id = ?2
                           AND k.sender_wire_jid = messages.sender_wire_jid
                           AND k.stanza_id = messages.stanza_id
                     )",
                    params![drop_conv, keep],
                )?;
                // Drop FTS rows for those deleted messages before repointing the rest.
                tx.execute(
                    "DELETE FROM messages_fts WHERE local_id NOT IN (SELECT local_id FROM messages)",
                    [],
                )?;
                tx.execute(
                    "UPDATE messages SET conversation_id = ?1 WHERE conversation_id = ?2",
                    params![keep, drop_conv],
                )?;
                tx.execute(
                    "UPDATE messages_fts SET conversation_id = ?1 WHERE conversation_id = ?2",
                    params![keep, drop_conv],
                )?;
                // Reactions share the same composite-key collision shape.
                tx.execute(
                    "DELETE FROM reactions WHERE conversation_id = ?1 AND EXISTS (
                        SELECT 1 FROM reactions k
                         WHERE k.conversation_id = ?2
                           AND k.target_stanza_id = reactions.target_stanza_id
                           AND k.sender_id = reactions.sender_id
                     )",
                    params![drop_conv, keep],
                )?;
                tx.execute(
                    "UPDATE reactions SET conversation_id = ?1 WHERE conversation_id = ?2",
                    params![keep, drop_conv],
                )?;
                tx.execute(
                    "UPDATE conversation_wire_aliases SET conversation_id = ?1 WHERE conversation_id = ?2",
                    params![keep, drop_conv],
                )?;
                tx.execute(
                    "DELETE FROM conversations WHERE conversation_id = ?1",
                    params![drop_conv],
                )?;
                tx.execute(
                    "UPDATE conversations SET
                        primary_wire_jid = ?1,
                        peer_id = COALESCE(?2, peer_id),
                        title = COALESCE(?3, title),
                        subtitle_preview = CASE WHEN COALESCE(?4, 0) > COALESCE(last_message_ms, 0) THEN ?5 ELSE subtitle_preview END,
                        last_message_ms = MAX(COALESCE(last_message_ms, 0), COALESCE(?4, 0)),
                        unread_count = unread_count + ?6,
                        avatar_cache_key = COALESCE(avatar_cache_key, ?7, ?8)
                     WHERE conversation_id = ?9",
                    params![
                        preferred_wire,
                        peer_id.map(|p| p.to_string()),
                        resolved_title_hint,
                        drop_last_ms,
                        drop_sub,
                        drop_unread,
                        drop_avatar,
                        peer_avatar,
                        keep
                    ],
                )?;
                ConversationId::parse(&keep)
            }
            (Some(existing), _) | (None, Some(existing)) => {
                insert_alias_safe(tx, &norm_chat, &existing)?;
                if chat_wire_jid != norm_chat {
                    insert_alias_safe(tx, chat_wire_jid, &existing)?;
                }
                if let Some(ref alt) = effective_alt {
                    insert_alias_safe(tx, alt, &existing)?;
                }
                if preferred_wire.ends_with("@s.whatsapp.net") {
                    tx.execute(
                        "UPDATE OR IGNORE conversations SET primary_wire_jid = ?1 WHERE conversation_id = ?2",
                        params![preferred_wire, existing],
                    )?;
                }
                if let Some(pid) = peer_id {
                    tx.execute(
                        "UPDATE conversations SET peer_id = COALESCE(peer_id, ?1), avatar_cache_key = COALESCE(avatar_cache_key, ?2) WHERE conversation_id = ?3",
                        params![pid.to_string(), peer_avatar, existing],
                    )?;
                }
                if is_chat_self {
                    tx.execute(
                        "UPDATE conversations SET title = 'You (Message Yourself)' WHERE conversation_id = ?1",
                        params![existing],
                    )?;
                } else if let Some(ref title) = resolved_title_hint
                    && !Self::is_placeholder_label(title)
                {
                    // Upgrade placeholder or stale pushname titles cleanly
                    tx.execute(
                        "UPDATE conversations SET title = ?1 WHERE conversation_id = ?2
                         AND (title LIKE '+%' OR title GLOB '[0-9]*' OR title LIKE '%@%' OR title LIKE '%∙%' OR title = 'Rabimba Karanjai' OR ?3 = 1)",
                        params![
                            title,
                            existing,
                            i32::from(kind == ConversationKind::Group)
                        ],
                    )?;
                }
                ConversationId::parse(&existing)
            }
            (None, None) => {
                let cid = ConversationId::new_v7();
                let cid_str = cid.to_string();
                let title = if is_chat_self {
                    "You (Message Yourself)".to_string()
                } else {
                    resolved_title_hint.unwrap_or_else(|| Self::human_jid_label(preferred_wire))
                };
                tx.execute(
                    "INSERT INTO conversations (
                        conversation_id, kind, primary_wire_jid, peer_id, title, subtitle_preview, avatar_cache_key
                    ) VALUES (?1, ?2, ?3, ?4, ?5, '', ?6)",
                    params![
                        cid_str,
                        kind_str,
                        preferred_wire,
                        peer_id.map(|p| p.to_string()),
                        title,
                        peer_avatar
                    ],
                )?;
                insert_alias_safe(tx, &norm_chat, &cid_str)?;
                if chat_wire_jid != norm_chat {
                    insert_alias_safe(tx, chat_wire_jid, &cid_str)?;
                }
                if let Some(ref alt) = effective_alt {
                    insert_alias_safe(tx, alt, &cid_str)?;
                }
                Ok(cid)
            }
        }
    }

    pub fn ensure_conversation(
        &self,
        chat_wire_jid: &str,
        chat_alt_jid: Option<&str>,
        kind: ConversationKind,
        title_hint: Option<&str>,
    ) -> Result<ConversationId> {
        let mut conn = self.conn.lock().expect("vault mutex poisoned");
        let tx = conn.transaction()?;
        let peer_id = if kind == ConversationKind::DirectMessage {
            Some(Self::resolve_peer_tx(
                &tx,
                chat_wire_jid,
                chat_alt_jid,
                title_hint,
            )?)
        } else {
            None
        };
        let cid = Self::resolve_conversation_tx(
            &tx,
            chat_wire_jid,
            chat_alt_jid,
            kind,
            peer_id,
            title_hint,
        )?;
        tx.commit()?;
        Ok(cid)
    }

    /// Commits a batch of inbound or历史 messages in a single WAL transaction.
    /// Designed to be called directly inside `whatsapp-rust`'s `InboundDurabilityHook`
    /// BEFORE network `<receipt>` ACKs are sent.
    pub fn commit_inbound_batch(
        &self,
        records: &[InboundCommitRecord],
    ) -> Result<Vec<ConversationId>> {
        if records.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = self.conn.lock().expect("vault mutex poisoned");
        let tx = conn.transaction()?;
        let mut touched = Vec::new();

        for rec in records {
            let sender_peer = Self::resolve_peer_tx(
                &tx,
                &rec.sender_wire_jid,
                rec.sender_alt_jid.as_deref(),
                rec.sender_push_name.as_deref(),
            )?;
            let dm_peer = if rec.chat_kind == ConversationKind::DirectMessage {
                Some(Self::resolve_peer_tx(
                    &tx,
                    &rec.chat_wire_jid,
                    rec.chat_alt_jid.as_deref(),
                    if rec.is_from_me {
                        None
                    } else {
                        rec.chat_title_hint.as_deref()
                    },
                )?)
            } else {
                None
            };
            let conv_id = Self::resolve_conversation_tx(
                &tx,
                &rec.chat_wire_jid,
                rec.chat_alt_jid.as_deref(),
                rec.chat_kind,
                dm_peer,
                rec.chat_title_hint.as_deref(),
            )?;

            let sender_display: String = if rec.is_from_me {
                "You".to_string()
            } else {
                tx.query_row(
                    "SELECT display_name FROM peers WHERE peer_id = ?1",
                    params![sender_peer.to_string()],
                    |r| r.get(0),
                )
                .unwrap_or_else(|_| Self::human_jid_label(&rec.sender_wire_jid))
            };

            let norm_sender_wire = Self::normalize_wire_jid(&rec.sender_wire_jid);
            let local_id = uuid::Uuid::now_v7().to_string();
            let delivery_json = serde_json::to_string(&rec.delivery)?;
            let content_json = serde_json::to_string(&rec.content)?;
            let quoted_json = rec.quoted.as_ref().map(serde_json::to_string).transpose()?;
            let fts_indexed = if rec.defer_fts { 0 } else { 1 };

            let inserted = tx.execute(
                "INSERT INTO messages (
                    local_id, conversation_id, stanza_id, sender_id, sender_wire_jid,
                    sender_display, is_from_me, timestamp_ms, sort_key, delivery_json,
                    content_json, quoted_json, raw_decrypted_proto, parser_schema_version, fts_indexed
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
                ON CONFLICT(conversation_id, sender_wire_jid, stanza_id) DO UPDATE SET
                    delivery_json = excluded.delivery_json,
                    content_json = excluded.content_json,
                    quoted_json = COALESCE(excluded.quoted_json, messages.quoted_json),
                    raw_decrypted_proto = CASE
                        WHEN length(excluded.raw_decrypted_proto) > 0 THEN excluded.raw_decrypted_proto
                        ELSE messages.raw_decrypted_proto
                    END,
                    fts_indexed = excluded.fts_indexed
                WHERE messages.delivery_json LIKE '%decrypt_pending%'",
                params![
                    local_id,
                    conv_id.to_string(),
                    rec.stanza_id,
                    sender_peer.to_string(),
                    norm_sender_wire,
                    sender_display,
                    i32::from(rec.is_from_me),
                    rec.timestamp_ms,
                    rec.timestamp_ms,
                    delivery_json,
                    content_json,
                    quoted_json,
                    rec.raw_decrypted_proto,
                    PARSER_SCHEMA_VERSION,
                    fts_indexed
                ],
            )?;

            if inserted > 0 {
                if !rec.defer_fts {
                    let searchable = rec.content.searchable_text();
                    if !searchable.is_empty() {
                        let actual_local_id: String = tx
                            .query_row(
                                "SELECT local_id FROM messages WHERE conversation_id = ?1 AND sender_wire_jid = ?2 AND stanza_id = ?3",
                                params![conv_id.to_string(), norm_sender_wire, rec.stanza_id],
                                |r| r.get(0),
                            )
                            .unwrap_or_else(|_| local_id.clone());
                        tx.execute(
                            "DELETE FROM messages_fts WHERE local_id = ?1",
                            params![actual_local_id],
                        )?;
                        tx.execute(
                            "INSERT INTO messages_fts (local_id, conversation_id, stanza_id, sender_display, body_text)
                             VALUES (?1, ?2, ?3, ?4, ?5)",
                            params![
                                actual_local_id,
                                conv_id.to_string(),
                                rec.stanza_id,
                                sender_display,
                                searchable
                            ],
                        )?;
                    }
                }

                let preview = rec.content.preview_text();
                let unread_inc = if rec.is_from_me || rec.defer_fts {
                    0
                } else {
                    1
                };
                tx.execute(
                    "UPDATE conversations SET
                        subtitle_preview = CASE WHEN COALESCE(last_message_ms, 0) <= ?1 THEN ?2 ELSE subtitle_preview END,
                        last_message_ms = MAX(COALESCE(last_message_ms, 0), ?1),
                        unread_count = unread_count + ?3
                     WHERE conversation_id = ?4",
                    params![rec.timestamp_ms, preview, unread_inc, conv_id.to_string()],
                )?;

                if !touched.contains(&conv_id) {
                    touched.push(conv_id);
                }
            }
        }

        tx.commit()?;
        Ok(touched)
    }

    /// Queues an outbound user message into the local outbox immediately so the UI
    /// updates in `<16 ms` even while offline or paced.
    pub fn insert_outbound_queued(
        &self,
        conversation_id: ConversationId,
        local_id: &str,
        content: &MessageContent,
        quoted: Option<&QuotedReplyRef>,
    ) -> Result<()> {
        let now_ms = Utc::now().timestamp_millis();
        let delivery_json = serde_json::to_string(&DeliveryState::Queued)?;
        let content_json = serde_json::to_string(content)?;
        let quoted_json = quoted.map(serde_json::to_string).transpose()?;
        let preview = content.preview_text();
        let searchable = content.searchable_text();

        let mut conn = self.conn.lock().expect("vault mutex poisoned");
        let tx = conn.transaction()?;
        let self_peer = CanonicalPeerId(uuid::Uuid::nil()).to_string();

        tx.execute(
            "INSERT INTO messages (
                local_id, conversation_id, stanza_id, sender_id, sender_wire_jid,
                sender_display, is_from_me, timestamp_ms, sort_key, delivery_json,
                content_json, quoted_json, raw_decrypted_proto, parser_schema_version, fts_indexed
            ) VALUES (?1, ?2, ?3, ?4, 'self', 'You', 1, ?5, ?5, ?6, ?7, ?8, NULL, ?9, 1)",
            params![
                local_id,
                conversation_id.to_string(),
                local_id,
                self_peer,
                now_ms,
                delivery_json,
                content_json,
                quoted_json,
                PARSER_SCHEMA_VERSION
            ],
        )?;

        if !searchable.is_empty() {
            tx.execute(
                "INSERT INTO messages_fts (local_id, conversation_id, stanza_id, sender_display, body_text)
                 VALUES (?1, ?2, ?3, 'You', ?4)",
                params![local_id, conversation_id.to_string(), local_id, searchable],
            )?;
        }

        tx.execute(
            "UPDATE conversations SET subtitle_preview = ?1, last_message_ms = ?2, unread_count = 0
             WHERE conversation_id = ?3",
            params![preview, now_ms, conversation_id.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn update_outbound_sent(
        &self,
        local_id: &str,
        server_stanza_id: &str,
        delivery: DeliveryState,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let delivery_json = serde_json::to_string(&delivery)?;
        conn.execute(
            "UPDATE messages SET stanza_id = ?1, delivery_json = ?2 WHERE local_id = ?3",
            params![server_stanza_id, delivery_json, local_id],
        )?;
        conn.execute(
            "UPDATE messages_fts SET stanza_id = ?1 WHERE local_id = ?2",
            params![server_stanza_id, local_id],
        )?;
        Ok(())
    }

    pub fn update_delivery_by_stanza(
        &self,
        chat_wire_jid: &str,
        stanza_id: &str,
        delivery: DeliveryState,
    ) -> Result<Option<ConversationId>> {
        let norm_jid = Self::normalize_wire_jid(chat_wire_jid);
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let conv_str: Option<String> = conn
            .query_row(
                "SELECT conversation_id FROM conversation_wire_aliases WHERE wire_jid = ?1 OR wire_jid = ?2 LIMIT 1",
                params![norm_jid, chat_wire_jid],
                |r| r.get(0),
            )
            .optional()?;
        let Some(conv_str) = conv_str else {
            return Ok(None);
        };
        let delivery_json = serde_json::to_string(&delivery)?;
        conn.execute(
            "UPDATE messages SET delivery_json = ?1 WHERE conversation_id = ?2 AND stanza_id = ?3",
            params![delivery_json, conv_str, stanza_id],
        )?;
        Ok(Some(ConversationId::parse(&conv_str)?))
    }

    pub fn apply_message_edit(
        &self,
        conversation_id: ConversationId,
        stanza_id: &str,
        new_body: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let existing_lp: Option<LinkPreviewCard> = conn
            .query_row(
                "SELECT content_json FROM messages WHERE conversation_id = ?1 AND stanza_id = ?2 LIMIT 1",
                params![conversation_id.to_string(), stanza_id],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .and_then(|s| serde_json::from_str::<MessageContent>(&s).ok())
            .and_then(|mc| match mc {
                MessageContent::Text { link_preview, .. } => link_preview,
                _ => None,
            });

        let new_content = MessageContent::Text {
            body: new_body.to_string(),
            edited_at: Some(Utc::now()),
            link_preview: existing_lp,
        };
        let content_json = serde_json::to_string(&new_content)?;
        conn.execute(
            "UPDATE messages SET content_json = ?1 WHERE conversation_id = ?2 AND stanza_id = ?3",
            params![content_json, conversation_id.to_string(), stanza_id],
        )?;
        conn.execute(
            "UPDATE messages_fts SET body_text = ?1 WHERE conversation_id = ?2 AND stanza_id = ?3",
            params![new_body, conversation_id.to_string(), stanza_id],
        )?;
        Ok(())
    }

    pub fn apply_message_revoke(
        &self,
        conversation_id: ConversationId,
        stanza_id: &str,
    ) -> Result<()> {
        let delivery_json = serde_json::to_string(&DeliveryState::Revoked)?;
        let revoked_content = MessageContent::Text {
            body: "This message was deleted".to_string(),
            edited_at: None,
            link_preview: None,
        };
        let content_json = serde_json::to_string(&revoked_content)?;
        let conn = self.conn.lock().expect("vault mutex poisoned");
        conn.execute(
            "UPDATE messages SET delivery_json = ?1, content_json = ?2 WHERE conversation_id = ?3 AND stanza_id = ?4",
            params![
                delivery_json,
                content_json,
                conversation_id.to_string(),
                stanza_id
            ],
        )?;
        conn.execute(
            "DELETE FROM messages_fts WHERE conversation_id = ?1 AND stanza_id = ?2",
            params![conversation_id.to_string(), stanza_id],
        )?;
        Ok(())
    }

    pub fn upsert_reaction(
        &self,
        conversation_id: ConversationId,
        target_stanza_id: &str,
        sender_id: CanonicalPeerId,
        emoji: &str,
        is_from_me: bool,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        if emoji.is_empty() {
            conn.execute(
                "DELETE FROM reactions WHERE conversation_id = ?1 AND target_stanza_id = ?2 AND sender_id = ?3",
                params![
                    conversation_id.to_string(),
                    target_stanza_id,
                    sender_id.to_string()
                ],
            )?;
        } else {
            conn.execute(
                "INSERT INTO reactions (conversation_id, target_stanza_id, sender_id, emoji, is_from_me, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(conversation_id, target_stanza_id, sender_id)
                 DO UPDATE SET emoji = excluded.emoji, updated_at_ms = excluded.updated_at_ms",
                params![
                    conversation_id.to_string(),
                    target_stanza_id,
                    sender_id.to_string(),
                    emoji,
                    i32::from(is_from_me),
                    Utc::now().timestamp_millis()
                ],
            )?;
        }
        Ok(())
    }

    pub fn mark_conversation_read(&self, conversation_id: ConversationId) -> Result<()> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        conn.execute(
            "UPDATE conversations SET unread_count = 0 WHERE conversation_id = ?1",
            params![conversation_id.to_string()],
        )?;
        Ok(())
    }

    pub fn conversation_primary_jid(&self, conversation_id: ConversationId) -> Result<String> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let jid: String = conn.query_row(
            "SELECT primary_wire_jid FROM conversations WHERE conversation_id = ?1",
            params![conversation_id.to_string()],
            |r| r.get(0),
        )?;
        Ok(jid)
    }

    /// Upserts an address-book contact, pushname, or `@lid` <-> `@s.whatsapp.net` mapping,
    /// merging split peer/conversation rows and retroactively propagating `display_name`
    /// (`contact_name > push_name > +phone`) to existing DM titles and timeline sender labels.
    pub fn upsert_contact(
        &self,
        pn_jid: Option<&str>,
        lid_jid: Option<&str>,
        contact_name: Option<&str>,
        push_name: Option<&str>,
    ) -> Result<CanonicalPeerId> {
        let (pn_norm, lid_norm) = Self::classify_pn_lid(pn_jid, lid_jid);
        let primary = pn_norm
            .as_deref()
            .or(lid_norm.as_deref())
            .or_else(|| pn_jid.filter(|s| !s.trim().is_empty()))
            .or_else(|| lid_jid.filter(|s| !s.trim().is_empty()))
            .ok_or_else(|| anyhow::anyhow!("upsert_contact requires at least one JID"))?;

        let alt = if pn_norm.is_some() {
            lid_norm.as_deref()
        } else {
            None
        };

        let clean_contact = contact_name.map(str::trim).filter(|s| !s.is_empty());
        let clean_push = push_name.map(str::trim).filter(|s| !s.is_empty());

        let mut conn = self.conn.lock().expect("vault mutex poisoned");
        let tx = conn.transaction()?;

        let pid = Self::resolve_peer_tx(&tx, primary, alt, clean_push)?;
        let pid_str = pid.to_string();
        let now_ms = Utc::now().timestamp_millis();

        tx.execute(
            "UPDATE peers SET
                contact_name = COALESCE(?1, contact_name),
                push_name = COALESCE(?2, push_name),
                display_name = COALESCE(
                    NULLIF(?1, ''),
                    NULLIF(contact_name, ''),
                    NULLIF(?2, ''),
                    NULLIF(push_name, ''),
                    ?3,
                    display_name
                ),
                updated_at_ms = ?4
             WHERE peer_id = ?5",
            params![
                clean_contact,
                clean_push,
                pn_norm.as_deref().map(Self::human_jid_label),
                now_ms,
                pid_str
            ],
        )?;

        let (final_pn, final_lid, final_display, final_contact, final_avatar): (
            Option<String>,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
        ) = tx.query_row(
            "SELECT pn_jid, lid_jid, display_name, contact_name, avatar_cache_key FROM peers WHERE peer_id = ?1",
            params![pid_str],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;

        // If an existing DM conversation already exists under either alias, merge split @lid/@s.whatsapp.net threads!
        if let (Some(pn), Some(lid)) = (&final_pn, &final_lid) {
            let has_existing_dm: Option<String> = tx
                .query_row(
                    "SELECT conversation_id FROM conversation_wire_aliases WHERE wire_jid = ?1 OR wire_jid = ?2 LIMIT 1",
                    params![pn, lid],
                    |r| r.get(0),
                )
                .optional()?;
            if has_existing_dm.is_some() {
                let _ = Self::resolve_conversation_tx(
                    &tx,
                    pn,
                    Some(lid),
                    ConversationKind::DirectMessage,
                    Some(pid),
                    Some(&final_display),
                )?;
            }
        }

        // Retroactively propagate saved contact / pushname to existing DirectMessage threads!
        let dm_kind_json = serde_json::to_string(&ConversationKind::DirectMessage)?;
        tx.execute(
            "UPDATE conversations SET
                peer_id = ?1,
                title = CASE
                    WHEN ?2 IS NOT NULL AND ?2 != '' THEN ?2
                    WHEN NOT (?3 GLOB '[0-9]*' OR ?3 LIKE '%@%') THEN ?3
                    WHEN title GLOB '[0-9]*' OR title LIKE '%@%' THEN ?3
                    ELSE title
                END,
                avatar_cache_key = COALESCE(conversations.avatar_cache_key, ?4)
             WHERE kind = ?5
               AND (
                   peer_id = ?1
                   OR conversation_id IN (
                       SELECT conversation_id FROM conversation_wire_aliases
                       WHERE wire_jid = COALESCE(?6, '') OR wire_jid = COALESCE(?7, '')
                   )
               )",
            params![
                pid_str,
                final_contact,
                final_display,
                final_avatar,
                dm_kind_json,
                final_pn,
                final_lid
            ],
        )?;

        // Retroactively propagate sender_display onto historical messages & FTS5 rows!
        if !Self::is_placeholder_label(&final_display) {
            let msg_updated = tx.execute(
                "UPDATE messages SET sender_id = ?1, sender_display = ?2
                 WHERE is_from_me = 0
                   AND (
                       sender_id = ?1
                       OR sender_wire_jid = COALESCE(?3, '')
                       OR sender_wire_jid = COALESCE(?4, '')
                   )",
                params![pid_str, final_display, final_pn, final_lid],
            )?;
            if msg_updated > 0 {
                tx.execute(
                    "UPDATE messages_fts SET sender_display = ?1
                     WHERE local_id IN (
                         SELECT local_id FROM messages WHERE is_from_me = 0 AND sender_id = ?2
                     )",
                    params![final_display, pid_str],
                )?;
            }
        }

        tx.commit()?;
        Ok(pid)
    }

    pub fn update_group_metadata(
        &self,
        group_jid: &str,
        subject: &str,
        participant_count: Option<u32>,
    ) -> Result<ConversationId> {
        let norm_gid = Self::normalize_wire_jid(group_jid);
        let clean_subj = subject.trim();
        let mut conn = self.conn.lock().expect("vault mutex poisoned");
        let tx = conn.transaction()?;
        let cid = Self::resolve_conversation_tx(
            &tx,
            &norm_gid,
            None,
            ConversationKind::Group,
            None,
            (!clean_subj.is_empty()).then_some(clean_subj),
        )?;
        tx.execute(
            "UPDATE conversations SET
                title = CASE WHEN ?1 != '' THEN ?1 ELSE title END,
                participant_count = COALESCE(?2, participant_count)
             WHERE conversation_id = ?3",
            params![clean_subj, participant_count, cid.to_string()],
        )?;
        tx.commit()?;
        Ok(cid)
    }

    pub fn set_conversation_flags(
        &self,
        wire_jid: &str,
        pinned: Option<bool>,
        muted: Option<bool>,
        archived: Option<bool>,
        mark_read: Option<bool>,
    ) -> Result<Option<ConversationId>> {
        let norm_jid = Self::normalize_wire_jid(wire_jid);
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let cid_str: Option<String> = conn
            .query_row(
                "SELECT conversation_id FROM conversation_wire_aliases WHERE wire_jid = ?1 OR wire_jid = ?2 LIMIT 1",
                params![norm_jid, wire_jid],
                |r| r.get(0),
            )
            .optional()?;
        let Some(cid_str) = cid_str else {
            return Ok(None);
        };
        conn.execute(
            "UPDATE conversations SET
                is_pinned = COALESCE(?1, is_pinned),
                is_muted = COALESCE(?2, is_muted),
                is_archived = COALESCE(?3, is_archived),
                unread_count = CASE
                    WHEN ?4 = 1 THEN 0
                    WHEN ?4 = 0 AND unread_count = 0 THEN 1
                    ELSE unread_count
                END
             WHERE conversation_id = ?5",
            params![
                pinned.map(i32::from),
                muted.map(i32::from),
                archived.map(i32::from),
                mark_read.map(i32::from),
                cid_str
            ],
        )?;
        Ok(Some(ConversationId::parse(&cid_str)?))
    }

    pub fn set_peer_about(&self, wire_jid: &str, status: &str) -> Result<()> {
        let norm_jid = Self::normalize_wire_jid(wire_jid);
        let conn = self.conn.lock().expect("vault mutex poisoned");
        conn.execute(
            "UPDATE peers SET about_status = ?1, updated_at_ms = ?2
             WHERE pn_jid = ?3 OR lid_jid = ?3",
            params![status.trim(), Utc::now().timestamp_millis(), norm_jid],
        )?;
        Ok(())
    }

    pub fn list_contacts(&self) -> Result<Vec<PeerIdentityRecord>> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT peer_id, pn_jid, lid_jid, display_name, push_name,
                    contact_name, avatar_cache_key, about_status, updated_at_ms
             FROM peers
             WHERE COALESCE(pn_jid, '') != 'self'
               AND COALESCE(pn_jid, '') NOT LIKE '%@g.us'
               AND COALESCE(pn_jid, '') NOT LIKE '%@newsletter'
               AND COALESCE(pn_jid, '') != 'status@broadcast'
               AND (pn_jid IS NOT NULL OR lid_jid IS NOT NULL)
             ORDER BY
               CASE WHEN contact_name IS NOT NULL AND contact_name != '' THEN 0 ELSE 1 END ASC,
               display_name COLLATE NOCASE ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, i64>(8)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (
                pid_s,
                pn_jid,
                lid_jid,
                display_name,
                push_name,
                contact_name,
                avatar_cache_key,
                about_status,
                ts_ms,
            ) = row?;
            out.push(PeerIdentityRecord {
                peer_id: CanonicalPeerId::parse(&pid_s)?,
                pn_jid,
                lid_jid,
                display_name,
                push_name,
                contact_name,
                avatar_cache_key: avatar_cache_key.filter(|s| !s.is_empty()),
                about_status,
                updated_at: Utc
                    .timestamp_millis_opt(ts_ms)
                    .single()
                    .unwrap_or_else(Utc::now),
            });
        }
        Ok(out)
    }

    /// Encrypts & stores a contact/group profile picture under `avatar:<blake3(norm_jid)>`,
    /// linking it onto both matching `peers` and `conversations` rows.
    pub fn store_avatar_for_jid(&self, wire_jid: &str, bytes: &[u8]) -> Result<String> {
        let norm_jid = Self::normalize_wire_jid(wire_jid);
        let cache_key = format!("avatar:{}", blake3::hash(norm_jid.as_bytes()).to_hex());
        self.store_encrypted_media(&cache_key, bytes)?;

        let conn = self.conn.lock().expect("vault mutex poisoned");
        conn.execute(
            "UPDATE peers SET avatar_cache_key = ?1 WHERE pn_jid = ?2 OR lid_jid = ?2",
            params![cache_key, norm_jid],
        )?;
        conn.execute(
            "UPDATE conversations SET avatar_cache_key = ?1
             WHERE primary_wire_jid = ?2
                OR conversation_id IN (
                    SELECT conversation_id FROM conversation_wire_aliases WHERE wire_jid = ?2
                )
                OR peer_id IN (
                    SELECT peer_id FROM peers WHERE pn_jid = ?2 OR lid_jid = ?2
                )",
            params![cache_key, norm_jid],
        )?;
        Ok(cache_key)
    }

    pub fn clear_avatar_for_jid(&self, wire_jid: &str) -> Result<()> {
        let norm_jid = Self::normalize_wire_jid(wire_jid);
        let conn = self.conn.lock().expect("vault mutex poisoned");
        conn.execute(
            "UPDATE peers SET avatar_cache_key = '' WHERE pn_jid = ?1 OR lid_jid = ?1",
            params![norm_jid],
        )?;
        conn.execute(
            "UPDATE conversations SET avatar_cache_key = ''
             WHERE primary_wire_jid = ?1
                OR conversation_id IN (
                    SELECT conversation_id FROM conversation_wire_aliases WHERE wire_jid = ?1
                )",
            params![norm_jid],
        )?;
        Ok(())
    }

    pub fn mark_avatar_absent_for_jid(&self, wire_jid: &str) -> Result<()> {
        self.clear_avatar_for_jid(wire_jid)
    }

    pub fn jids_missing_avatars(&self, limit: usize) -> Result<Vec<String>> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let mut out = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT c.primary_wire_jid
                 FROM conversations c
                 LEFT JOIN peers p ON p.peer_id = c.peer_id
                 WHERE COALESCE(c.avatar_cache_key, p.avatar_cache_key) IS NULL
                   AND c.primary_wire_jid != 'status@broadcast'
                   AND c.primary_wire_jid != 'self'
                 ORDER BY c.is_pinned DESC, COALESCE(c.last_message_ms, 0) DESC
                 LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit as i64], |r| r.get::<_, String>(0))?;
            for r in rows {
                let j = r?;
                if !j.is_empty() && !out.contains(&j) {
                    out.push(j);
                }
            }
        }
        if out.len() < limit {
            let rem = (limit - out.len()) as i64;
            let mut stmt = conn.prepare(
                "SELECT COALESCE(pn_jid, lid_jid)
                 FROM peers
                 WHERE avatar_cache_key IS NULL
                   AND COALESCE(pn_jid, lid_jid) IS NOT NULL
                   AND COALESCE(pn_jid, '') != 'self'
                   AND COALESCE(pn_jid, '') != 'status@broadcast'
                 ORDER BY
                   CASE WHEN contact_name IS NOT NULL AND contact_name != '' THEN 0 ELSE 1 END ASC,
                   updated_at_ms DESC
                 LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![rem], |r| r.get::<_, String>(0))?;
            for r in rows {
                let j = r?;
                if !j.is_empty() && !out.contains(&j) {
                    out.push(j);
                }
            }
        }
        Ok(out)
    }

    pub fn update_message_media_keys(
        &self,
        conversation_id: ConversationId,
        stanza_id: &str,
        full_cache_key: Option<&str>,
        thumb_cache_key: Option<&str>,
        waveform: Option<&[u8]>,
        link_preview: Option<&LinkPreviewCard>,
    ) -> Result<bool> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let cid_str = conversation_id.to_string();
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT local_id, content_json FROM messages WHERE conversation_id = ?1 AND stanza_id = ?2 LIMIT 1",
                params![cid_str, stanza_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((local_id, content_s)) = row else {
            return Ok(false);
        };
        let Ok(mut content) = serde_json::from_str::<MessageContent>(&content_s) else {
            return Ok(false);
        };

        let mut changed = false;
        match &mut content {
            MessageContent::Media {
                cache_key,
                thumb_cache_key: t_key,
                waveform: wf,
                ..
            } => {
                if let Some(fk) = full_cache_key
                    && cache_key.as_deref() != Some(fk)
                {
                    *cache_key = Some(fk.to_string());
                    changed = true;
                }
                if let Some(tk) = thumb_cache_key
                    && t_key.as_deref() != Some(tk)
                {
                    *t_key = Some(tk.to_string());
                    changed = true;
                }
                if let Some(w) = waveform
                    && !w.is_empty()
                    && wf.as_deref() != Some(w)
                {
                    *wf = Some(w.to_vec());
                    changed = true;
                }
            }
            MessageContent::Text {
                link_preview: lp_slot,
                ..
            } => {
                if let Some(lp) = link_preview
                    && lp_slot.as_ref() != Some(lp)
                {
                    *lp_slot = Some(lp.clone());
                    changed = true;
                }
            }
            MessageContent::Location {
                thumb_cache_key: t_key,
                ..
            } => {
                if let Some(tk) = thumb_cache_key
                    && t_key.as_deref() != Some(tk)
                {
                    *t_key = Some(tk.to_string());
                    changed = true;
                }
            }
            _ => {}
        }

        if changed {
            let updated_json = serde_json::to_string(&content)?;
            conn.execute(
                "UPDATE messages SET content_json = ?1 WHERE local_id = ?2",
                params![updated_json, local_id],
            )?;
        }
        Ok(changed)
    }

    pub fn load_raw_message_proto(
        &self,
        conversation_id: ConversationId,
        stanza_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let raw: Option<Option<Vec<u8>>> = conn
            .query_row(
                "SELECT raw_decrypted_proto FROM messages WHERE conversation_id = ?1 AND stanza_id = ?2 LIMIT 1",
                params![conversation_id.to_string(), stanza_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(raw.flatten().filter(|b| !b.is_empty()))
    }

    #[allow(clippy::type_complexity)]
    pub fn list_messages_needing_media_backfill(
        &self,
        limit: usize,
    ) -> Result<Vec<(ConversationId, String, MessageContent, Vec<u8>)>> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let scan_limit = (limit.saturating_mul(4)).max(120) as i64;
        let mut stmt = conn.prepare(
            "SELECT conversation_id, stanza_id, content_json, raw_decrypted_proto
             FROM messages
             WHERE raw_decrypted_proto IS NOT NULL
               AND length(raw_decrypted_proto) > 0
             ORDER BY sort_key DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![scan_limit], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            if out.len() >= limit {
                break;
            }
            let (cid_s, stanza_id, content_s, raw_proto) = row?;
            let Ok(cid) = ConversationId::parse(&cid_s) else {
                continue;
            };
            let Ok(content) = serde_json::from_str::<MessageContent>(&content_s) else {
                continue;
            };
            let needs_backfill = match &content {
                MessageContent::Media {
                    cache_key,
                    thumb_cache_key,
                    ..
                } => cache_key.is_none() || thumb_cache_key.is_none(),
                MessageContent::Location {
                    thumb_cache_key, ..
                } => thumb_cache_key.is_none(),
                MessageContent::Text { link_preview, .. } => link_preview.is_none(),
                _ => false,
            };
            if needs_backfill {
                out.push((cid, stanza_id, content, raw_proto));
            }
        }
        Ok(out)
    }

    pub fn list_conversations(&self) -> Result<Vec<ConversationSummary>> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT c.conversation_id, c.kind, c.primary_wire_jid, c.title, c.subtitle_preview,
                    c.last_message_ms, c.unread_count, c.is_pinned, c.is_muted, c.is_archived,
                    COALESCE(c.avatar_cache_key, p.avatar_cache_key),
                    c.participant_count
             FROM conversations c
             LEFT JOIN peers p ON p.peer_id = c.peer_id
             ORDER BY c.is_pinned DESC, COALESCE(c.last_message_ms, 0) DESC, c.title ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let cid_str: String = row.get(0)?;
            let kind_json: String = row.get(1)?;
            let primary_wire_jid: String = row.get(2)?;
            let title: String = row.get(3)?;
            let subtitle_preview: String = row.get(4)?;
            let last_ms: Option<i64> = row.get(5)?;
            let unread_count: u32 = row.get(6)?;
            let is_pinned: i32 = row.get(7)?;
            let is_muted: i32 = row.get(8)?;
            let is_archived: i32 = row.get(9)?;
            let avatar_cache_key: Option<String> = row.get(10)?;
            let participant_count: Option<u32> = row.get(11)?;
            Ok((
                cid_str,
                kind_json,
                primary_wire_jid,
                title,
                subtitle_preview,
                last_ms,
                unread_count,
                is_pinned != 0,
                is_muted != 0,
                is_archived != 0,
                avatar_cache_key,
                participant_count,
            ))
        })?;

        let mut out = Vec::new();
        for r in rows {
            let (
                cid_str,
                kind_json,
                primary_wire_jid,
                title,
                subtitle_preview,
                last_ms,
                unread_count,
                is_pinned,
                is_muted,
                is_archived,
                avatar_cache_key,
                participant_count,
            ) = r?;
            out.push(ConversationSummary {
                id: ConversationId::parse(&cid_str)?,
                kind: serde_json::from_str(&kind_json).unwrap_or(ConversationKind::DirectMessage),
                primary_wire_jid,
                title,
                subtitle_preview,
                last_message_at: last_ms.and_then(|ms| Utc.timestamp_millis_opt(ms).single()),
                unread_count,
                is_pinned,
                is_muted,
                is_archived,
                typing_peer: None,
                avatar_cache_key: avatar_cache_key.filter(|s| !s.is_empty()),
                participant_count,
            });
        }
        Ok(out)
    }

    /// Keyset-paginated timeline query (`WHERE sort_key < ? ORDER BY sort_key DESC LIMIT ?`).
    /// Never uses `OFFSET`, keeping chat switching `<16 ms` even on 500k-message archives.
    pub fn load_timeline_window(
        &self,
        conversation_id: ConversationId,
        before_sort_key: Option<i64>,
        limit: usize,
    ) -> Result<Vec<TimelineMessage>> {
        let ceiling = before_sort_key.unwrap_or(i64::MAX);
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let cid_str = conversation_id.to_string();

        let mut reaction_map: HashMap<String, Vec<(String, bool)>> = HashMap::new();
        {
            let mut r_stmt = conn.prepare(
                "SELECT target_stanza_id, emoji, is_from_me FROM reactions WHERE conversation_id = ?1",
            )?;
            let r_rows = r_stmt.query_map(params![&cid_str], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i32>(2)? != 0,
                ))
            })?;
            for item in r_rows {
                let (stanza, emoji, mine) = item?;
                reaction_map.entry(stanza).or_default().push((emoji, mine));
            }
        }

        let mut stmt = conn.prepare(
            "SELECT m.local_id, m.stanza_id, m.sender_id,
                    CASE WHEN m.is_from_me != 0 THEN m.sender_display
                         ELSE COALESCE(NULLIF(p.contact_name, ''), NULLIF(p.display_name, ''), m.sender_display)
                    END,
                    m.is_from_me, m.timestamp_ms, m.sort_key, m.delivery_json, m.content_json, m.quoted_json,
                    p.avatar_cache_key
             FROM messages m
             LEFT JOIN peers p ON p.peer_id = m.sender_id
             WHERE m.conversation_id = ?1 AND m.sort_key < ?2
             ORDER BY m.sort_key DESC, m.rowid DESC
             LIMIT ?3",
        )?;

        let rows = stmt.query_map(params![&cid_str, ceiling, limit as i64], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i32>(4)? != 0,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, String>(8)?,
                r.get::<_, Option<String>>(9)?,
                r.get::<_, Option<String>>(10)?,
            ))
        })?;

        let mut messages = Vec::new();
        for row in rows {
            let (
                local_id,
                stanza_id,
                sender_str,
                sender_display,
                is_from_me,
                ts_ms,
                sort_key,
                deliv_s,
                content_s,
                quoted_s,
                sender_avatar_cache_key,
            ) = row?;
            let reactions = summarize_reactions(reaction_map.get(&stanza_id));
            messages.push(TimelineMessage {
                local_id,
                stanza_id,
                conversation_id,
                sender_id: CanonicalPeerId::parse(&sender_str)
                    .unwrap_or(CanonicalPeerId(uuid::Uuid::nil())),
                sender_display,
                sender_avatar_cache_key: sender_avatar_cache_key.filter(|s| !s.is_empty()),
                is_from_me,
                timestamp: Utc
                    .timestamp_millis_opt(ts_ms)
                    .single()
                    .unwrap_or_else(Utc::now),
                sort_key,
                delivery: serde_json::from_str(&deliv_s).unwrap_or(DeliveryState::Sent),
                content: serde_json::from_str(&content_s).unwrap_or(
                    MessageContent::UnknownPlaceholder {
                        schema_version: PARSER_SCHEMA_VERSION,
                        summary: "Unsupported message".to_string(),
                    },
                ),
                quoted: quoted_s.and_then(|q| serde_json::from_str(&q).ok()),
                reactions,
            });
        }

        // Reverse so chronological order flows top -> bottom in the timeline view.
        messages.reverse();
        Ok(messages)
    }

    /// Stages a raw compressed `HistorySync` chunk to disk before inflation so
    /// interrupted one-shot syncs can resume locally without unlinking/re-pairing.
    pub fn stage_history_sync_chunk(
        &self,
        sync_type: i32,
        chunk_order: Option<u32>,
        progress: Option<u32>,
        compressed_bytes: &[u8],
    ) -> Result<String> {
        let hash = blake3::hash(compressed_bytes).to_hex().to_string();
        let conn = self.conn.lock().expect("vault mutex poisoned");
        conn.execute(
            "INSERT OR IGNORE INTO history_sync_staging (
                chunk_hash, sync_type, chunk_order, progress, compressed_blob, ingested, staged_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
            params![
                hash,
                sync_type,
                chunk_order,
                progress,
                compressed_bytes,
                Utc::now().timestamp_millis()
            ],
        )?;
        Ok(hash)
    }

    pub fn mark_history_chunk_ingested(&self, chunk_hash: &str) -> Result<()> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        conn.execute(
            "UPDATE history_sync_staging SET ingested = 1, compressed_blob = X'' WHERE chunk_hash = ?1",
            params![chunk_hash],
        )?;
        Ok(())
    }

    /// Asynchronous background `FTS5` batch indexer for deferred `HistorySync` rows.
    pub fn flush_pending_fts_batch(&self, batch_limit: usize) -> Result<usize> {
        let mut conn = self.conn.lock().expect("vault mutex poisoned");
        let tx = conn.transaction()?;
        let pending: Vec<(String, String, String, String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT local_id, conversation_id, stanza_id, sender_display, content_json
                 FROM messages
                 WHERE fts_indexed = 0
                 LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![batch_limit as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };

        let count = pending.len();
        for (local_id, conv_id, stanza_id, sender_display, content_json) in pending {
            if let Ok(content) = serde_json::from_str::<MessageContent>(&content_json) {
                let text = content.searchable_text();
                if !text.is_empty() {
                    tx.execute(
                        "INSERT INTO messages_fts (local_id, conversation_id, stanza_id, sender_display, body_text)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![local_id, conv_id, stanza_id, sender_display, text],
                    )?;
                }
            }
            tx.execute(
                "UPDATE messages SET fts_indexed = 1 WHERE local_id = ?1",
                params![local_id],
            )?;
        }
        tx.commit()?;
        Ok(count)
    }

    pub fn search_messages(
        &self,
        raw_query: &str,
        conversation_filter: Option<ConversationId>,
        limit: usize,
    ) -> Result<Vec<SearchHit>> {
        let fts_query = sanitize_fts5_prefix_query(raw_query);
        if fts_query.is_empty() {
            return Ok(Vec::new());
        }

        let conn = self.conn.lock().expect("vault mutex poisoned");
        let sql = "
            SELECT f.conversation_id, c.title, f.stanza_id, f.sender_display,
                   snippet(messages_fts, 4, '[', ']', '…', 14),
                   m.timestamp_ms, m.sort_key
            FROM messages_fts f
            JOIN messages m ON m.local_id = f.local_id
            JOIN conversations c ON c.conversation_id = f.conversation_id
            WHERE messages_fts MATCH ?1
              AND (?2 IS NULL OR f.conversation_id = ?2)
            ORDER BY rank, m.sort_key DESC
            LIMIT ?3
        ";
        let filter_str = conversation_filter.map(|c| c.to_string());
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(params![fts_query, filter_str, limit as i64], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
            ))
        })?;

        let mut hits = Vec::new();
        for row in rows {
            let (cid_str, conv_title, stanza_id, sender_display, snippet, ts_ms, sort_key) = row?;
            hits.push(SearchHit {
                conversation_id: ConversationId::parse(&cid_str)?,
                conversation_title: conv_title,
                stanza_id,
                sender_display,
                snippet,
                timestamp: Utc
                    .timestamp_millis_opt(ts_ms)
                    .single()
                    .unwrap_or_else(Utc::now),
                sort_key,
            });
        }
        Ok(hits)
    }

    pub fn sync_stats(&self) -> Result<HistorySyncStats> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let chunks_staged: i64 =
            conn.query_row("SELECT count(*) FROM history_sync_staging", [], |r| {
                r.get(0)
            })?;
        let uningested: i64 = conn.query_row(
            "SELECT count(*) FROM history_sync_staging WHERE ingested = 0",
            [],
            |r| r.get(0),
        )?;
        let pending_fts: i64 = conn.query_row(
            "SELECT count(*) FROM messages WHERE fts_indexed = 0",
            [],
            |r| r.get(0),
        )?;
        let messages_committed: i64 =
            conn.query_row("SELECT count(*) FROM messages", [], |r| r.get(0))?;
        let max_prog: Option<i64> =
            conn.query_row("SELECT MAX(progress) FROM history_sync_staging", [], |r| {
                r.get(0)
            })?;
        Ok(HistorySyncStats {
            chunks_staged: chunks_staged as u64,
            messages_committed: messages_committed as u64,
            progress_pct: max_prog.unwrap_or(100).clamp(0, 100) as u8,
            in_progress: uningested > 0 || pending_fts > 0,
        })
    }

    /// Encrypts a downloaded media blob onto disk with a unique per-file ChaCha20-Poly1305 key,
    /// storing the key inside the SQLCipher `vault.db` and evicting LRU entries above `media_cap_bytes`.
    pub fn store_encrypted_media(&self, cache_key: &str, plaintext: &[u8]) -> Result<()> {
        let mut raw_key = [0u8; 32];
        let mut raw_nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut raw_key);
        rand::thread_rng().fill_bytes(&mut raw_nonce);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&raw_key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&raw_nonce), plaintext)
            .map_err(|e| anyhow::anyhow!("AEAD media cache encryption failed: {e}"))?;

        let file_name = format!("{}.bin", blake3::hash(cache_key.as_bytes()).to_hex());
        let path = self.media_cache_dir.join(&file_name);
        fs::write(&path, &ciphertext)?;

        let now_ms = Utc::now().timestamp_millis();
        let mut conn = self.conn.lock().expect("vault mutex poisoned");
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO media_cache_entries (
                cache_key, file_name, byte_len, file_key_hex, nonce_hex, last_accessed_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(cache_key) DO UPDATE SET
                file_name = excluded.file_name,
                byte_len = excluded.byte_len,
                file_key_hex = excluded.file_key_hex,
                nonce_hex = excluded.nonce_hex,
                last_accessed_ms = excluded.last_accessed_ms",
            params![
                cache_key,
                file_name,
                ciphertext.len() as i64,
                hex::encode(raw_key),
                hex::encode(raw_nonce),
                now_ms
            ],
        )?;

        // Enforce LRU quota cap.
        let mut total_bytes: u64 = tx
            .query_row(
                "SELECT COALESCE(SUM(byte_len), 0) FROM media_cache_entries",
                [],
                |r| r.get::<_, i64>(0),
            )?
            .max(0) as u64;

        if total_bytes > self.media_cap_bytes {
            let mut stmt = tx.prepare(
                "SELECT cache_key, file_name, byte_len
                 FROM media_cache_entries
                 WHERE cache_key != ?1
                 ORDER BY last_accessed_ms ASC",
            )?;
            let candidates: Vec<(String, String, u64)> = stmt
                .query_map(params![cache_key], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)?.max(0) as u64))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(stmt);

            for (evict_key, evict_file, evict_len) in candidates {
                if total_bytes <= self.media_cap_bytes {
                    break;
                }
                let _ = fs::remove_file(self.media_cache_dir.join(&evict_file));
                tx.execute(
                    "DELETE FROM media_cache_entries WHERE cache_key = ?1",
                    params![evict_key],
                )?;
                total_bytes = total_bytes.saturating_sub(evict_len);
            }
        }

        tx.commit()?;
        Ok(())
    }

    pub fn load_encrypted_media(&self, cache_key: &str) -> Result<Option<Vec<u8>>> {
        let row: Option<(String, String, String)> = {
            let conn = self.conn.lock().expect("vault mutex poisoned");
            let entry = conn
                .query_row(
                    "SELECT file_name, file_key_hex, nonce_hex
                     FROM media_cache_entries WHERE cache_key = ?1",
                    params![cache_key],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            if entry.is_some() {
                let _ = conn.execute(
                    "UPDATE media_cache_entries SET last_accessed_ms = ?1 WHERE cache_key = ?2",
                    params![Utc::now().timestamp_millis(), cache_key],
                );
            }
            entry
        };

        let Some((file_name, key_hex, nonce_hex)) = row else {
            return Ok(None);
        };
        let path = self.media_cache_dir.join(&file_name);
        if !path.exists() {
            return Ok(None);
        }
        let ciphertext = fs::read(&path)?;
        let key_bytes = hex::decode(key_hex)?;
        let nonce_bytes = hex::decode(nonce_hex)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("AEAD media cache decryption failed: {e}"))?;
        Ok(Some(plaintext))
    }

    pub fn inspect_backup(&self, backup_path: &Path, master_key: &[u8; 32]) -> Result<()> {
        if !backup_path.exists() {
            println!("Backup file does not exist at {:?}", backup_path);
            return Ok(());
        }
        let conn = rusqlite::Connection::open(backup_path)?;
        conn.pragma_update(None, "key", format!("x'{}'", hex::encode(master_key)))?;
        conn.pragma_update(None, "cipher_compatibility", 4)?;
        println!("\n=== INSPECTING VAULT BACKUP BEFORE REPAIR ===");
        let b_peers: i64 = conn.query_row("SELECT count(*) FROM peers", [], |r| r.get(0))?;
        let b_convs: i64 =
            conn.query_row("SELECT count(*) FROM conversations", [], |r| r.get(0))?;
        let b_msgs: i64 = conn.query_row("SELECT count(*) FROM messages", [], |r| r.get(0))?;
        println!("Backup totals: peers={b_peers}, convs={b_convs}, msgs={b_msgs}");

        // Distinct sender_displays in backup
        println!("\n--- Backup: Distinct sender_display for key wire JIDs ---");
        let mut b_stmt = conn.prepare(
            "SELECT DISTINCT sender_wire_jid, sender_display, count(*)
             FROM messages
             WHERE is_from_me = 0
               AND (sender_wire_jid LIKE '%4917652623600%'
                    OR sender_wire_jid LIKE '%204273409335409%'
                    OR sender_wire_jid LIKE '%19792185914%'
                    OR sender_wire_jid LIKE '%134634490826876%'
                    OR sender_wire_jid LIKE '%4915163605356%'
                    OR sender_wire_jid LIKE '%252720187486278%'
                    OR sender_wire_jid LIKE '%919433334500%'
                    OR sender_wire_jid LIKE '%7000930918511%')
             GROUP BY sender_wire_jid, sender_display",
        )?;
        let rows = b_stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for r in rows {
            let (wire, disp, cnt) = r?;
            println!("  Backup msg sender: wire='{wire}' disp='{disp}' cnt={cnt}");
        }

        // All distinct sender_displays in backup messages that are human names (not +phone or digits)
        println!("\n--- Backup: Best human sender_displays in messages ---");
        let mut h_stmt = conn.prepare(
            "SELECT sender_wire_jid, sender_display, count(*) as cnt
             FROM messages
             WHERE is_from_me = 0
               AND sender_display NOT LIKE '+%'
               AND sender_display NOT GLOB '[0-9]*'
               AND sender_display NOT LIKE '%@%'
               AND sender_display != 'You'
               AND sender_display != 'Rabimba Karanjai'
             GROUP BY sender_wire_jid
             ORDER BY cnt DESC",
        )?;
        let h_rows = h_stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for r in h_rows {
            let (wire, disp, cnt) = r?;
            println!("  Human name from backup: wire='{wire}' -> disp='{disp}' (count={cnt})");
        }

        // Check peers in backup
        println!("\n--- Backup: Peers for key wire JIDs ---");
        let mut bp_stmt = conn.prepare(
            "SELECT peer_id, pn_jid, lid_jid, contact_name, display_name, push_name
             FROM peers
             WHERE pn_jid LIKE '%4917652623600%'
                OR lid_jid LIKE '%204273409335409%'
                OR pn_jid LIKE '%19792185914%'
                OR lid_jid LIKE '%134634490826876%'
                OR pn_jid LIKE '%4915163605356%'
                OR lid_jid LIKE '%252720187486278%'
                OR pn_jid LIKE '%919433334500%'
                OR lid_jid LIKE '%7000930918511%'",
        )?;
        let bp_rows = bp_stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<String>>(5)?,
            ))
        })?;
        for r in bp_rows {
            let (pid, pn, lid, contact, disp, push) = r?;
            println!(
                "  Backup peer: id={pid} pn={pn:?} lid={lid:?} contact={contact:?} disp='{disp}' push={push:?}"
            );
        }

        Ok(())
    }

    pub fn run_data_attribution_audit(&self) -> Result<()> {
        println!("=== DATA ATTRIBUTION AUDIT ===");

        let top_convs = {
            let conn = self.conn.lock().expect("vault mutex poisoned");

            let mut kv_stmt = conn.prepare("SELECT k, v FROM vault_kv")?;
            let kvs: Vec<(String, String)> = kv_stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .filter_map(Result::ok)
                .collect();
            println!("KV store entries:");
            for (k, v) in &kvs {
                println!("  {k} = {v}");
            }

            let total_peers: i64 =
                conn.query_row("SELECT count(*) FROM peers", [], |r| r.get(0))?;
            let total_convs: i64 =
                conn.query_row("SELECT count(*) FROM conversations", [], |r| r.get(0))?;
            let total_msgs: i64 =
                conn.query_row("SELECT count(*) FROM messages", [], |r| r.get(0))?;
            println!(
                "Totals: peers={}, conversations={}, messages={}",
                total_peers, total_convs, total_msgs
            );

            // Inspect peers with Rabimba in their names
            println!("\n--- Inspecting Peers with 'Rabimba' in name ---");
            let mut r_stmt = conn.prepare(
                "SELECT peer_id, pn_jid, lid_jid, contact_name, display_name, push_name FROM peers
                 WHERE (display_name LIKE '%Rabimba%' OR push_name LIKE '%Rabimba%' OR contact_name LIKE '%Rabimba%')"
            )?;
            let r_rows = r_stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                ))
            })?;
            for r in r_rows {
                let (pid, pn, lid, contact, disp, push) = r?;
                println!(
                    "  Rabimba peer: id={pid} pn={pn:?} lid={lid:?} contact={contact:?} disp='{disp}' push={push:?}"
                );
            }

            // Inspect specific numbers: 4917652623600, 19792185914, 4915163605356, 919433334500
            println!("\n--- Inspecting specific peers ---");
            let mut s_stmt = conn.prepare(
                "SELECT peer_id, pn_jid, lid_jid, contact_name, display_name, push_name FROM peers
                 WHERE pn_jid LIKE '%4917652623600%' OR pn_jid LIKE '%19792185914%' OR pn_jid LIKE '%4915163605356%' OR pn_jid LIKE '%919433334500%'"
            )?;
            let s_rows = s_stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                ))
            })?;
            for r in s_rows {
                let (pid, pn, lid, contact, disp, push) = r?;
                println!(
                    "  Specific peer: id={pid} pn={pn:?} lid={lid:?} contact={contact:?} disp='{disp}' push={push:?}"
                );
            }

            // Check if crypto_session.db lid_pn_mapping has those numbers
            let crypto_db_path = self
                .media_cache_dir
                .parent()
                .map(|p| p.join("crypto_session.db"));
            if let Some(ref crypto_db_path) = crypto_db_path
                && crypto_db_path.exists()
                && let Ok(cs) = rusqlite::Connection::open_with_flags(
                    crypto_db_path,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                )
            {
                println!("\n--- lid_pn_mapping in crypto_session.db ---");
                let mut lp_stmt = cs.prepare(
                    "SELECT lid, phone_number FROM lid_pn_mapping
                     WHERE phone_number LIKE '%4917652623600%' OR phone_number LIKE '%19792185914%' OR phone_number LIKE '%4915163605356%' OR phone_number LIKE '%919433334500%'"
                )?;
                let lp_rows = lp_stmt
                    .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
                for r in lp_rows {
                    let (lid, pn) = r?;
                    println!("  mapping: pn='{pn}' lid='{lid}'");
                }
            }

            // Check 1: In DirectMessage conversations, what are the distinct wire_jids of messages?
            println!("\n--- Check 1: DM Conversations message sender wire check ---");
            let mut dm_stmt = conn.prepare(
                "SELECT c.conversation_id, c.title, c.primary_wire_jid,
                        m.sender_wire_jid, m.sender_display, m.is_from_me, count(*) as cnt
                 FROM messages m
                 JOIN conversations c ON c.conversation_id = m.conversation_id
                 WHERE c.kind LIKE '%direct%'
                 GROUP BY c.conversation_id, m.sender_wire_jid, m.is_from_me
                 ORDER BY c.conversation_id",
            )?;
            let mut last_cid = String::new();
            let mut current_conv_title = String::new();
            let mut current_primary = String::new();
            let mut senders_in_conv = Vec::new();

            let mut anomaly_convs = 0;
            let dm_rows = dm_stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i32>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            })?;

            for r in dm_rows {
                let (cid, title, primary, swire, sdisp, from_me, _cnt) = r?;
                if cid != last_cid {
                    if !last_cid.is_empty() {
                        let distinct_non_me_peers: std::collections::HashSet<_> = senders_in_conv
                            .iter()
                            .filter(|(fm, _, _)| *fm == 0)
                            .map(|(_, _, sd)| sd)
                            .collect();
                        if distinct_non_me_peers.len() > 1 {
                            anomaly_convs += 1;
                            println!(
                                "ANOMALY DM: '{}' (primary='{}')",
                                current_conv_title, current_primary
                            );
                            for (fm, sw, sd) in &senders_in_conv {
                                println!("   from_me={fm} wire='{sw}' disp='{sd}'");
                            }
                        }
                    }
                    last_cid = cid;
                    current_conv_title = title;
                    current_primary = primary;
                    senders_in_conv.clear();
                }
                senders_in_conv.push((from_me, swire, sdisp));
            }
            if !last_cid.is_empty() {
                let distinct_non_me_peers: std::collections::HashSet<_> = senders_in_conv
                    .iter()
                    .filter(|(fm, _, _)| *fm == 0)
                    .map(|(_, _, sd)| sd)
                    .collect();
                if distinct_non_me_peers.len() > 1 {
                    anomaly_convs += 1;
                    println!(
                        "ANOMALY DM: '{}' (primary='{}')",
                        current_conv_title, current_primary
                    );
                    for (fm, sw, sd) in &senders_in_conv {
                        println!("   from_me={fm} wire='{sw}' disp='{sd}'");
                    }
                }
            }
            println!(
                "Total DM conversations with multiple non-me senders: {}",
                anomaly_convs
            );

            // Check 2: Check messages where m.sender_display doesn't match the peer's actual name
            println!("\n--- Check 2: Mismatched sender_display vs peer name ---");
            let mut mismatch_stmt = conn.prepare(
                "SELECT m.sender_wire_jid, m.sender_display, p.display_name, p.contact_name, p.push_name, count(*)
                 FROM messages m
                 LEFT JOIN peers p ON p.peer_id = m.sender_id
                 WHERE m.is_from_me = 0 AND m.sender_display != p.display_name
                 GROUP BY m.sender_wire_jid, m.sender_display, p.display_name
                 LIMIT 25"
            )?;
            let mm_rows = mismatch_stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            })?;
            let mut mm_count = 0;
            for r in mm_rows {
                let (wire, m_disp, p_disp, p_contact, p_push, cnt) = r?;
                mm_count += 1;
                println!(
                    "  mismatch #{mm_count}: wire='{wire}' msg.sender_display='{m_disp}' vs peer.display_name='{p_disp:?}' contact='{p_contact:?}' push='{p_push:?}' (count={cnt})"
                );
            }

            // Check 3: Check messages in groups where is_from_me = 0 but sender_wire_jid is 'self' or user's JID
            println!("\n--- Check 3: Messages with is_from_me confusion ---");
            let mut me_stmt = conn.prepare(
                "SELECT count(*) FROM messages WHERE is_from_me = 0 AND (sender_wire_jid = 'self' OR sender_wire_jid LIKE '%240617053519947%' OR sender_wire_jid LIKE '%14694382410%')"
            )?;
            let confused_me: i64 = me_stmt.query_row([], |r| r.get(0))?;
            println!(
                "Messages with is_from_me=0 but user's wire JID: {}",
                confused_me
            );

            // Check 4: Check messages where is_from_me = 1 but sender_display != 'You'
            let mut you_stmt = conn.prepare(
                "SELECT sender_display, count(*) FROM messages WHERE is_from_me = 1 AND sender_display != 'You' GROUP BY sender_display"
            )?;
            let you_rows =
                you_stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
            for r in you_rows {
                let (disp, cnt) = r?;
                println!("  is_from_me=1 but sender_display='{disp}' (count={cnt})");
            }

            // Check 5: Check conversation titles vs their peer names in DMs
            println!("\n--- Check 5: DM Conversation title vs peer display_name ---");
            let mut conv_peer_stmt = conn.prepare(
                "SELECT c.title, c.primary_wire_jid, p.display_name, p.contact_name, p.push_name, count(*)
                 FROM conversations c
                 JOIN peers p ON p.peer_id = c.peer_id
                 WHERE c.kind LIKE '%direct%' AND c.title != p.display_name
                 GROUP BY c.title, c.primary_wire_jid, p.display_name
                 LIMIT 25"
            )?;
            let cp_rows = conv_peer_stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            })?;
            let mut cp_mismatch = 0;
            for r in cp_rows {
                let (c_title, wire, p_disp, p_contact, p_push, _cnt) = r?;
                cp_mismatch += 1;
                println!(
                    "  DM title mismatch #{cp_mismatch}: conv.title='{c_title}' wire='{wire}' vs peer.display_name='{p_disp}' contact='{p_contact:?}' push='{p_push:?}'"
                );
            }

            // Check 5A: DMs where conversation title differs from message sender_display of incoming messages
            println!("\n--- Check 5A: DM Conv title vs incoming message sender_display ---");
            let mut diff_title_stmt = conn.prepare(
                "SELECT c.conversation_id, c.title, c.primary_wire_jid,
                        m.sender_display, m.sender_wire_jid, count(*) as cnt
                 FROM conversations c
                 JOIN messages m ON m.conversation_id = c.conversation_id
                 WHERE c.kind LIKE '%direct%'
                   AND m.is_from_me = 0
                   AND c.title != m.sender_display
                 GROUP BY c.conversation_id, c.title, c.primary_wire_jid, m.sender_display, m.sender_wire_jid
                 ORDER BY cnt DESC"
            )?;
            let diff_rows = diff_title_stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            })?;
            for r in diff_rows {
                let (cid, ctitle, primary, mdisp, mwire, cnt) = r?;
                println!(
                    "  MISMATCH: Conv '{ctitle}' (primary={primary}, cid={cid}) has incoming messages from disp='{mdisp}' wire='{mwire}' (count={cnt})"
                );
            }

            // Check 5B: DMs where conversation peer_id differs from incoming message sender_id
            println!("\n--- Check 5B: DM Conv peer_id vs incoming message sender_id ---");
            let mut diff_peer_stmt = conn.prepare(
                "SELECT c.title, c.primary_wire_jid, c.peer_id,
                        m.sender_id, m.sender_display, m.sender_wire_jid, count(*) as cnt
                 FROM conversations c
                 JOIN messages m ON m.conversation_id = c.conversation_id
                 WHERE c.kind LIKE '%direct%'
                   AND m.is_from_me = 0
                   AND (c.peer_id IS NULL OR c.peer_id != m.sender_id)
                 GROUP BY c.title, c.primary_wire_jid, c.peer_id, m.sender_id, m.sender_display, m.sender_wire_jid
                 ORDER BY cnt DESC"
            )?;
            let diff_p_rows = diff_peer_stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            })?;
            for r in diff_p_rows {
                let (ctitle, primary, cpeer, msender, mdisp, mwire, cnt) = r?;
                println!(
                    "  PEER MISMATCH: Conv '{ctitle}' (primary={primary}, c.peer_id={cpeer:?}) has messages from sender_id='{msender}' disp='{mdisp}' wire='{mwire}' (count={cnt})"
                );
            }

            // Check 5C: Inspect all Direct Message conversations with message counts and sender previews
            println!("\n--- Check 5C: All DM conversations summary ---");
            let mut all_dm_stmt = conn.prepare(
                "SELECT c.conversation_id, c.title, c.primary_wire_jid, c.peer_id,
                        p.contact_name, p.display_name, p.push_name,
                        (SELECT count(*) FROM messages WHERE conversation_id = c.conversation_id) as msg_cnt,
                        (SELECT count(*) FROM messages WHERE conversation_id = c.conversation_id AND is_from_me = 0) as inc_cnt
                 FROM conversations c
                 LEFT JOIN peers p ON p.peer_id = c.peer_id
                 WHERE c.kind LIKE '%direct%'
                 ORDER BY msg_cnt DESC"
            )?;
            let all_dm_rows = all_dm_stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, i64>(8)?,
                ))
            })?;
            for r in all_dm_rows {
                let (_cid, ctitle, primary, cpeer, pcontact, pdisp, ppush, msg_cnt, inc_cnt) = r?;
                println!(
                    "  DM: '{ctitle}' primary='{primary}' msgs={msg_cnt} (inc={inc_cnt}) peer_id={cpeer:?} p.contact={pcontact:?} p.disp={pdisp:?} p.push={ppush:?}"
                );
            }

            // Check 6: Check conversation_wire_aliases
            println!("\n--- Check 6: conversation_wire_aliases mapping check ---");
            let mut alias_stmt = conn.prepare(
                "SELECT c.title, c.primary_wire_jid, a.wire_jid
                 FROM conversation_wire_aliases a
                 JOIN conversations c ON c.conversation_id = a.conversation_id
                 WHERE a.wire_jid != c.primary_wire_jid
                 LIMIT 30",
            )?;
            let alias_rows = alias_stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            for r in alias_rows {
                let (title, primary, alias) = r?;
                println!("  Conv '{title}' (primary='{primary}') has alias='{alias}'");
            }

            // Check 7: How are timeline messages returned for the top 5 conversations?
            println!("\n--- Check 7: Timeline messages inspection for top 5 conversations ---");
            let mut top_convs_stmt = conn.prepare(
                "SELECT conversation_id, title, primary_wire_jid, kind FROM conversations ORDER BY last_message_ms DESC LIMIT 5"
            )?;
            let top_convs = top_convs_stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;

            println!("\n--- Deep Inspection of Rohan Mukherjee conversation ---");
            let (rohan_cid, rohan_title): (String, String) = conn.query_row(
            "SELECT conversation_id, title FROM conversations WHERE primary_wire_jid = '14694382410@s.whatsapp.net'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
            println!("Rohan conversation: id={rohan_cid} title='{rohan_title}'");

            let rohan_aliases: Vec<String> = {
                let mut a_stmt = conn.prepare(
                    "SELECT wire_jid FROM conversation_wire_aliases WHERE conversation_id = ?1",
                )?;
                a_stmt
                    .query_map(params![&rohan_cid], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            println!(
                "Total aliases attached to Rohan conv: {}",
                rohan_aliases.len()
            );
            for a in &rohan_aliases {
                println!("   alias: {a}");
            }

            let mut m_stmt = conn.prepare(
                "SELECT m.is_from_me, m.sender_wire_jid, m.sender_display, count(*)
             FROM messages m
             WHERE m.conversation_id = ?1
             GROUP BY m.is_from_me, m.sender_wire_jid, m.sender_display",
            )?;
            let m_rows = m_stmt.query_map(params![&rohan_cid], |r| {
                Ok((
                    r.get::<_, i32>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?;
            println!("Messages in Rohan conv grouped by sender:");
            for r in m_rows {
                let (fm, sw, sd, cnt) = r?;
                println!("   from_me={fm} sender_wire='{sw}' disp='{sd}' count={cnt}");
            }

            println!(
                "\n--- Inspecting messages in Rohan conv where sender_wire = '240617053519947@lid' ---"
            );
            let mut self_wire_stmt = conn.prepare(
            "SELECT stanza_id, timestamp_ms, content_json, raw_decrypted_proto IS NOT NULL, length(raw_decrypted_proto)
             FROM messages
             WHERE conversation_id = ?1 AND sender_wire_jid = '240617053519947@lid'
             ORDER BY timestamp_ms DESC
             LIMIT 10"
        )?;
            let sw_rows = self_wire_stmt.query_map(params![&rohan_cid], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, bool>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                ))
            })?;
            for r in sw_rows {
                let (stanza, ts, content, has_proto, proto_len) = r?;
                println!(
                    "   stanza={stanza} ts={ts} has_proto={has_proto} (len={proto_len:?}) content={content}"
                );
            }

            println!("\n--- Contact and Push Names for the top sender wire JIDs ---");
            let mut top_senders_stmt = conn.prepare(
            "SELECT m.sender_wire_jid, count(*),
                    (SELECT p.display_name FROM peers p WHERE p.pn_jid = m.sender_wire_jid OR p.lid_jid = m.sender_wire_jid LIMIT 1),
                    (SELECT p.contact_name FROM peers p WHERE p.pn_jid = m.sender_wire_jid OR p.lid_jid = m.sender_wire_jid LIMIT 1),
                    (SELECT p.push_name FROM peers p WHERE p.pn_jid = m.sender_wire_jid OR p.lid_jid = m.sender_wire_jid LIMIT 1)
             FROM messages m
             WHERE m.is_from_me = 0
             GROUP BY m.sender_wire_jid
             ORDER BY count(*) DESC
             LIMIT 20"
        )?;
            let ts_rows = top_senders_stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })?;
            for r in ts_rows {
                let (wire, cnt, disp, contact, push) = r?;
                println!(
                    "  wire={wire:<30} cnt={cnt:<5} disp={disp:?} contact={contact:?} push={push:?}"
                );
            }
            let mut proto_stmt = conn.prepare(
            "SELECT stanza_id, raw_decrypted_proto
             FROM messages
             WHERE conversation_id = ?1 AND sender_wire_jid = '240617053519947@lid' AND raw_decrypted_proto IS NOT NULL
             LIMIT 5"
        )?;
            let pr_rows = proto_stmt.query_map(params![&rohan_cid], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?;
            for r in pr_rows {
                let (stanza, bytes) = r?;
                println!("  Stanza: {stanza}, bytes_len: {}", bytes.len());
            }

            println!("\n--- Inspecting quoted_json in 240617053519947@lid messages ---");
            let mut q_stmt = conn.prepare(
            "SELECT m.stanza_id, m.quoted_json, (
                SELECT target.sender_wire_jid FROM messages target WHERE target.stanza_id = json_extract(m.quoted_json, '$.target_stanza_id') LIMIT 1
             ) as target_sender
             FROM messages m
             WHERE m.conversation_id = ?1 AND m.sender_wire_jid = '240617053519947@lid' AND m.quoted_json IS NOT NULL
             LIMIT 10"
        )?;
            let q_rows = q_stmt.query_map(params![&rohan_cid], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })?;
            for r in q_rows {
                let (st, q, tgt) = r?;
                println!("  stanza={st} target_sender={tgt:?} quoted={q}");
            }

            top_convs
        };

        for (cid_str, title, primary, kind) in top_convs {
            let cid = ConversationId::parse(&cid_str)?;
            let tl = self.load_timeline_window(cid, None, 5)?;
            println!("\nConversation: '{title}' ({kind}) primary='{primary}'");
            for m in tl {
                let content_snip = m.content.preview_text();
                println!(
                    "   msg: from_me={} disp='{}' avatar_key={:?} text='{}'",
                    m.is_from_me, m.sender_display, m.sender_avatar_cache_key, content_snip
                );
            }
        }

        println!("\n=== END OF AUDIT ===");
        Ok(())
    }
}

fn summarize_reactions(raw: Option<&Vec<(String, bool)>>) -> Vec<ReactionChip> {
    let Some(list) = raw else {
        return Vec::new();
    };
    let mut map: HashMap<String, (usize, bool)> = HashMap::new();
    for (emoji, mine) in list {
        let entry = map.entry(emoji.clone()).or_insert((0, false));
        entry.0 += 1;
        entry.1 |= *mine;
    }
    let mut chips: Vec<ReactionChip> = map
        .into_iter()
        .map(|(emoji, (count, reacted_by_me))| ReactionChip {
            emoji,
            count,
            reacted_by_me,
        })
        .collect();
    chips.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.emoji.cmp(&b.emoji)));
    chips
}

fn sanitize_fts5_prefix_query(raw: &str) -> String {
    raw.split_whitespace()
        .filter_map(|tok| {
            let cleaned: String = tok
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if cleaned.is_empty() {
                None
            } else {
                Some(format!("\"{cleaned}\"*"))
            }
        })
        .collect::<Vec<_>>()
        .join(" AND ")
}

fn ensure_column(conn: &Connection, table: &str, col: &str, col_def: &str) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let cols: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !cols.iter().any(|c| c.eq_ignore_ascii_case(col)) {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {col} {col_def};"))?;
    }
    Ok(())
}

fn set_dir_0700_unix(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "whatsnative-store-test-{tag}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sqlcipher_encrypts_messages_and_fts5_at_rest() {
        let dir = temp_test_dir("sqlcipher");
        let db_path = dir.join("vault.db");
        let media_dir = dir.join("media");
        let key = [42u8; 32];

        let secret_phrase = "TOPSECRET_WHATSNATIVE_VAULT_PLAINTEXT_CANARY_998877";
        {
            let store = VaultStore::open_encrypted(&db_path, &media_dir, &key).unwrap();
            store
                .commit_inbound_batch(&[InboundCommitRecord {
                    chat_wire_jid: "14155550199@s.whatsapp.net".to_string(),
                    chat_alt_jid: None,
                    chat_kind: ConversationKind::DirectMessage,
                    chat_title_hint: Some("Ada Lovelace".to_string()),
                    sender_wire_jid: "14155550199@s.whatsapp.net".to_string(),
                    sender_alt_jid: None,
                    sender_push_name: Some("Ada Lovelace".to_string()),
                    stanza_id: "MSG-1".to_string(),
                    is_from_me: false,
                    timestamp_ms: 1_730_000_000_000,
                    delivery: DeliveryState::Delivered,
                    content: MessageContent::Text {
                        body: secret_phrase.to_string(),
                        edited_at: None,
                        link_preview: None,
                    },
                    quoted: None,
                    raw_decrypted_proto: secret_phrase.as_bytes().to_vec(),
                    defer_fts: false,
                }])
                .unwrap();

            let hits = store
                .search_messages("TOPSECRET_WHATSNATIVE", None, 10)
                .unwrap();
            assert_eq!(hits.len(), 1);
        }

        // Verify raw database + WAL files on disk contain ZERO plaintext canary bytes!
        for ext in ["vault.db", "vault.db-wal"] {
            let candidate = dir.join(ext);
            if candidate.exists() {
                let raw_bytes = fs::read(&candidate).unwrap();
                assert!(
                    !raw_bytes
                        .windows(b"TOPSECRET_WHATSNATIVE".len())
                        .any(|w| w == b"TOPSECRET_WHATSNATIVE"),
                    "plaintext canary leaked into {ext}!"
                );
            }
        }

        // Verify wrong key is rejected.
        let wrong_key = [99u8; 32];
        assert!(VaultStore::open_encrypted(&db_path, &media_dir, &wrong_key).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn late_lid_to_phone_jid_discovery_merges_split_threads_atomically() {
        let dir = temp_test_dir("lid-merge");
        let store =
            VaultStore::open_encrypted(&dir.join("vault.db"), &dir.join("media"), &[11u8; 32])
                .unwrap();

        // 1. Message arrives under @s.whatsapp.net alone.
        store
            .commit_inbound_batch(&[InboundCommitRecord {
                chat_wire_jid: "14155550100@s.whatsapp.net".to_string(),
                chat_alt_jid: None,
                chat_kind: ConversationKind::DirectMessage,
                chat_title_hint: Some("Grace Hopper".to_string()),
                sender_wire_jid: "14155550100@s.whatsapp.net".to_string(),
                sender_alt_jid: None,
                sender_push_name: Some("Grace Hopper".to_string()),
                stanza_id: "M-PN".to_string(),
                is_from_me: false,
                timestamp_ms: 1_000,
                delivery: DeliveryState::Delivered,
                content: MessageContent::Text {
                    body: "First over phone JID".to_string(),
                    edited_at: None,
                    link_preview: None,
                },
                quoted: None,
                raw_decrypted_proto: vec![1, 2],
                defer_fts: false,
            }])
            .unwrap();

        // 2. Second message arrives under @lid BEFORE alt mapping is known -> creates temporary second thread.
        store
            .commit_inbound_batch(&[InboundCommitRecord {
                chat_wire_jid: "9988776655@lid".to_string(),
                chat_alt_jid: None,
                chat_kind: ConversationKind::DirectMessage,
                chat_title_hint: None,
                sender_wire_jid: "9988776655@lid".to_string(),
                sender_alt_jid: None,
                sender_push_name: None,
                stanza_id: "M-LID-1".to_string(),
                is_from_me: false,
                timestamp_ms: 2_000,
                delivery: DeliveryState::Delivered,
                content: MessageContent::Text {
                    body: "Second over unlinked LID".to_string(),
                    edited_at: None,
                    link_preview: None,
                },
                quoted: None,
                raw_decrypted_proto: vec![3, 4],
                defer_fts: false,
            }])
            .unwrap();
        assert_eq!(store.list_conversations().unwrap().len(), 2);

        // 3. Third message arrives carrying BOTH @lid and sender_alt=@s.whatsapp.net -> merges into 1 thread!
        store
            .commit_inbound_batch(&[InboundCommitRecord {
                chat_wire_jid: "9988776655@lid".to_string(),
                chat_alt_jid: Some("14155550100@s.whatsapp.net".to_string()),
                chat_kind: ConversationKind::DirectMessage,
                chat_title_hint: Some("Grace Hopper".to_string()),
                sender_wire_jid: "9988776655@lid".to_string(),
                sender_alt_jid: Some("14155550100@s.whatsapp.net".to_string()),
                sender_push_name: Some("Grace Hopper".to_string()),
                stanza_id: "M-LID-2".to_string(),
                is_from_me: false,
                timestamp_ms: 3_000,
                delivery: DeliveryState::Delivered,
                content: MessageContent::Text {
                    body: "Third bridges LID and PN".to_string(),
                    edited_at: None,
                    link_preview: None,
                },
                quoted: None,
                raw_decrypted_proto: vec![5, 6],
                defer_fts: false,
            }])
            .unwrap();

        let convs = store.list_conversations().unwrap();
        assert_eq!(convs.len(), 1, "split-brain threads must merge into one");
        let timeline = store.load_timeline_window(convs[0].id, None, 50).unwrap();
        assert_eq!(
            timeline.len(),
            3,
            "all three messages preserved in merged thread"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn crypto_guard_blocks_downgrade_and_media_cache_evicts_lru() {
        let dir = temp_test_dir("guard-lru");
        let guard_path = dir.join("crypto_schema_guard.json");
        CryptoSchemaGuard::verify_or_init(&guard_path, 2).unwrap();
        assert!(CryptoSchemaGuard::verify_or_init(&guard_path, 1).is_err());

        let store =
            VaultStore::open_encrypted(&dir.join("vault.db"), &dir.join("media"), &[21u8; 32])
                .unwrap()
                .with_media_cap_bytes(120);

        store.store_encrypted_media("k1", &[0xAA; 60]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        store.store_encrypted_media("k2", &[0xBB; 60]).unwrap();

        // Exceeds 120-byte ciphertext cap -> oldest entry k1 is evicted while k2 survives!
        assert!(store.load_encrypted_media("k1").unwrap().is_none());
        assert_eq!(
            store.load_encrypted_media("k2").unwrap().unwrap(),
            vec![0xBB; 60]
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn retroactive_contact_sync_updates_existing_chat_titles_and_sender_names() {
        let dir = temp_test_dir("retroactive-contacts");
        let store =
            VaultStore::open_encrypted(&dir.join("vault.db"), &dir.join("media"), &[33u8; 32])
                .unwrap();

        // 1. Message arrives from raw @lid before contacts or pushnames were synced!
        store
            .commit_inbound_batch(&[InboundCommitRecord {
                chat_wire_jid: "7788990011@lid".to_string(),
                chat_alt_jid: None,
                chat_kind: ConversationKind::DirectMessage,
                chat_title_hint: None,
                sender_wire_jid: "7788990011:4@lid".to_string(),
                sender_alt_jid: None,
                sender_push_name: None,
                stanza_id: "MSG-RAW-LID".to_string(),
                is_from_me: false,
                timestamp_ms: 10_000,
                delivery: DeliveryState::Delivered,
                content: MessageContent::Text {
                    body: "Hey from LID before contact sync!".to_string(),
                    edited_at: None,
                    link_preview: None,
                },
                quoted: None,
                raw_decrypted_proto: vec![1, 2, 3],
                defer_fts: false,
            }])
            .unwrap();

        assert_eq!(store.list_conversations().unwrap()[0].title, "7788990011");

        // 2. Contact sync arrives later carrying pn_jid + lid_jid + saved address-book name + avatar!
        store
            .upsert_contact(
                Some("14155550177@s.whatsapp.net"),
                Some("7788990011@lid"),
                Some("Dr. Barbara Liskov"),
                Some("Barb"),
            )
            .unwrap();
        let av_key = store
            .store_avatar_for_jid("14155550177@s.whatsapp.net", b"fake-png-bytes")
            .unwrap();

        // Verify conversation title, primary_wire_jid, avatar_cache_key, AND timeline sender_display all upgraded!
        let convs = store.list_conversations().unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].title, "Dr. Barbara Liskov");
        assert_eq!(convs[0].primary_wire_jid, "14155550177@s.whatsapp.net");
        assert_eq!(convs[0].avatar_cache_key.as_deref(), Some(av_key.as_str()));

        let timeline = store.load_timeline_window(convs[0].id, None, 20).unwrap();
        assert_eq!(timeline[0].sender_display, "Dr. Barbara Liskov");
        assert_eq!(
            timeline[0].sender_avatar_cache_key.as_deref(),
            Some(av_key.as_str())
        );

        // Verify subsequent pushname update does NOT overwrite saved address-book contact_name!
        store
            .resolve_or_merge_peer("14155550177@s.whatsapp.net", None, Some("ShortPush"))
            .unwrap();
        let contacts = store.list_contacts().unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].display_name, "Dr. Barbara Liskov");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lid_merge_preserves_messages_with_duplicate_stanza_ids() {
        let dir = temp_test_dir("lid-merge-duplicate-stanza");
        let store =
            VaultStore::open_encrypted(&dir.join("vault.db"), &dir.join("media"), &[31u8; 32])
                .unwrap();

        let record = |chat: &str, stanza: &str, body: &str| InboundCommitRecord {
            chat_wire_jid: chat.to_string(),
            chat_alt_jid: None,
            chat_kind: ConversationKind::DirectMessage,
            chat_title_hint: None,
            sender_wire_jid: "self@s.whatsapp.net".to_string(),
            sender_alt_jid: None,
            sender_push_name: None,
            stanza_id: stanza.to_string(),
            is_from_me: true,
            timestamp_ms: 1_000,
            delivery: DeliveryState::Delivered,
            content: MessageContent::Text {
                body: body.to_string(),
                edited_at: None,
                link_preview: None,
            },
            quoted: None,
            raw_decrypted_proto: vec![1],
            defer_fts: false,
        };

        // The same self-authored stanza is visible in both the PN and the LID thread.
        store
            .commit_inbound_batch(&[record("14155550100@s.whatsapp.net", "DUP-1", "PN copy")])
            .unwrap();
        store
            .commit_inbound_batch(&[record("9988776655@lid", "DUP-1", "LID copy")])
            .unwrap();
        assert_eq!(store.list_conversations().unwrap().len(), 2);

        // A message carrying both identities bridges the two threads.
        let mut bridge = record("9988776655@lid", "BRIDGE", "bridge");
        bridge.chat_alt_jid = Some("14155550100@s.whatsapp.net".to_string());
        store.commit_inbound_batch(&[bridge]).unwrap();

        let convs = store.list_conversations().unwrap();
        assert_eq!(convs.len(), 1, "threads must merge");
        let timeline = store.load_timeline_window(convs[0].id, None, 50).unwrap();
        assert_eq!(
            timeline.len(),
            2,
            "the duplicate stanza is deduplicated, and the bridge message survives"
        );

        // The cascade-deleted duplicate used to leave a stale FTS row behind,
        // which made searches return hits that no longer resolve to a message.
        let conn = store.conn.lock().unwrap();
        let orphan_fts: i64 = conn
            .query_row(
                "SELECT count(*) FROM messages_fts
                 WHERE local_id NOT IN (SELECT local_id FROM messages)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphan_fts, 0, "no FTS rows may outlive their message");
        drop(conn);

        let _ = fs::remove_dir_all(&dir);
    }
}

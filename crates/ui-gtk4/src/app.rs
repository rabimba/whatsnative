//! Native GTK4 + `libadwaita 1.5` desktop shell bridging the background Tokio runtime,
//! encrypted `VaultStore`, `DesktopCapabilities`, and `ProtocolEnginePort`.

use crate::cli::CliArgs;
use crate::qr_widget::QrCanvas;
use crate::style::install_app_css;
use adw::prelude::*;
use gtk4::{cairo, gdk, gio, glib, pango};
use libadwaita as adw;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use whatsnative_adapter_wa::{LiveWhatsAppAdapter, MockCompanionAdapter};
use whatsnative_domain::{
    ActiveCallBanner, CompatManifest, ConversationId, ConversationKind, ConversationSummary,
    DeliveryState, DiagnosticCounterSnapshot, DomainEvent, EngineCommand, HistorySyncStats,
    LinkPreviewCard, MediaKind, MessageContent, PUBLIC_APP_ID, PUBLIC_APP_TITLE,
    PeerIdentityRecord, ProtocolEnginePort, QuotedReplyRef, TimelineMessage, VaultLifecycleState,
};
use whatsnative_platform_xdg::{
    CloseWindowPolicy, DesktopCapabilities, KeyUnlockOutcome, KeystoreManager,
    RedactedDiagnosticsRing, XdgLayout, request_background_portal_status,
    send_desktop_notification, spawn_sleep_wake_listener,
};
use whatsnative_store::VaultStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SidebarFilter {
    All,
    Unread,
    Contacts,
    Groups,
    Channels,
}

#[derive(Debug, Clone)]
enum ComposerMode {
    Normal,
    Reply(QuotedReplyRef),
    Edit {
        target_stanza_id: String,
        original_snippet: String,
    },
}

struct UnlockedSession {
    vault: VaultStore,
    engine: Arc<dyn ProtocolEnginePort>,
}

struct AppController {
    cli: CliArgs,
    rt: tokio::runtime::Handle,
    layout: XdgLayout,
    caps: DesktopCapabilities,
    diagnostics: RedactedDiagnosticsRing,
    event_tx: async_channel::Sender<DomainEvent>,

    // Mutable UI state owned on the GTK main thread
    session: RefCell<Option<UnlockedSession>>,
    lifecycle: RefCell<VaultLifecycleState>,
    conversations: RefCell<Vec<ConversationSummary>>,
    contacts: RefCell<Vec<PeerIdentityRecord>>,
    texture_cache: RefCell<HashMap<String, gdk::Texture>>,
    active_audio: RefCell<Option<(String, gtk4::MediaFile)>>,
    pending_open_jid: RefCell<Option<String>>,
    typing_by_conv: RefCell<HashMap<ConversationId, String>>,
    selected_conv: RefCell<Option<ConversationId>>,
    oldest_loaded_sort_key: RefCell<Option<i64>>,
    timeline_limit: RefCell<usize>,
    sidebar_filter: RefCell<SidebarFilter>,
    search_query: RefCell<String>,
    composer_mode: RefCell<ComposerMode>,
    active_call: RefCell<Option<ActiveCallBanner>>,
    sync_stats: RefCell<HistorySyncStats>,
    rebuilding_rows: std::cell::Cell<bool>,

    // Top-level GTK / Adwaita widgets
    window: adw::ApplicationWindow,
    toast_overlay: adw::ToastOverlay,
    root_stack: gtk4::Stack,

    // Lock view widgets
    lock_hint_label: gtk4::Label,
    lock_pass_entry: gtk4::PasswordEntry,

    // Pairing view widgets
    qr_canvas: QrCanvas,
    pair_status_label: gtk4::Label,
    pair_code_label: gtk4::Label,
    phone_entry: gtk4::Entry,

    // Chat shell widgets
    split_view: adw::NavigationSplitView,
    safety_banner: adw::Banner,
    call_banner: adw::Banner,
    search_entry: gtk4::SearchEntry,
    filter_all_btn: gtk4::ToggleButton,
    sidebar_stack: gtk4::Stack,
    conv_list: gtk4::ListBox,
    contacts_list: gtk4::ListBox,
    contacts_count_label: gtk4::Label,
    search_list: gtk4::ListBox,
    search_scope_label: gtk4::Label,
    header_avatar: adw::Avatar,
    chat_title_widget: adw::WindowTitle,
    timeline_scroll: gtk4::ScrolledWindow,
    timeline_box: gtk4::Box,
    load_older_btn: gtk4::Button,
    context_bar_box: gtk4::Box,
    context_bar_label: gtk4::Label,
    composer_buffer: gtk4::TextBuffer,
}

pub fn run_gtk_application(
    cli: CliArgs,
    rt: tokio::runtime::Handle,
    layout: XdgLayout,
    caps: DesktopCapabilities,
    diagnostics: RedactedDiagnosticsRing,
) -> i32 {
    let app = adw::Application::builder()
        .application_id(PUBLIC_APP_ID)
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();

    app.connect_activate(move |adw_app| {
        install_app_css();
        build_and_present_ui(
            adw_app,
            cli.clone(),
            rt.clone(),
            layout.clone(),
            caps.clone(),
            diagnostics.clone(),
        );
    });

    // Pass empty argv to GApplication because we already parsed `CliArgs`.
    let empty_args: [&str; 0] = [];
    app.run_with_args(&empty_args).value()
}

fn build_and_present_ui(
    app: &adw::Application,
    cli: CliArgs,
    rt: tokio::runtime::Handle,
    layout: XdgLayout,
    caps: DesktopCapabilities,
    diagnostics: RedactedDiagnosticsRing,
) {
    let (event_tx, event_rx) = async_channel::unbounded::<DomainEvent>();

    let toast_overlay = adw::ToastOverlay::new();
    let root_stack = gtk4::Stack::builder()
        .transition_type(gtk4::StackTransitionType::Crossfade)
        .transition_duration(150)
        .build();
    toast_overlay.set_child(Some(&root_stack));

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title(PUBLIC_APP_TITLE)
        .default_width(1080)
        .default_height(740)
        .content(&toast_overlay)
        .build();

    // --- 1. Vault Lock View ---
    let lock_hint_label = gtk4::Label::builder()
        .label("Encrypted local vault requires unlock.")
        .wrap(true)
        .justify(gtk4::Justification::Center)
        .css_classes(["dim-label"])
        .build();
    let lock_pass_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("Vault passphrase (or unlock login keyring)")
        .show_peek_icon(true)
        .width_request(320)
        .halign(gtk4::Align::Center)
        .build();
    let unlock_btn = gtk4::Button::builder()
        .label("Unlock Encrypted Vault")
        .halign(gtk4::Align::Center)
        .css_classes(["suggested-action", "pill"])
        .build();
    let retry_keyring_btn = gtk4::Button::builder()
        .label("Retry Keyring Unlock")
        .halign(gtk4::Align::Center)
        .css_classes(["pill"])
        .build();

    let lock_box = gtk4::Box::new(gtk4::Orientation::Vertical, 14);
    lock_box.set_valign(gtk4::Align::Center);
    lock_box.set_halign(gtk4::Align::Center);
    lock_box.set_margin_top(32);
    lock_box.set_margin_bottom(32);
    lock_box.set_margin_start(24);
    lock_box.set_margin_end(24);
    let lock_status = adw::StatusPage::builder()
        .icon_name("channel-secure-symbolic")
        .title("Vault Locked")
        .description(
            "Paired companion state is preserved safely on disk. Unlock your keyring or enter your vault passphrase to open SQLCipher storage.",
        )
        .child(&lock_box)
        .build();
    lock_box.append(&lock_hint_label);
    lock_box.append(&lock_pass_entry);
    lock_box.append(&unlock_btn);
    lock_box.append(&retry_keyring_btn);

    let lock_toolbar = adw::ToolbarView::new();
    lock_toolbar.add_top_bar(&adw::HeaderBar::new());
    lock_toolbar.set_content(Some(&lock_status));
    root_stack.add_named(&lock_toolbar, Some("locked"));

    // --- 2. First-Run Unofficial Companion Risk Consent Gate ---
    let consent_accept_btn = gtk4::Button::builder()
        .label("I Understand — Continue to Companion Pairing")
        .halign(gtk4::Align::Center)
        .css_classes(["suggested-action", "pill"])
        .build();
    let consent_mock_btn = gtk4::Button::builder()
        .label("Launch Offline Mock Demo (--mock, Zero Account Risk)")
        .halign(gtk4::Align::Center)
        .css_classes(["pill"])
        .build();
    let consent_actions = gtk4::Box::new(gtk4::Orientation::Vertical, 10);
    consent_actions.set_halign(gtk4::Align::Center);
    consent_actions.append(&consent_accept_btn);
    consent_actions.append(&consent_mock_btn);

    let consent_page = adw::StatusPage::builder()
        .icon_name("security-high-symbolic")
        .title("Unofficial Linux Companion Notice")
        .description(
            "Kestrel Companion is an independent, open-source native Linux client and is not affiliated with or endorsed by WhatsApp or Meta.\n\n\
             • Built-in safety guardrails: human-paced rate limiting, sender-key retry-storm quarantine, and instant 405/TemporaryBan offline circuit breakers.\n\
             • All messages, search indexes, and cached media are encrypted at rest with SQLCipher + ChaCha20-Poly1305.",
        )
        .child(&consent_actions)
        .build();
    let consent_toolbar = adw::ToolbarView::new();
    consent_toolbar.add_top_bar(&adw::HeaderBar::new());
    consent_toolbar.set_content(Some(&consent_page));
    root_stack.add_named(&consent_toolbar, Some("consent"));

    // --- 3. Companion Pairing View (QR + 8-Char Phone Link Code) ---
    let qr_canvas = QrCanvas::new(256);
    let pair_status_label = gtk4::Label::builder()
        .label("Open WhatsApp on your phone → Linked Devices → Link a Device")
        .wrap(true)
        .justify(gtk4::Justification::Center)
        .build();
    let pair_code_label = gtk4::Label::builder()
        .label("")
        .visible(false)
        .selectable(true)
        .halign(gtk4::Align::Center)
        .css_classes(["pair-code-pill"])
        .build();
    let phone_entry = gtk4::Entry::builder()
        .placeholder_text("Phone digits for 8-char code (e.g. 14155550199)")
        .width_request(290)
        .build();
    if let Some(p) = &cli.phone_number {
        phone_entry.set_text(p);
    }
    let request_code_btn = gtk4::Button::builder()
        .label("Get 8-Char Code")
        .css_classes(["suggested-action"])
        .build();
    let phone_row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    phone_row.set_halign(gtk4::Align::Center);
    phone_row.append(&phone_entry);
    phone_row.append(&request_code_btn);

    let refresh_qr_btn = gtk4::Button::builder()
        .label("Start / Refresh QR Session")
        .halign(gtk4::Align::Center)
        .css_classes(["pill"])
        .build();
    let browse_offline_btn = gtk4::Button::builder()
        .label("Open Local Encrypted Archive Offline")
        .halign(gtk4::Align::Center)
        .css_classes(["flat"])
        .build();

    let pair_inner = gtk4::Box::new(gtk4::Orientation::Vertical, 14);
    pair_inner.set_valign(gtk4::Align::Center);
    pair_inner.set_halign(gtk4::Align::Center);
    pair_inner.set_margin_top(24);
    pair_inner.set_margin_bottom(24);
    pair_inner.set_margin_start(24);
    pair_inner.set_margin_end(24);
    let pair_heading = gtk4::Label::builder()
        .label("Link Companion Device")
        .css_classes(["title-1"])
        .build();
    pair_inner.append(&pair_heading);
    pair_inner.append(&pair_status_label);
    pair_inner.append(qr_canvas.widget());
    pair_inner.append(&pair_code_label);
    pair_inner.append(&phone_row);
    pair_inner.append(&refresh_qr_btn);
    pair_inner.append(&browse_offline_btn);

    let pair_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .child(&pair_inner)
        .vexpand(true)
        .build();
    let pair_toolbar = adw::ToolbarView::new();
    pair_toolbar.add_top_bar(&adw::HeaderBar::new());
    pair_toolbar.set_content(Some(&pair_scroll));
    root_stack.add_named(&pair_toolbar, Some("pairing"));

    // --- 4. Adaptive Split Chat Shell ---
    let safety_banner = adw::Banner::new("");
    safety_banner.set_revealed(false);

    let call_banner = adw::Banner::new("");
    call_banner.set_button_label(Some("Decline Call"));
    call_banner.set_revealed(false);

    // Sidebar header + menu
    let menu = gio::Menu::new();
    menu.append(
        Some("Sync Contacts & Profile Pictures"),
        Some("win.sync-contacts"),
    );
    menu.append(Some("Reconnect / Pair Companion"), Some("win.reconnect"));
    menu.append(
        Some("Simulate Incoming Call (Demo)"),
        Some("win.simulate-call"),
    );
    menu.append(
        Some("Export Redacted Diagnostics…"),
        Some("win.export-diagnostics"),
    );
    menu.append(Some("Work Offline (Read-Only)"), Some("win.go-offline"));
    menu.append(Some("Unlink Companion"), Some("win.logout"));

    let sync_contacts_btn = gtk4::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text("Sync contacts, profile pictures & chat media")
        .build();

    let menu_btn = gtk4::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .menu_model(&menu)
        .tooltip_text("Companion Menu")
        .build();

    let sidebar_title = adw::WindowTitle::new(
        PUBLIC_APP_TITLE,
        if cli.mock_mode {
            "Offline Mock Archive · SQLCipher"
        } else {
            "Encrypted Companion"
        },
    );
    let sidebar_header = adw::HeaderBar::builder()
        .title_widget(&sidebar_title)
        .build();
    sidebar_header.pack_start(&sync_contacts_btn);
    sidebar_header.pack_end(&menu_btn);

    let search_entry = gtk4::SearchEntry::builder()
        .placeholder_text("Search contacts & encrypted archive (Ctrl+K)…")
        .hexpand(true)
        .margin_start(10)
        .margin_end(10)
        .margin_top(6)
        .margin_bottom(4)
        .build();

    // Filter pills
    let filter_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 2);
    filter_box.set_margin_start(8);
    filter_box.set_margin_end(8);
    filter_box.set_margin_bottom(6);
    let filter_all_btn = gtk4::ToggleButton::builder()
        .label("All")
        .active(true)
        .css_classes(["flat"])
        .build();
    let filter_unread_btn = gtk4::ToggleButton::builder()
        .label("Unread")
        .group(&filter_all_btn)
        .css_classes(["flat"])
        .build();
    let filter_contacts_btn = gtk4::ToggleButton::builder()
        .label("Contacts")
        .group(&filter_all_btn)
        .css_classes(["flat"])
        .build();
    let filter_groups_btn = gtk4::ToggleButton::builder()
        .label("Groups")
        .group(&filter_all_btn)
        .css_classes(["flat"])
        .build();
    let filter_channels_btn = gtk4::ToggleButton::builder()
        .label("Channels")
        .group(&filter_all_btn)
        .css_classes(["flat"])
        .build();
    filter_box.append(&filter_all_btn);
    filter_box.append(&filter_unread_btn);
    filter_box.append(&filter_contacts_btn);
    filter_box.append(&filter_groups_btn);
    filter_box.append(&filter_channels_btn);
    let filter_scroll = gtk4::ScrolledWindow::builder()
        .vscrollbar_policy(gtk4::PolicyType::Never)
        .hscrollbar_policy(gtk4::PolicyType::External)
        .child(&filter_box)
        .build();

    let conv_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::Single)
        .css_classes(["navigation-sidebar"])
        .build();
    let conv_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&conv_list)
        .build();

    let contacts_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::None)
        .css_classes(["navigation-sidebar"])
        .build();
    let contacts_count_label = gtk4::Label::builder()
        .label("Syncing contacts…")
        .wrap(true)
        .xalign(0.0)
        .margin_start(12)
        .margin_end(12)
        .margin_top(6)
        .margin_bottom(8)
        .css_classes(["caption", "dim-label"])
        .build();
    let contacts_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&contacts_list)
        .build();
    let contacts_pane_box = gtk4::Box::new(gtk4::Orientation::Vertical, 4);
    contacts_pane_box.append(&contacts_scroll);
    contacts_pane_box.append(&contacts_count_label);

    let search_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::None)
        .css_classes(["navigation-sidebar"])
        .build();
    let search_scope_label = gtk4::Label::builder()
        .label("")
        .wrap(true)
        .xalign(0.0)
        .margin_start(12)
        .margin_end(12)
        .margin_top(6)
        .margin_bottom(8)
        .css_classes(["caption", "dim-label"])
        .build();
    let search_pane_box = gtk4::Box::new(gtk4::Orientation::Vertical, 4);
    let search_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&search_list)
        .build();
    search_pane_box.append(&search_scroll);
    search_pane_box.append(&search_scope_label);

    let sidebar_stack = gtk4::Stack::new();
    sidebar_stack.add_named(&conv_scroll, Some("conversations"));
    sidebar_stack.add_named(&contacts_pane_box, Some("contacts"));
    sidebar_stack.add_named(&search_pane_box, Some("search"));

    let sidebar_body = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    sidebar_body.append(&search_entry);
    sidebar_body.append(&filter_scroll);
    sidebar_body.append(&sidebar_stack);

    let sidebar_toolbar = adw::ToolbarView::new();
    sidebar_toolbar.add_top_bar(&sidebar_header);
    sidebar_toolbar.set_content(Some(&sidebar_body));
    let sidebar_page = adw::NavigationPage::builder()
        .title("Chats")
        .tag("sidebar")
        .child(&sidebar_toolbar)
        .build();

    // Content / Timeline pane
    let header_avatar = adw::Avatar::new(32, None, true);
    header_avatar.set_visible(false);
    let chat_title_widget = adw::WindowTitle::new("Select a Conversation", "");
    let load_older_btn = gtk4::Button::builder()
        .icon_name("go-up-symbolic")
        .tooltip_text("Load older messages (keyset pagination)")
        .sensitive(false)
        .build();
    let content_header = adw::HeaderBar::builder()
        .title_widget(&chat_title_widget)
        .build();
    content_header.pack_start(&header_avatar);
    content_header.pack_end(&load_older_btn);

    let timeline_box = gtk4::Box::new(gtk4::Orientation::Vertical, 10);
    timeline_box.set_margin_top(14);
    timeline_box.set_margin_bottom(14);
    timeline_box.set_margin_start(16);
    timeline_box.set_margin_end(16);
    timeline_box.set_valign(gtk4::Align::End);

    let timeline_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&timeline_box)
        .build();

    // Context bar for Reply / Edit
    let context_bar_label = gtk4::Label::builder()
        .xalign(0.0)
        .hexpand(true)
        .ellipsize(pango::EllipsizeMode::End)
        .css_classes(["caption"])
        .build();
    let context_cancel_btn = gtk4::Button::builder()
        .icon_name("window-close-symbolic")
        .css_classes(["flat", "circular"])
        .tooltip_text("Cancel reply / edit (Esc)")
        .build();
    let context_bar_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    context_bar_box.add_css_class("reply-bar");
    context_bar_box.set_visible(false);
    context_bar_box.append(&context_bar_label);
    context_bar_box.append(&context_cancel_btn);

    // Composer bar
    let attach_btn = gtk4::Button::builder()
        .icon_name("mail-attachment-symbolic")
        .tooltip_text("Attach file / photo via XDG FileChooser Portal")
        .valign(gtk4::Align::End)
        .build();

    let composer_buffer = gtk4::TextBuffer::new(None);
    let composer_view = gtk4::TextView::builder()
        .buffer(&composer_buffer)
        .wrap_mode(gtk4::WrapMode::WordChar)
        .hexpand(true)
        .top_margin(6)
        .bottom_margin(6)
        .left_margin(8)
        .right_margin(8)
        .css_classes(["composer-input"])
        .build();
    let composer_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .max_content_height(110)
        .propagate_natural_height(true)
        .hexpand(true)
        .child(&composer_view)
        .build();

    let send_btn = gtk4::Button::builder()
        .icon_name("paper-plane-symbolic")
        .label("Send")
        .valign(gtk4::Align::End)
        .css_classes(["suggested-action"])
        .build();

    let composer_row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    composer_row.add_css_class("composer-frame");
    composer_row.append(&attach_btn);
    composer_row.append(&composer_scroll);
    composer_row.append(&send_btn);

    let content_column = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    content_column.append(&timeline_scroll);
    content_column.append(&context_bar_box);
    content_column.append(&composer_row);

    let content_toolbar = adw::ToolbarView::new();
    content_toolbar.add_top_bar(&content_header);
    content_toolbar.set_content(Some(&content_column));
    let content_page = adw::NavigationPage::builder()
        .title("Timeline")
        .tag("content")
        .child(&content_toolbar)
        .build();

    let split_view = adw::NavigationSplitView::builder()
        .sidebar(&sidebar_page)
        .content(&content_page)
        .min_sidebar_width(290.0)
        .max_sidebar_width(380.0)
        .vexpand(true)
        .build();

    let shell_outer = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    shell_outer.append(&call_banner);
    shell_outer.append(&safety_banner);
    shell_outer.append(&split_view);
    root_stack.add_named(&shell_outer, Some("chat"));

    let ctrl = Rc::new(AppController {
        cli: cli.clone(),
        rt: rt.clone(),
        layout,
        caps: caps.clone(),
        diagnostics,
        event_tx,
        session: RefCell::new(None),
        lifecycle: RefCell::new(VaultLifecycleState::Unpaired),
        conversations: RefCell::new(Vec::new()),
        contacts: RefCell::new(Vec::new()),
        texture_cache: RefCell::new(HashMap::new()),
        active_audio: RefCell::new(None),
        pending_open_jid: RefCell::new(None),
        typing_by_conv: RefCell::new(HashMap::new()),
        selected_conv: RefCell::new(None),
        oldest_loaded_sort_key: RefCell::new(None),
        timeline_limit: RefCell::new(60),
        sidebar_filter: RefCell::new(SidebarFilter::All),
        search_query: RefCell::new(String::new()),
        composer_mode: RefCell::new(ComposerMode::Normal),
        active_call: RefCell::new(None),
        sync_stats: RefCell::new(HistorySyncStats::default()),
        rebuilding_rows: std::cell::Cell::new(false),
        window: window.clone(),
        toast_overlay,
        root_stack,
        lock_hint_label,
        lock_pass_entry: lock_pass_entry.clone(),
        qr_canvas,
        pair_status_label,
        pair_code_label,
        phone_entry: phone_entry.clone(),
        split_view,
        safety_banner,
        call_banner: call_banner.clone(),
        search_entry: search_entry.clone(),
        filter_all_btn: filter_all_btn.clone(),
        sidebar_stack,
        conv_list: conv_list.clone(),
        contacts_list: contacts_list.clone(),
        contacts_count_label,
        search_list,
        search_scope_label,
        header_avatar,
        chat_title_widget,
        timeline_scroll,
        timeline_box,
        load_older_btn: load_older_btn.clone(),
        context_bar_box,
        context_bar_label,
        composer_buffer: composer_buffer.clone(),
    });

    // --- Wire UI Actions & Event Handlers ---
    wire_window_actions(&ctrl);

    {
        let c = ctrl.clone();
        sync_contacts_btn.connect_clicked(move |_| {
            c.show_toast("Refreshing contacts, profile pictures & chat media…");
            c.submit_engine_command(EngineCommand::RefreshContactsAndAvatars);
        });
    }

    {
        let c = ctrl.clone();
        unlock_btn.connect_clicked(move |_| {
            let pass = c.lock_pass_entry.text().to_string();
            c.try_unlock_vault(Some(pass).filter(|s| !s.is_empty()), c.cli.mock_mode);
        });
    }
    {
        let c = ctrl.clone();
        lock_pass_entry.connect_activate(move |entry| {
            let pass = entry.text().to_string();
            c.try_unlock_vault(Some(pass).filter(|s| !s.is_empty()), c.cli.mock_mode);
        });
    }
    {
        let c = ctrl.clone();
        retry_keyring_btn.connect_clicked(move |_| {
            c.try_unlock_vault(None, c.cli.mock_mode);
        });
    }
    {
        let c = ctrl.clone();
        consent_accept_btn.connect_clicked(move |_| {
            if let Some(sess) = c.session.borrow().as_ref() {
                let _ = sess.vault.set_risk_consent_accepted(true);
            }
            c.diagnostics
                .record_sanitized_event("consent", "User accepted companion risk notice");
            c.transition_lifecycle(VaultLifecycleState::Unpaired);
            c.start_engine_session(c.cli.phone_number.clone(), c.cli.custom_pair_code.clone());
        });
    }
    {
        let c = ctrl.clone();
        consent_mock_btn.connect_clicked(move |_| {
            c.switch_to_mock_session();
        });
    }
    {
        let c = ctrl.clone();
        refresh_qr_btn.connect_clicked(move |_| {
            c.pair_code_label.set_visible(false);
            c.start_engine_session(None, None);
        });
    }
    {
        let c = ctrl.clone();
        request_code_btn.connect_clicked(move |_| {
            let phone = c.phone_entry.text().trim().to_string();
            if phone.is_empty() {
                c.show_toast("Enter your phone number in international digits first");
                return;
            }
            c.start_engine_session(Some(phone), c.cli.custom_pair_code.clone());
        });
    }
    {
        let c = ctrl.clone();
        browse_offline_btn.connect_clicked(move |_| {
            c.transition_lifecycle(VaultLifecycleState::OfflineReadOnly {
                reason: "Offline archive mode — encrypted FTS5 search active".into(),
            });
            c.refresh_conversations_from_store();
        });
    }
    {
        let c = ctrl.clone();
        call_banner.connect_button_clicked(move |_| {
            let maybe_call = c.active_call.borrow().clone();
            if let Some(call) = maybe_call {
                c.submit_engine_command(EngineCommand::DeclineCall {
                    call_id: call.call_id,
                    peer_wire_jid: call.peer_wire_jid,
                    creator_wire_jid: call.creator_wire_jid,
                });
            }
        });
    }

    // Sidebar filter buttons
    for (btn, mode) in [
        (&filter_all_btn, SidebarFilter::All),
        (&filter_unread_btn, SidebarFilter::Unread),
        (&filter_contacts_btn, SidebarFilter::Contacts),
        (&filter_groups_btn, SidebarFilter::Groups),
        (&filter_channels_btn, SidebarFilter::Channels),
    ] {
        let c = ctrl.clone();
        btn.connect_toggled(move |b| {
            if b.is_active() {
                *c.sidebar_filter.borrow_mut() = mode;
                if c.search_query.borrow().is_empty() {
                    if mode == SidebarFilter::Contacts {
                        c.rebuild_contact_rows();
                        c.sidebar_stack.set_visible_child_name("contacts");
                    } else {
                        c.rebuild_conversation_rows();
                        c.sidebar_stack.set_visible_child_name("conversations");
                    }
                }
            }
        });
    }

    // Search entry (<100 ms SQLCipher FTS5 + contact match)
    {
        let c = ctrl.clone();
        search_entry.connect_search_changed(move |entry| {
            let q = entry.text().trim().to_string();
            *c.search_query.borrow_mut() = q;
            c.refresh_search_results();
        });
    }

    // Conversation selection
    {
        let c = ctrl.clone();
        conv_list.connect_row_selected(move |_, maybe_row| {
            if c.rebuilding_rows.get() {
                return;
            }
            let Some(row) = maybe_row else {
                return;
            };
            let name = row.widget_name();
            if let Ok(cid) = ConversationId::parse(name.as_str())
                && *c.selected_conv.borrow() != Some(cid)
            {
                c.select_conversation(cid);
            }
        });
    }

    // Contact activation (opens existing 1:1 thread or creates a new DM thread)
    {
        let c = ctrl.clone();
        contacts_list.connect_row_activated(move |_, row| {
            if c.rebuilding_rows.get() {
                return;
            }
            let wire_jid = row.widget_name().to_string();
            if wire_jid.is_empty() {
                return;
            }
            let hint = c
                .contacts
                .borrow()
                .iter()
                .find(|p| {
                    p.pn_jid.as_deref() == Some(wire_jid.as_str())
                        || p.lid_jid.as_deref() == Some(wire_jid.as_str())
                })
                .map(|p| p.display_name.clone());
            c.open_contact_chat(wire_jid, hint);
        });
    }

    // Load older timeline messages (keyset pagination)
    {
        let c = ctrl.clone();
        load_older_btn.connect_clicked(move |_| {
            let next_limit = *c.timeline_limit.borrow() + 60;
            *c.timeline_limit.borrow_mut() = next_limit;
            c.reload_active_timeline(false);
        });
    }

    // Cancel Reply / Edit
    {
        let c = ctrl.clone();
        context_cancel_btn.connect_clicked(move |_| {
            c.set_composer_mode(ComposerMode::Normal);
        });
    }

    // Send button
    {
        let c = ctrl.clone();
        send_btn.connect_clicked(move |_| {
            c.send_from_composer();
        });
    }

    // Attachment FileDialog (XDG FileChooser Portal)
    {
        let c = ctrl.clone();
        attach_btn.connect_clicked(move |_| {
            let c_inner = c.clone();
            glib::spawn_future_local(async move {
                let dialog = gtk4::FileDialog::builder()
                    .title("Send Attachment")
                    .modal(true)
                    .build();
                if let Ok(file) = dialog.open_future(Some(&c_inner.window)).await
                    && let Some(path) = file.path()
                {
                    c_inner.send_attachment_path(path);
                }
            });
        });
    }

    // Composer keyboard controller: Enter sends, Shift+Enter inserts newline, Esc clears reply/edit, Ctrl+V pastes image
    {
        let key_ctrl = gtk4::EventControllerKey::new();
        let c = ctrl.clone();
        key_ctrl.connect_key_pressed(move |_, key, _code, state| {
            if key == gdk::Key::Escape {
                c.set_composer_mode(ComposerMode::Normal);
                return glib::Propagation::Stop;
            }
            if (key == gdk::Key::Return || key == gdk::Key::KP_Enter)
                && !state.contains(gdk::ModifierType::SHIFT_MASK)
            {
                c.send_from_composer();
                return glib::Propagation::Stop;
            }
            if state.contains(gdk::ModifierType::CONTROL_MASK)
                && (key == gdk::Key::v || key == gdk::Key::V)
            {
                let c_paste = c.clone();
                glib::spawn_future_local(async move {
                    c_paste.try_paste_clipboard_image().await;
                });
            }
            glib::Propagation::Proceed
        });
        composer_view.add_controller(key_ctrl);
    }

    // Window-global Ctrl+K focuses FTS5 search
    {
        let win_key = gtk4::EventControllerKey::new();
        let search_ref = search_entry.clone();
        win_key.connect_key_pressed(move |_, key, _code, state| {
            if state.contains(gdk::ModifierType::CONTROL_MASK)
                && (key == gdk::Key::k || key == gdk::Key::K)
            {
                search_ref.grab_focus();
                return glib::Propagation::Stop;
            }
            glib::Propagation::Proceed
        });
        window.add_controller(win_key);
    }

    // Close-window policy honoring live XDG DesktopCapabilities
    {
        let c = ctrl.clone();
        window.connect_close_request(move |win| match c.caps.close_policy {
            CloseWindowPolicy::HideToBackgroundPortal | CloseWindowPolicy::HideToStatusTray => {
                win.set_visible(false);
                let rt_bg = c.rt.clone();
                rt_bg.spawn(async move {
                    let _ = request_background_portal_status(
                        "Connected — receiving encrypted companion messages",
                    )
                    .await;
                });
                glib::Propagation::Stop
            }
            CloseWindowPolicy::QuitCleanly => glib::Propagation::Proceed,
        });
    }

    // Pump DomainEvents from Tokio onto the GTK main thread
    {
        let c = ctrl.clone();
        glib::spawn_future_local(async move {
            while let Ok(ev) = event_rx.recv().await {
                c.handle_domain_event(ev);
            }
        });
    }

    // Perform initial vault unlock + startup transition
    ctrl.try_unlock_vault(cli.passphrase.clone(), cli.mock_mode);
    window.present();
}

fn wire_window_actions(ctrl: &Rc<AppController>) {
    let act_sync = gio::SimpleAction::new("sync-contacts", None);
    {
        let c = ctrl.clone();
        act_sync.connect_activate(move |_, _| {
            c.show_toast("Refreshing contacts, profile pictures & chat media…");
            c.submit_engine_command(EngineCommand::RefreshContactsAndAvatars);
        });
    }
    ctrl.window.add_action(&act_sync);

    let act_reconnect = gio::SimpleAction::new("reconnect", None);
    {
        let c = ctrl.clone();
        act_reconnect.connect_activate(move |_, _| {
            c.transition_lifecycle(VaultLifecycleState::Unpaired);
            c.start_engine_session(c.cli.phone_number.clone(), c.cli.custom_pair_code.clone());
        });
    }
    ctrl.window.add_action(&act_reconnect);

    let act_sim_call = gio::SimpleAction::new("simulate-call", None);
    {
        let c = ctrl.clone();
        act_sim_call.connect_activate(move |_, _| {
            let banner = ActiveCallBanner {
                call_id: format!("DEMO-CALL-{}", chrono::Utc::now().timestamp()),
                peer_wire_jid: "14155550101@s.whatsapp.net".into(),
                creator_wire_jid: "14155550101@s.whatsapp.net".into(),
                caller_display: "Linus (+14155550101)".into(),
                is_video: true,
                is_group: false,
                started_at: chrono::Utc::now(),
            };
            let tx = c.event_tx.clone();
            c.rt.spawn(async move {
                let _ = tx.send(DomainEvent::CallBannerUpdated(Some(banner))).await;
            });
        });
    }
    ctrl.window.add_action(&act_sim_call);

    let act_diag = gio::SimpleAction::new("export-diagnostics", None);
    {
        let c = ctrl.clone();
        act_diag.connect_activate(move |_, _| {
            let out_path = c.layout.state_log_dir.join("kestrel-diagnostics.json");
            let counters = c
                .session
                .borrow()
                .as_ref()
                .map(|s| s.engine.diagnostics())
                .unwrap_or(DiagnosticCounterSnapshot {
                    messages_persisted: 0,
                    retry_receipts_quarantined: 0,
                    history_chunks_staged: 0,
                    outbound_commands_paced: 0,
                    call_signals_observed: 0,
                    circuit_breaker_trips: 0,
                    last_protocol_anomaly: None,
                });
            let sync_stats = c.sync_stats.borrow().clone();
            match c
                .diagnostics
                .export_bundle(&out_path, c.caps.clone(), counters, sync_stats)
            {
                Ok(()) => c.show_toast(&format!(
                    "Exported redacted diagnostics to {}",
                    out_path.display()
                )),
                Err(e) => c.show_toast(&format!("Diagnostic export failed: {e}")),
            }
        });
    }
    ctrl.window.add_action(&act_diag);

    let act_offline = gio::SimpleAction::new("go-offline", None);
    {
        let c = ctrl.clone();
        act_offline.connect_activate(move |_, _| {
            c.submit_engine_command(EngineCommand::Disconnect);
        });
    }
    ctrl.window.add_action(&act_offline);

    let act_logout = gio::SimpleAction::new("logout", None);
    {
        let c = ctrl.clone();
        act_logout.connect_activate(move |_, _| {
            c.submit_engine_command(EngineCommand::Logout);
        });
    }
    ctrl.window.add_action(&act_logout);
}

impl AppController {
    fn try_unlock_vault(self: &Rc<Self>, passphrase: Option<String>, use_mock: bool) {
        let keystore = KeystoreManager::new(self.layout.keystore_manifest_path.clone());
        match keystore.unlock_or_initialize(&self.caps, passphrase.as_deref()) {
            Ok(KeyUnlockOutcome::Unlocked(master_key)) => {
                match VaultStore::open_encrypted(
                    &self.layout.vault_db_path,
                    &self.layout.cache_media_dir,
                    &master_key,
                ) {
                    Ok(vault) => {
                        self.diagnostics
                            .record_sanitized_event("vault", "SQLCipher vault unlocked");
                        self.attach_unlocked_vault(vault, use_mock);
                    }
                    Err(e) => {
                        self.lock_hint_label
                            .set_label(&format!("SQLCipher unlock failed: {e}"));
                        self.transition_lifecycle(VaultLifecycleState::VaultLocked {
                            backend_hint: e.to_string(),
                        });
                    }
                }
            }
            Ok(KeyUnlockOutcome::LockedNeedsPassphrase) => {
                self.lock_hint_label
                    .set_label("Enter your passphrase to unlock SQLCipher storage.");
                self.transition_lifecycle(VaultLifecycleState::VaultLocked {
                    backend_hint: "Passphrase required".into(),
                });
            }
            Ok(KeyUnlockOutcome::LockedWaitingForKeyring { backend_hint }) => {
                self.lock_hint_label.set_label(&backend_hint);
                self.transition_lifecycle(VaultLifecycleState::VaultLocked { backend_hint });
            }
            Err(e) => {
                self.lock_hint_label
                    .set_label(&format!("Unlock error (check passphrase): {e}"));
                self.transition_lifecycle(VaultLifecycleState::VaultLocked {
                    backend_hint: e.to_string(),
                });
            }
        }
    }

    fn attach_unlocked_vault(self: &Rc<Self>, vault: VaultStore, use_mock: bool) {
        let engine: Arc<dyn ProtocolEnginePort> = if use_mock {
            Arc::new(MockCompanionAdapter::new(
                vault.clone(),
                self.event_tx.clone(),
            ))
        } else {
            let engine_live = Arc::new(LiveWhatsAppAdapter::new(
                vault.clone(),
                self.layout.crypto_db_path.clone(),
                self.layout.crypto_guard_path.clone(),
                CompatManifest::default_local(),
                self.cli.allow_unverified_protocol,
                self.event_tx.clone(),
            ));
            let eng_wake = engine_live.clone();
            let rt_wake = self.rt.clone();
            let _guard = self.rt.enter();
            spawn_sleep_wake_listener(move |cmd| {
                let eng = eng_wake.clone();
                rt_wake.spawn(async move {
                    let _ = eng.submit(cmd).await;
                });
            });
            engine_live
        };

        let consent_done = vault.is_risk_consent_accepted().unwrap_or(false);
        let has_existing_session = self.layout.crypto_db_path.exists();

        *self.session.borrow_mut() = Some(UnlockedSession { vault, engine });

        self.refresh_conversations_from_store();

        if use_mock {
            self.start_engine_session(None, None);
        } else if !consent_done {
            self.transition_lifecycle(VaultLifecycleState::ConsentRequired);
        } else if has_existing_session || self.cli.phone_number.is_some() {
            self.start_engine_session(
                self.cli.phone_number.clone(),
                self.cli.custom_pair_code.clone(),
            );
        } else {
            self.transition_lifecycle(VaultLifecycleState::Unpaired);
            self.start_engine_session(None, None);
        }
    }

    fn switch_to_mock_session(self: &Rc<Self>) {
        let maybe_vault = self.session.borrow().as_ref().map(|s| s.vault.clone());
        if let Some(vault) = maybe_vault {
            self.attach_unlocked_vault(vault, true);
            self.show_toast("Switched to zero-account Offline Mock Demo");
        }
    }

    fn start_engine_session(
        &self,
        phone_number_for_code: Option<String>,
        custom_pair_code: Option<String>,
    ) {
        self.submit_engine_command(EngineCommand::StartSession {
            phone_number_for_code,
            custom_pair_code,
        });
    }

    fn submit_engine_command(&self, cmd: EngineCommand) {
        let Some(engine) = self.session.borrow().as_ref().map(|s| s.engine.clone()) else {
            return;
        };
        let tx = self.event_tx.clone();
        self.rt.spawn(async move {
            if let Err(e) = engine.submit(cmd).await {
                let _ = tx
                    .send(DomainEvent::ToastMessage(format!("Engine error: {e}")))
                    .await;
            }
        });
    }

    fn handle_domain_event(self: &Rc<Self>, ev: DomainEvent) {
        match ev {
            DomainEvent::LifecycleChanged(state) => {
                self.diagnostics
                    .record_sanitized_event("lifecycle", &format!("State -> {:?}", state));
                self.transition_lifecycle(state);
            }
            DomainEvent::ConversationsUpdated(list) => {
                *self.conversations.borrow_mut() = list;

                let pending_target = self.pending_open_jid.borrow().clone();
                let pending_cid = pending_target.and_then(|target| {
                    let norm_target = VaultStore::normalize_wire_jid(&target);
                    self.conversations
                        .borrow()
                        .iter()
                        .find(|c| {
                            VaultStore::normalize_wire_jid(&c.primary_wire_jid) == norm_target
                        })
                        .map(|c| c.id)
                });

                if let Some(cid) = pending_cid {
                    *self.pending_open_jid.borrow_mut() = None;
                    self.select_conversation(cid);
                } else if self.selected_conv.borrow().is_none() {
                    let auto_select = self.conversations.borrow().first().map(|c| c.id);
                    if let Some(first_id) = auto_select {
                        self.select_conversation(first_id);
                    } else {
                        self.rebuild_conversation_rows();
                        self.update_active_header();
                    }
                } else {
                    self.rebuild_conversation_rows();
                    self.update_active_header();
                }
            }
            DomainEvent::ContactsUpdated(list) => {
                *self.contacts.borrow_mut() = list;
                if *self.sidebar_filter.borrow() == SidebarFilter::Contacts {
                    self.rebuild_contact_rows();
                }
                if !self.search_query.borrow().is_empty() {
                    self.refresh_search_results();
                }
            }
            DomainEvent::AvatarUpdated { cache_key, jid } => {
                self.texture_cache.borrow_mut().remove(&cache_key);

                let norm_jid = VaultStore::normalize_wire_jid(&jid);
                let active_wire_jid = self.selected_conv.borrow().and_then(|id| {
                    self.conversations
                        .borrow()
                        .iter()
                        .find(|c| c.id == id)
                        .map(|c| VaultStore::normalize_wire_jid(&c.primary_wire_jid))
                });
                if active_wire_jid.as_deref() == Some(&norm_jid) {
                    self.update_active_header();
                    if self.selected_conv.borrow().is_some() {
                        self.reload_active_timeline(false);
                    }
                }

                let mut conv_matched = false;
                for conv in self.conversations.borrow_mut().iter_mut() {
                    if VaultStore::normalize_wire_jid(&conv.primary_wire_jid) == norm_jid {
                        conv.avatar_cache_key = Some(cache_key.clone());
                        conv_matched = true;
                    }
                }
                if conv_matched && *self.sidebar_filter.borrow() != SidebarFilter::Contacts {
                    self.rebuild_conversation_rows();
                }

                let mut contact_matched = false;
                for contact in self.contacts.borrow_mut().iter_mut() {
                    if contact
                        .pn_jid
                        .as_deref()
                        .map(VaultStore::normalize_wire_jid)
                        .as_deref()
                        == Some(&norm_jid)
                        || contact
                            .lid_jid
                            .as_deref()
                            .map(VaultStore::normalize_wire_jid)
                            .as_deref()
                            == Some(&norm_jid)
                    {
                        contact.avatar_cache_key = Some(cache_key.clone());
                        contact_matched = true;
                    }
                }
                if contact_matched && *self.sidebar_filter.borrow() == SidebarFilter::Contacts {
                    self.rebuild_contact_rows();
                }
            }
            DomainEvent::MediaUpdated {
                conversation_id,
                stanza_id,
            } => {
                {
                    let mut cache = self.texture_cache.borrow_mut();
                    cache.remove(&format!("media:{stanza_id}"));
                    cache.remove(&format!("thumb:{stanza_id}"));
                    cache.remove(&format!("thumb:lp-{stanza_id}"));
                }
                if *self.selected_conv.borrow() == Some(conversation_id) {
                    self.reload_active_timeline(false);
                }
            }
            DomainEvent::MessagesUpdated { conversation_id } => {
                if *self.selected_conv.borrow() == Some(conversation_id) {
                    self.reload_active_timeline(true);
                }
                if !self.search_query.borrow().is_empty() {
                    self.refresh_search_results();
                }
            }
            DomainEvent::IncomingNotification { title, body, .. } => {
                if !self.window.is_active() || !self.window.is_visible() {
                    self.rt.spawn(async move {
                        let _ = send_desktop_notification(&title, &body, false).await;
                    });
                }
            }
            DomainEvent::HistorySyncUpdated(stats) => {
                *self.sync_stats.borrow_mut() = stats.clone();
                if stats.in_progress {
                    self.safety_banner.set_title(&format!(
                        "Syncing encrypted history ({}% · {} messages indexed)…",
                        stats.progress_pct, stats.messages_committed
                    ));
                    self.safety_banner.set_revealed(true);
                } else if matches!(
                    *self.lifecycle.borrow(),
                    VaultLifecycleState::Connected { .. }
                ) {
                    self.safety_banner.set_revealed(false);
                }
            }
            DomainEvent::CallBannerUpdated(maybe_call) => {
                if let Some(call) = &maybe_call {
                    let kind = if call.is_video { "video" } else { "voice" };
                    self.call_banner.set_title(&format!(
                        "Incoming {kind} call from {} — answer on primary phone or decline here",
                        call.caller_display
                    ));
                    self.call_banner.set_revealed(true);
                } else {
                    self.call_banner.set_revealed(false);
                }
                *self.active_call.borrow_mut() = maybe_call;
            }
            DomainEvent::TypingUpdated {
                conversation_id,
                peer_label,
            } => {
                if let Some(lbl) = peer_label {
                    self.typing_by_conv
                        .borrow_mut()
                        .insert(conversation_id, lbl);
                } else {
                    self.typing_by_conv.borrow_mut().remove(&conversation_id);
                }
                self.rebuild_conversation_rows();
                self.update_active_header();
            }
            DomainEvent::ToastMessage(msg) => {
                self.show_toast(&msg);
            }
        }
    }

    fn transition_lifecycle(&self, state: VaultLifecycleState) {
        *self.lifecycle.borrow_mut() = state.clone();
        match state {
            VaultLifecycleState::VaultLocked { .. } => {
                self.root_stack.set_visible_child_name("locked");
            }
            VaultLifecycleState::ConsentRequired => {
                self.root_stack.set_visible_child_name("consent");
            }
            VaultLifecycleState::Unpaired => {
                self.qr_canvas.set_payload(None);
                self.pair_status_label.set_label(
                    "Generating companion session… scan QR or request an 8-character phone link code.",
                );
                self.root_stack.set_visible_child_name("pairing");
            }
            VaultLifecycleState::Connecting => {
                if self.conversations.borrow().is_empty() {
                    self.pair_status_label
                        .set_label("Connecting Noise XX / Signal companion session…");
                    self.root_stack.set_visible_child_name("pairing");
                } else {
                    self.root_stack.set_visible_child_name("chat");
                }
            }
            VaultLifecycleState::Pairing {
                qr_payload,
                pair_code,
                expires_in_secs,
            } => {
                if let Some(qr) = qr_payload {
                    self.qr_canvas.set_payload(Some(qr));
                    self.pair_status_label.set_label(&format!(
                        "Scan QR from WhatsApp → Linked Devices (refreshes in {expires_in_secs}s)"
                    ));
                }
                if let Some(code) = pair_code {
                    self.pair_code_label.set_label(&code);
                    self.pair_code_label.set_visible(true);
                    self.pair_status_label.set_label(&format!(
                        "Enter this 8-character code on your phone within {expires_in_secs}s:"
                    ));
                }
                self.root_stack.set_visible_child_name("pairing");
            }
            VaultLifecycleState::Connected { push_name, .. } => {
                self.safety_banner.set_revealed(false);
                self.root_stack.set_visible_child_name("chat");
                if !push_name.is_empty() {
                    self.window
                        .set_title(Some(&format!("{PUBLIC_APP_TITLE} — {push_name}")));
                }
            }
            VaultLifecycleState::Quarantined { reason } => {
                self.safety_banner
                    .set_title(&format!("Account-Safety Quarantine: {reason}"));
                self.safety_banner.set_revealed(true);
                self.root_stack.set_visible_child_name("chat");
            }
            VaultLifecycleState::OfflineReadOnly { reason } => {
                self.safety_banner.set_title(&reason);
                self.safety_banner.set_revealed(true);
                self.root_stack.set_visible_child_name("chat");
            }
        }
    }

    fn refresh_conversations_from_store(self: &Rc<Self>) {
        let (maybe_convs, maybe_contacts) = {
            let sess = self.session.borrow();
            (
                sess.as_ref()
                    .and_then(|s| s.vault.list_conversations().ok()),
                sess.as_ref().and_then(|s| s.vault.list_contacts().ok()),
            )
        };
        if let Some(contacts) = maybe_contacts {
            *self.contacts.borrow_mut() = contacts;
            if *self.sidebar_filter.borrow() == SidebarFilter::Contacts {
                self.rebuild_contact_rows();
            }
        }
        if let Some(convs) = maybe_convs {
            *self.conversations.borrow_mut() = convs;
            let auto_select = if self.selected_conv.borrow().is_none() {
                self.conversations.borrow().first().map(|c| c.id)
            } else {
                None
            };
            if let Some(first_id) = auto_select {
                self.select_conversation(first_id);
            } else {
                self.rebuild_conversation_rows();
            }
        }
    }

    fn open_contact_chat(self: &Rc<Self>, wire_jid: String, display_hint: Option<String>) {
        let norm = VaultStore::normalize_wire_jid(&wire_jid);
        if !self.search_query.borrow().is_empty() {
            self.search_entry.set_text("");
        }
        if !self.filter_all_btn.is_active() {
            self.filter_all_btn.set_active(true);
        }
        self.sidebar_stack.set_visible_child_name("conversations");

        let existing = self
            .conversations
            .borrow()
            .iter()
            .find(|c| VaultStore::normalize_wire_jid(&c.primary_wire_jid) == norm)
            .map(|c| c.id);

        if let Some(cid) = existing {
            *self.pending_open_jid.borrow_mut() = None;
            self.select_conversation(cid);
        } else {
            *self.pending_open_jid.borrow_mut() = Some(norm.clone());
            self.submit_engine_command(EngineCommand::OpenOrCreateDirectChat {
                wire_jid: norm,
                display_hint,
            });
        }
    }

    fn rebuild_conversation_rows(&self) {
        self.rebuilding_rows.set(true);
        while let Some(child) = self.conv_list.first_child() {
            self.conv_list.remove(&child);
        }

        let filter = *self.sidebar_filter.borrow();
        let selected = *self.selected_conv.borrow();
        let typing_map = self.typing_by_conv.borrow().clone();
        let conv_snapshot = self.conversations.borrow().clone();

        const MAX_CONVERSATION_ROWS: usize = 100;
        let mut rendered = 0usize;

        for conv in &conv_snapshot {
            let keep = match filter {
                SidebarFilter::All | SidebarFilter::Contacts => {
                    conv.kind != ConversationKind::StatusBroadcast
                }
                SidebarFilter::Unread => conv.unread_count > 0,
                SidebarFilter::Groups => conv.kind == ConversationKind::Group,
                SidebarFilter::Channels => conv.kind == ConversationKind::NewsletterChannel,
            };
            if !keep {
                continue;
            }

            let is_selected = selected == Some(conv.id);
            if rendered >= MAX_CONVERSATION_ROWS && !is_selected {
                continue;
            }
            rendered += 1;

            let row_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 10);
            row_box.set_margin_top(8);
            row_box.set_margin_bottom(8);
            row_box.set_margin_start(10);
            row_box.set_margin_end(10);

            let avatar = adw::Avatar::new(40, Some(&conv.title), true);
            avatar.set_valign(gtk4::Align::Center);
            if let Some(tex) = conv
                .avatar_cache_key
                .as_deref()
                .and_then(|k| self.load_cached_texture(k))
            {
                avatar.set_custom_image(Some(&tex));
            }

            let text_col = gtk4::Box::new(gtk4::Orientation::Vertical, 3);
            text_col.set_hexpand(true);

            let top_line = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
            let title_lbl = gtk4::Label::builder()
                .label(&conv.title)
                .xalign(0.0)
                .hexpand(true)
                .ellipsize(pango::EllipsizeMode::End)
                .css_classes(["heading"])
                .build();
            top_line.append(&title_lbl);

            if conv.is_pinned {
                let pin_lbl = gtk4::Image::builder()
                    .icon_name("view-pin-symbolic")
                    .pixel_size(12)
                    .css_classes(["dim-label"])
                    .build();
                top_line.append(&pin_lbl);
            }
            if conv.is_muted {
                let mute_lbl = gtk4::Image::builder()
                    .icon_name("audio-volume-muted-symbolic")
                    .pixel_size(12)
                    .css_classes(["dim-label"])
                    .build();
                top_line.append(&mute_lbl);
            }

            if let Some(ts) = conv.last_message_at {
                let ts_lbl = gtk4::Label::builder()
                    .label(ts.format("%H:%M").to_string())
                    .css_classes(["caption", "dim-label"])
                    .build();
                top_line.append(&ts_lbl);
            }

            let bottom_line = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
            let sub_text = typing_map
                .get(&conv.id)
                .cloned()
                .unwrap_or_else(|| conv.subtitle_preview.clone());
            let sub_lbl = gtk4::Label::builder()
                .label(&sub_text)
                .xalign(0.0)
                .hexpand(true)
                .ellipsize(pango::EllipsizeMode::End)
                .css_classes(["caption", "dim-label"])
                .build();
            bottom_line.append(&sub_lbl);

            if conv.unread_count > 0 {
                let badge = gtk4::Label::builder()
                    .label(conv.unread_count.to_string())
                    .css_classes(["unread-pill"])
                    .build();
                bottom_line.append(&badge);
            }

            text_col.append(&top_line);
            text_col.append(&bottom_line);

            row_box.append(&avatar);
            row_box.append(&text_col);

            let row = gtk4::ListBoxRow::builder()
                .name(conv.id.to_string())
                .child(&row_box)
                .build();
            self.conv_list.append(&row);

            if selected == Some(conv.id) {
                self.conv_list.select_row(Some(&row));
            }
        }
        self.rebuilding_rows.set(false);
    }

    fn rebuild_contact_rows(&self) {
        if *self.sidebar_filter.borrow() != SidebarFilter::Contacts {
            return;
        }
        self.rebuilding_rows.set(true);
        while let Some(child) = self.contacts_list.first_child() {
            self.contacts_list.remove(&child);
        }

        let contacts_snapshot = self.contacts.borrow().clone();
        const MAX_CONTACT_ROWS: usize = 100;
        let total_contacts = contacts_snapshot.len();

        if contacts_snapshot.is_empty() {
            self.contacts_count_label
                .set_label("No contacts synced yet — click ↻ in the header bar while connected");
        } else if total_contacts > MAX_CONTACT_ROWS {
            self.contacts_count_label.set_label(&format!(
                "Showing first {} of {} synced contacts · Use Ctrl+K or search to find any contact instantly",
                MAX_CONTACT_ROWS, total_contacts
            ));
        } else {
            self.contacts_count_label.set_label(&format!(
                "{} synced contacts · Click any contact to open encrypted chat",
                total_contacts
            ));
        }

        for peer in contacts_snapshot.iter().take(MAX_CONTACT_ROWS) {
            let Some(wire_jid) = peer.pn_jid.clone().or_else(|| peer.lid_jid.clone()) else {
                continue;
            };

            let row_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 10);
            row_box.set_margin_top(7);
            row_box.set_margin_bottom(7);
            row_box.set_margin_start(10);
            row_box.set_margin_end(10);

            let avatar = adw::Avatar::new(38, Some(&peer.display_name), true);
            avatar.set_valign(gtk4::Align::Center);
            if let Some(tex) = peer
                .avatar_cache_key
                .as_deref()
                .and_then(|k| self.load_cached_texture(k))
            {
                avatar.set_custom_image(Some(&tex));
            }

            let text_col = gtk4::Box::new(gtk4::Orientation::Vertical, 2);
            text_col.set_hexpand(true);

            let top_line = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
            let name_lbl = gtk4::Label::builder()
                .label(&peer.display_name)
                .xalign(0.0)
                .hexpand(true)
                .ellipsize(pango::EllipsizeMode::End)
                .css_classes(["heading"])
                .build();
            top_line.append(&name_lbl);

            if let Some(pn) = peer
                .pn_jid
                .as_deref()
                .and_then(|j| j.split('@').next())
                .filter(|d| !d.is_empty())
            {
                let phone_fmt = format!("+{pn}");
                if phone_fmt != peer.display_name {
                    let phone_lbl = gtk4::Label::builder()
                        .label(&phone_fmt)
                        .css_classes(["caption", "dim-label"])
                        .build();
                    top_line.append(&phone_lbl);
                }
            }

            let sub_str = peer
                .about_status
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    if peer.contact_name.is_some() {
                        "Saved WhatsApp contact"
                    } else {
                        "WhatsApp peer"
                    }
                });
            let sub_lbl = gtk4::Label::builder()
                .label(sub_str)
                .xalign(0.0)
                .ellipsize(pango::EllipsizeMode::End)
                .css_classes(["caption", "dim-label"])
                .build();

            text_col.append(&top_line);
            text_col.append(&sub_lbl);

            row_box.append(&avatar);
            row_box.append(&text_col);

            let row = gtk4::ListBoxRow::builder()
                .name(&wire_jid)
                .activatable(true)
                .child(&row_box)
                .build();
            self.contacts_list.append(&row);
        }
        self.rebuilding_rows.set(false);
    }

    fn refresh_search_results(self: &Rc<Self>) {
        let query = self.search_query.borrow().clone();
        if query.is_empty() {
            if *self.sidebar_filter.borrow() == SidebarFilter::Contacts {
                self.sidebar_stack.set_visible_child_name("contacts");
            } else {
                self.sidebar_stack.set_visible_child_name("conversations");
            }
            return;
        }

        self.sidebar_stack.set_visible_child_name("search");
        while let Some(child) = self.search_list.first_child() {
            self.search_list.remove(&child);
        }

        let Some(vault) = self.session.borrow().as_ref().map(|s| s.vault.clone()) else {
            return;
        };

        let q_lower = query.to_lowercase();
        let matching_convs: Vec<ConversationSummary> = self
            .conversations
            .borrow()
            .iter()
            .filter(|c| c.title.to_lowercase().contains(&q_lower))
            .take(8)
            .cloned()
            .collect();

        let matching_contacts: Vec<PeerIdentityRecord> = self
            .contacts
            .borrow()
            .iter()
            .filter(|p| {
                p.display_name.to_lowercase().contains(&q_lower)
                    || p.pn_jid
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&q_lower)
                    || p.about_status
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&q_lower)
            })
            .take(12)
            .cloned()
            .collect();

        let started = std::time::Instant::now();
        let hits = vault.search_messages(&query, None, 40).unwrap_or_default();
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        let stats = vault.sync_stats().unwrap_or_default();

        self.search_scope_label.set_label(&format!(
            "{} chats · {} contacts · {} message hits in {:.1} ms ({} encrypted msgs)",
            matching_convs.len(),
            matching_contacts.len(),
            hits.len(),
            elapsed_ms,
            stats.messages_committed
        ));

        for conv in matching_convs {
            let row_content = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
            row_content.set_margin_top(5);
            row_content.set_margin_bottom(5);
            row_content.set_margin_start(6);
            row_content.set_margin_end(6);

            let avatar = adw::Avatar::new(30, Some(&conv.title), true);
            if let Some(tex) = conv
                .avatar_cache_key
                .as_deref()
                .and_then(|k| self.load_cached_texture(k))
            {
                avatar.set_custom_image(Some(&tex));
            }
            let lbl_col = gtk4::Box::new(gtk4::Orientation::Vertical, 1);
            lbl_col.set_hexpand(true);
            let name_lbl = gtk4::Label::builder()
                .label(&conv.title)
                .xalign(0.0)
                .ellipsize(pango::EllipsizeMode::End)
                .css_classes(["heading"])
                .build();
            let sub_lbl = gtk4::Label::builder()
                .label(format!("Chat · {}", conv.subtitle_preview))
                .xalign(0.0)
                .ellipsize(pango::EllipsizeMode::End)
                .css_classes(["caption", "dim-label"])
                .build();
            lbl_col.append(&name_lbl);
            lbl_col.append(&sub_lbl);
            row_content.append(&avatar);
            row_content.append(&lbl_col);

            let conv_btn = gtk4::Button::builder()
                .child(&row_content)
                .css_classes(["flat"])
                .build();
            let c = self.clone();
            let cid = conv.id;
            conv_btn.connect_clicked(move |_| {
                c.select_conversation(cid);
            });
            self.search_list.append(&conv_btn);
        }

        for peer in matching_contacts {
            let Some(wire_jid) = peer.pn_jid.clone().or_else(|| peer.lid_jid.clone()) else {
                continue;
            };
            let row_content = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
            row_content.set_margin_top(5);
            row_content.set_margin_bottom(5);
            row_content.set_margin_start(6);
            row_content.set_margin_end(6);

            let avatar = adw::Avatar::new(30, Some(&peer.display_name), true);
            if let Some(tex) = peer
                .avatar_cache_key
                .as_deref()
                .and_then(|k| self.load_cached_texture(k))
            {
                avatar.set_custom_image(Some(&tex));
            }
            let lbl_col = gtk4::Box::new(gtk4::Orientation::Vertical, 1);
            lbl_col.set_hexpand(true);
            let name_lbl = gtk4::Label::builder()
                .label(&peer.display_name)
                .xalign(0.0)
                .ellipsize(pango::EllipsizeMode::End)
                .css_classes(["heading"])
                .build();
            let sub_lbl = gtk4::Label::builder()
                .label(format!(
                    "Contact · {}",
                    peer.pn_jid
                        .as_deref()
                        .and_then(|j| j.split('@').next())
                        .map(|d| format!("+{d}"))
                        .unwrap_or_else(|| wire_jid.clone())
                ))
                .xalign(0.0)
                .ellipsize(pango::EllipsizeMode::End)
                .css_classes(["caption", "dim-label"])
                .build();
            lbl_col.append(&name_lbl);
            lbl_col.append(&sub_lbl);
            row_content.append(&avatar);
            row_content.append(&lbl_col);

            let contact_btn = gtk4::Button::builder()
                .child(&row_content)
                .css_classes(["flat"])
                .build();
            let c = self.clone();
            let hint = peer.display_name.clone();
            contact_btn.connect_clicked(move |_| {
                c.open_contact_chat(wire_jid.clone(), Some(hint.clone()));
            });
            self.search_list.append(&contact_btn);
        }

        for hit in hits {
            let btn_content = gtk4::Box::new(gtk4::Orientation::Vertical, 3);
            btn_content.set_margin_top(6);
            btn_content.set_margin_bottom(6);
            btn_content.set_margin_start(8);
            btn_content.set_margin_end(8);

            let hdr = gtk4::Label::builder()
                .label(format!(
                    "{} · {} ({})",
                    hit.conversation_title,
                    hit.sender_display,
                    hit.timestamp.format("%b %d %H:%M")
                ))
                .xalign(0.0)
                .ellipsize(pango::EllipsizeMode::End)
                .css_classes(["heading"])
                .build();
            let snip = gtk4::Label::builder()
                .label(&hit.snippet)
                .xalign(0.0)
                .wrap(true)
                .css_classes(["caption"])
                .build();
            btn_content.append(&hdr);
            btn_content.append(&snip);

            let jump_btn = gtk4::Button::builder()
                .child(&btn_content)
                .css_classes(["flat"])
                .build();

            let cid = hit.conversation_id;
            let c = self.clone();
            jump_btn.connect_clicked(move |_| {
                c.search_entry.set_text("");
                if !c.filter_all_btn.is_active() {
                    c.filter_all_btn.set_active(true);
                }
                c.select_conversation(cid);
            });

            self.search_list.append(&jump_btn);
        }
    }

    fn select_conversation(self: &Rc<Self>, cid: ConversationId) {
        *self.selected_conv.borrow_mut() = Some(cid);
        *self.timeline_limit.borrow_mut() = 60;
        self.set_composer_mode(ComposerMode::Normal);

        if let Some(sess) = self.session.borrow().as_ref() {
            let _ = sess.vault.mark_conversation_read(cid);
            if let Ok(convs) = sess.vault.list_conversations() {
                *self.conversations.borrow_mut() = convs;
            }
        }

        self.update_active_header();
        self.rebuild_conversation_rows();
        self.reload_active_timeline(true);
        self.split_view.set_show_content(true);
    }

    fn update_active_header(&self) {
        let Some(cid) = *self.selected_conv.borrow() else {
            self.header_avatar.set_visible(false);
            self.chat_title_widget.set_title("Select a Conversation");
            self.chat_title_widget.set_subtitle("");
            return;
        };

        if let Some(conv) = self.conversations.borrow().iter().find(|c| c.id == cid) {
            self.header_avatar.set_visible(true);
            self.header_avatar.set_text(Some(&conv.title));
            let tex = conv
                .avatar_cache_key
                .as_deref()
                .and_then(|k| self.load_cached_texture(k));
            self.header_avatar.set_custom_image(tex.as_ref());

            self.chat_title_widget.set_title(&conv.title);
            if let Some(typing) = self.typing_by_conv.borrow().get(&cid) {
                self.chat_title_widget.set_subtitle(typing);
            } else {
                let subtitle = match conv.kind {
                    ConversationKind::DirectMessage => "End-to-end encrypted chat".to_string(),
                    ConversationKind::Group => match conv.participant_count {
                        Some(n) if n > 0 => {
                            format!("{n} participants · End-to-end encrypted group")
                        }
                        _ => "End-to-end encrypted group".to_string(),
                    },
                    ConversationKind::NewsletterChannel => "Channel feed (MEX bulkhead)".into(),
                    ConversationKind::StatusBroadcast => "Status broadcast".into(),
                };
                self.chat_title_widget.set_subtitle(&subtitle);
            }
        }
    }

    fn reload_active_timeline(self: &Rc<Self>, scroll_to_bottom: bool) {
        while let Some(child) = self.timeline_box.first_child() {
            self.timeline_box.remove(&child);
        }

        let Some(cid) = *self.selected_conv.borrow() else {
            self.load_older_btn.set_sensitive(false);
            return;
        };
        let Some(vault) = self.session.borrow().as_ref().map(|s| s.vault.clone()) else {
            return;
        };

        let limit = *self.timeline_limit.borrow();
        let messages = vault
            .load_timeline_window(cid, None, limit)
            .unwrap_or_default();
        *self.oldest_loaded_sort_key.borrow_mut() = messages.first().map(|m| m.sort_key);
        self.load_older_btn.set_sensitive(messages.len() >= limit);

        for msg in &messages {
            let row_widget = self.build_message_bubble(msg);
            self.timeline_box.append(&row_widget);
        }

        if scroll_to_bottom {
            let adj = self.timeline_scroll.vadjustment();
            glib::idle_add_local_once(move || {
                adj.set_value(adj.upper() - adj.page_size());
            });
        }
    }

    fn build_message_bubble(self: &Rc<Self>, msg: &TimelineMessage) -> gtk4::Box {
        let outer = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        outer.set_halign(if msg.is_from_me {
            gtk4::Align::End
        } else {
            gtk4::Align::Start
        });

        if !msg.is_from_me {
            let sender_avatar = adw::Avatar::new(28, Some(&msg.sender_display), true);
            sender_avatar.set_valign(gtk4::Align::End);
            if let Some(tex) = msg
                .sender_avatar_cache_key
                .as_deref()
                .and_then(|k| self.load_cached_texture(k))
            {
                sender_avatar.set_custom_image(Some(&tex));
            }
            outer.append(&sender_avatar);
        }

        let bubble = gtk4::Box::new(gtk4::Orientation::Vertical, 6);
        bubble.set_size_request(180, -1);
        bubble.add_css_class(if msg.is_from_me {
            "bubble-out"
        } else {
            "bubble-in"
        });

        if !msg.is_from_me {
            let sender_lbl = gtk4::Label::builder()
                .label(&msg.sender_display)
                .xalign(0.0)
                .css_classes(["caption", "heading"])
                .build();
            bubble.append(&sender_lbl);
        }

        // Quoted reply block
        if let Some(q) = &msg.quoted {
            let q_box = gtk4::Box::new(gtk4::Orientation::Vertical, 2);
            q_box.add_css_class("quoted-block");
            let q_sender = gtk4::Label::builder()
                .label(&q.sender_label)
                .xalign(0.0)
                .css_classes(["caption", "heading"])
                .build();
            let q_snip = gtk4::Label::builder()
                .label(&q.snippet)
                .xalign(0.0)
                .wrap(true)
                .max_width_chars(52)
                .css_classes(["caption", "dim-label"])
                .build();
            q_box.append(&q_sender);
            q_box.append(&q_snip);
            bubble.append(&q_box);
        }

        // Primary message body by content variant
        match &msg.content {
            MessageContent::Text {
                body,
                edited_at,
                link_preview,
            } => {
                let text_lbl = gtk4::Label::builder()
                    .label(body)
                    .xalign(0.0)
                    .wrap(true)
                    .wrap_mode(pango::WrapMode::WordChar)
                    .max_width_chars(62)
                    .selectable(true)
                    .build();
                if msg.delivery == DeliveryState::Revoked {
                    text_lbl.add_css_class("dim-label");
                }
                bubble.append(&text_lbl);

                if let Some(lp) = link_preview {
                    let lp_widget = self.build_link_preview_card(lp);
                    bubble.append(&lp_widget);
                }

                if edited_at.is_some() {
                    let ed = gtk4::Label::builder()
                        .label("edited")
                        .xalign(0.0)
                        .css_classes(["caption", "dim-label"])
                        .build();
                    bubble.append(&ed);
                }
            }
            MessageContent::Media {
                media_kind,
                caption,
                mime_type,
                file_name,
                byte_len,
                dimensions,
                cache_key,
                thumb_cache_key,
                duration_secs,
                waveform,
            } => {
                let media_widget = self.build_media_content_widget(
                    msg,
                    *media_kind,
                    mime_type,
                    file_name.as_deref(),
                    *byte_len,
                    *dimensions,
                    cache_key.as_deref(),
                    thumb_cache_key.as_deref(),
                    *duration_secs,
                    waveform.as_deref(),
                );
                bubble.append(&media_widget);

                if let Some(cap) = caption.as_deref().filter(|s| !s.is_empty()) {
                    let cap_lbl = gtk4::Label::builder()
                        .label(cap)
                        .xalign(0.0)
                        .wrap(true)
                        .max_width_chars(58)
                        .selectable(true)
                        .build();
                    bubble.append(&cap_lbl);
                }
            }
            MessageContent::Poll { question, options } => {
                let p_title = gtk4::Label::builder()
                    .label(format!("📊 {question}"))
                    .xalign(0.0)
                    .wrap(true)
                    .css_classes(["heading"])
                    .build();
                bubble.append(&p_title);
                for opt in options {
                    let row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
                    row.add_css_class("poll-option-row");
                    let bullet = gtk4::Label::builder()
                        .label("○")
                        .css_classes(["dim-label"])
                        .build();
                    let o_lbl = gtk4::Label::builder()
                        .label(opt)
                        .xalign(0.0)
                        .hexpand(true)
                        .wrap(true)
                        .build();
                    row.append(&bullet);
                    row.append(&o_lbl);
                    bubble.append(&row);
                }
            }
            MessageContent::Location {
                latitude,
                longitude,
                label,
                thumb_cache_key,
            } => {
                let loc_card = gtk4::Box::new(gtk4::Orientation::Vertical, 6);
                loc_card.add_css_class("location-card");

                if let Some(tex) = thumb_cache_key
                    .as_deref()
                    .and_then(|k| self.load_cached_texture(k))
                {
                    let map_pic = gtk4::Picture::for_paintable(&tex);
                    map_pic.set_content_fit(gtk4::ContentFit::Cover);
                    map_pic.set_can_shrink(true);
                    map_pic.set_size_request(240, 128);
                    map_pic.add_css_class("chat-photo-frame");
                    loc_card.append(&map_pic);
                }

                let loc_title = gtk4::Label::builder()
                    .label(format!(
                        "📍 {}",
                        label.as_deref().unwrap_or("Shared location")
                    ))
                    .xalign(0.0)
                    .wrap(true)
                    .css_classes(["heading"])
                    .build();
                let loc_coords = gtk4::Label::builder()
                    .label(format!("{latitude:.5}, {longitude:.5}"))
                    .xalign(0.0)
                    .selectable(true)
                    .css_classes(["caption", "dim-label"])
                    .build();
                let osm_url = format!(
                    "https://www.openstreetmap.org/?mlat={latitude:.6}&mlon={longitude:.6}#map=16/{latitude:.6}/{longitude:.6}"
                );
                let map_btn = gtk4::Button::builder()
                    .label("Open in OpenStreetMap ↗")
                    .halign(gtk4::Align::Start)
                    .css_classes(["flat", "caption"])
                    .build();
                {
                    let win = self.window.clone();
                    map_btn.connect_clicked(move |_| {
                        let launcher = gtk4::UriLauncher::new(&osm_url);
                        launcher.launch(Some(&win), gio::Cancellable::NONE, |_| {});
                    });
                }
                loc_card.append(&loc_title);
                loc_card.append(&loc_coords);
                loc_card.append(&map_btn);
                bubble.append(&loc_card);
            }
            MessageContent::ViewOnceCompanionStub { media_label } => {
                let vo_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
                vo_box.add_css_class("view-once-stub");
                let icon = gtk4::Image::from_icon_name("changes-prevent-symbolic");
                let lbl = gtk4::Label::builder()
                    .label(format!(
                        "View-once {media_label} · Open WhatsApp on your primary phone to view"
                    ))
                    .xalign(0.0)
                    .wrap(true)
                    .max_width_chars(50)
                    .build();
                vo_box.append(&icon);
                vo_box.append(&lbl);
                bubble.append(&vo_box);
            }
            MessageContent::CallTimelineItem { .. } => {
                let c_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
                c_box.add_css_class("call-item-card");
                let icon = gtk4::Image::from_icon_name("call-start-symbolic");
                let lbl = gtk4::Label::builder()
                    .label(msg.content.preview_text())
                    .xalign(0.0)
                    .build();
                c_box.append(&icon);
                c_box.append(&lbl);
                bubble.append(&c_box);
            }
            MessageContent::UnknownPlaceholder { summary, .. } => {
                let u_lbl = gtk4::Label::builder()
                    .label(summary)
                    .xalign(0.0)
                    .css_classes(["dim-label"])
                    .build();
                bubble.append(&u_lbl);
            }
        }

        // Reaction chips
        if !msg.reactions.is_empty() {
            let react_row = gtk4::Box::new(gtk4::Orientation::Horizontal, 4);
            for chip in &msg.reactions {
                let chip_btn = gtk4::Button::builder()
                    .label(format!("{} {}", chip.emoji, chip.count))
                    .css_classes(["reaction-chip"])
                    .build();
                if chip.reacted_by_me {
                    chip_btn.add_css_class("reaction-chip-mine");
                }
                let c = self.clone();
                let cid = msg.conversation_id;
                let stanza = msg.stanza_id.clone();
                let next_emoji = if chip.reacted_by_me {
                    String::new()
                } else {
                    chip.emoji.clone()
                };
                chip_btn.connect_clicked(move |_| {
                    c.submit_engine_command(EngineCommand::SendReaction {
                        conversation_id: cid,
                        target_stanza_id: stanza.clone(),
                        emoji: next_emoji.clone(),
                    });
                });
                react_row.append(&chip_btn);
            }
            bubble.append(&react_row);
        }

        // Footer: timestamp + delivery badge + inline message actions
        let footer = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
        let meta_str = if msg.is_from_me {
            format!(
                "{} · {}",
                msg.timestamp.format("%H:%M"),
                msg.delivery.badge_label()
            )
        } else {
            msg.timestamp.format("%H:%M").to_string()
        };
        let meta_lbl = gtk4::Label::builder()
            .label(&meta_str)
            .xalign(0.0)
            .hexpand(true)
            .css_classes(["caption", "dim-label"])
            .build();
        footer.append(&meta_lbl);

        if msg.delivery != DeliveryState::Revoked {
            // Quick Reply
            let reply_btn = gtk4::Button::builder()
                .label("Reply")
                .css_classes(["flat", "caption"])
                .build();
            {
                let c = self.clone();
                let q_ref = QuotedReplyRef {
                    target_stanza_id: msg.stanza_id.clone(),
                    sender_label: if msg.is_from_me {
                        "You".into()
                    } else {
                        msg.sender_display.clone()
                    },
                    snippet: msg.content.preview_text(),
                };
                reply_btn.connect_clicked(move |_| {
                    c.set_composer_mode(ComposerMode::Reply(q_ref.clone()));
                });
            }
            footer.append(&reply_btn);

            // Quick emoji reaction buttons
            for emoji in ["👍", "❤️"] {
                let r_btn = gtk4::Button::builder()
                    .label(emoji)
                    .css_classes(["flat", "caption"])
                    .build();
                let c = self.clone();
                let cid = msg.conversation_id;
                let stanza = msg.stanza_id.clone();
                let em = emoji.to_string();
                r_btn.connect_clicked(move |_| {
                    c.submit_engine_command(EngineCommand::SendReaction {
                        conversation_id: cid,
                        target_stanza_id: stanza.clone(),
                        emoji: em.clone(),
                    });
                });
                footer.append(&r_btn);
            }

            // Own-message Edit & Revoke
            if msg.is_from_me {
                if let MessageContent::Text { body, .. } = &msg.content {
                    let edit_btn = gtk4::Button::builder()
                        .label("Edit")
                        .css_classes(["flat", "caption"])
                        .build();
                    let c = self.clone();
                    let stanza = msg.stanza_id.clone();
                    let body_clone = body.clone();
                    edit_btn.connect_clicked(move |_| {
                        c.composer_buffer.set_text(&body_clone);
                        c.set_composer_mode(ComposerMode::Edit {
                            target_stanza_id: stanza.clone(),
                            original_snippet: body_clone.clone(),
                        });
                    });
                    footer.append(&edit_btn);
                }

                let del_btn = gtk4::Button::builder()
                    .label("Delete")
                    .css_classes(["flat", "caption"])
                    .build();
                let c = self.clone();
                let cid = msg.conversation_id;
                let stanza = msg.stanza_id.clone();
                del_btn.connect_clicked(move |_| {
                    c.submit_engine_command(EngineCommand::RevokeMessage {
                        conversation_id: cid,
                        target_stanza_id: stanza.clone(),
                    });
                });
                footer.append(&del_btn);
            }
        }

        bubble.append(&footer);
        outer.append(&bubble);
        outer
    }

    #[allow(clippy::too_many_arguments)]
    fn build_media_content_widget(
        self: &Rc<Self>,
        msg: &TimelineMessage,
        media_kind: MediaKind,
        mime_type: &str,
        file_name: Option<&str>,
        byte_len: u64,
        dimensions: Option<(u32, u32)>,
        cache_key: Option<&str>,
        thumb_cache_key: Option<&str>,
        duration_secs: Option<u32>,
        waveform: Option<&[u8]>,
    ) -> gtk4::Widget {
        match media_kind {
            MediaKind::Image | MediaKind::Sticker => {
                let is_sticker = media_kind == MediaKind::Sticker;
                let full_tex = cache_key.and_then(|k| self.load_cached_texture(k));
                let thumb_tex = if full_tex.is_none() {
                    thumb_cache_key.and_then(|k| self.load_cached_texture(k))
                } else {
                    None
                };
                let active_tex = full_tex.clone().or(thumb_tex);

                let (disp_w, disp_h) = if is_sticker {
                    (148, 148)
                } else if let Some((w, h)) = dimensions {
                    let pw = (w as i32).clamp(180, 320);
                    let ph = ((h as f64 / (w as f64).max(1.0)) * f64::from(pw))
                        .round()
                        .clamp(110.0, 280.0) as i32;
                    (pw, ph)
                } else {
                    (260, 180)
                };

                if let Some(tex) = active_tex {
                    let pic = gtk4::Picture::for_paintable(&tex);
                    pic.set_content_fit(if is_sticker {
                        gtk4::ContentFit::Contain
                    } else {
                        gtk4::ContentFit::Cover
                    });
                    pic.set_can_shrink(true);
                    pic.set_size_request(disp_w, disp_h);
                    pic.add_css_class(if is_sticker {
                        "sticker-frame"
                    } else {
                        "chat-photo-frame"
                    });

                    let overlay = gtk4::Overlay::new();
                    overlay.set_halign(gtk4::Align::Start);
                    overlay.set_child(Some(&pic));

                    if full_tex.is_none() {
                        let hd_badge = gtk4::Button::builder()
                            .label(if byte_len > 0 {
                                format!("⬇ HD · {}", format_bytes_human(byte_len))
                            } else {
                                "⬇ Load HD".to_string()
                            })
                            .halign(gtk4::Align::End)
                            .valign(gtk4::Align::End)
                            .margin_end(8)
                            .margin_bottom(8)
                            .css_classes(["overlay-badge", "flat"])
                            .build();
                        let c = self.clone();
                        let cid = msg.conversation_id;
                        let stanza = msg.stanza_id.clone();
                        hd_badge.connect_clicked(move |_| {
                            c.show_toast("Downloading full-resolution encrypted image…");
                            c.submit_engine_command(EngineCommand::DownloadMessageMedia {
                                conversation_id: cid,
                                stanza_id: stanza.clone(),
                            });
                        });
                        overlay.add_overlay(&hd_badge);
                    }

                    let gesture = gtk4::GestureClick::new();
                    {
                        let c = self.clone();
                        let tex_clone = tex.clone();
                        let save_key = cache_key
                            .map(str::to_string)
                            .or_else(|| thumb_cache_key.map(str::to_string));
                        let has_full = full_tex.is_some();
                        let cid = msg.conversation_id;
                        let stanza = msg.stanza_id.clone();
                        let title = file_name.map(str::to_string).unwrap_or_else(|| {
                            format!("{} — {}", msg.sender_display, media_kind.label())
                        });
                        let ext = infer_media_extension(file_name, mime_type);
                        let suggested = file_name
                            .map(str::to_string)
                            .unwrap_or_else(|| format!("whatsapp-{}.{ext}", msg.stanza_id));
                        gesture.connect_released(move |_, _, _, _| {
                            if !has_full {
                                c.submit_engine_command(EngineCommand::DownloadMessageMedia {
                                    conversation_id: cid,
                                    stanza_id: stanza.clone(),
                                });
                            }
                            c.present_image_lightbox(
                                &tex_clone,
                                save_key.clone(),
                                suggested.clone(),
                                title.clone(),
                            );
                        });
                    }
                    pic.add_controller(gesture);
                    overlay.upcast()
                } else {
                    let placeholder = gtk4::Box::new(gtk4::Orientation::Horizontal, 10);
                    placeholder.add_css_class("doc-card");
                    let icon = gtk4::Image::builder()
                        .icon_name("image-x-generic-symbolic")
                        .pixel_size(26)
                        .build();
                    let info_col = gtk4::Box::new(gtk4::Orientation::Vertical, 2);
                    info_col.set_hexpand(true);
                    let title_lbl = gtk4::Label::builder()
                        .label(file_name.unwrap_or_else(|| media_kind.label()))
                        .xalign(0.0)
                        .css_classes(["heading"])
                        .build();
                    let meta_lbl = gtk4::Label::builder()
                        .label(format!(
                            "{} · Encrypted {}",
                            format_bytes_human(byte_len),
                            mime_type
                        ))
                        .xalign(0.0)
                        .css_classes(["caption", "dim-label"])
                        .build();
                    info_col.append(&title_lbl);
                    info_col.append(&meta_lbl);

                    let dl_btn = gtk4::Button::builder()
                        .label("Load Photo")
                        .valign(gtk4::Align::Center)
                        .css_classes(["suggested-action"])
                        .build();
                    let c = self.clone();
                    let cid = msg.conversation_id;
                    let stanza = msg.stanza_id.clone();
                    dl_btn.connect_clicked(move |_| {
                        c.show_toast("Downloading encrypted photo…");
                        c.submit_engine_command(EngineCommand::DownloadMessageMedia {
                            conversation_id: cid,
                            stanza_id: stanza.clone(),
                        });
                    });
                    placeholder.append(&icon);
                    placeholder.append(&info_col);
                    placeholder.append(&dl_btn);
                    placeholder.upcast()
                }
            }
            MediaKind::Video => {
                let (disp_w, disp_h) = if let Some((w, h)) = dimensions {
                    let pw = (w as i32).clamp(200, 320);
                    let ph = ((h as f64 / (w as f64).max(1.0)) * f64::from(pw))
                        .round()
                        .clamp(120.0, 220.0) as i32;
                    (pw, ph)
                } else {
                    (260, 156)
                };

                let outer_v = gtk4::Box::new(gtk4::Orientation::Vertical, 4);
                let overlay = gtk4::Overlay::new();
                overlay.set_halign(gtk4::Align::Start);
                overlay.add_css_class("chat-photo-frame");

                if let Some(tex) = thumb_cache_key.and_then(|k| self.load_cached_texture(k)) {
                    let pic = gtk4::Picture::for_paintable(&tex);
                    pic.set_content_fit(gtk4::ContentFit::Cover);
                    pic.set_can_shrink(true);
                    pic.set_size_request(disp_w, disp_h);
                    overlay.set_child(Some(&pic));
                } else {
                    let backdrop = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
                    backdrop.set_size_request(disp_w, disp_h);
                    backdrop.add_css_class("video-card-backdrop");
                    overlay.set_child(Some(&backdrop));
                }

                let play_btn = gtk4::Button::builder()
                    .label(if cache_key.is_some() {
                        "▶ Play Video"
                    } else {
                        "⬇ Download & Play"
                    })
                    .halign(gtk4::Align::Center)
                    .valign(gtk4::Align::Center)
                    .css_classes(["pill", "osd"])
                    .build();
                {
                    let c = self.clone();
                    let ck = cache_key.map(str::to_string);
                    let fname = file_name.map(str::to_string);
                    let mime_owned = mime_type.to_string();
                    let cid = msg.conversation_id;
                    let stanza = msg.stanza_id.clone();
                    play_btn.connect_clicked(move |_| {
                        if let Some(ref key) = ck {
                            c.present_video_player(key.clone(), fname.clone(), mime_owned.clone());
                        } else {
                            c.show_toast("Downloading encrypted video…");
                            c.submit_engine_command(EngineCommand::DownloadMessageMedia {
                                conversation_id: cid,
                                stanza_id: stanza.clone(),
                            });
                        }
                    });
                }
                overlay.add_overlay(&play_btn);

                let mut badge_parts = vec!["🎬".to_string()];
                if let Some(sec) = duration_secs {
                    badge_parts.push(format_duration_mmss(sec));
                }
                if byte_len > 0 {
                    badge_parts.push(format_bytes_human(byte_len));
                }
                let meta_badge = gtk4::Label::builder()
                    .label(badge_parts.join(" · "))
                    .halign(gtk4::Align::Start)
                    .valign(gtk4::Align::End)
                    .margin_start(8)
                    .margin_bottom(8)
                    .css_classes(["overlay-badge", "caption"])
                    .build();
                overlay.add_overlay(&meta_badge);
                outer_v.append(&overlay);

                if let Some(ck) = cache_key {
                    let save_btn = gtk4::Button::builder()
                        .label("Save Video As…")
                        .halign(gtk4::Align::Start)
                        .css_classes(["flat", "caption"])
                        .build();
                    let c = self.clone();
                    let ck_owned = ck.to_string();
                    let ext = infer_media_extension(file_name, mime_type);
                    let suggested = file_name
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("whatsapp-video-{}.{ext}", msg.stanza_id));
                    save_btn.connect_clicked(move |_| {
                        c.save_media_via_portal(ck_owned.clone(), suggested.clone());
                    });
                    outer_v.append(&save_btn);
                }

                outer_v.upcast()
            }
            MediaKind::VoiceNote | MediaKind::Audio => {
                let card = gtk4::Box::new(gtk4::Orientation::Horizontal, 10);
                card.add_css_class("audio-card");

                let is_playing_this = self
                    .active_audio
                    .borrow()
                    .as_ref()
                    .is_some_and(|(id, mf)| id == &msg.stanza_id && mf.is_playing());

                let play_btn = gtk4::Button::builder()
                    .icon_name(if cache_key.is_none() {
                        "folder-download-symbolic"
                    } else if is_playing_this {
                        "media-playback-pause-symbolic"
                    } else {
                        "media-playback-start-symbolic"
                    })
                    .valign(gtk4::Align::Center)
                    .css_classes(["circular", "suggested-action"])
                    .build();

                let mid_col = gtk4::Box::new(gtk4::Orientation::Vertical, 4);
                mid_col.set_hexpand(true);

                let wave_area =
                    build_waveform_drawing_area(waveform, &msg.stanza_id, msg.is_from_me);
                mid_col.append(&wave_area);

                let meta_row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
                let dur_str = duration_secs
                    .map(format_duration_mmss)
                    .unwrap_or_else(|| format_bytes_human(byte_len));
                let kind_str = if media_kind == MediaKind::VoiceNote {
                    format!("Voice message · {dur_str}")
                } else {
                    format!("{} · {dur_str}", file_name.unwrap_or("Audio clip"))
                };
                let sub_lbl = gtk4::Label::builder()
                    .label(&kind_str)
                    .xalign(0.0)
                    .hexpand(true)
                    .ellipsize(pango::EllipsizeMode::End)
                    .css_classes(["caption", "dim-label"])
                    .build();
                meta_row.append(&sub_lbl);

                if let Some(ck) = cache_key {
                    let save_btn = gtk4::Button::builder()
                        .label("Save…")
                        .css_classes(["flat", "caption"])
                        .build();
                    let c = self.clone();
                    let ck_owned = ck.to_string();
                    let ext = infer_media_extension(file_name, mime_type);
                    let suggested = file_name
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("voice-{}.{ext}", msg.stanza_id));
                    save_btn.connect_clicked(move |_| {
                        c.save_media_via_portal(ck_owned.clone(), suggested.clone());
                    });
                    meta_row.append(&save_btn);
                }
                mid_col.append(&meta_row);

                {
                    let c = self.clone();
                    let ck = cache_key.map(str::to_string);
                    let fname = file_name.map(str::to_string);
                    let mime_owned = mime_type.to_string();
                    let cid = msg.conversation_id;
                    let stanza = msg.stanza_id.clone();
                    play_btn.connect_clicked(move |btn| {
                        let Some(ref key) = ck else {
                            c.show_toast("Downloading encrypted audio…");
                            c.submit_engine_command(EngineCommand::DownloadMessageMedia {
                                conversation_id: cid,
                                stanza_id: stanza.clone(),
                            });
                            return;
                        };
                        c.toggle_audio_playback(&stanza, key, fname.as_deref(), &mime_owned, btn);
                    });
                }

                card.append(&play_btn);
                card.append(&mid_col);
                card.upcast()
            }
            MediaKind::Document => {
                let card = gtk4::Box::new(gtk4::Orientation::Horizontal, 10);
                card.add_css_class("doc-card");

                if let Some(tex) = thumb_cache_key.and_then(|k| self.load_cached_texture(k)) {
                    let pic = gtk4::Picture::for_paintable(&tex);
                    pic.set_content_fit(gtk4::ContentFit::Cover);
                    pic.set_can_shrink(true);
                    pic.set_size_request(42, 54);
                    card.append(&pic);
                } else {
                    let icon = gtk4::Image::builder()
                        .icon_name("x-office-document-symbolic")
                        .pixel_size(28)
                        .valign(gtk4::Align::Center)
                        .build();
                    card.append(&icon);
                }

                let info_col = gtk4::Box::new(gtk4::Orientation::Vertical, 2);
                info_col.set_hexpand(true);
                info_col.set_valign(gtk4::Align::Center);
                let title = file_name.unwrap_or("Encrypted Document");
                let title_lbl = gtk4::Label::builder()
                    .label(title)
                    .xalign(0.0)
                    .max_width_chars(34)
                    .ellipsize(pango::EllipsizeMode::Middle)
                    .css_classes(["heading"])
                    .build();
                let meta_lbl = gtk4::Label::builder()
                    .label(format!("{} · {mime_type}", format_bytes_human(byte_len)))
                    .xalign(0.0)
                    .ellipsize(pango::EllipsizeMode::End)
                    .css_classes(["caption", "dim-label"])
                    .build();
                info_col.append(&title_lbl);
                info_col.append(&meta_lbl);
                card.append(&info_col);

                let actions_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 4);
                actions_box.set_valign(gtk4::Align::Center);
                if let Some(ck) = cache_key {
                    let open_btn = gtk4::Button::builder()
                        .label("Open")
                        .css_classes(["flat"])
                        .build();
                    {
                        let c = self.clone();
                        let ck_owned = ck.to_string();
                        let fname = file_name.map(str::to_string);
                        let mime_owned = mime_type.to_string();
                        open_btn.connect_clicked(move |_| {
                            if let Some(path) = c.materialize_media_temp_file(
                                &ck_owned,
                                fname.as_deref(),
                                &mime_owned,
                            ) {
                                let uri = gio::File::for_path(&path).uri();
                                let launcher = gtk4::UriLauncher::new(&uri);
                                launcher.launch(Some(&c.window), gio::Cancellable::NONE, |_| {});
                            } else {
                                c.show_toast("Unable to decrypt document from local cache");
                            }
                        });
                    }
                    let save_btn = gtk4::Button::builder()
                        .label("Save…")
                        .css_classes(["flat"])
                        .build();
                    {
                        let c = self.clone();
                        let ck_owned = ck.to_string();
                        let ext = infer_media_extension(file_name, mime_type);
                        let suggested = file_name
                            .map(str::to_string)
                            .unwrap_or_else(|| format!("document-{}.{ext}", msg.stanza_id));
                        save_btn.connect_clicked(move |_| {
                            c.save_media_via_portal(ck_owned.clone(), suggested.clone());
                        });
                    }
                    actions_box.append(&open_btn);
                    actions_box.append(&save_btn);
                } else {
                    let dl_btn = gtk4::Button::builder()
                        .label("Download")
                        .css_classes(["suggested-action"])
                        .build();
                    let c = self.clone();
                    let cid = msg.conversation_id;
                    let stanza = msg.stanza_id.clone();
                    dl_btn.connect_clicked(move |_| {
                        c.show_toast("Downloading encrypted document…");
                        c.submit_engine_command(EngineCommand::DownloadMessageMedia {
                            conversation_id: cid,
                            stanza_id: stanza.clone(),
                        });
                    });
                    actions_box.append(&dl_btn);
                }
                card.append(&actions_box);
                card.upcast()
            }
        }
    }

    fn build_link_preview_card(&self, lp: &LinkPreviewCard) -> gtk4::Widget {
        let card_inner = gtk4::Box::new(gtk4::Orientation::Vertical, 4);
        if let Some(tex) = lp
            .thumb_cache_key
            .as_deref()
            .and_then(|k| self.load_cached_texture(k))
        {
            let pic = gtk4::Picture::for_paintable(&tex);
            pic.set_content_fit(gtk4::ContentFit::Cover);
            pic.set_can_shrink(true);
            pic.set_size_request(250, 126);
            pic.add_css_class("chat-photo-frame");
            card_inner.append(&pic);
        }
        if let Some(title) = lp.title.as_deref().filter(|s| !s.is_empty()) {
            let t_lbl = gtk4::Label::builder()
                .label(title)
                .xalign(0.0)
                .wrap(true)
                .max_width_chars(50)
                .css_classes(["heading"])
                .build();
            card_inner.append(&t_lbl);
        }
        if let Some(desc) = lp.description.as_deref().filter(|s| !s.is_empty()) {
            let d_lbl = gtk4::Label::builder()
                .label(desc)
                .xalign(0.0)
                .wrap(true)
                .max_width_chars(52)
                .lines(3)
                .ellipsize(pango::EllipsizeMode::End)
                .css_classes(["caption", "dim-label"])
                .build();
            card_inner.append(&d_lbl);
        }
        let url_lbl = gtk4::Label::builder()
            .label(format!("🔗 {}", lp.url))
            .xalign(0.0)
            .max_width_chars(48)
            .ellipsize(pango::EllipsizeMode::End)
            .css_classes(["caption"])
            .build();
        card_inner.append(&url_lbl);

        let btn = gtk4::Button::builder()
            .child(&card_inner)
            .css_classes(["flat", "link-preview-card"])
            .build();
        let url_owned = lp.url.clone();
        let win = self.window.clone();
        btn.connect_clicked(move |_| {
            let launcher = gtk4::UriLauncher::new(&url_owned);
            launcher.launch(Some(&win), gio::Cancellable::NONE, |_| {});
        });
        btn.upcast()
    }

    fn load_cached_texture(&self, cache_key: &str) -> Option<gdk::Texture> {
        if cache_key.is_empty() {
            return None;
        }
        if let Some(existing) = self.texture_cache.borrow().get(cache_key) {
            return Some(existing.clone());
        }
        let bytes = self
            .session
            .borrow()
            .as_ref()?
            .vault
            .load_encrypted_media(cache_key)
            .ok()??;
        let gbytes = glib::Bytes::from_owned(bytes);
        let tex = gdk::Texture::from_bytes(&gbytes).ok()?;
        let mut cache = self.texture_cache.borrow_mut();
        if cache.len() >= 1024 {
            let to_remove: Vec<_> = cache.keys().take(256).cloned().collect();
            for k in to_remove {
                cache.remove(&k);
            }
        }
        cache.insert(cache_key.to_string(), tex.clone());
        Some(tex)
    }

    fn materialize_media_temp_file(
        &self,
        cache_key: &str,
        file_name: Option<&str>,
        mime_type: &str,
    ) -> Option<PathBuf> {
        let bytes = self
            .session
            .borrow()
            .as_ref()?
            .vault
            .load_encrypted_media(cache_key)
            .ok()??;
        let playback_dir = self.layout.cache_media_dir.join("playback");
        std::fs::create_dir_all(&playback_dir).ok()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&playback_dir, std::fs::Permissions::from_mode(0o700));
        }

        let ext = infer_media_extension(file_name, mime_type);
        let safe_stem: String = cache_key
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                    ch
                } else {
                    '_'
                }
            })
            .collect();
        let out_path = playback_dir.join(format!("{safe_stem}.{ext}"));
        let needs_write = std::fs::metadata(&out_path)
            .map(|m| m.len() != bytes.len() as u64)
            .unwrap_or(true);
        if needs_write {
            std::fs::write(&out_path, &bytes).ok()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600));
            }
        }
        Some(out_path)
    }

    fn save_media_via_portal(self: &Rc<Self>, cache_key: String, suggested_name: String) {
        let c = self.clone();
        glib::spawn_future_local(async move {
            let dialog = gtk4::FileDialog::builder()
                .title("Save Decrypted Media")
                .initial_name(&suggested_name)
                .modal(true)
                .build();
            let Ok(dest_file) = dialog.save_future(Some(&c.window)).await else {
                return;
            };
            let Some(dest_path) = dest_file.path() else {
                return;
            };
            let maybe_bytes = c
                .session
                .borrow()
                .as_ref()
                .and_then(|s| s.vault.load_encrypted_media(&cache_key).ok().flatten());
            let Some(bytes) = maybe_bytes else {
                c.show_toast("Media is not cached locally yet");
                return;
            };
            match std::fs::write(&dest_path, &bytes) {
                Ok(()) => c.show_toast(&format!("Saved to {}", dest_path.display())),
                Err(e) => c.show_toast(&format!("Save failed: {e}")),
            }
        });
    }

    fn present_image_lightbox(
        self: &Rc<Self>,
        tex: &gdk::Texture,
        cache_key: Option<String>,
        suggested_name: String,
        title: String,
    ) {
        let viewer = adw::Window::builder()
            .transient_for(&self.window)
            .title(&title)
            .default_width(820)
            .default_height(600)
            .build();

        let header = adw::HeaderBar::new();
        if let Some(ck) = cache_key {
            let save_btn = gtk4::Button::builder()
                .icon_name("document-save-symbolic")
                .label("Save Image As…")
                .css_classes(["suggested-action"])
                .build();
            let c = self.clone();
            save_btn.connect_clicked(move |_| {
                c.save_media_via_portal(ck.clone(), suggested_name.clone());
            });
            header.pack_end(&save_btn);
        }

        let pic = gtk4::Picture::for_paintable(tex);
        pic.set_content_fit(gtk4::ContentFit::Contain);
        pic.set_can_shrink(true);
        pic.set_hexpand(true);
        pic.set_vexpand(true);
        pic.set_margin_top(12);
        pic.set_margin_bottom(12);
        pic.set_margin_start(12);
        pic.set_margin_end(12);

        let tb = adw::ToolbarView::new();
        tb.add_top_bar(&header);
        tb.set_content(Some(&pic));
        viewer.set_content(Some(&tb));

        let esc_ctrl = gtk4::EventControllerKey::new();
        let viewer_weak = viewer.downgrade();
        esc_ctrl.connect_key_pressed(move |_, key, _, _| {
            if key == gdk::Key::Escape
                && let Some(v) = viewer_weak.upgrade()
            {
                v.close();
                return glib::Propagation::Stop;
            }
            glib::Propagation::Proceed
        });
        viewer.add_controller(esc_ctrl);
        viewer.present();
    }

    fn present_video_player(
        self: &Rc<Self>,
        cache_key: String,
        file_name: Option<String>,
        mime_type: String,
    ) {
        let Some(path) =
            self.materialize_media_temp_file(&cache_key, file_name.as_deref(), &mime_type)
        else {
            self.show_toast("Unable to materialize encrypted video for playback");
            return;
        };

        let title = file_name
            .clone()
            .unwrap_or_else(|| "Encrypted Video Playback".to_string());
        let viewer = adw::Window::builder()
            .transient_for(&self.window)
            .title(&title)
            .default_width(780)
            .default_height(520)
            .build();

        let header = adw::HeaderBar::new();
        let save_btn = gtk4::Button::builder()
            .icon_name("document-save-symbolic")
            .label("Save As…")
            .build();
        {
            let c = self.clone();
            let ck = cache_key.clone();
            let ext = infer_media_extension(file_name.as_deref(), &mime_type);
            let suggested = file_name.unwrap_or_else(|| format!("whatsapp-video.{ext}"));
            save_btn.connect_clicked(move |_| {
                c.save_media_via_portal(ck.clone(), suggested.clone());
            });
        }
        let ext_btn = gtk4::Button::builder()
            .label("Open Externally ↗")
            .css_classes(["flat"])
            .build();
        {
            let uri = gio::File::for_path(&path).uri();
            let viewer_ref = viewer.clone();
            ext_btn.connect_clicked(move |_| {
                let launcher = gtk4::UriLauncher::new(&uri);
                launcher.launch(Some(&viewer_ref), gio::Cancellable::NONE, |_| {});
            });
        }
        header.pack_start(&ext_btn);
        header.pack_end(&save_btn);

        let video = gtk4::Video::for_filename(Some(&path));
        video.set_autoplay(true);
        video.set_hexpand(true);
        video.set_vexpand(true);

        let tb = adw::ToolbarView::new();
        tb.add_top_bar(&header);
        tb.set_content(Some(&video));
        viewer.set_content(Some(&tb));
        viewer.present();
    }

    fn toggle_audio_playback(
        &self,
        stanza_id: &str,
        cache_key: &str,
        file_name: Option<&str>,
        mime_type: &str,
        btn: &gtk4::Button,
    ) {
        {
            let mut active = self.active_audio.borrow_mut();
            if let Some((active_id, mf)) = active.as_ref() {
                if active_id == stanza_id {
                    if mf.is_playing() {
                        mf.pause();
                        btn.set_icon_name("media-playback-start-symbolic");
                        return;
                    } else {
                        if mf.is_ended() {
                            mf.seek(0);
                        }
                        mf.play();
                        btn.set_icon_name("media-playback-pause-symbolic");
                        return;
                    }
                }
                mf.pause();
            }
            *active = None;
        }

        let Some(path) = self.materialize_media_temp_file(cache_key, file_name, mime_type) else {
            self.show_toast("Unable to prepare encrypted voice note for playback");
            return;
        };

        let mf = gtk4::MediaFile::for_filename(&path);
        let btn_weak = btn.downgrade();
        mf.connect_ended_notify(move |stream| {
            if stream.is_ended()
                && let Some(b) = btn_weak.upgrade()
            {
                b.set_icon_name("media-playback-start-symbolic");
            }
        });
        mf.play();
        btn.set_icon_name("media-playback-pause-symbolic");
        *self.active_audio.borrow_mut() = Some((stanza_id.to_string(), mf));
    }

    fn set_composer_mode(&self, mode: ComposerMode) {
        match &mode {
            ComposerMode::Normal => {
                self.context_bar_box.set_visible(false);
            }
            ComposerMode::Reply(q) => {
                self.context_bar_label
                    .set_label(&format!("Replying to {}: {}", q.sender_label, q.snippet));
                self.context_bar_box.set_visible(true);
            }
            ComposerMode::Edit {
                original_snippet, ..
            } => {
                self.context_bar_label
                    .set_label(&format!("Editing message: {original_snippet}"));
                self.context_bar_box.set_visible(true);
            }
        }
        *self.composer_mode.borrow_mut() = mode;
    }

    fn send_from_composer(self: &Rc<Self>) {
        let Some(cid) = *self.selected_conv.borrow() else {
            self.show_toast("Select a conversation first");
            return;
        };
        let start = self.composer_buffer.start_iter();
        let end = self.composer_buffer.end_iter();
        let text = self
            .composer_buffer
            .text(&start, &end, false)
            .trim()
            .to_string();
        if text.is_empty() {
            return;
        }
        self.composer_buffer.set_text("");

        let mode = self.composer_mode.borrow().clone();
        self.set_composer_mode(ComposerMode::Normal);

        match mode {
            ComposerMode::Edit {
                target_stanza_id, ..
            } => {
                self.submit_engine_command(EngineCommand::EditMessage {
                    conversation_id: cid,
                    target_stanza_id,
                    new_text: text,
                });
            }
            ComposerMode::Normal | ComposerMode::Reply(_) => {
                let quoted = match mode {
                    ComposerMode::Reply(q) => Some(q),
                    _ => None,
                };
                let reply_stanza = quoted.as_ref().map(|q| q.target_stanza_id.clone());
                let local_id = format!("LOCAL-{}", uuid::Uuid::now_v7());
                let content = MessageContent::Text {
                    body: text.clone(),
                    edited_at: None,
                    link_preview: None,
                };

                if let Some(sess) = self.session.borrow().as_ref() {
                    let _ = sess.vault.insert_outbound_queued(
                        cid,
                        &local_id,
                        &content,
                        quoted.as_ref(),
                    );
                }
                self.reload_active_timeline(true);
                self.refresh_conversations_from_store();

                self.submit_engine_command(EngineCommand::SendText {
                    conversation_id: cid,
                    local_id,
                    text,
                    reply_to_stanza_id: reply_stanza,
                });
            }
        }
    }

    fn send_attachment_path(self: &Rc<Self>, path: PathBuf) {
        let Some(cid) = *self.selected_conv.borrow() else {
            self.show_toast("Select a conversation before attaching media");
            return;
        };
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let (media_kind, mime) = match ext.as_str() {
            "png" => (MediaKind::Image, "image/png"),
            "jpg" | "jpeg" => (MediaKind::Image, "image/jpeg"),
            "webp" => (MediaKind::Image, "image/webp"),
            "mp4" | "mkv" | "webm" => (MediaKind::Video, "video/mp4"),
            "ogg" | "opus" => (MediaKind::VoiceNote, "audio/ogg; codecs=opus"),
            "mp3" | "flac" | "wav" => (MediaKind::Audio, "audio/mpeg"),
            _ => (MediaKind::Document, "application/octet-stream"),
        };
        let byte_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string);
        let local_id = format!("LOCAL-ATT-{}", uuid::Uuid::now_v7());

        let content = MessageContent::Media {
            media_kind,
            caption: None,
            mime_type: mime.to_string(),
            file_name,
            byte_len,
            dimensions: (media_kind == MediaKind::Image).then_some((280, 180)),
            cache_key: Some(local_id.clone()),
            thumb_cache_key: None,
            duration_secs: None,
            waveform: None,
        };

        if let Some(sess) = self.session.borrow().as_ref() {
            if byte_len <= 32 * 1024 * 1024
                && let Ok(bytes) = std::fs::read(&path)
            {
                let _ = sess.vault.store_encrypted_media(&local_id, &bytes);
            }
            let _ = sess
                .vault
                .insert_outbound_queued(cid, &local_id, &content, None);
        }
        self.reload_active_timeline(true);
        self.refresh_conversations_from_store();

        self.submit_engine_command(EngineCommand::SendAttachment {
            conversation_id: cid,
            local_id,
            file_path: path,
            mime_type: mime.to_string(),
            media_kind,
            caption: None,
        });
    }

    async fn try_paste_clipboard_image(self: &Rc<Self>) {
        let Some(display) = gdk::Display::default() else {
            return;
        };
        let clipboard = display.clipboard();
        if let Ok(Some(texture)) = clipboard.read_texture_future().await {
            let paste_path = self
                .layout
                .cache_media_dir
                .join(format!("clipboard-{}.png", uuid::Uuid::now_v7()));
            if texture.save_to_png(&paste_path).is_ok() {
                self.show_toast("Sending pasted clipboard image…");
                self.send_attachment_path(paste_path);
            }
        }
    }

    fn show_toast(&self, message: &str) {
        let toast = adw::Toast::new(message);
        self.toast_overlay.add_toast(toast);
    }
}

fn build_waveform_drawing_area(
    waveform: Option<&[u8]>,
    seed_stanza_id: &str,
    is_from_me: bool,
) -> gtk4::DrawingArea {
    let samples: Vec<f64> = match waveform.filter(|w| !w.is_empty()) {
        Some(raw) => {
            let target_bars = 40usize;
            let max_val = raw.iter().copied().max().unwrap_or(100).max(1) as f64;
            (0..target_bars)
                .map(|i| {
                    let idx = (i * raw.len()) / target_bars;
                    (f64::from(raw[idx]) / max_val).clamp(0.14, 1.0)
                })
                .collect()
        }
        None => {
            let seed_bytes = seed_stanza_id.as_bytes();
            (0..36usize)
                .map(|i| {
                    let b = seed_bytes
                        .get(i % seed_bytes.len().max(1))
                        .copied()
                        .unwrap_or(42);
                    let v = ((usize::from(b).wrapping_mul(37).wrapping_add(i * 19)) % 82) as f64;
                    (0.18 + v / 100.0).clamp(0.18, 0.98)
                })
                .collect()
        }
    };

    let area = gtk4::DrawingArea::builder()
        .content_width(184)
        .content_height(30)
        .hexpand(true)
        .valign(gtk4::Align::Center)
        .build();

    area.set_draw_func(move |_widget, cr, width, height| {
        let n = samples.len().max(1);
        let w = f64::from(width);
        let h = f64::from(height);
        let step = w / (n as f64);
        let line_w = (step * 0.56).clamp(2.0, 3.6);

        cr.set_line_cap(cairo::LineCap::Round);
        cr.set_line_width(line_w);
        if is_from_me {
            cr.set_source_rgba(0.18, 0.78, 0.49, 0.92);
        } else {
            cr.set_source_rgba(0.32, 0.67, 0.54, 0.88);
        }

        for (i, amp) in samples.iter().copied().enumerate() {
            let x = (i as f64 + 0.5) * step;
            let bar_h = (amp * (h - 6.0)).max(4.0);
            let y0 = (h - bar_h) * 0.5;
            cr.move_to(x, y0);
            cr.line_to(x, y0 + bar_h);
        }
        let _ = cr.stroke();
    });

    area
}

fn infer_media_extension(file_name: Option<&str>, mime_type: &str) -> String {
    if let Some(ext) = file_name
        .and_then(|n| std::path::Path::new(n).extension())
        .and_then(|e| e.to_str())
        .filter(|e| !e.is_empty() && e.len() <= 8)
    {
        return ext.to_ascii_lowercase();
    }
    let m = mime_type.to_ascii_lowercase();
    if m.contains("png") {
        "png"
    } else if m.contains("jpeg") || m.contains("jpg") {
        "jpg"
    } else if m.contains("webp") {
        "webp"
    } else if m.contains("gif") {
        "gif"
    } else if m.contains("webm") {
        "webm"
    } else if m.contains("mp4") || m.contains("video") {
        "mp4"
    } else if m.contains("ogg") || m.contains("opus") {
        "ogg"
    } else if m.contains("mpeg") || m.contains("mp3") {
        "mp3"
    } else if m.contains("wav") {
        "wav"
    } else if m.contains("pdf") {
        "pdf"
    } else {
        "bin"
    }
    .to_string()
}

fn format_bytes_human(byte_len: u64) -> String {
    if byte_len >= 1024 * 1024 {
        format!("{:.1} MiB", byte_len as f64 / (1024.0 * 1024.0))
    } else if byte_len >= 1024 {
        format!("{:.1} KiB", byte_len as f64 / 1024.0)
    } else if byte_len > 0 {
        format!("{byte_len} B")
    } else {
        "encrypted".to_string()
    }
}

fn format_duration_mmss(secs: u32) -> String {
    format!("{}:{:02}", secs / 60, secs % 60)
}

//! Native GTK4 / Adwaita stylesheet adapting automatically to system light, dark,
//! and high-contrast themes via named Adwaita palette colors.

use gtk4::gdk;

const APP_CSS: &str = r#"
.qr-card {
    border-radius: 16px;
    border: 1px solid alpha(@borders, 0.65);
    padding: 8px;
}

.pair-code-pill {
    font-family: monospace;
    font-size: 24px;
    font-weight: 800;
    letter-spacing: 4px;
    padding: 12px 20px;
    border-radius: 12px;
    background-color: alpha(@accent_bg_color, 0.14);
    color: @accent_color;
}

.unread-pill {
    background-color: @accent_bg_color;
    color: @accent_fg_color;
    border-radius: 999px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 700;
    min-width: 18px;
}

.bubble-in {
    background-color: @card_bg_color;
    border: 1px solid alpha(@borders, 0.45);
    border-radius: 16px 16px 16px 4px;
    padding: 10px 14px;
}

.bubble-out {
    background-color: alpha(@accent_bg_color, 0.20);
    border: 1px solid alpha(@accent_bg_color, 0.40);
    border-radius: 16px 16px 4px 16px;
    padding: 10px 14px;
}

.quoted-block {
    background-color: alpha(@window_fg_color, 0.06);
    border-left: 3px solid @accent_bg_color;
    border-radius: 6px;
    padding: 6px 10px;
    margin-bottom: 6px;
}

.view-once-stub {
    background-color: alpha(@warning_bg_color, 0.16);
    border: 1px solid alpha(@warning_bg_color, 0.45);
    border-radius: 10px;
    padding: 8px 12px;
}

.call-item-card {
    background-color: alpha(@window_fg_color, 0.05);
    border: 1px solid alpha(@borders, 0.55);
    border-radius: 10px;
    padding: 8px 12px;
}

.media-frame {
    background-color: alpha(@window_fg_color, 0.05);
    border: 1px solid alpha(@borders, 0.45);
    border-radius: 10px;
    padding: 10px 12px;
}

.chat-photo-frame {
    border-radius: 12px;
    border: 1px solid alpha(@borders, 0.45);
    background-color: alpha(@window_fg_color, 0.04);
}

.sticker-frame {
    padding: 4px;
}

.video-card-backdrop {
    border-radius: 12px;
    border: 1px solid alpha(@borders, 0.55);
    background-color: alpha(black, 0.78);
}

.overlay-badge {
    background-color: alpha(black, 0.65);
    color: white;
    border-radius: 999px;
    padding: 3px 9px;
    font-size: 11px;
    font-weight: 600;
}

.audio-card {
    background-color: alpha(@window_fg_color, 0.05);
    border: 1px solid alpha(@borders, 0.45);
    border-radius: 12px;
    padding: 8px 12px;
}

.doc-card {
    background-color: alpha(@window_fg_color, 0.05);
    border: 1px solid alpha(@borders, 0.45);
    border-radius: 10px;
    padding: 8px 12px;
}

.link-preview-card {
    background-color: alpha(@window_fg_color, 0.06);
    border-left: 3px solid @accent_bg_color;
    border-radius: 8px;
    padding: 8px 10px;
    margin-top: 4px;
}

.poll-option-row {
    background-color: alpha(@window_fg_color, 0.05);
    border: 1px solid alpha(@borders, 0.40);
    border-radius: 8px;
    padding: 6px 10px;
}

.location-card {
    background-color: alpha(@accent_bg_color, 0.10);
    border: 1px solid alpha(@accent_bg_color, 0.35);
    border-radius: 10px;
    padding: 8px 10px;
}

.reaction-chip {
    border-radius: 999px;
    padding: 2px 8px;
    font-size: 12px;
    min-height: 24px;
}

.reaction-chip-mine {
    background-color: alpha(@accent_bg_color, 0.22);
    border: 1px solid alpha(@accent_bg_color, 0.55);
}

.composer-frame {
    background-color: @card_bg_color;
    border-top: 1px solid alpha(@borders, 0.55);
    padding: 8px 12px;
}

.composer-input {
    border-radius: 12px;
    padding: 6px 10px;
    background-color: alpha(@window_fg_color, 0.05);
}

.reply-bar {
    background-color: alpha(@accent_bg_color, 0.12);
    border-top: 1px solid alpha(@accent_bg_color, 0.30);
    padding: 6px 12px;
}

.call-banner-bar {
    background-color: alpha(@success_bg_color, 0.22);
    border-bottom: 1px solid alpha(@success_bg_color, 0.50);
    padding: 8px 14px;
}
"#;

pub fn install_app_css() {
    let provider = gtk4::CssProvider::new();
    provider.load_from_string(APP_CSS);
    if let Some(display) = gdk::Display::default() {
        gtk4::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}

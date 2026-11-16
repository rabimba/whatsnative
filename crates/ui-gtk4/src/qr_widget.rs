//! Native Cairo vector QR code widget (`gtk4::DrawingArea`) for WhatsApp companion
//! pairing. Renders crisp, pixel-aligned QR modules at any Wayland fractional HiDPI scale.

use gtk4::prelude::*;
use qrcode::{Color, QrCode};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone)]
pub struct QrCanvas {
    area: gtk4::DrawingArea,
    payload: Rc<RefCell<Option<String>>>,
}

impl QrCanvas {
    pub fn new(size_px: i32) -> Self {
        let payload: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
        let area = gtk4::DrawingArea::builder()
            .content_width(size_px)
            .content_height(size_px)
            .halign(gtk4::Align::Center)
            .valign(gtk4::Align::Center)
            .build();
        area.add_css_class("qr-card");

        let payload_draw = payload.clone();
        area.set_draw_func(move |_widget, cr, width, height| {
            let side = f64::from(width.min(height));
            // Crisp white quiet-zone background so phone cameras scan reliably in dark mode.
            cr.set_source_rgb(1.0, 1.0, 1.0);
            cr.rectangle(0.0, 0.0, f64::from(width), f64::from(height));
            let _ = cr.fill();

            let maybe_data = payload_draw.borrow().clone();
            let Some(data) = maybe_data.filter(|s| !s.is_empty()) else {
                // Draw subtle placeholder grid while waiting for WebSocket QR ref.
                cr.set_source_rgb(0.86, 0.88, 0.91);
                let pad = side * 0.14;
                cr.set_line_width(2.0);
                cr.rectangle(pad, pad, side - pad * 2.0, side - pad * 2.0);
                let _ = cr.stroke();
                return;
            };

            let Ok(qr) = QrCode::new(data.as_bytes()) else {
                return;
            };
            let modules = qr.width();
            if modules == 0 {
                return;
            }
            let quiet_modules = 4usize;
            let total_units = (modules + quiet_modules * 2) as f64;
            let cell = (side / total_units).floor().max(2.0);
            let grid_px = cell * total_units;
            let origin_x = ((f64::from(width) - grid_px) * 0.5).floor();
            let origin_y = ((f64::from(height) - grid_px) * 0.5).floor();

            cr.set_source_rgb(0.06, 0.08, 0.11);
            for y in 0..modules {
                for x in 0..modules {
                    if qr[(x, y)] == Color::Dark {
                        let px = origin_x + ((x + quiet_modules) as f64) * cell;
                        let py = origin_y + ((y + quiet_modules) as f64) * cell;
                        cr.rectangle(px, py, cell, cell);
                    }
                }
            }
            let _ = cr.fill();
        });

        Self { area, payload }
    }

    pub fn set_payload(&self, next: Option<String>) {
        *self.payload.borrow_mut() = next;
        self.area.queue_draw();
    }

    pub fn widget(&self) -> &gtk4::DrawingArea {
        &self.area
    }
}

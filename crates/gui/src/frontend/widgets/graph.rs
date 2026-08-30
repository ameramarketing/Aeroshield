use gtk4::prelude::*;
use gtk4::DrawingArea;
use std::cell::RefCell;
use std::rc::Rc;

pub struct SignalGraph {
    pub handle: DrawingArea,
    history: Rc<RefCell<Vec<i32>>>,
}

impl SignalGraph {
    pub fn new() -> Self {
        let handle = DrawingArea::new();
        let history = Rc::new(RefCell::new(Vec::new()));

        let history_clone = history.clone();
        handle.set_draw_func(move |area, cr, width, height| {
            let history = history_clone.borrow();
            let w = width as f64;
            let h = height as f64;

            // Draw dark background
            cr.set_source_rgba(0.08, 0.08, 0.08, 1.0);
            let _ = cr.paint();

            if history.is_empty() {
                // Draw placeholder text
                cr.set_source_rgba(0.6, 0.6, 0.6, 0.8);
                let text = "Select an Access Point to see live signal strength";
                cr.select_font_face("sans-serif", gtk4::cairo::FontSlant::Normal, gtk4::cairo::FontWeight::Normal);
                cr.set_font_size(12.0);
                
                // Simple centering helper
                let extents = cr.text_extents(text).unwrap();
                let x = (w - extents.width()) / 2.0;
                let y = (h + extents.height()) / 2.0;
                let _ = cr.move_to(x, y);
                let _ = cr.show_text(text);
                return;
            }

            // Draw horizontal grid lines (every 20 dBm from -20 to -100)
            cr.set_source_rgba(0.2, 0.2, 0.2, 0.4);
            cr.set_line_width(1.0);
            
            let grid_dbms = [-20, -40, -60, -80, -100];
            for &dbm in &grid_dbms {
                // Normalize: -100 is bottom (h), -10 is top (0)
                let pct = (dbm + 100) as f64 / 90.0;
                let y = h - (pct * h).clamp(0.0, h);
                let _ = cr.move_to(0.0, y);
                let _ = cr.line_to(w, y);
                let _ = cr.stroke();

                // Draw labels
                cr.set_source_rgba(0.4, 0.4, 0.4, 0.7);
                cr.set_font_size(9.0);
                let _ = cr.move_to(5.0, y - 2.0);
                let _ = cr.show_text(&format!("{} dBm", dbm));
                cr.set_source_rgba(0.2, 0.2, 0.2, 0.4);
            }

            // Draw the signal history line
            cr.set_source_rgba(0.12, 0.74, 0.38, 1.0); // Bright green
            cr.set_line_width(2.0);

            let max_points = 50;
            let start_idx = if history.len() > max_points {
                history.len() - max_points
            } else {
                0
            };

            let view_slice = &history[start_idx..];
            let x_step = w / ((max_points - 1) as f64);

            for (i, &sig) in view_slice.iter().enumerate() {
                // Signal power ranges from -100 to -10 dBm
                let sig_clamped = sig.clamp(-100, -10);
                let pct = (sig_clamped + 100) as f64 / 90.0;
                let y = h - (pct * h);
                let x = (i as f64) * x_step;

                if i == 0 {
                    let _ = cr.move_to(x, y);
                } else {
                    let _ = cr.line_to(x, y);
                }
            }
            let _ = cr.stroke();
        });

        Self { handle, history }
    }

    pub fn push_signal(&self, signal: i32) {
        let mut history = self.history.borrow_mut();
        history.push(signal);
        if history.len() > 100 {
            history.remove(0);
        }
        self.handle.queue_draw();
    }

    pub fn clear(&self) {
        self.history.borrow_mut().clear();
        self.handle.queue_draw();
    }
}

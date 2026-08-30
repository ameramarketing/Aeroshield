use gtk4::prelude::*;
use gtk4::*;

pub struct WpsTab {
    pub container: Box,
    pub pixie_check: CheckButton,
    pub action_but: Button,
    pub progress: ProgressBar,
    pub status_label: Label,
    pub pin_label: Label,
    pub psk_label: Label,
    pub log_view: TextView,
}

impl WpsTab {
    pub fn new() -> Self {
        let container = Box::new(Orientation::Vertical, 10);
        container.set_margin_top(10);
        container.set_margin_bottom(10);
        container.set_margin_start(10);
        container.set_margin_end(10);

        let title = Label::builder()
            .label("WPS PIN Auditor")
            .halign(Align::Start)
            .build();
        title.add_css_class("title-4");

        let desc = Label::builder()
            .label("Perform authorized WPS recovery audits against selected access points.")
            .wrap(true)
            .halign(Align::Start)
            .build();

        let pixie_check = CheckButton::with_label("Use Pixie Dust attack (-K)");
        pixie_check.set_active(true);

        let action_but = Button::with_label("Start WPS Audit");
        action_but.add_css_class("suggested-action");
        action_but.set_sensitive(false); // Enabled on selection

        let status_box = Box::new(Orientation::Horizontal, 5);
        let status_title = Label::new(Some("Status:"));
        let status_label = Label::new(Some("IDLE"));
        status_label.add_css_class("dim-label");
        status_box.append(&status_title);
        status_box.append(&status_label);

        let progress = ProgressBar::new();
        progress.set_show_text(true);

        let results_frame = Frame::new(Some("Recovered Credentials"));
        let results_box = Box::new(Orientation::Vertical, 6);
        results_box.set_margin_start(8);
        results_box.set_margin_end(8);
        results_box.set_margin_top(8);
        results_box.set_margin_bottom(8);

        let pin_box = Box::new(Orientation::Horizontal, 5);
        let pin_title = Label::new(Some("WPS PIN:"));
        let pin_label = Label::new(Some("Not recovered"));
        pin_label.add_css_class("dim-label");
        pin_box.append(&pin_title);
        pin_box.append(&pin_label);

        let psk_box = Box::new(Orientation::Horizontal, 5);
        let psk_title = Label::new(Some("WPA Key:"));
        let psk_label = Label::new(Some("Not recovered"));
        psk_label.add_css_class("dim-label");
        psk_box.append(&psk_title);
        psk_box.append(&psk_label);

        results_box.append(&pin_box);
        results_box.append(&psk_box);
        results_frame.set_child(Some(&results_box));

        let log_frame = Frame::new(Some("Process Output logs"));
        let log_view = TextView::builder()
            .editable(false)
            .cursor_visible(false)
            .wrap_mode(WrapMode::Word)
            .build();
        
        let scroll = ScrolledWindow::new();
        scroll.set_vexpand(true);
        scroll.set_child(Some(&log_view));
        log_frame.set_child(Some(&scroll));

        container.append(&title);
        container.append(&desc);
        container.append(&pixie_check);
        container.append(&action_but);
        container.append(&status_box);
        container.append(&progress);
        container.append(&results_frame);
        container.append(&log_frame);

        Self {
            container,
            pixie_check,
            action_but,
            progress,
            status_label,
            pin_label,
            psk_label,
            log_view,
        }
    }

    pub fn set_idle(&self) {
        self.status_label.set_text("IDLE");
        self.action_but.set_label("Start WPS Audit");
        self.action_but.remove_css_class("destructive-action");
        self.action_but.add_css_class("suggested-action");
        self.progress.set_fraction(0.0);
        self.progress.set_text(Some("0%"));
    }

    pub fn set_running(&self) {
        self.status_label.set_text("RUNNING");
        self.action_but.set_label("Stop WPS Audit");
        self.action_but.remove_css_class("suggested-action");
        self.action_but.add_css_class("destructive-action");
    }

    pub fn update_logs(&self, logs: &[String]) {
        let buffer = self.log_view.buffer();
        buffer.set_text(&logs.join("\n"));
        // Scroll to the end of the text buffer
        let mark = buffer.create_mark(None, &buffer.end_iter(), false);
        self.log_view.scroll_to_mark(&mark, 0.0, true, 0.0, 1.0);
    }
}

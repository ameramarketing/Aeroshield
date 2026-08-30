use gtk4::prelude::*;
use gtk4::*;

pub struct EvilTwinTab {
    pub container: Box,
    pub essid_entry: Entry,
    pub channel_entry: Entry,
    pub ip_entry: Entry,
    pub interface_combo: ComboBoxText,
    pub action_but: Button,
    pub status_label: Label,
    pub creds_store: ListStore,
    pub creds_view: TreeView,
}

impl EvilTwinTab {
    pub fn new() -> Self {
        let container = Box::new(Orientation::Vertical, 10);
        container.set_margin_top(10);
        container.set_margin_bottom(10);
        container.set_margin_start(10);
        container.set_margin_end(10);

        let title = Label::builder()
            .label("Evil Twin Captive Portal")
            .halign(Align::Start)
            .build();
        title.add_css_class("title-4");

        let desc = Label::builder()
            .label("Audit user awareness by configuring a rogue access point and captive portal.")
            .wrap(true)
            .halign(Align::Start)
            .build();

        let config_frame = Frame::new(Some("Rogue AP Configuration"));
        let config_box = Grid::new();
        config_box.set_row_spacing(6);
        config_box.set_column_spacing(10);
        config_box.set_margin_start(8);
        config_box.set_margin_end(8);
        config_box.set_margin_top(8);
        config_box.set_margin_bottom(8);

        // Interface Selector
        let iface_label = Label::new(Some("Interface:"));
        let interface_combo = ComboBoxText::new();
        interface_combo.set_hexpand(true);
        config_box.attach(&iface_label, 0, 0, 1, 1);
        config_box.attach(&interface_combo, 1, 0, 1, 1);

        // ESSID Configuration
        let essid_label = Label::new(Some("SSID:"));
        let essid_entry = Entry::builder()
            .placeholder_text("AeroShield_Guest")
            .text("AeroShield_Secure_Guest")
            .build();
        config_box.attach(&essid_label, 0, 1, 1, 1);
        config_box.attach(&essid_entry, 1, 1, 1, 1);

        // Channel Configuration
        let channel_label = Label::new(Some("Channel:"));
        let channel_entry = Entry::builder()
            .placeholder_text("6")
            .text("6")
            .build();
        config_box.attach(&channel_label, 0, 2, 1, 1);
        config_box.attach(&channel_entry, 1, 2, 1, 1);

        // Gateway / Portal IP Configuration
        let ip_label = Label::new(Some("Portal IP:"));
        let ip_entry = Entry::builder()
            .placeholder_text("192.168.1.1")
            .text("192.168.1.1")
            .build();
        config_box.attach(&ip_label, 0, 3, 1, 1);
        config_box.attach(&ip_entry, 1, 3, 1, 1);

        config_frame.set_child(Some(&config_box));

        let action_but = Button::with_label("Start Evil Twin");
        action_but.add_css_class("suggested-action");

        let status_box = Box::new(Orientation::Horizontal, 5);
        let status_title = Label::new(Some("Status:"));
        let status_label = Label::new(Some("INACTIVE"));
        status_label.add_css_class("dim-label");
        status_box.append(&status_title);
        status_box.append(&status_label);

        let creds_frame = Frame::new(Some("Captured Audit Sign-ins"));
        let creds_store = ListStore::new(&[glib::Type::STRING]);
        
        let column = TreeViewColumn::new();
        column.set_title("Password / Key Attempts");
        let text_renderer = CellRendererText::new();
        column.pack_start(&text_renderer, true);
        column.add_attribute(&text_renderer, "text", 0);

        let creds_view = TreeView::new();
        creds_view.set_model(Some(&creds_store));
        creds_view.append_column(&column);
        creds_view.set_vexpand(true);

        let scroll = ScrolledWindow::new();
        scroll.set_child(Some(&creds_view));
        creds_frame.set_child(Some(&scroll));

        container.append(&title);
        container.append(&desc);
        container.append(&config_frame);
        container.append(&action_but);
        container.append(&status_box);
        container.append(&creds_frame);

        Self {
            container,
            essid_entry,
            channel_entry,
            ip_entry,
            interface_combo,
            action_but,
            status_label,
            creds_store,
            creds_view,
        }
    }

    pub fn set_idle(&self) {
        self.status_label.set_text("INACTIVE");
        self.action_but.set_label("Start Evil Twin");
        self.action_but.remove_css_class("destructive-action");
        self.action_but.add_css_class("suggested-action");
        self.essid_entry.set_sensitive(true);
        self.channel_entry.set_sensitive(true);
        self.ip_entry.set_sensitive(true);
        self.interface_combo.set_sensitive(true);
    }

    pub fn set_running(&self) {
        self.status_label.set_text("ACTIVE");
        self.action_but.set_label("Stop Evil Twin");
        self.action_but.remove_css_class("suggested-action");
        self.action_but.add_css_class("destructive-action");
        self.essid_entry.set_sensitive(false);
        self.channel_entry.set_sensitive(false);
        self.ip_entry.set_sensitive(false);
        self.interface_combo.set_sensitive(false);
    }
}

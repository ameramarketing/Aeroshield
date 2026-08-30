use gtk4::prelude::*;
use gtk4::*;

pub struct SessionTab {
    pub container: ScrolledWindow,
    pub status_label: Label,
    pub action_but: Button,
    pub interface_label: Label,
    pub environment_combo: ComboBoxText,
    pub target_scope_entry: Entry,
    
    pub risk_high_label: Label,
    pub risk_med_label: Label,
    pub risk_low_label: Label,
    
    pub handshakes_label: Label,
    pub pmkids_label: Label,
    
    pub findings_store: ListStore,
    pub findings_view: TreeView,
    
    pub timeline_store: ListStore,
    pub timeline_view: TreeView,
    
    pub notes_view: TextView,
    pub notes_buffer: TextBuffer,
}

impl SessionTab {
    pub fn new() -> Self {
        let root_scroll = ScrolledWindow::builder()
            .hscrollbar_policy(PolicyType::Never)
            .vscrollbar_policy(PolicyType::Automatic)
            .build();

        let container = Box::new(Orientation::Vertical, 10);
        container.set_margin_top(10);
        container.set_margin_bottom(10);
        container.set_margin_start(10);
        container.set_margin_end(10);

        // Title and Header
        let title = Label::builder()
            .label("Assessment Session Dashboard")
            .halign(Align::Start)
            .build();
        title.add_css_class("title-4");

        let desc = Label::builder()
            .label("Designate authorized assessment scopes, verify threat evidence, and log security assessment findings.")
            .wrap(true)
            .halign(Align::Start)
            .build();

        // 1. Session Status and Controls
        let status_frame = Frame::new(Some("Session Lifecycle & Scope"));
        let status_box = Box::new(Orientation::Vertical, 8);
        status_box.set_margin_start(8);
        status_box.set_margin_end(8);
        status_box.set_margin_top(8);
        status_box.set_margin_bottom(8);

        let status_row = Box::new(Orientation::Horizontal, 10);
        let status_title = Label::new(Some("Status:"));
        let status_label = Label::new(Some("NEW"));
        status_label.add_css_class("title-5");
        let action_but = Button::with_label("Activate Session");
        action_but.add_css_class("suggested-action");

        status_row.append(&status_title);
        status_row.append(&status_label);
        status_row.append(&action_but);

        let interface_row = Box::new(Orientation::Horizontal, 10);
        let interface_title = Label::new(Some("Active Interface:"));
        let interface_label = Label::new(Some("None"));
        interface_row.append(&interface_title);
        interface_row.append(&interface_label);

        let env_row = Box::new(Orientation::Horizontal, 10);
        let env_title = Label::new(Some("Environment:"));
        let environment_combo = ComboBoxText::new();
        environment_combo.append_text("Authorized Lab Scope");
        environment_combo.append_text("Corporate Infrastructure Scope");
        environment_combo.append_text("Field Penetration Test");
        environment_combo.append_text("Educational Demo");
        environment_combo.set_active(Some(0));
        env_row.append(&env_title);
        env_row.append(&environment_combo);

        let scope_row = Box::new(Orientation::Vertical, 5);
        let scope_title = Label::builder()
            .label("Target BSSID/SSID Scope (Comma-separated filter):")
            .halign(Align::Start)
            .build();
        let target_scope_entry = Entry::new();
        target_scope_entry.set_placeholder_text(Some("e.g. 00:11:22:33:44:55, TestNet"));
        scope_row.append(&scope_title);
        scope_row.append(&target_scope_entry);

        status_box.append(&status_row);
        status_box.append(&interface_row);
        status_box.append(&env_row);
        status_box.append(&scope_row);
        status_frame.set_child(Some(&status_box));

        // 2. Risk Metrics Dashboard
        let metrics_frame = Frame::new(Some("Security Posture & Risk Metrics"));
        let metrics_grid = Grid::new();
        metrics_grid.set_column_spacing(10);
        metrics_grid.set_row_spacing(10);
        metrics_grid.set_margin_start(8);
        metrics_grid.set_margin_end(8);
        metrics_grid.set_margin_top(8);
        metrics_grid.set_margin_bottom(8);

        let high_box = Box::new(Orientation::Vertical, 4);
        high_box.set_halign(Align::Center);
        let high_title = Label::new(Some("High Risk APs"));
        let risk_high_label = Label::new(Some("0"));
        risk_high_label.add_css_class("title-3");
        risk_high_label.set_markup("<span foreground='red'>0</span>");
        high_box.append(&high_title);
        high_box.append(&risk_high_label);

        let med_box = Box::new(Orientation::Vertical, 4);
        med_box.set_halign(Align::Center);
        let med_title = Label::new(Some("Med Risk APs"));
        let risk_med_label = Label::new(Some("0"));
        risk_med_label.add_css_class("title-3");
        risk_med_label.set_markup("<span foreground='orange'>0</span>");
        med_box.append(&med_title);
        med_box.append(&risk_med_label);

        let low_box = Box::new(Orientation::Vertical, 4);
        low_box.set_halign(Align::Center);
        let low_title = Label::new(Some("Low Risk APs"));
        let risk_low_label = Label::new(Some("0"));
        risk_low_label.add_css_class("title-3");
        risk_low_label.set_markup("<span foreground='green'>0</span>");
        low_box.append(&low_title);
        low_box.append(&risk_low_label);

        metrics_grid.attach(&high_box, 0, 0, 1, 1);
        metrics_grid.attach(&med_box, 1, 0, 1, 1);
        metrics_grid.attach(&low_box, 2, 0, 1, 1);

        metrics_grid.set_column_homogeneous(true);
        metrics_frame.set_child(Some(&metrics_grid));

        // 3. Evidence Status
        let evidence_frame = Frame::new(Some("Collected Authentication Evidence"));
        let evidence_box = Box::new(Orientation::Horizontal, 15);
        evidence_box.set_margin_start(8);
        evidence_box.set_margin_end(8);
        evidence_box.set_margin_top(8);
        evidence_box.set_margin_bottom(8);

        let hs_box = Box::new(Orientation::Horizontal, 5);
        let hs_title = Label::new(Some("4-Way Handshakes:"));
        let handshakes_label = Label::new(Some("0"));
        handshakes_label.add_css_class("bold");
        hs_box.append(&hs_title);
        hs_box.append(&handshakes_label);

        let pmkid_box = Box::new(Orientation::Horizontal, 5);
        let pmkid_title = Label::new(Some("PMKID Captures:"));
        let pmkids_label = Label::new(Some("0"));
        pmkids_label.add_css_class("bold");
        pmkid_box.append(&pmkid_title);
        pmkid_box.append(&pmkids_label);

        evidence_box.append(&hs_box);
        evidence_box.append(&pmkid_box);
        evidence_frame.set_child(Some(&evidence_box));

        // 4. Findings Table
        let findings_frame = Frame::new(Some("Assessment Security Findings"));
        let findings_store = ListStore::new(&[
            glib::Type::STRING, // Severity
            glib::Type::STRING, // Target (BSSID)
            glib::Type::STRING, // Title
            glib::Type::STRING, // Description
        ]);
        let findings_view = TreeView::builder().height_request(120).build();
        findings_view.set_model(Some(&findings_store));

        let severity_col = TreeViewColumn::builder().title("Severity").fixed_width(80).build();
        let target_col = TreeViewColumn::builder().title("Target").fixed_width(120).build();
        let title_col = TreeViewColumn::builder().title("Title").expand(true).build();

        let cell_sev = CellRendererText::new();
        severity_col.pack_start(&cell_sev, true);
        severity_col.add_attribute(&cell_sev, "text", 0);

        let cell_target = CellRendererText::new();
        target_col.pack_start(&cell_target, true);
        target_col.add_attribute(&cell_target, "text", 1);

        let cell_title = CellRendererText::new();
        title_col.pack_start(&cell_title, true);
        title_col.add_attribute(&cell_title, "text", 2);

        findings_view.append_column(&severity_col);
        findings_view.append_column(&target_col);
        findings_view.append_column(&title_col);

        let findings_scroll = ScrolledWindow::new();
        findings_scroll.set_height_request(120);
        findings_scroll.set_child(Some(&findings_view));
        findings_frame.set_child(Some(&findings_scroll));

        // 5. Timeline View
        let timeline_frame = Frame::new(Some("Assessment Event Timeline"));
        let timeline_store = ListStore::new(&[
            glib::Type::STRING, // Timestamp
            glib::Type::STRING, // Event Type
            glib::Type::STRING, // Description
        ]);
        let timeline_view = TreeView::builder().height_request(120).build();
        timeline_view.set_model(Some(&timeline_store));

        let time_col = TreeViewColumn::builder().title("Timestamp").fixed_width(80).build();
        let type_col = TreeViewColumn::builder().title("Type").fixed_width(100).build();
        let desc_col = TreeViewColumn::builder().title("Description").expand(true).build();

        let cell_time = CellRendererText::new();
        time_col.pack_start(&cell_time, true);
        time_col.add_attribute(&cell_time, "text", 0);

        let cell_type = CellRendererText::new();
        type_col.pack_start(&cell_type, true);
        type_col.add_attribute(&cell_type, "text", 1);

        let cell_desc = CellRendererText::new();
        desc_col.pack_start(&cell_desc, true);
        desc_col.add_attribute(&cell_desc, "text", 2);

        timeline_view.append_column(&time_col);
        timeline_view.append_column(&type_col);
        timeline_view.append_column(&desc_col);

        let timeline_scroll = ScrolledWindow::new();
        timeline_scroll.set_height_request(120);
        timeline_scroll.set_child(Some(&timeline_view));
        timeline_frame.set_child(Some(&timeline_scroll));

        // 6. Operator Notes
        let notes_frame = Frame::new(Some("Operator Assessment Notes"));
        let notes_view = TextView::builder()
            .editable(true)
            .cursor_visible(true)
            .wrap_mode(WrapMode::Word)
            .build();
        let notes_buffer = notes_view.buffer();
        
        let notes_scroll = ScrolledWindow::new();
        notes_scroll.set_height_request(100);
        notes_scroll.set_child(Some(&notes_view));
        notes_frame.set_child(Some(&notes_scroll));

        // Assemble Dashboard
        container.append(&title);
        container.append(&desc);
        container.append(&status_frame);
        container.append(&metrics_frame);
        container.append(&evidence_frame);
        container.append(&findings_frame);
        container.append(&timeline_frame);
        container.append(&notes_frame);

        root_scroll.set_child(Some(&container));

        Self {
            container: root_scroll,
            status_label,
            action_but,
            interface_label,
            environment_combo,
            target_scope_entry,
            risk_high_label,
            risk_med_label,
            risk_low_label,
            handshakes_label,
            pmkids_label,
            findings_store,
            findings_view,
            timeline_store,
            timeline_view,
            notes_view,
            notes_buffer,
        }
    }
}

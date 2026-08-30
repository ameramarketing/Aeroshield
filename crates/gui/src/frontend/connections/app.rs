use crate::backend;
use crate::frontend::interfaces::*;
use crate::frontend::*;
use crate::globals;
use crate::list_store_get;
use crate::types::*;

use glib::ControlFlow;
use glib::clone;
use gtk4::gdk_pixbuf::Pixbuf;
use gtk4::prelude::*;
use gtk4::*;
use std::io::BufReader;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::Duration;

fn list_store_find(storage: &ListStore, pos: i32, to_match: &str) -> Option<TreeIter> {
    let mut iter = storage.iter_first();

    while let Some(mut it) = iter {
        let value = list_store_get!(storage, &it, pos, String);

        if value == to_match {
            return Some(it);
        }

        iter = match storage.iter_next(&mut it) {
            true => Some(it),
            false => None,
        }
    }

    None
}

fn get_channel_entries(entry: &Entry) -> Vec<i32> {
    let entry_text = String::from(entry.text().as_str());

    if entry_text.is_empty() {
        return Vec::new();
    }

    let channels: Vec<i32> = entry_text
        .split(',')
        .map(|num| num.parse::<i32>().unwrap())
        .collect();

    channels
}

/// Refresh the channel status bar with the channel the interface is
/// currently listening on, as reported by the capture thread. Shows `none` when
/// no scan is running (or the card has not tuned to a channel yet).
pub fn update_channel_status(app_data: &Rc<AppData>) {
    let text = match backend::get_current_channel() {
        Some(channel) => format!("Channel: {channel}"),
        None => String::from("Channel: none"),
    };

    app_data.app_gui.channel_status_bar.pop(0);
    app_data.app_gui.channel_status_bar.push(0, &text);
}

/// The channels of every access point currently under attack, as a sorted,
/// de-duplicated, comma-separated channel-filter string.
fn attacked_channels_filter() -> String {
    let mut channels: Vec<i32> = backend::get_attack_pool()
        .values()
        .filter_map(|state| state.ap.channel.trim().parse::<i32>().ok())
        .collect();

    channels.sort_unstable();
    channels.dedup();

    channels
        .iter()
        .map(|channel| channel.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// While at least one deauth attack is running the radio must stay parked on the
/// attacked channels, so the controls that could move it off them are locked: the
/// channel filter, the hop / focus / add buttons, the band toggles and the scan
/// restart. The "Display hidden APs" toggle is locked too, so an attacked hidden
/// AP cannot be hidden from the list mid-attack. Does nothing when no attack is
/// running, so the normal per-selection logic keeps owning these widgets.
fn lock_channel_controls(app_data: &Rc<AppData>) {
    if backend::get_attack_pool().is_empty() {
        return;
    }

    app_data.app_gui.channel_filter_entry.set_sensitive(false);
    app_data.app_gui.hopping_but.set_sensitive(false);
    app_data.app_gui.focus_but.set_sensitive(false);
    app_data.app_gui.add_but.set_sensitive(false);
    app_data.app_gui.ghz_2_4_but.set_sensitive(false);
    app_data.app_gui.ghz_5_but.set_sensitive(false);
    app_data.app_gui.restart_but.set_sensitive(false);
    app_data.settings_gui.display_hidden_ap.set_sensitive(false);
}

/// Keep the channel filter in sync with the set of access points under attack.
///
/// While an attack is running the filter is driven from the attack pool (the
/// union of the attacked channels) so the scan only dwells on channels a deauth
/// is actually targeting. When the last attack stops, the filter is cleared and
/// the locked controls are handed back to the user.
fn drive_channel_filter_from_attacks(app_data: &Rc<AppData>) {
    let attacking = !backend::get_attack_pool().is_empty();
    let was_locked = globals::CHANNEL_LOCK_ACTIVE.load(Ordering::Relaxed);

    if attacking {
        let desired = attacked_channels_filter();

        if app_data.app_gui.channel_filter_entry.text() != desired {
            app_data.app_gui.channel_filter_entry.set_text(&desired);
        }

        globals::CHANNEL_LOCK_ACTIVE.store(true, Ordering::Relaxed);
    } else if was_locked {
        app_data.app_gui.channel_filter_entry.set_sensitive(true);
        app_data.app_gui.ghz_2_4_but.set_sensitive(true);
        app_data.app_gui.ghz_5_but.set_sensitive(true);
        app_data.app_gui.restart_but.set_sensitive(true);
        app_data.settings_gui.display_hidden_ap.set_sensitive(true);

        app_data.app_gui.channel_filter_entry.set_text("");

        globals::CHANNEL_LOCK_ACTIVE.store(false, Ordering::Relaxed);
    }
}

fn connect_window_controller(app_data: Rc<AppData>) {
    let controller = gtk4::EventControllerKey::new();

    controller.connect_key_pressed(clone!(
        #[strong]
        app_data,
        move |_, key, _, _| {
            if key == gdk::Key::Escape {
                app_data.app_gui.cli_view.selection().unselect_all();

                if app_data.app_gui.aps_view.selection().selected().is_some() {
                    app_data.app_gui.aps_view.selection().unselect_all();
                    app_data.app_gui.cli_model.clear();
                }

                app_data.app_gui.client_status_bar.pop(0);
                app_data
                    .app_gui
                    .client_status_bar
                    .push(0, "Showing unassociated clients");

                update_buttons_sensitivity(&app_data);
            }

            glib::Propagation::Proceed
        }
    ));

    app_data.app_gui.window.add_controller(controller);
}

fn connect_aps_controller(app: &Application, app_data: Rc<AppData>) {
    let gesture = GestureClick::new();
    gesture.set_button(gdk::ffi::GDK_BUTTON_SECONDARY as u32);
    gesture.connect_pressed(clone!(
        #[strong]
        app_data,
        move |gesture, _, x, y| {
            gesture.set_state(EventSequenceState::Claimed);

            if app_data.app_gui.aps_view.selection().selected().is_some() {
                let pos = gdk::Rectangle::new(x as i32, y as i32, 0, 0);

                app_data.app_gui.aps_menu.set_pointing_to(Some(&pos));
                app_data.app_gui.aps_menu.popup();
            }
        }
    ));

    app_data.app_gui.aps_scroll.add_controller(gesture);

    let copy_bssid = gio::SimpleAction::new("copy_bssid", None);
    copy_bssid.connect_activate(clone!(
        #[strong]
        app_data,
        move |_, _| {
            let iter = match app_data.app_gui.aps_view.selection().selected() {
                Some((_, iter)) => iter,
                None => return,
            };

            let bssid = list_store_get!(app_data.app_gui.aps_model, &iter, 1, String);

            if let Some(display) = gdk::Display::default() {
                display.clipboard().set_text(&bssid);
            }
        }
    ));
    app.add_action(&copy_bssid);

    let copy_essid = gio::SimpleAction::new("copy_essid", None);
    copy_essid.connect_activate(clone!(
        #[strong]
        app_data,
        move |_, _| {
            let iter = match app_data.app_gui.aps_view.selection().selected() {
                Some((_, iter)) => iter,
                None => return,
            };

            let essid = list_store_get!(app_data.app_gui.aps_model, &iter, 0, String);

            if let Some(display) = gdk::Display::default() {
                display.clipboard().set_text(&essid);
            }
        }
    ));
    app.add_action(&copy_essid);

    let copy_channel = gio::SimpleAction::new("copy_channel", None);
    copy_channel.connect_activate(clone!(
        #[strong]
        app_data,
        move |_, _| {
            let iter = match app_data.app_gui.aps_view.selection().selected() {
                Some((_, iter)) => iter,
                None => return,
            };

            let channel = list_store_get!(app_data.app_gui.aps_model, &iter, 3, i32);

            if let Some(display) = gdk::Display::default() {
                display.clipboard().set_text(&channel.to_string());
            }
        }
    ));
    app.add_action(&copy_channel);
}

fn connect_cli_controller(app: &Application, app_data: Rc<AppData>) {
    let gesture = GestureClick::new();
    gesture.set_button(gdk::ffi::GDK_BUTTON_SECONDARY as u32);
    gesture.connect_pressed(clone!(
        #[strong]
        app_data,
        move |gesture, _, x, y| {
            gesture.set_state(EventSequenceState::Claimed);

            if app_data.app_gui.cli_view.selection().selected().is_some() {
                let pos = gdk::Rectangle::new(x as i32, y as i32, 0, 0);

                app_data.app_gui.cli_menu.set_pointing_to(Some(&pos));
                app_data.app_gui.cli_menu.popup();
            }
        }
    ));

    app_data.app_gui.cli_scroll.add_controller(gesture);

    let copy_mac = gio::SimpleAction::new("copy_mac", None);
    copy_mac.connect_activate(clone!(
        #[strong]
        app_data,
        move |_, _| {
            let iter = match app_data.app_gui.cli_view.selection().selected() {
                Some((_, iter)) => iter,
                None => return,
            };

            let mac = list_store_get!(app_data.app_gui.cli_model, &iter, 0, String);

            if let Some(display) = gdk::Display::default() {
                display.clipboard().set_text(&mac);
            }
        }
    ));
    app.add_action(&copy_mac);

    let copy_vendor = gio::SimpleAction::new("copy_vendor", None);
    copy_vendor.connect_activate(clone!(
        #[strong]
        app_data,
        move |_, _| {
            let iter = match app_data.app_gui.cli_view.selection().selected() {
                Some((_, iter)) => iter,
                None => return,
            };

            let vendor = list_store_get!(app_data.app_gui.cli_model, &iter, 5, String);

            if let Some(display) = gdk::Display::default() {
                display.clipboard().set_text(&vendor);
            }
        }
    ));
    app.add_action(&copy_vendor);

    let copy_probes = gio::SimpleAction::new("copy_probes", None);
    copy_probes.connect_activate(clone!(
        #[strong]
        app_data,
        move |_, _| {
            let iter = match app_data.app_gui.cli_view.selection().selected() {
                Some((_, iter)) => iter,
                None => return,
            };

            let probes = list_store_get!(app_data.app_gui.cli_model, &iter, 6, String);

            if let Some(display) = gdk::Display::default() {
                display.clipboard().set_text(&probes);
            }
        }
    ));
    app.add_action(&copy_probes);
}

fn connect_about_button(app_data: Rc<AppData>) {
    app_data.app_gui.about_button.connect_clicked(clone!(
        #[strong]
        app_data,
        move |_| {
            let icon = Pixbuf::from_read(BufReader::new(globals::APP_ICON)).unwrap();
            let desc = "A WiFi security auditing software mainly based on aircrack-ng tools suite";

            AboutDialog::builder()
                .program_name("AeroShield")
                .version(globals::VERSION)
                .authors(vec!["Martin OLIVIER (martin.olivier@live.fr)".to_string(), "Antigravity AI Assistant".to_string()])
                .copyright("Copyright (c) AeroShield Contributors")
                .license_type(License::MitX11)
                .logo(&Picture::for_pixbuf(&icon).paintable().unwrap())
                .comments(desc)
                .website_label("https://github.com/ameramarketing/aeroshield")
                .transient_for(&app_data.app_gui.window)
                .modal(true)
                .build()
                .show();
        }
    ));
}

fn connect_update_button(app_data: Rc<AppData>) {
    app_data.app_gui.update_button.connect_clicked(clone!(
        #[strong]
        app_data,
        move |_| {
            let version = globals::VERSION;
            let new_version = globals::NEW_VERSION.lock().unwrap();

            let new_version = match new_version.as_ref() {
                Some(result) => result.clone(),
                None => "unknown".to_string(),
            };

            UpdateDialog::spawn(&app_data.app_gui.window, version, &new_version);
        }
    ));
}

fn connect_decrypt_button(app_data: Rc<AppData>) {
    app_data.app_gui.decrypt_button.connect_clicked(clone!(
        #[strong]
        app_data,
        move |_| {
            app_data.decrypt_gui.show(None);
        }
    ));
}

fn connect_settings_button(app_data: Rc<AppData>) {
    app_data.app_gui.settings_button.connect_clicked(clone!(
        #[strong]
        app_data,
        move |_| {
            app_data.settings_gui.show();
        }
    ));
}

fn connect_hopping_button(app_data: Rc<AppData>) {
    app_data.app_gui.hopping_but.connect_clicked(clone!(
        #[strong]
        app_data,
        move |this| {
            app_data.app_gui.channel_filter_entry.set_text("");

            this.set_sensitive(false);
            update_buttons_sensitivity(&app_data);
        }
    ));
}

fn connect_focus_button(app_data: Rc<AppData>) {
    app_data.app_gui.focus_but.connect_clicked(clone!(
        #[strong]
        app_data,
        move |this| {
            if let Some((_, iter)) = app_data.app_gui.aps_view.selection().selected() {
                let channel = list_store_get!(app_data.app_gui.aps_model, &iter, 3, i32);
                app_data
                    .app_gui
                    .channel_filter_entry
                    .set_text(&channel.to_string());

                this.set_sensitive(false);
                app_data.app_gui.hopping_but.set_sensitive(true);
            }
        }
    ));
}

fn connect_add_button(app_data: Rc<AppData>) {
    app_data.app_gui.add_but.connect_clicked(clone!(
        #[strong]
        app_data,
        move |this| {
            if let Some((_, iter)) = app_data.app_gui.aps_view.selection().selected() {
                let channel = list_store_get!(app_data.app_gui.aps_model, &iter, 3, i32);
                let entry = app_data.app_gui.channel_filter_entry.text();
                let ghz_2_4_but = app_data.app_gui.ghz_2_4_but.is_active();
                let ghz_5_but = app_data.app_gui.ghz_5_but.is_active();

                if !backend::is_valid_channel_filter(&entry, ghz_2_4_but, ghz_5_but) {
                    return;
                }

                let entries = get_channel_entries(&app_data.app_gui.channel_filter_entry);

                if entries.contains(&channel) {
                    return;
                }

                let extend = match !entries.is_empty() {
                    true => format!(",{channel}"),
                    false => format!("{channel}"),
                };

                if !backend::is_valid_channel_filter(
                    &format!("{entry}{extend}"),
                    ghz_2_4_but,
                    ghz_5_but,
                ) {
                    return;
                }

                app_data
                    .app_gui
                    .channel_filter_entry
                    .set_text(&format!("{entry}{extend}"));
                app_data.app_gui.hopping_but.set_sensitive(true);
                this.set_sensitive(false);
            }
        }
    ));
}

pub fn update_buttons_sensitivity(app_data: &Rc<AppData>) {
    let iter = match app_data.app_gui.aps_view.selection().selected() {
        Some((_, iter)) => {
            app_data.app_gui.wps_tab.action_but.set_sensitive(true);
            iter
        }
        None => {
            app_data.app_gui.focus_but.set_sensitive(false);
            app_data.app_gui.add_but.set_sensitive(false);
            app_data.app_gui.deauth_but.set_sensitive(false);
            app_data.app_gui.capture_but.set_sensitive(false);
            app_data.app_gui.wps_tab.action_but.set_sensitive(false);

            app_data.app_gui.previous_but.set_sensitive(false);
            app_data.app_gui.next_but.set_sensitive(false);

            match app_data.app_gui.aps_model.iter_first() {
                Some(_) => {
                    app_data.app_gui.top_but.set_sensitive(true);
                    app_data.app_gui.bottom_but.set_sensitive(true);
                }
                None => {
                    app_data.app_gui.top_but.set_sensitive(false);
                    app_data.app_gui.bottom_but.set_sensitive(false);
                }
            }

            lock_channel_controls(app_data);
            return;
        }
    };

    let channel = list_store_get!(app_data.app_gui.aps_model, &iter, 3, i32);
    let entry = app_data.app_gui.channel_filter_entry.text();
    let ghz_2_4_but = app_data.app_gui.ghz_2_4_but.is_active();
    let ghz_5_but = app_data.app_gui.ghz_5_but.is_active();

    match channel
        != app_data
            .app_gui
            .channel_filter_entry
            .text()
            .parse::<i32>()
            .unwrap_or(-1)
        && backend::is_valid_channel_filter(&format!("{channel}"), ghz_2_4_but, ghz_5_but)
    {
        true => app_data.app_gui.focus_but.set_sensitive(true),
        false => app_data.app_gui.focus_but.set_sensitive(false),
    }

    match backend::is_valid_channel_filter(&entry, ghz_2_4_but, ghz_5_but) {
        true => {
            let entries = get_channel_entries(&app_data.app_gui.channel_filter_entry);
            match entries.contains(&channel) {
                true => app_data.app_gui.add_but.set_sensitive(false),
                false => {
                    let extand = match !entries.is_empty() {
                        true => format!(",{channel}"),
                        false => format!("{channel}"),
                    };
                    match backend::is_valid_channel_filter(
                        &format!("{entry}{extand}"),
                        ghz_2_4_but,
                        ghz_5_but,
                    ) {
                        true => app_data.app_gui.add_but.set_sensitive(true),
                        false => app_data.app_gui.add_but.set_sensitive(false),
                    }
                }
            }
        }
        false => app_data.app_gui.add_but.set_sensitive(false),
    }

    app_data.app_gui.deauth_but.set_sensitive(true);

    let mut prev_iter = iter;
    match app_data.app_gui.aps_model.iter_previous(&mut prev_iter) {
        true => {
            app_data.app_gui.previous_but.set_sensitive(true);
            app_data.app_gui.top_but.set_sensitive(true);
        }
        false => {
            app_data.app_gui.previous_but.set_sensitive(false);
            app_data.app_gui.top_but.set_sensitive(false);
        }
    }

    let mut next_iter = iter;
    match app_data.app_gui.aps_model.iter_next(&mut next_iter) {
        true => {
            app_data.app_gui.next_but.set_sensitive(true);
            app_data.app_gui.bottom_but.set_sensitive(true);
        }
        false => {
            app_data.app_gui.next_but.set_sensitive(false);
            app_data.app_gui.bottom_but.set_sensitive(false);
        }
    }

    lock_channel_controls(app_data);
}

fn connect_previous_button(app_data: Rc<AppData>) {
    app_data.app_gui.previous_but.connect_clicked(clone!(
        #[strong]
        app_data,
        move |_| {
            let iter = match app_data.app_gui.aps_view.selection().selected() {
                Some((_, iter)) => iter,
                None => return update_buttons_sensitivity(&app_data),
            };

            let mut prev_iter = iter;
            if !app_data.app_gui.aps_model.iter_previous(&mut prev_iter) {
                return update_buttons_sensitivity(&app_data);
            }

            let path = app_data.app_gui.aps_model.path(&prev_iter);
            app_data
                .app_gui
                .aps_view
                .selection()
                .select_iter(&prev_iter);
            app_data
                .app_gui
                .aps_view
                .scroll_to_cell(Some(&path), None, false, 0.0, 0.0);
            app_data.app_gui.cli_model.clear();

            let essid = list_store_get!(app_data.app_gui.aps_model, &prev_iter, 0, String);
            app_data.app_gui.client_status_bar.pop(0);
            app_data
                .app_gui
                .client_status_bar
                .push(0, &format!("Showing '{essid}' clients"));

            update_buttons_sensitivity(&app_data);
        }
    ));
}

fn connect_next_button(app_data: Rc<AppData>) {
    app_data.app_gui.next_but.connect_clicked(clone!(
        #[strong]
        app_data,
        move |_| {
            let iter = match app_data.app_gui.aps_view.selection().selected() {
                Some((_, iter)) => iter,
                None => return update_buttons_sensitivity(&app_data),
            };

            let mut next_iter = iter;
            if !app_data.app_gui.aps_model.iter_next(&mut next_iter) {
                return update_buttons_sensitivity(&app_data);
            }

            let path = app_data.app_gui.aps_model.path(&next_iter);
            app_data
                .app_gui
                .aps_view
                .selection()
                .select_iter(&next_iter);
            app_data
                .app_gui
                .aps_view
                .scroll_to_cell(Some(&path), None, false, 0.0, 0.0);
            app_data.app_gui.cli_model.clear();

            let essid = list_store_get!(app_data.app_gui.aps_model, &next_iter, 0, String);
            app_data.app_gui.client_status_bar.pop(0);
            app_data
                .app_gui
                .client_status_bar
                .push(0, &format!("Showing '{essid}' clients"));

            update_buttons_sensitivity(&app_data);
        }
    ));
}

fn connect_top_button(app_data: Rc<AppData>) {
    app_data.app_gui.top_but.connect_clicked(clone!(
        #[strong]
        app_data,
        move |_| {
            let first_iter = match app_data.app_gui.aps_model.iter_first() {
                Some(iter) => iter,
                None => return update_buttons_sensitivity(&app_data),
            };

            let path = app_data.app_gui.aps_model.path(&first_iter);
            app_data
                .app_gui
                .aps_view
                .selection()
                .select_iter(&first_iter);
            app_data
                .app_gui
                .aps_view
                .scroll_to_cell(Some(&path), None, false, 0.0, 0.0);
            app_data.app_gui.cli_model.clear();

            let essid = list_store_get!(app_data.app_gui.aps_model, &first_iter, 0, String);
            app_data.app_gui.client_status_bar.pop(0);
            app_data
                .app_gui
                .client_status_bar
                .push(0, &format!("Showing '{essid}' clients"));

            update_buttons_sensitivity(&app_data);
        }
    ));
}

fn connect_bottom_button(app_data: Rc<AppData>) {
    app_data.app_gui.bottom_but.connect_clicked(clone!(
        #[strong]
        app_data,
        move |_| {
            let mut iter = match app_data.app_gui.aps_model.iter_first() {
                Some(iter) => iter,
                None => return update_buttons_sensitivity(&app_data),
            };

            let mut last_iter = iter;

            while app_data.app_gui.aps_model.iter_next(&mut iter) {
                last_iter = iter;
            }

            let path = app_data.app_gui.aps_model.path(&last_iter);
            app_data
                .app_gui
                .aps_view
                .selection()
                .select_iter(&last_iter);
            app_data
                .app_gui
                .aps_view
                .scroll_to_cell(Some(&path), None, false, 0.0, 0.0);
            app_data.app_gui.cli_model.clear();

            let essid = list_store_get!(app_data.app_gui.aps_model, &last_iter, 0, String);
            app_data.app_gui.client_status_bar.pop(0);
            app_data
                .app_gui
                .client_status_bar
                .push(0, &format!("Showing '{essid}' clients"));

            update_buttons_sensitivity(&app_data);
        }
    ));
}

fn refresh_session_dashboard(app_data: &AppData) {
    let mut session = globals::CURRENT_SESSION.lock().unwrap();
    if session.status != aeroshield_common::types::SessionStatus::Active {
        return;
    }

    // Sync observations from local mirror
    let local_aps = backend::get_aps();
    let local_clients = backend::get_unlinked_clients();
    session.observations.access_points = local_aps.clone();
    session.observations.clients = local_clients.clone();

    // Drop lock briefly to log timeline and findings safely (since they lock CURRENT_SESSION themselves)
    drop(session);

    // Threat analysis & findings logic
    for (bssid, ap) in &local_aps {
        let privacy = ap.privacy.to_uppercase();
        if privacy.contains("WEP") {
            log_finding(
                "Encryption",
                aeroshield_common::types::Severity::Critical,
                &format!("WEP Protocol In Use: {}", ap.essid),
                &format!("The network {} ({}) utilizes WEP encryption, which is cryptographically vulnerable and trivially compromised.", ap.essid, bssid),
                bssid,
                "Upgrade security to WPA2/WPA3 and disable WEP support.",
                Vec::new(),
            );
        } else if privacy.contains("OPN") {
            log_finding(
                "Encryption",
                aeroshield_common::types::Severity::High,
                &format!("Open Unencrypted Network: {}", ap.essid),
                &format!("The network {} ({}) does not require any credentials (OPN). All wireless traffic is broadcast in the clear.", ap.essid, bssid),
                bssid,
                "Implement OWE (Opportunistic Wireless Encryption) or secure with WPA3-SAE.",
                Vec::new(),
            );
        }

        // Evidence capture mapping
        if ap.handshake {
            let already_exists = {
                let s = globals::CURRENT_SESSION.lock().unwrap();
                s.evidence.iter().any(|ev| ev.target_bssid == *bssid && ev.evidence_type == aeroshield_common::types::EvidenceType::Handshake)
            };
            if !already_exists {
                let evidence_id = add_session_evidence(
                    aeroshield_common::types::EvidenceType::Handshake,
                    bssid,
                    &ap.essid,
                    ap.saved_handshake.clone(),
                    "Captured WPA/WPA2 4-Way Handshake EAPOL packets."
                );
                log_timeline_event("Evidence", &format!("Authentication handshake captured for network {} ({}).", ap.essid, bssid));
                log_finding(
                    "Authentication",
                    aeroshield_common::types::Severity::Medium,
                    &format!("Captured Handshake: {}", ap.essid),
                    &format!("EAPOL handshake collected from {} ({}). This payload can be subject to offline dictionary cracking.", ap.essid, bssid),
                    bssid,
                    "Enforce complex passwords (high entropy) to defend against offline dictionary attacks.",
                    vec![evidence_id],
                );
            }
        }

        if ap.pmkid {
            let already_exists = {
                let s = globals::CURRENT_SESSION.lock().unwrap();
                s.evidence.iter().any(|ev| ev.target_bssid == *bssid && ev.evidence_type == aeroshield_common::types::EvidenceType::Pmkid)
            };
            if !already_exists {
                let evidence_id = add_session_evidence(
                    aeroshield_common::types::EvidenceType::Pmkid,
                    bssid,
                    &ap.essid,
                    None,
                    "Extracted RSN IE PMKID packet."
                );
                log_timeline_event("Evidence", &format!("Captured RSN IE PMKID for network {} ({}).", ap.essid, bssid));
                log_finding(
                    "Authentication",
                    aeroshield_common::types::Severity::Medium,
                    &format!("Captured PMKID: {}", ap.essid),
                    &format!("RSN IE PMKID frame collected from {} ({}). PMKID attacks allow offline recovery without active client stations.", ap.essid, bssid),
                    bssid,
                    "Enforce high-entropy WPA credentials and transition to WPA3 SAE.",
                    vec![evidence_id],
                );
            }
        }
    }

    // Re-lock to perform dashboard counts and list updates
    let session = globals::CURRENT_SESSION.lock().unwrap();
    let status_str = format!("{:?}", session.status).to_uppercase();
    app_data.app_gui.session_tab.status_label.set_text(&status_str);
    
    // Auto-update interface if empty
    if session.scope.interface != "None" {
        app_data.app_gui.session_tab.interface_label.set_text(&session.scope.interface);
    }

    let mut high = 0;
    let mut med = 0;
    let mut low = 0;
    for ap in session.observations.access_points.values() {
        let privacy = ap.privacy.to_uppercase();
        if privacy.contains("WEP") || privacy.contains("OPN") {
            high += 1;
        } else if privacy.contains("WPA3") {
            low += 1;
        } else {
            med += 1;
        }
    }
    app_data.app_gui.session_tab.risk_high_label.set_markup(&format!("<span foreground='red'>{}</span>", high));
    app_data.app_gui.session_tab.risk_med_label.set_markup(&format!("<span foreground='orange'>{}</span>", med));
    app_data.app_gui.session_tab.risk_low_label.set_markup(&format!("<span foreground='green'>{}</span>", low));

    let hs_count = session.evidence.iter().filter(|ev| ev.evidence_type == aeroshield_common::types::EvidenceType::Handshake).count();
    let pmkid_count = session.evidence.iter().filter(|ev| ev.evidence_type == aeroshield_common::types::EvidenceType::Pmkid).count();
    app_data.app_gui.session_tab.handshakes_label.set_text(&hs_count.to_string());
    app_data.app_gui.session_tab.pmkids_label.set_text(&pmkid_count.to_string());

    // Sync findings Table
    app_data.app_gui.session_tab.findings_store.clear();
    for f in &session.findings {
        app_data.app_gui.session_tab.findings_store.set(
            &app_data.app_gui.session_tab.findings_store.append(),
            &[
                (0, &format!("{:?}", f.severity).to_uppercase()),
                (1, &f.affected_target),
                (2, &f.title),
                (3, &f.description),
            ],
        );
    }

    // Sync timeline Table (Newest on top)
    app_data.app_gui.session_tab.timeline_store.clear();
    let mut sorted_timeline = session.timeline.clone();
    sorted_timeline.reverse();
    for t in &sorted_timeline {
        app_data.app_gui.session_tab.timeline_store.set(
            &app_data.app_gui.session_tab.timeline_store.append(),
            &[
                (0, &t.timestamp),
                (1, &t.event_type),
                (2, &t.description),
            ],
        );
    }
}

fn start_app_refresh(app_data: Rc<AppData>) {
    glib::timeout_add_local(
        Duration::from_millis(100),
        clone!(
            #[strong]
            app_data,
            move || {
                match app_data.app_gui.aps_view.selection().selected() {
                    Some((_, iter)) => {
                        let bssid = list_store_get!(app_data.app_gui.aps_model, &iter, 1, String);
                        let attack_pool = backend::get_attack_pool();

                        match attack_pool.contains_key(&bssid) {
                            true => {
                                app_data.app_gui.deauth_but.set_icon(globals::STOP_ICON);
                            }
                            false => {
                                app_data.app_gui.deauth_but.set_icon(globals::DEAUTH_ICON);
                            }
                        }

                        match backend::get_aps()[&bssid].handshake {
                            true => app_data.app_gui.capture_but.set_sensitive(true),
                            false => app_data.app_gui.capture_but.set_sensitive(false),
                        }
                    }
                    None => {
                        app_data.app_gui.deauth_but.set_icon(globals::DEAUTH_ICON);
                    }
                };

                let aps = backend::get_airodump_data();

                for (bssid, ap) in aps.iter() {
                    if !backend::get_settings().display_hidden_ap && ap.hidden {
                        if let Some(iter) =
                            list_store_find(app_data.app_gui.aps_model.as_ref(), 1, bssid.as_str())
                        {
                            app_data.app_gui.aps_model.remove(&iter);
                        }
                        continue;
                    }

                    let it = match list_store_find(
                        app_data.app_gui.aps_model.as_ref(),
                        1,
                        bssid.as_str(),
                    ) {
                        Some(it) => it,
                        None => app_data.app_gui.aps_model.append(),
                    };

                    let background_color = match backend::get_attack_pool().contains_key(bssid) {
                        true => gdk::RGBA::RED,
                        false => gdk::RGBA::new(0.0, 0.0, 0.0, 0.0),
                    };

                    app_data.app_gui.aps_model.set(
                        &it,
                        &[
                            (0, &ap.essid),
                            (1, &ap.bssid),
                            (2, &ap.band),
                            (3, &ap.channel.parse::<i32>().unwrap_or(-1)),
                            (4, &ap.power.parse::<i32>().unwrap_or(-1)),
                            (5, &ap.privacy),
                            (6, &(ap.clients.len() as i32)),
                            (7, &ap.first_time_seen),
                            (8, &ap.last_time_seen),
                            (9, &ap.handshake),
                            (10, &background_color.to_str()),
                        ],
                    );
                }

                if let Some((_, iter)) = app_data.app_gui.aps_view.selection().selected() {
                    let bssid = list_store_get!(app_data.app_gui.aps_model, &iter, 1, String);
                    let clients = &aps[&bssid].clients;

                    for cli in clients.values() {
                        let it = match list_store_find(
                            app_data.app_gui.cli_model.as_ref(),
                            0,
                            cli.mac.as_str(),
                        ) {
                            Some(it) => it,
                            None => app_data.app_gui.cli_model.append(),
                        };

                        let background_color = match backend::get_attack_pool().get(&bssid) {
                            Some(attack_state) => match &attack_state.target {
                                AttackTarget::All => gdk::RGBA::RED,
                                AttackTarget::Selection(selection) => {
                                    let mut color = gdk::RGBA::new(0.0, 0.0, 0.0, 0.0);

                                    for sel in selection.iter() {
                                        if sel == cli.mac.as_str() {
                                            color = gdk::RGBA::RED;
                                        }
                                    }
                                    color
                                }
                            },
                            None => gdk::RGBA::new(0.0, 0.0, 0.0, 0.0),
                        };

                        app_data.app_gui.cli_model.set(
                            &it,
                            &[
                                (0, &cli.mac),
                                (1, &cli.packets.parse::<i32>().unwrap_or(-1)),
                                (2, &cli.power.parse::<i32>().unwrap_or(-1)),
                                (3, &cli.first_time_seen),
                                (4, &cli.last_time_seen),
                                (5, &cli.vendor),
                                (6, &cli.probes),
                                (7, &background_color.to_str()),
                            ],
                        );

                        if app_data.deauth_gui.window.is_visible()
                            && list_store_find(
                                app_data.deauth_gui.store.as_ref(),
                                1,
                                cli.mac.as_str(),
                            )
                            .is_none()
                        {
                            app_data.deauth_gui.store.set(
                                &app_data.deauth_gui.store.append(),
                                &[(0, &false), (1, &cli.mac)],
                            );
                        }
                    }
                } else {
                    let clients = backend::get_unlinked_clients().clone();

                    for (_, cli) in clients {
                        let it = match list_store_find(
                            app_data.app_gui.cli_model.as_ref(),
                            0,
                            cli.mac.as_str(),
                        ) {
                            Some(it) => it,
                            None => app_data.app_gui.cli_model.append(),
                        };

                        app_data.app_gui.cli_model.set(
                            &it,
                            &[
                                (0, &cli.mac),
                                (1, &cli.packets.parse::<i32>().unwrap_or(-1)),
                                (2, &cli.power.parse::<i32>().unwrap_or(-1)),
                                (3, &cli.first_time_seen),
                                (4, &cli.last_time_seen),
                                (5, &cli.vendor),
                                (6, &cli.probes),
                                (7, &gdk::RGBA::new(0.0, 0.0, 0.0, 0.0).to_str()),
                            ],
                        );
                    }
                }

                if !backend::get_aps().is_empty() {
                    app_data.app_gui.export_but.set_sensitive(true);
                    app_data.app_gui.report_but.set_sensitive(true);
                }

                // Push current signal level to graph
                if let Some((_, iter)) = app_data.app_gui.aps_view.selection().selected() {
                    let bssid = list_store_get!(app_data.app_gui.aps_model, &iter, 1, String);
                    if let Some(ap) = aps.get(&bssid) {
                        if let Ok(power) = ap.power.parse::<i32>() {
                            app_data.app_gui.signal_graph.push_signal(power);
                        }
                    }
                } else {
                    app_data.app_gui.signal_graph.clear();
                }

                // Poll WPS status
                if let Ok((status, progress, logs, pin, psk)) = backend::get_wps_status() {
                    let wps_tab = &app_data.app_gui.wps_tab;
                    wps_tab.status_label.set_text(&status);
                    wps_tab.progress.set_text(Some(&progress));
                    if let Ok(fraction) = progress.replace("%", "").trim().parse::<f64>() {
                        wps_tab.progress.set_fraction(fraction / 100.0);
                    }
                    wps_tab.update_logs(&logs);
                    if let Some(p) = pin.clone() {
                        wps_tab.pin_label.set_text(&p);
                        
                        let already_exists = {
                            let s = globals::CURRENT_SESSION.lock().unwrap();
                            s.evidence.iter().any(|ev| ev.evidence_type == aeroshield_common::types::EvidenceType::WpsPinResponse && ev.details.contains(&p))
                        };
                        if !already_exists {
                            let evidence_id = add_session_evidence(
                                aeroshield_common::types::EvidenceType::WpsPinResponse,
                                "WPS Target",
                                "WPS Target",
                                None,
                                &format!("Recovered WPS PIN: {} (PSK: {:?})", p, psk),
                            );
                            log_timeline_event("WPS", &format!("WPS PIN cracked: {}.", p));
                            log_finding(
                                "WPS",
                                aeroshield_common::types::Severity::Critical,
                                "WPS PIN Recovered",
                                &format!("Exploitation of router WPS vulnerability successfully recovered PIN: {} and PSK: {:?}", p, psk),
                                "WPS Target",
                                "Disable WPS (Wi-Fi Protected Setup) in router administration panel.",
                                vec![evidence_id],
                            );
                        }
                    }
                    if let Some(s) = psk {
                        wps_tab.psk_label.set_text(&s);
                    }
                    if status == "RUNNING" {
                        wps_tab.set_running();
                    } else {
                        wps_tab.set_idle();
                    }
                }

                // Poll Evil Twin status
                if let Ok((active, _clients, credentials)) = backend::get_evil_twin_status() {
                    let et_tab = &app_data.app_gui.evil_twin_tab;
                    if active {
                        et_tab.set_running();
                    } else {
                        et_tab.set_idle();
                    }
                    
                    et_tab.creds_store.clear();
                    for cred in &credentials {
                        et_tab.creds_store.set(&et_tab.creds_store.append(), &[(0, cred)]);
                        
                        let already_exists = {
                            let s = globals::CURRENT_SESSION.lock().unwrap();
                            s.evidence.iter().any(|ev| ev.details.contains(cred))
                        };
                        if !already_exists {
                            let evidence_id = add_session_evidence(
                                aeroshield_common::types::EvidenceType::Handshake,
                                "Rogue AP",
                                "Evil Twin Portal",
                                None,
                                &format!("Credentials submitted: {}", cred),
                            );
                            log_timeline_event("Evil Twin", &format!("Twin portal captured credential: {}.", cred));
                            log_finding(
                                "Social Engineering",
                                aeroshield_common::types::Severity::Critical,
                                "Credential Exposed to Rogue Access Point",
                                &format!("Simulated security assessment portal collected authentication: {}", cred),
                                "Rogue Portal",
                                "Conduct training for users to inspect portal domain names, avoid untrusted HTTP pages, and leverage Enterprise WPA (802.1X).",
                                vec![evidence_id],
                            );
                        }
                    }
                }

                refresh_session_dashboard(&app_data);

                drive_channel_filter_from_attacks(&app_data);
                update_channel_status(&app_data);
                update_buttons_sensitivity(&app_data);

                ControlFlow::Continue
            }
        ),
    );

    glib::timeout_add_local(
        Duration::from_millis(1000),
        clone!(
            #[strong]
            app_data,
            move || {
                let mut updater = globals::UPDATE_PROC.lock().unwrap();

                if let Some(proc) = updater.as_mut()
                    && proc.is_finished()
                {
                    if updater.take().unwrap().join().unwrap_or(false) {
                        app_data.app_gui.update_button.show();
                    }
                    return ControlFlow::Break;
                }
                ControlFlow::Continue
            }
        ),
    );
}

fn start_update_checker() {
    globals::UPDATE_PROC
        .lock()
        .unwrap()
        .replace(std::thread::spawn(|| {
            let update = backend::check_update(globals::VERSION);

            match update {
                Some(update) => {
                    *globals::NEW_VERSION.lock().unwrap() = Some(update);
                    true
                }
                None => false,
            }
        }));
}

fn connect_deauth_button(app_data: Rc<AppData>) {
    app_data.app_gui.deauth_but.connect_clicked(clone!(
        #[strong]
        app_data,
        move |_| {
            let iter = match app_data.app_gui.aps_view.selection().selected() {
                Some((_, iter)) => iter,
                None => return,
            };

            let bssid = list_store_get!(app_data.app_gui.aps_model, &iter, 1, String);
            let under_attack = backend::get_attack_pool().contains_key(&bssid);

            match under_attack {
                true => backend::stop_deauth_attack(&bssid),
                false => app_data.deauth_gui.show(backend::get_aps()[&bssid].clone()),
            }
        }
    ));
}

fn connect_capture_button(app_data: Rc<AppData>) {
    app_data.app_gui.capture_but.connect_clicked(clone!(
        #[strong]
        app_data,
        move |_| {
            let iter = match app_data.app_gui.aps_view.selection().selected() {
                Some((_, iter)) => iter,
                None => return,
            };

            let essid = list_store_get!(app_data.app_gui.aps_model, &iter, 0, String);
            let bssid = list_store_get!(app_data.app_gui.aps_model, &iter, 1, String);

            let ap = match backend::get_aps().get(&bssid) {
                Some(ap) => ap.clone(),
                None => return,
            };

            if !ap.handshake {
                return;
            }

            if let Some(ref cap) = ap.saved_handshake {
                return app_data.decrypt_gui.show(Some((cap.clone(), bssid)));
            }

            let was_scanning = backend::is_scan_process();

            if was_scanning {
                app_data.app_gui.scan_but.emit_clicked();
            }

            let file_chooser_dialog = FileChooserDialog::new(
                Some("Save capture"),
                Some(&app_data.app_gui.window),
                FileChooserAction::Save,
                &[
                    ("Cancel", ResponseType::Cancel),
                    ("Save", ResponseType::Accept),
                ],
            );

            file_chooser_dialog.set_current_name(&format!("{essid}.cap"));
            file_chooser_dialog.run_async(clone!(
                #[strong]
                app_data,
                move |this, response| {
                    this.close();

                    if response == ResponseType::Accept {
                        let gio_file = match this.file() {
                            Some(file) => file,
                            None => return,
                        };
                        let path = gio_file.path().unwrap().to_str().unwrap().to_string();

                        if let Err(e) = backend::save_capture(&path) {
                            return ErrorDialog::spawn(
                                &app_data.app_gui.window,
                                "Save failed",
                                &e.to_string(),
                            );
                        }

                        backend::mark_handshakes_saved(&path);

                        app_data.decrypt_gui.show(Some((path, bssid)));
                    }

                    if was_scanning {
                        app_data.app_gui.scan_but.emit_clicked();
                    }
                }
            ));
        }
    ));
}

fn connect_wps_tab(app_data: Rc<AppData>) {
    app_data.app_gui.wps_tab.action_but.connect_clicked(clone!(
        #[strong]
        app_data,
        move |_| {
            let status = app_data.app_gui.wps_tab.status_label.text();
            if status == "RUNNING" {
                if let Err(e) = backend::stop_wps_audit() {
                    ErrorDialog::spawn(&app_data.app_gui.window, "Error", &e.to_string());
                }
            } else {
                let iter = match app_data.app_gui.aps_view.selection().selected() {
                    Some((_, iter)) => iter,
                    None => return,
                };
                let bssid = list_store_get!(app_data.app_gui.aps_model, &iter, 1, String);
                let channel = list_store_get!(app_data.app_gui.aps_model, &iter, 3, i32).to_string();
                let pixie = app_data.app_gui.wps_tab.pixie_check.is_active();
                let iface = match backend::get_iface() {
                    Some(iface) => iface,
                    None => return ErrorDialog::spawn(&app_data.app_gui.window, "Error", "No monitor interface enabled"),
                };
                if let Err(e) = backend::start_wps_audit(&iface, &bssid, &channel, pixie) {
                    ErrorDialog::spawn(&app_data.app_gui.window, "Error", &e.to_string());
                }
            }
        }
    ));
}

fn connect_evil_twin_tab(app_data: Rc<AppData>) {
    // Populate interface combobox with existing interfaces on connect
    if let Ok(interfaces) = backend::get_interfaces() {
        for iface in &interfaces {
            app_data.app_gui.evil_twin_tab.interface_combo.append_text(iface);
        }
        if !interfaces.is_empty() {
            app_data.app_gui.evil_twin_tab.interface_combo.set_active(Some(0));
        }
    }

    app_data.app_gui.evil_twin_tab.action_but.connect_clicked(clone!(
        #[strong]
        app_data,
        move |_| {
            let active = app_data.app_gui.evil_twin_tab.status_label.text() == "ACTIVE";
            if active {
                if let Err(e) = backend::stop_evil_twin() {
                    ErrorDialog::spawn(&app_data.app_gui.window, "Error", &e.to_string());
                }
            } else {
                let iface = match app_data.app_gui.evil_twin_tab.interface_combo.active_text() {
                    Some(text) => text.to_string(),
                    None => return ErrorDialog::spawn(&app_data.app_gui.window, "Error", "No interface selected"),
                };
                let essid = app_data.app_gui.evil_twin_tab.essid_entry.text().to_string();
                let channel = app_data.app_gui.evil_twin_tab.channel_entry.text().parse::<u32>().unwrap_or(6);
                let portal_ip = app_data.app_gui.evil_twin_tab.ip_entry.text().to_string();

                if let Err(e) = backend::start_evil_twin(&iface, &essid, channel, &portal_ip) {
                    ErrorDialog::spawn(&app_data.app_gui.window, "Error", &e.to_string());
                }
            }
        }
    ));
}

fn connect_session_tab(app_data: Rc<AppData>) {
    // Sync UI notes editor to model notes
    app_data.app_gui.session_tab.notes_buffer.connect_changed(clone!(
        #[strong]
        app_data,
        move |buf| {
            let (start, end) = buf.bounds();
            let text = buf.text(&start, &end, false).to_string();
            let mut session = globals::CURRENT_SESSION.lock().unwrap();
            session.scope.operator_notes = text;
        }
    ));

    // Sync environment dropdown
    app_data.app_gui.session_tab.environment_combo.connect_changed(clone!(
        #[strong]
        app_data,
        move |combo| {
            if let Some(text) = combo.active_text() {
                let mut session = globals::CURRENT_SESSION.lock().unwrap();
                session.scope.environment = text.to_string();
            }
        }
    ));

    // Sync target scope entry
    app_data.app_gui.session_tab.target_scope_entry.connect_changed(clone!(
        #[strong]
        app_data,
        move |entry| {
            let text = entry.text().to_string();
            let mut session = globals::CURRENT_SESSION.lock().unwrap();
            let targets: Vec<String> = text.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            let (bssids, ssids): (Vec<String>, Vec<String>) = targets.into_iter().partition(|t| t.contains(':'));
            session.scope.target_bssids = bssids;
            session.scope.target_ssids = ssids;
        }
    ));

    // Wire up Session status button
    app_data.app_gui.session_tab.action_but.connect_clicked(clone!(
        #[strong]
        app_data,
        move |but| {
            let mut session = globals::CURRENT_SESSION.lock().unwrap();
            match session.status {
                aeroshield_common::types::SessionStatus::New => {
                    session.status = aeroshield_common::types::SessionStatus::Active;
                    session.metadata.start_time = get_chrono_now();
                    but.set_label("Pause Session");
                    let notes_buf = &app_data.app_gui.session_tab.notes_buffer;
                    let (start, end) = notes_buf.bounds();
                    session.scope.operator_notes = notes_buf.text(&start, &end, false).to_string();
                    if let Some(text) = app_data.app_gui.session_tab.environment_combo.active_text() {
                        session.scope.environment = text.to_string();
                    }
                    drop(session);
                    log_timeline_event("Lifecycle", "Session status changed to ACTIVE.");
                }
                aeroshield_common::types::SessionStatus::Active => {
                    session.status = aeroshield_common::types::SessionStatus::Paused;
                    but.set_label("Resume Session");
                    drop(session);
                    log_timeline_event("Lifecycle", "Session status changed to PAUSED.");
                }
                aeroshield_common::types::SessionStatus::Paused => {
                    session.status = aeroshield_common::types::SessionStatus::Active;
                    but.set_label("Pause Session");
                    drop(session);
                    log_timeline_event("Lifecycle", "Session status changed to ACTIVE.");
                }
                _ => {}
            }
            let session = globals::CURRENT_SESSION.lock().unwrap();
            app_data.app_gui.session_tab.status_label.set_text(&format!("{:?}", session.status).to_uppercase());
        }
    ));
}

pub fn log_timeline_event(event_type: &str, description: &str) {
    let mut session = globals::CURRENT_SESSION.lock().unwrap();
    let timestamp = get_chrono_now();
    session.timeline.push(aeroshield_common::types::TimelineEvent {
        timestamp,
        event_type: event_type.to_string(),
        description: description.to_string(),
    });
}

pub fn log_finding(
    category: &str,
    severity: aeroshield_common::types::Severity,
    title: &str,
    description: &str,
    affected_target: &str,
    remediation: &str,
    evidence_ids: Vec<String>,
) {
    let mut session = globals::CURRENT_SESSION.lock().unwrap();
    let id = format!("finding_{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    
    if session.findings.iter().any(|f| f.affected_target == affected_target && f.category == category) {
        return;
    }
    
    session.findings.push(aeroshield_common::types::Finding {
        id,
        category: category.to_string(),
        severity,
        title: title.to_string(),
        description: description.to_string(),
        affected_target: affected_target.to_string(),
        evidence_ids,
        timestamp: get_chrono_now(),
        remediation: remediation.to_string(),
        references: vec!["NIST Wireless Security Guidelines".to_string()],
    });
}

pub fn add_session_evidence(
    evidence_type: aeroshield_common::types::EvidenceType,
    target_bssid: &str,
    target_essid: &str,
    file_path: Option<String>,
    details: &str,
) -> String {
    let mut session = globals::CURRENT_SESSION.lock().unwrap();
    let id = format!("evidence_{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    session.evidence.push(aeroshield_common::types::SessionEvidence {
        id: id.clone(),
        evidence_type,
        target_bssid: target_bssid.to_string(),
        target_essid: target_essid.to_string(),
        timestamp: get_chrono_now(),
        file_path,
        details: details.to_string(),
    });
    id
}

pub fn get_chrono_now() -> String {
    let local = chrono::Local::now();
    local.format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn connect(app: &Application, app_data: Rc<AppData>) {
    connect_window_controller(app_data.clone());

    connect_aps_controller(app, app_data.clone());
    connect_cli_controller(app, app_data.clone());

    connect_about_button(app_data.clone());
    connect_update_button(app_data.clone());
    connect_decrypt_button(app_data.clone());
    connect_settings_button(app_data.clone());

    connect_previous_button(app_data.clone());
    connect_next_button(app_data.clone());
    connect_top_button(app_data.clone());
    connect_bottom_button(app_data.clone());

    start_app_refresh(app_data.clone());

    start_update_checker();

    connect_hopping_button(app_data.clone());
    connect_focus_button(app_data.clone());
    connect_add_button(app_data.clone());

    connect_deauth_button(app_data.clone());
    connect_capture_button(app_data.clone());

    connect_wps_tab(app_data.clone());
    connect_evil_twin_tab(app_data.clone());
    connect_session_tab(app_data);
}

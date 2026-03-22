#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

extern crate nostr_vpn_gui_lib;

fn main() {
    nostr_vpn_gui_lib::run();
}

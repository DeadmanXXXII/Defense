//4. Rust with Suricata IDS
 - quick_switch_suricata.rs
rust
// Quick Switch v1
// Compatible with IDS: Suricata

use std::process::Command;

fn main() {
    println!("Executing IP configuration commands...");
    Command::new("ipconfig").arg("/release").status().expect("Failed to execute ipconfig /release");
    Command::new("ipconfig").arg("/release6").status().expect("Failed to execute ipconfig /release6");
    Command::new("ipconfig").arg("/renew").status().expect("Failed to execute ipconfig /renew");
    Command::new("ipconfig").arg("/renew6").status().expect("Failed to execute ipconfig /renew6");
    Command::new("ipconfig").arg("/flushdns").status().expect("Failed to execute ipconfig /flushdns");
    println!("Task completed successfully.");

    // Footer
    println!("Created by DeadmanXXXII");
}
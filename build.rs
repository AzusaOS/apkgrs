//! Bakes the build's date tag (`YYYYMMDDhhmmss`, UTC commit time) into the
//! binary, like the Go daemon's DATE_TAG. The self-updater compares it with
//! the version of `azusa.apkg.core`.
//!
//! Sources, in order: `APKG_DATE_TAG` in the environment, a `date_tag.txt`
//! file next to Cargo.toml (written by the release workflow, since the
//! fullrust build container does not see the runner's environment), else
//! `unknown` — which never self-updates.

fn main() {
    println!("cargo:rerun-if-env-changed=APKG_DATE_TAG");
    println!("cargo:rerun-if-changed=date_tag.txt");
    let tag = std::env::var("APKG_DATE_TAG")
        .ok()
        .or_else(|| std::fs::read_to_string("date_tag.txt").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| s.len() == 14 && s.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=APKG_DATE_TAG={tag}");
}

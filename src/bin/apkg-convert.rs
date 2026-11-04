//! `apkg-convert`: turn squashfs images into signed `.apkg` packages.
//!
//! ```text
//! HSM=yubihsm2 apkg-convert [-out <dir>] image.squashfs...
//! ```

use std::path::PathBuf;

use apkg::sign::{KeySource, PKG_KEY_LABEL};
use apkg::{convert, log, sig};

fn usage() -> ! {
    eprintln!(
        "usage: apkg-convert [options] <category.name.subcat.version.os.arch.squashfs>...\n\
         \n\
         Signs each image with the package key ({PKG_KEY_LABEL}) and writes\n\
         <out>/<category>/<name>/<subcat>/<full name>-<hash>.apkg\n\
         \n\
         options:\n  \
           -out <dir>          output directory (default: ~/projects/apkg-tools/repo/apkg/dist/main)\n  \
           -allow_untrusted    accept a signing key that clients do not trust (testing)\n\
         \n\
         Key: HSM=yubihsm2 (yubihsm-connector at $YUBIHSM_CONNECTOR, default\n\
         localhost:12345; passphrase from $YUBIHSM_PASSWORD or prompted), or\n\
         HSM=file:<ed25519 seed file> for tests."
    );
    std::process::exit(2)
}

fn main() {
    let mut out: Option<PathBuf> = None;
    let mut allow_untrusted = false;
    let mut files = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.trim_start_matches('-') {
            "out" if a.starts_with('-') => {
                out = Some(args.next().unwrap_or_else(|| usage()).into())
            }
            "allow_untrusted" if a.starts_with('-') => allow_untrusted = true,
            "h" | "help" if a.starts_with('-') => usage(),
            _ if a.starts_with('-') => usage(),
            _ => files.push(PathBuf::from(a)),
        }
    }
    if files.is_empty() {
        usage();
    }
    let out = out.unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("projects/apkg-tools/repo/apkg/dist/main")
    });

    let key = match KeySource::from_env().and_then(|s| s.key(PKG_KEY_LABEL)) {
        Ok(k) => k,
        Err(e) => {
            log!("failed to get signing key: {e}");
            std::process::exit(1);
        }
    };
    let kid = match key.key_id() {
        Ok(k) => k,
        Err(e) => {
            log!("failed to read public key: {e}");
            std::process::exit(1);
        }
    };
    log!("found key: {}", key.describe());
    log!("Public key: {kid}");
    if !sig::TRUSTED_PKG_KEYS.iter().any(|(k, _)| *k == kid) {
        if !allow_untrusted {
            log!("this key is not trusted by apkg clients; use -allow_untrusted for tests");
            std::process::exit(1);
        }
        log!("WARNING: signing with a key apkg clients do not trust");
    }

    let mut failed = false;
    for f in &files {
        match convert::convert(key.as_ref(), f, &out) {
            Ok(c) => log!("wrote {} ({})", c.path.display(), c.full_name),
            Err(e) => {
                log!("failed to process {}: {e}", f.display());
                failed = true;
            }
        }
    }
    std::process::exit(if failed { 1 } else { 0 })
}

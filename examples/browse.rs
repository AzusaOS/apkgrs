//! Browse a package from the live repository.
//!
//! ```text
//! cargo run --example browse -- <cache dir> <package name> [path]
//! ```
//!
//! Lists `path` (default `/`) if it is a directory, prints a symlink target,
//! or writes a regular file's contents to stdout.

use std::io::Write;

use apkg::{Config, Db, FileKind};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} <cache dir> <package> [path]", args[0]);
        std::process::exit(2);
    }
    let db = Db::open(Config::new("main", &args[1]))?;
    eprintln!("database version {}", db.version());
    let pkg = db.find(&args[2])?;
    eprintln!("package {} ({} bytes)", pkg.name(), pkg.size());
    let path = args.get(3).map(String::as_str).unwrap_or("/");
    let st = pkg.stat(path)?;
    match st.kind {
        FileKind::Dir => {
            for e in pkg.read_dir(path)? {
                let a = pkg.stat(&format!("{path}/{}", e.name))?;
                println!("{:o} {:>10} {}", a.mode(), a.size, e.name);
            }
        }
        FileKind::Symlink => println!("{}", pkg.read_link(path)?),
        _ => std::io::stdout().write_all(&pkg.read_file(path)?)?,
    }
    Ok(())
}

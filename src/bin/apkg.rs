//! `apkg` daemon: mounts the AzusaOS package database on `/pkg/<db>`
//! (or `~/pkg/<db>` for non-root users), keeps it updated, and answers on a
//! small HTTP control socket.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use apkg::fuse::{Mount, MountOptions, Server};
use apkg::{ArchOs, Config, Db, log, sys};

const UPDATE_INTERVAL: Duration = Duration::from_secs(3600);

struct Opts {
    db: String,
    data: Option<PathBuf>,
    base: Option<PathBuf>,
    prefix: Option<String>,
    threads: usize,
    ctrl: bool,
}

fn usage() -> ! {
    eprintln!(
        "usage: apkg [options]\n\
         \n\
         Mounts the AzusaOS package database and keeps it updated.\n\
         \n\
         options:\n  \
           -db <name>        database name (default: main)\n  \
           -data <dir>       data/cache directory (default: /var/lib/apkg, or ~/.cache/apkg)\n  \
           -base <dir>       mount base directory (default: /pkg, or ~/pkg)\n  \
           -prefix <url>     repository URL prefix (default: {})\n  \
           -threads <n>      FUSE worker threads (default: 8)\n  \
           -no_ctrl          do not open the control socket\n  \
           -version          print version and exit",
        apkg::db::DEFAULT_PREFIX
    );
    std::process::exit(2)
}

fn parse_args() -> Opts {
    let mut o = Opts {
        db: "main".into(),
        data: None,
        base: None,
        prefix: None,
        threads: 8,
        ctrl: true,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let flag = a.trim_start_matches('-');
        let (flag, inline) = match flag.split_once('=') {
            Some((f, v)) => (f.to_string(), Some(v.to_string())),
            None => (flag.to_string(), None),
        };
        let mut val = || {
            inline
                .clone()
                .or_else(|| args.next())
                .unwrap_or_else(|| usage())
        };
        match flag.as_str() {
            "db" => o.db = val(),
            "data" | "path" => o.data = Some(val().into()),
            "base" => o.base = Some(val().into()),
            "prefix" => o.prefix = Some(val()),
            "threads" => o.threads = val().parse().unwrap_or_else(|_| usage()),
            "no_ctrl" => o.ctrl = false,
            "load_unsigned" => {
                log!("apkg: -load_unsigned is not supported by this version, ignored")
            }
            "version" | "v" => {
                println!("apkg {}", apkg::VERSION);
                std::process::exit(0)
            }
            _ => usage(),
        }
    }
    o
}

/// Default data and mount locations, as the Go daemon chose them.
fn default_paths(root: bool) -> (PathBuf, PathBuf) {
    let mut data = PathBuf::from("/var/lib/apkg");
    let mut base = PathBuf::from("/pkg");
    if root {
        // a /mnt/<x>/AZUSA directory means we're on a live/installed media
        if let Ok(rd) = std::fs::read_dir("/mnt") {
            let mut names: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
            names.sort();
            for d in names {
                if d.join("AZUSA").is_dir() {
                    data = d.join("AZUSA/apkg");
                    break;
                }
            }
        }
    } else if let Some(h) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        let h = PathBuf::from(h);
        data = h.join(".cache/apkg");
        base = h.join("pkg");
    }
    (data, base)
}

/// Mounts the FUSE filesystem, optionally under an overlay when
/// `<base>/.<db>-rw` exists (root only).
struct Mounted {
    server: Arc<Server>,
    overlay: Option<PathBuf>,
}

fn mount(db: &Db, base: &Path, name: &str, root: bool) -> std::io::Result<Mounted> {
    let target = base.join(name);
    let rw = base.join(format!(".{name}-rw"));
    let mut fuse_point = target.clone();
    let mut overlay = None;
    if root && rw.is_dir() {
        let ro = base.join(format!(".{name}-ro"));
        let work = base.join(format!(".{name}-work"));
        if std::fs::create_dir_all(&ro).is_ok() && std::fs::create_dir_all(&work).is_ok() {
            fuse_point = ro;
            overlay = Some((rw, work));
        }
    }
    let m = Mount::new(&fuse_point, &MountOptions::default())?;
    let server = Server::new(db.clone(), m);
    let mut ov = None;
    if let Some((rw, work)) = overlay {
        std::fs::create_dir_all(&target)?;
        let data = format!(
            "lowerdir={},upperdir={},workdir={}",
            fuse_point.display(),
            rw.display(),
            work.display()
        );
        if let Err(e) = sys::mount(
            "overlay",
            &target.to_string_lossy(),
            "overlay",
            sys::MS_NOATIME,
            &data,
        ) {
            let _ = server.unmount();
            return Err(e);
        }
        ov = Some(target.clone());
    }
    log!("apkgfs: filesystem mounted on {}", target.display());
    Ok(Mounted {
        server,
        overlay: ov,
    })
}

fn main() {
    let opts = parse_args();
    log!("apkg: Starting apkg daemon version {}", apkg::VERSION);

    // Block the signals we handle before any thread exists, so every thread
    // inherits the mask and they are only delivered through the signalfd.
    let mut sigs = match sys::signalfd(&[sys::SIGINT, sys::SIGTERM, sys::SIGHUP]) {
        Ok(f) => Some(f),
        Err(e) => {
            log!("apkg: signal handling unavailable: {e}");
            None
        }
    };
    match sys::set_nofile_limit(65536) {
        Ok(n) if n < 65536 => log!("apkg: file descriptor limit is {n}"),
        Ok(_) => {}
        Err(e) => log!("apkg: failed to raise file descriptor limit: {e}"),
    }

    let root = sys::geteuid() == 0;
    let (data, base) = default_paths(root);
    let data = opts.data.clone().unwrap_or(data);
    let base = opts.base.clone().unwrap_or(base);

    let mut cfg = Config::new(&opts.db, &data);
    if let Some(p) = &opts.prefix {
        cfg.prefix = if p.ends_with('/') {
            p.clone()
        } else {
            format!("{p}/")
        };
    }
    let db = match Db::open(cfg) {
        Ok(db) => db,
        Err(e) => {
            log!("db: failed to load: {e}");
            std::process::exit(1);
        }
    };

    let mounted = match mount(&db, &base, &opts.db, root) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Mount fail: {e}");
            std::process::exit(1);
        }
    };

    let srv = mounted.server.clone();
    let threads = opts.threads;
    let serve = std::thread::Builder::new()
        .name("fuse".into())
        .spawn(move || srv.run(threads))
        .expect("spawn fuse");

    // periodic updates
    {
        let db = db.clone();
        std::thread::Builder::new()
            .name("updater".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(UPDATE_INTERVAL);
                    if let Err(e) = db.update() {
                        log!("apkgdb: update failed: {e}");
                    }
                }
            })
            .expect("spawn updater");
    }

    if opts.ctrl {
        listen_ctrl(db.clone(), if root { 100 } else { 10000 });
    }

    // main loop: signals
    match sigs.as_mut() {
        Some(f) => loop {
            match sys::read_signal(f) {
                Ok(sys::SIGHUP) => {
                    let db = db.clone();
                    std::thread::spawn(move || {
                        if let Err(e) = db.update() {
                            log!("apkgdb: update failed: {e}");
                        }
                    });
                }
                Ok(_) => break,
                Err(e) => {
                    log!("apkg: reading signals failed: {e}");
                    let _ = serve.join();
                    return;
                }
            }
        },
        None => {
            let _ = serve.join();
            return;
        }
    }

    log!("apkg: shutting down...");
    if let Some(ov) = &mounted.overlay
        && let Err(e) = sys::umount(&ov.to_string_lossy(), sys::MNT_DETACH)
    {
        log!("apkg: failed to unmount overlay: {e}");
    }
    if let Err(e) = mounted.server.unmount() {
        log!("apkg: failed to unmount: {e}");
    }
    // workers exit once the kernel drops the connection; don't hang on it
    std::thread::sleep(Duration::from_millis(200));
    std::process::exit(0);
}

// ---- control socket --------------------------------------------------------

fn listen_ctrl(db: Db, port: u16) {
    let tcp = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => {
            log!("ctrl: failed to create control socket on port {port}: {e}");
            return;
        }
    };
    log!("ctrl: control socket ready");
    {
        let db = db.clone();
        std::thread::Builder::new()
            .name("ctrl".into())
            .spawn(move || {
                for s in tcp.incoming().flatten() {
                    let db = db.clone();
                    std::thread::spawn(move || {
                        let _ = handle_http(&db, s);
                    });
                }
            })
            .expect("spawn ctrl");
    }
    match UdpSocket::bind(("0.0.0.0", port)) {
        Ok(u) => {
            std::thread::Builder::new()
                .name("ctrl-udp".into())
                .spawn(move || {
                    let mut buf = [0u8; 1500];
                    while let Ok((n, addr)) = u.recv_from(&mut buf) {
                        if &buf[..n] == b"DISCOVER" {
                            let _ = u.send_to(format!("tcp/{port}").as_bytes(), addr);
                        }
                    }
                })
                .expect("spawn ctrl-udp");
        }
        Err(e) => log!("ctrl: failed to create udp listener: {e}"),
    }
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (k == key).then_some(v)
    })
}

fn handle_http(db: &Db, s: TcpStream) -> std::io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut r = BufReader::new(s.try_clone()?);
    let mut line = String::new();
    r.read_line(&mut line)?;
    // drain headers
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
            break;
        }
    }
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or("/"));
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let (status, body) = if method != "GET" && method != "HEAD" {
        ("405 Method Not Allowed", "method not allowed\n".to_string())
    } else if path == "/" {
        (
            "200 OK",
            "apkg control channel\n\napkgdb: db related endpoints\n".to_string(),
        )
    } else if path == format!("/apkgdb/{}", db.name()) {
        db_status(db, query)
    } else {
        ("404 Not Found", "404 page not found\n".to_string())
    };
    let mut w = s;
    write!(
        w,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    if method != "HEAD" {
        w.write_all(body.as_bytes())?;
    }
    w.flush()
}

fn db_status(db: &Db, query: &str) -> (&'static str, String) {
    let sub = match query_param(query, "sub").filter(|s| !s.is_empty()) {
        Some(s) => match ArchOs::parse(s) {
            Some(ao) => match db.sub(ao) {
                Ok(sub) => sub,
                Err(e) => return ("500 Internal Server Error", format!("{e}\n")),
            },
            None => return ("400 Bad Request", "Bad value for sub\n".into()),
        },
        None => db.primary(),
    };
    if query_param(query, "action") == Some("list") {
        let mut out = String::new();
        for n in sub.list() {
            out.push_str(&n);
            out.push('\n');
        }
        return ("200 OK", out);
    }
    let ao = sub.archos();
    let mut out = format!(
        "APKGDB STATUS\n\nName: {}\nOS: {}\nArch: {}\nPrefix: {}\nVersion: {}\n",
        db.name(),
        ao.os,
        ao.arch,
        db.config().prefix,
        sub.version()
    );
    let subs: Vec<ArchOs> = db
        .subs()
        .into_iter()
        .filter(|s| *s != db.archos())
        .collect();
    if !subs.is_empty() {
        out.push_str("Sub databases:\n");
        for s in subs {
            out.push_str(&format!("  - {s}\n"));
        }
    }
    ("200 OK", out)
}

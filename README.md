# apkg

[![CI](https://github.com/AzusaOS/apkgrs/actions/workflows/ci.yml/badge.svg)](https://github.com/AzusaOS/apkgrs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/apkg.svg)](https://crates.io/crates/apkg)
[![docs.rs](https://img.shields.io/docsrs/apkg)](https://docs.rs/apkg)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

AzusaOS package manager, in Rust. A port of [apkg](https://github.com/AzusaOS/apkg) (Go).

It ships as two things:

* **A library** (crate `apkg`) that gives access to AzusaOS packages. It keeps a
  signature-verified local index of a package database, resolves package names
  (including "latest version" matching), and reads files out of packages. Packages
  are downloaded on demand, block by block.
* **The `apkg` daemon** (features `fuse` + `bin`). It mounts the database as
  `/pkg/main` through FUSE. This is the binary AzusaOS and its tooling use.

Everything is pure Rust with no C dependencies. The only dependencies are the
first-party [`rsurl`](https://crates.io/crates/rsurl) (HTTP/TLS),
[`purecrypto`](https://crates.io/crates/purecrypto) (sha256, ed25519) and
[`fstool`](https://crates.io/crates/fstool) (squashfs, with
[`compcol`](https://crates.io/crates/compcol) for decompression). The FUSE
server talks to `/dev/fuse` directly, without libfuse, using a handful of raw
syscalls. Release binaries are built for the libc-free
`x86_64-unknown-linux-fullrust` target, so they run on any Linux kernel with
nothing else installed.

## Using the daemon

```console
$ apkg                      # as root: mounts /pkg/main, data in /var/lib/apkg
$ apkg                      # as a user: mounts ~/pkg/main, data in ~/.cache/apkg
$ ~/pkg/main/dev-lang.python.core/bin/python3 --version
Python 3.12.8
```

Options:

| flag | default | meaning |
|------|---------|---------|
| `-db <name>` | `main` | database name |
| `-data <dir>` | `/var/lib/apkg` (root, or `/mnt/*/AZUSA/apkg` if present), `~/.cache/apkg` | index and package cache |
| `-base <dir>` | `/pkg`, `~/pkg` | mount base |
| `-prefix <url>` | `https://data.apkg.net/` | repository |
| `-threads <n>` | `8` | FUSE worker threads |
| `-no_ctrl` | | don't open the control socket |

Non-root mounts need `fusermount3` (or `fusermount`). As root, if
`<base>/.<db>-rw` exists, the package tree is mounted read-only on
`<base>/.<db>-ro`, and an overlayfs with that writable upper layer is mounted on
`<base>/<db>`.

`SIGHUP` triggers a database update. Updates also run every hour. `SIGINT`
and `SIGTERM` unmount and exit. The control socket listens on TCP and UDP port
100 (10000 for users). `GET /apkgdb/main` returns the status, `?action=list`
lists packages, and `?sub=linux.arm64` selects another platform. A UDP
`DISCOVER` datagram is answered with `tcp/<port>`.

### Filesystem layout

* `/pkg/main` itself cannot be listed. Looking up a name resolves a package:
  * an exact full name (`sys-libs.zlib.libs.1.3.1.linux.amd64`) is the package
    directory;
  * any prefix ending at a `.` boundary (`sys-libs.zlib.libs`, `…libs.1.3`) is a
    symlink to the latest matching version. Versions compare numerically.
* A `.os.arch` suffix (`….linux.arm64`) reaches another platform's database.
  That database is downloaded on first use.
* `/pkg/main/ld.so.cache` is the merged loader cache of every library package.

## Using the library

```toml
[dependencies]
apkg = "0.0"
```

```rust,no_run
use apkg::{Config, Db};

let db = Db::open(Config::new("main", "/tmp/apkg-cache"))?;
let zlib = db.find("sys-libs.zlib.libs")?;          // latest version
for e in zlib.read_dir("/lib64")? {
    println!("{} {:?}", e.name, e.kind);
}
let conf = zlib.read_file("/.ld.so.conf")?;
db.update()?;                                        // pull a newer database
# Ok::<(), apkg::Error>(())
```

See `examples/browse.rs`:

```console
$ cargo run --example browse -- /tmp/apkg-cache sys-libs.zlib.libs /lib64
```

## Security model

The repository is untrusted. Everything is verified before it is used:

1. `LATEST.jwt` is an EdDSA token signed by a trusted database key. It names
   the current database version.
2. The database file (`APDB`) carries a sha256 of its data and an ed25519
   signature of its header by a trusted database key.
3. Each package header is identified by its sha256, which is listed in the
   signed database, and is signed by a trusted package key. The header holds
   the sha256 of the package's hash table.
4. The hash table has one sha256 per data block. Every block is checked
   before it is served, whether it was just downloaded or read back from the
   local cache. A damaged or partial cache heals itself.

The Go implementation trusted the TLS channel for package data. This port
verifies each block itself, so it would stay safe even over plain HTTP.

## Building

```console
$ cargo build --release --features bin          # glibc/musl build
$ docker run --rm -v "$PWD":/src ghcr.io/karpeleslab/fullrust:latest \
      build --release --features bin             # static libc-free build
```

Minimum Rust version: 1.95 (edition 2024).

## Differences from the Go version

* The local index is a single signed-checksum file (`<db>.<os>.<arch>.apkgdb`),
  not a bolt database. Existing package caches under `<data>/<db>/` are reused
  as they are, and every block is re-verified on first access.
* Package blocks are verified against the hash table (a TODO in the Go code).
* `ld.so.cache` keeps one entry per (soname, flags) pair, so 32-bit and 64-bit
  libraries with the same soname coexist. The Go version kept one per soname.
* Not ported yet: `-load_unsigned` (loading unsigned local squashfs images),
  the in-place self-updater, and the `apkg-index`/`apkg-convert` repository
  tools.

## License

MIT

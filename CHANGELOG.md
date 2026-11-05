# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.2](https://github.com/AzusaOS/apkgrs/compare/v0.0.1...v0.0.2) - 2026-11-05

### Other

- never lose a request across graceful restart
- VM integration tests: AzusaOS kernel in QEMU against the live repository
- cache eviction under Unreleased
- Add Db::clean_cache and -cache_days to evict unused cached packages

### Fixed

- Graceful restart could lose a FUSE request read just before the
  handover, hanging the caller forever; workers now read under the gate.
  The inode state is also saved after in-flight requests are drained.

### Added

- Cache eviction: `Db::clean_cache(max_age)` deletes cached package files
  unused for `max_age`; the daemon runs it hourly and on `SIGHUP` with
  `-cache_days <n>` (fractions allowed).
- VM integration tests (`tests/vm/run.sh`): an AzusaOS kernel in QEMU runs
  the static daemon against the live repository, in CI too.

## [0.0.1](https://github.com/AzusaOS/apkgrs/compare/v0.0.0...v0.0.1) - 2026-11-04

### Other

- Add apkg-convert and apkg-index repository tools
- skip the page-cache store notification for empty data
- Port upstream apkg changes: release channels, graceful restart, self-update
- crates.io, docs.rs and license badges
- adaptive read-ahead in bytes, doubling on sequential misses

### Added

- Release channels with server-distributed version pins (`-channel`,
  `Config::channel`, `Db::set_channel`), as in apkg (Go) since 2026-03.
- Graceful restart on `SIGUSR2`: the new process inherits the FUSE
  connection and the inode allocation, so the mount survives.
- Self-updater from `azusa.apkg.core`, restricted to compatible builds.
- Repository tools (`tools` feature): `apkg-convert` and `apkg-index`
  binaries, ed25519 signing through a YubiHSM 2 (pure-Rust SCP03 client) or
  a seed file, pin management in `apkg-index`.
- Rust port of apkg: signed database sync (JWT + APDB), package lookup with
  version collation, on-demand block-verified package fetching, squashfs access
  through fstool.
- Pure-Rust FUSE server (`fuse` feature) and the `apkg` daemon (`bin` feature).

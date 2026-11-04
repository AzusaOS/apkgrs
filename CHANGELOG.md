# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Rust port of apkg: signed database sync (JWT + APDB), package lookup with
  version collation, on-demand block-verified package fetching, squashfs access
  through fstool.
- Pure-Rust FUSE server (`fuse` feature) and the `apkg` daemon (`bin` feature).

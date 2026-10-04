If a push is requested, only push to `origin`. Never push to a mirror remote unless the user explicitly overrides this rule.

Do NOT update the README unless explicitly requested.

# Development workflow

Run from the repository root with the stable toolchain. Update
`Cargo.toml` and `Cargo.lock` together. After Rust changes, run these
checks in order:

```sh
cargo fmt --all
cargo check --locked --all-targets
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Repeat check, test, and clippy with `--no-default-features`; the crate
must build without `alloc`. After changes to `unsafe` code, also run
`scripts/test-miri`, which needs nightly with Miri.

Repeat test and clippy with `--target i686-unknown-linux-musl`, with and
without `--no-default-features`, to cover 32-bit `usize` arithmetic. Some
tests compile only for 32-bit targets. Install the target once with
`rustup target add i686-unknown-linux-musl`.

Every Rust source and test starts with:

```rust
// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
```

Use Conventional Commits: `<type>[optional scope][!]: <summary>`. Write an
imperative subject of at most 50 characters, with no trailing period. Follow
it with one blank line and a single short paragraph explaining what changed
and why in plain language. Limit the body to four lines, each at most 72
characters; avoid lists and exhaustive change logs.

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! # b2t-codecs
//!
//! Freestanding binary-to-text codecs for Base16, Base32, Base64, and Base85.
//!
//! The `alloc` feature is enabled by default. To use only allocation-free APIs,
//! disable default features in your `Cargo.toml`:
//!
//! ```yaml
//! [dependencies]
//! b2t-codecs = { version = "2", default-features = false }
//! ```
//!
//! ## Quick Start
//!
//! ```rust
//! use b2t_codecs::{try_decode_from_base16, try_encode_into_base16};
//!
//! let mut encoded = [0; 28];
//! let mut decoded = [0; 14];
//! let encoded = try_encode_into_base16(b"Rust is great!", &mut encoded).unwrap();
//! let decoded = try_decode_from_base16(encoded, &mut decoded);
//!
//! assert_eq!(encoded, b"5275737420697320677265617421");
//! assert_eq!(decoded, Some(b"Rust is great!".as_slice()));
//! ```
//!
//! ## Todo
//!
//! - [x] No-alloc API for Base16, v2.0
//! - [ ] No-alloc API for Base32, v2.1
//! - [ ] No-alloc API for Base64, v2.2
//! - [ ] No-alloc API for Base85, v2.3
//!
//! ## Codecs
//!
//! ### Which do I Choose?
//!
//! Choose based on where the encoded string will live:
//!
//! - For easy inspection or transcription, use Base16 or Base32.
//! - For broadly interoperable binary text, use Base64.
//! - For URL tokens and filenames, use Base64URL.
//! - For denser JSON, YAML, or TOML strings, use Z85.
//!
//! | Codec | Size | Padding | URL | JSON | XML | YAML | TOML | HTML |
//! |---|---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
//! | [`Base16`](base16) | 2.00× | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
//! | [`Base32`](base32) | 1.60× | ✅ | ✅* | ✅ | ✅ | ✅ | ✅ | ✅ |
//! | [`Base32Hex`](base32) | 1.60× | ✅ | ✅* | ✅ | ✅ | ✅ | ✅ | ✅ |
//! | [`Base64`](base64) | 1.33× | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
//! | [`Base64URL`](base64) | 1.33× | ✅ | ✅* | ✅ | ✅ | ✅ | ✅ | ✅ |
//! | [`Ascii85`](base85) | 1.25× | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
//! | [`Adobe85`](base85) | ~1.25× | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
//! | [`Z85`](base85) | 1.25× | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ |
//!
//! - Padding: ✅ accepts arbitrary byte lengths; ❌ requires aligned input.
//! - URL through HTML: ✅ every alphabet character can be embedded without
//!   escaping; ❌ at least one alphabet character must be escaped.
//!
//! JSON, YAML, and TOML assume double-quoted strings. XML and HTML cover text
//! content and quoted attribute values. Sizes compare complete encoding quanta.
//! Padding indicates whether arbitrary byte lengths are accepted: Base16 needs
//! no padding symbols, Base32 and Base64 pad partial tails, Adobe85 uses
//! implicit tail padding, and strict Ascii85 and Z85 require four-byte input
//! alignment.
//!
//! Adobe85 APIs use raw payloads. Encoders omit the traditional `<~` and `~>`
//! delimiters, while decoders ignore ASCII whitespace within payloads.
//!
//! \* Canonical Base32, Base32Hex, and Base64URL output includes reserved `=`
//! padding. Remove it to make the output URL-safe as-is, or percent-encode it
//! with the rest of the URL component.
//!
//! ## License
//!
//! Licensed under the GNU Affero General Public License, version 3 only
//! (`AGPL-3.0-only`).

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod codecs;

pub use codecs::base16;
pub use codecs::base16::{
    Base16, decoded_length_base16, encoded_length_base16, try_decode_from_base16,
    try_decode_from_base16lower, try_decode_from_base16upper, try_encode_into_base16,
    try_encode_into_base16upper,
};
#[cfg(feature = "alloc")]
pub use codecs::base16::{
    encode_base16, encode_base16_string, encode_base16upper, encode_base16upper_string,
    try_decode_base16, try_decode_base16_string, try_decode_base16lower,
    try_decode_base16lower_string, try_decode_base16upper, try_decode_base16upper_string,
};
#[cfg(feature = "alloc")]
pub use codecs::base32;
#[cfg(feature = "alloc")]
pub use codecs::base32::{
    Base32, Base32Hex, encode_base32, encode_base32_string, encode_base32hex,
    encode_base32hex_string, try_decode_base32, try_decode_base32_string, try_decode_base32hex,
    try_decode_base32hex_string,
};
#[cfg(feature = "alloc")]
pub use codecs::base64;
#[cfg(feature = "alloc")]
pub use codecs::base64::{
    Base64, Base64Url, encode_base64, encode_base64_string, encode_base64url,
    encode_base64url_string, trim_base64_end_padding, try_decode_base64, try_decode_base64_string,
    try_decode_base64ext, try_decode_base64ext_string, try_decode_base64url,
    try_decode_base64url_string, try_decode_base64urlext, try_decode_base64urlext_string,
};
#[cfg(feature = "alloc")]
pub use codecs::base85;
#[cfg(feature = "alloc")]
pub use codecs::base85::{
    Adobe85, Base85, Z85, encode_adobe85, encode_adobe85_string, try_decode_adobe85,
    try_decode_adobe85_string, try_decode_ascii85, try_decode_ascii85_string, try_decode_z85,
    try_decode_z85_string, try_encode_ascii85, try_encode_ascii85_string, try_encode_z85,
    try_encode_z85_string,
};

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! # b2t-codecs
//!
//! Binary-to-text codecs for Base16, Base32, Base64, Ascii85, Adobe85, and Z85.
//!
//! The crate provides slice-based encoding and decoding functions as well as
//! sealed conversion traits for fixed-width integer values. Encoders produce
//! ASCII as either [`String`] or boxed byte slices, and fallible decoders return
//! [`None`] for malformed or non-canonical input.
//!
//! ## Quick Start
//!
//! ```rust
//! use b2t_codecs::{encode_base64_string, try_decode_base64_string};
//!
//! let encoded = encode_base64_string(b"Rust is great!");
//! assert_eq!(encoded, "UnVzdCBpcyBncmVhdCE=");
//!
//! let decoded = &*try_decode_base64_string(&encoded).unwrap();
//! assert_eq!(decoded, b"Rust is great!");
//! ```
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
mod codecs;

pub use codecs::base16;
pub use codecs::base16::{
    Base16, encode_base16, encode_base16_string, encode_base16upper, encode_base16upper_string,
    try_decode_base16, try_decode_base16_string, try_decode_base16lower,
    try_decode_base16lower_string, try_decode_base16upper, try_decode_base16upper_string,
};
pub use codecs::base32;
pub use codecs::base32::{
    Base32, Base32Hex, encode_base32, encode_base32_string, encode_base32hex,
    encode_base32hex_string, try_decode_base32, try_decode_base32_string, try_decode_base32hex,
    try_decode_base32hex_string,
};
pub use codecs::base64;
pub use codecs::base64::{
    Base64, Base64Url, encode_base64, encode_base64_string, encode_base64url,
    encode_base64url_string, trim_base64_end_padding, try_decode_base64, try_decode_base64_string,
    try_decode_base64ext, try_decode_base64ext_string, try_decode_base64url,
    try_decode_base64url_string, try_decode_base64urlext, try_decode_base64urlext_string,
};
pub use codecs::base85;
pub use codecs::base85::{
    Adobe85, Base85, Z85, encode_adobe85, encode_adobe85_string, try_decode_adobe85,
    try_decode_adobe85_string, try_decode_ascii85, try_decode_ascii85_string, try_decode_z85,
    try_decode_z85_string, try_encode_ascii85, try_encode_ascii85_string, try_encode_z85,
    try_encode_z85_string,
};

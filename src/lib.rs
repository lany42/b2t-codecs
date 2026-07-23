// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! # b2t-codecs
//!
//! Binary-to-text codecs for Base16, Base32, Base64, ASCII85, Adobe85, and Z85.
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
//! let encoded = encode_base64_string(b"Rust");
//! assert_eq!(encoded, "UnVzdA==");
//! assert_eq!(
//!     try_decode_base64_string(&encoded).as_deref(),
//!     Some(b"Rust".as_slice()),
//! );
//! ```
//!
//! ## Available Codecs
//!
//! - [`base16`] supports lowercase and uppercase encoding plus case-selective
//!   decoding.
//! - [`base32`] supports canonical padded Base32 and Base32Hex.
//! - [`base64`] supports canonical Base64 and Base64URL, with extended decoders
//!   for unpadded or concatenated data.
//! - [`base85`] supports strict ASCII85 and Z85 framing plus Adobe85 tails and
//!   zero compression.
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

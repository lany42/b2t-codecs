// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Implementations of the crate's supported binary-to-text codecs.
//!
//! Each child module exposes free functions for byte slices and sealed traits
//! for converting fixed-width integers through their big-endian byte
//! representation.
//!
//! ```rust
//! use b2t_codecs::{encode_base16_string, try_decode_base16_string};
//!
//! let encoded = encode_base16_string(b"codec");
//! assert_eq!(encoded, "636f646563");
//! assert_eq!(
//!     try_decode_base16_string(&encoded).as_deref(),
//!     Some(b"codec".as_slice()),
//! );
//! ```
pub mod base16;
pub mod base32;
pub mod base64;
pub mod base85;

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Implementations of the crate's supported binary-to-text codecs.
//!
//! Each child module exposes free functions for byte slices and sealed traits
//! for converting fixed-width integers through their big-endian byte
//! representation.
//!
//! ```rust
//! use b2t_codecs::{try_decode_from_base16, try_encode_into_base16};
//!
//! let mut encoded = [0; 10];
//! let mut decoded = [0; 5];
//! let encoded = try_encode_into_base16(b"codec", &mut encoded).unwrap();
//! let decoded = try_decode_from_base16(encoded, &mut decoded);
//!
//! assert_eq!(encoded, b"636f646563");
//! assert_eq!(decoded, Some(b"codec".as_slice()));
//! ```
pub mod base16;
pub mod base32;
#[cfg(feature = "alloc")]
pub mod base64;
#[cfg(feature = "alloc")]
pub mod base85;

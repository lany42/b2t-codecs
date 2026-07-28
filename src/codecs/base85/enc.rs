// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Encoders for strict Ascii85, Adobe85, and ZeroMQ Z85.
//!
//! Strict Ascii85 and Z85 require complete four-byte input quanta. Adobe85
//! accepts partial final quanta and compresses each full all-zero quantum as
//! `z`. Adobe85 encoders emit raw payloads without the traditional `<~` and
//! `~>` delimiters.
//!
//! ```rust
//! use b2t_codecs::base85::{encode_adobe85_string, try_encode_z85_string};
//!
//! assert_eq!(encode_adobe85_string(&[0, 0, 0, 0]), "z");
//! assert_eq!(
//!     try_encode_z85_string(&[0x86, 0x4f, 0xd2, 0x6f]).as_deref(),
//!     Some("Hello"),
//! );
//! ```
const ASCII85: Encoder = const {
    use super::ENCODER_ASCII85;
    Encoder::from_alphabet(&ENCODER_ASCII85)
};
const Z85: Encoder = const {
    use super::ENCODER_Z85;
    Encoder::from_alphabet(&ENCODER_Z85)
};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String, vec::Vec};

/// Encodes `bytes` as a raw Adobe85 string.
///
/// Full zero quanta are compressed as `z`, and a final partial quantum uses
/// implicit padding. The output does not include the traditional `<~` and `~>`
/// delimiters.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_adobe85_string(bytes: &[u8]) -> String {
    ASCII85.encode_base85ext_string(bytes, super::ADOBE85_ZEROS)
}

/// Encodes `bytes` as raw Adobe85 ASCII bytes.
///
/// Full zero quanta are compressed as `z`, and a final partial quantum uses
/// implicit padding. The output does not include the traditional `<~` and `~>`
/// delimiters.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_adobe85(bytes: &[u8]) -> Box<[u8]> {
    ASCII85.encode_base85ext(bytes, super::ADOBE85_ZEROS)
}

/// Encodes complete four-byte quanta as a strict Ascii85 string.
///
/// Returns [`None`] if `bytes.len()` is not divisible by four or the encoded
/// length cannot be represented as a [`usize`].
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_ascii85_string(bytes: &[u8]) -> Option<String> {
    ASCII85.try_encode_base85_string(bytes)
}

/// Encodes complete four-byte quanta as strict Ascii85 bytes.
///
/// Returns [`None`] if `bytes.len()` is not divisible by four or the encoded
/// length cannot be represented as a [`usize`].
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_ascii85(bytes: &[u8]) -> Option<Box<[u8]>> {
    ASCII85.try_encode_base85(bytes)
}

/// Encodes complete four-byte quanta as a ZeroMQ Z85 string.
///
/// Returns [`None`] if `bytes.len()` is not divisible by four or the encoded
/// length cannot be represented as a [`usize`].
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_z85_string(bytes: &[u8]) -> Option<String> {
    Z85.try_encode_base85_string(bytes)
}

/// Encodes complete four-byte quanta as ZeroMQ Z85 bytes.
///
/// Returns [`None`] if `bytes.len()` is not divisible by four or the encoded
/// length cannot be represented as a [`usize`].
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_z85(bytes: &[u8]) -> Option<Box<[u8]>> {
    Z85.try_encode_base85(bytes)
}

struct Encoder<'e> {
    encoder: &'e [u8],
}

impl<'e> Encoder<'e> {
    #[inline]
    const fn from_alphabet(encoder: &'e [u8]) -> Self {
        // INVARIANT: encoder table MUST be exactly 85
        assert!(encoder.len() == 85);
        assert!(84 < encoder.len());
        Self { encoder }
    }

    #[inline]
    fn try_encode_base85_string(&self, bytes: &[u8]) -> Option<String> {
        let encoded = self.try_encode_base85(bytes)?;
        // SAFETY: base85 bytes are ASCII, therefore always valid UTF-8
        unsafe { Some(String::from_utf8_unchecked(encoded.into_vec())) }
    }

    #[inline]
    fn encode_base85ext_string(&self, bytes: &[u8], zeros_byte: u8) -> String {
        let encoded = self.encode_base85ext(bytes, zeros_byte);
        // SAFETY: base85 bytes are ASCII, therefore always valid UTF-8
        unsafe { String::from_utf8_unchecked(encoded.into_vec()) }
    }

    fn try_encode_base85(&self, bytes: &[u8]) -> Option<Box<[u8]>> {
        if bytes.is_empty() {
            return Some(Vec::<u8>::new().into_boxed_slice());
        }

        // INVARIANT: strict base85 does not handle padding automatically
        // "The binary frame SHALL have a length that is divisible by 4 with no remainder."
        if !bytes.len().is_multiple_of(4) {
            return None;
        }

        // INVARIANT: base85 encodes five ASCII bytes per four input bytes
        // "The string frame SHALL have a length that is divisible by 5 with no remainder."
        let capacity = bytes.len().checked_mul(5)? / 4;
        let mut ret = Vec::<u8>::with_capacity(capacity);
        let (chunks, []) = bytes.as_chunks::<4>() else {
            unreachable!("bytes slice always a multiple of 4")
        };

        // "To encode a frame, an implementation SHALL take four octets at a time from
        // the binary frame and convert them into five printable characters"
        for &chunk in chunks {
            ret.extend_from_slice(&self.encode_base85_chunk(chunk));
        }

        Some(ret.into_boxed_slice())
    }

    fn encode_base85ext(&self, bytes: &[u8], zeros_byte: u8) -> Box<[u8]> {
        if bytes.is_empty() {
            return Vec::<u8>::new().into_boxed_slice();
        }

        // base85ext encodes five bytes per full chunk and at most four bytes for a tail.
        let capacity = bytes
            .len()
            .checked_mul(5)
            .expect("base85 encoded length overflow")
            / 4
            + 4;

        let mut ret = Vec::<u8>::with_capacity(capacity);
        let (chunks, remainder) = bytes.as_chunks::<4>();

        for &chunk in chunks {
            if chunk == [0; 4] {
                ret.push(zeros_byte);
            } else {
                ret.extend_from_slice(&self.encode_base85_chunk(chunk));
            }
        }

        if !remainder.is_empty() {
            self.encode_base85_implicit_tail(remainder, &mut ret);
        }

        ret.into_boxed_slice()
    }

    fn encode_base85_chunk(&self, chunk: [u8; 4]) -> [u8; 5] {
        let mut buf = [0u8; 5];

        // "The four octets SHALL be treated as an
        // unsigned 32-bit integer in network byte order (big endian)."
        let n = u32::from_be_bytes(chunk);

        // "The five characters SHALL be output from most significant to least significant (big endian)."
        let mut d = 85u32.pow(4);
        for b in &mut buf {
            let i = ((n / d) % 85) as usize;

            // SAFETY: mod 85 gaurentees safe encoder indexing
            *b = unsafe { *self.encoder.get_unchecked(i) };
            d /= 85;
        }

        buf
    }

    #[inline]
    fn encode_base85_implicit_tail(&self, tail: &[u8], ret: &mut Vec<u8>) {
        // must be 1, 2, or 3
        let len = tail.len();

        // pad with 0 bytes
        let mut padded = [0; 4];
        padded[..len].copy_from_slice(tail);

        // the number of padding null bytes added are equal to the amount
        // of bytes stripped from the encoded chunk (length 5)
        //      - 1 byte  => 3 '0' bytes => 2 bytes output
        //      - 2 bytes => 2 '0' bytes => 3 bytes output
        //      - 3 bytes => 1 '0' byte  => 4 bytes output
        //
        // that is, bytes kept: remainder.len() + 1
        let encoded = self.encode_base85_chunk(padded);
        ret.extend_from_slice(&encoded[..=len]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Encode = fn(&[u8]) -> Option<Box<[u8]>>;

    #[test]
    fn z85_known_vector_encodes_through_byte_and_string_apis() {
        let input = [0x86u8, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b];
        let expected = b"HelloWorld";

        assert_eq!(&*try_encode_z85(&input).unwrap(), expected);
        assert_eq!(try_encode_z85_string(&input).as_deref(), Some("HelloWorld"));
    }

    #[test]
    fn ascii85_known_vector_encodes_through_byte_and_string_apis() {
        let input = [0x86u8, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b];
        let expected = b"L/669[9<6.";

        assert_eq!(&*try_encode_ascii85(&input).unwrap(), expected);
        assert_eq!(
            try_encode_ascii85_string(&input).as_deref(),
            Some("L/669[9<6.")
        );
    }

    #[test]
    fn empty_input_encodes() {
        assert_eq!(try_encode_ascii85(b"").as_deref(), Some(b"".as_slice()));
        assert_eq!(try_encode_ascii85_string(b"").as_deref(), Some(""));
        assert_eq!(try_encode_z85(b"").as_deref(), Some(b"".as_slice()));
        assert_eq!(try_encode_z85_string(b"").as_deref(), Some(""));
    }

    #[test]
    fn encoders_select_the_requested_alphabet() {
        assert_eq!(
            try_encode_ascii85(&[0; 4]).as_deref(),
            Some(b"!!!!!".as_slice())
        );
        assert_eq!(
            try_encode_z85(&[0; 4]).as_deref(),
            Some(b"00000".as_slice())
        );
    }

    #[test]
    fn encoder_alphabets_preserve_unsafe_indexing_and_utf8_invariants() {
        fn assert_invariants(name: &str, encoder: &Encoder<'_>) {
            assert_eq!(encoder.encoder.len(), 85);

            let mut seen = [false; 128];
            for &ascii in encoder.encoder {
                assert!(ascii.is_ascii());
                assert!(
                    !seen[ascii as usize],
                    "duplicate {name} byte at ASCII {ascii}"
                );
                seen[ascii as usize] = true;
            }
        }

        assert_invariants("ASCII85", &ASCII85);
        assert_invariants("Z85", &Z85);
    }

    #[test]
    fn encode_rejects_unpadded_lengths() {
        let encoders: &[(&str, Encode)] =
            &[("ASCII85", try_encode_ascii85), ("Z85", try_encode_z85)];

        for len in [1, 2, 3, 5, 6, 7] {
            let input = alloc::vec![0u8; len];
            for &(name, encode) in encoders {
                assert_eq!(encode(&input), None, "{name} accepted {len} bytes");
            }
        }
    }

    #[test]
    fn adobe85_known_vector_encodes_through_byte_and_string_apis() {
        let input = [0x86u8, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b];
        let expected = b"L/669[9<6.";

        assert_eq!(&*encode_adobe85(&input), expected);
        assert_eq!(encode_adobe85_string(&input), "L/669[9<6.");
    }

    #[test]
    fn adobe85_empty_input_encodes() {
        assert_eq!(&*encode_adobe85(b""), b"");
        assert_eq!(encode_adobe85_string(b""), "");
    }

    #[test]
    fn adobe85_encode_handles_tail_chunks() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"M", b"9`"),
            (b"Ma", b"9jn"),
            (b"Man", b"9jqo"),
            (b"Man s", b"9jqo^Er"),
        ];

        for &(input, expected) in cases {
            assert_eq!(encode_adobe85(input).as_ref(), expected);
        }
    }

    #[test]
    fn adobe85_encode_compresses_full_zero_chunks_but_not_zero_tails() {
        let cases: &[(&[u8], &[u8])] = &[
            (&[0], b"!!"),
            (&[0, 0], b"!!!"),
            (&[0, 0, 0], b"!!!!"),
            (&[0, 0, 0, 0], b"z"),
            (&[0, 0, 0, 1], b"!!!!\""),
        ];

        for &(input, expected) in cases {
            assert_eq!(encode_adobe85(input).as_ref(), expected);
        }
    }
}

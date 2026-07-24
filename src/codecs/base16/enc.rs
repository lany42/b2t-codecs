// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Base16 encoders for lowercase and uppercase ASCII output.
//!
//! Each input byte is represented by exactly two hexadecimal symbols.
//!
//! ```rust
//! use b2t_codecs::base16::{encode_base16_string, encode_base16upper_string};
//!
//! assert_eq!(encode_base16_string(&[0xab, 0xcd]), "abcd");
//! assert_eq!(encode_base16upper_string(&[0xab, 0xcd]), "ABCD");
//! ```

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String, vec::Vec};

const BASE16_LOWER: Encoder = const {
    use super::ENCODER_LOWER;
    Encoder::from_alphabet(&ENCODER_LOWER)
};
const BASE16_UPPER: Encoder = const {
    use super::ENCODER_UPPER;
    Encoder::from_alphabet(&ENCODER_UPPER)
};

/// Encodes `bytes` as a lowercase Base16 string.
///
/// The output contains exactly two ASCII symbols per input byte.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base16_string(bytes: &[u8]) -> String {
    BASE16_LOWER.encode_base16_string(bytes)
}

/// Encodes `bytes` as an uppercase Base16 string.
///
/// The output contains exactly two ASCII symbols per input byte.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base16upper_string(bytes: &[u8]) -> String {
    BASE16_UPPER.encode_base16_string(bytes)
}

/// Encodes `bytes` as lowercase Base16 ASCII bytes.
///
/// The output contains exactly two ASCII symbols per input byte.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base16(bytes: &[u8]) -> Box<[u8]> {
    BASE16_LOWER.encode_base16(bytes)
}

/// Encodes `bytes` as uppercase Base16 ASCII bytes.
///
/// The output contains exactly two ASCII symbols per input byte.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base16upper(bytes: &[u8]) -> Box<[u8]> {
    BASE16_UPPER.encode_base16(bytes)
}

struct Encoder<'e> {
    encoder: &'e [u8],
}

impl<'e> Encoder<'e> {
    #[inline]
    const fn from_alphabet(encoder: &'e [u8]) -> Self {
        // INVARIANT: encoder table MUST be exactly 16.
        assert!(encoder.len() == 16);
        assert!(0x0f < encoder.len());
        Self { encoder }
    }

    #[inline]
    fn encoded_length(&self, src: &[u8]) -> usize {
        src.len()
            .checked_mul(2)
            .expect("base16 encoded length overflow")
    }

    #[inline]
    fn encode_base16_string(&self, bytes: &[u8]) -> String {
        let encoded = self.encode_base16(bytes);
        // SAFETY: base16 bytes are ASCII, therefore always valid UTF-8.
        unsafe { String::from_utf8_unchecked(encoded.into_vec()) }
    }

    #[cfg(feature = "alloc")]
    fn encode_base16(&self, bytes: &[u8]) -> Box<[u8]> {
        if bytes.is_empty() {
            return Vec::<u8>::new().into_boxed_slice();
        }

        let length = self.encoded_length(bytes);
        let mut ret = Vec::<u8>::with_capacity(length);

        let ret = self.try_encode_base16_into(src, &dst)

        ret.into_boxed_slice()
    }

    fn try_encode_base16_into<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
        if src.is_empty() {
            return Some(&[]);
        }

        // INVARIANT: length == 2 * src.len() <= dst.len()
        let length = self.encoded_length(src);
        if dst.len() < length {
            return None;
        }

        let written = self.encode_base16_payload(src, dst.as_mut_ptr());
        assert!(written == length);

        Some(&dst[..written])
    }

    #[inline]
    fn encode_base16_payload(&self, src: &[u8], dst: *mut u8) -> usize {
        // INVARIANT: 2 * i + 1 < dst.len()
        let mut i = 0usize;

        // SAFETY:
        //  - ptr derived from dst
        //  - 2 * i + 1 < dst.len() always
        //  - dst never accessed during ptr's lifetime
        unsafe {
            for &byte in src {
                let (hi, lo) = self.encode_base16_byte(byte);
                dst.add(2 * i).write(hi);
                dst.add(2 * i + 1).write(lo);
                i += 1;
            }
        }
        i
    }

    #[inline]
    fn encode_base16_byte(&self, byte: u8) -> (u8, u8) {
        let hi = (byte >> 4) as usize;
        let lo = (byte & 0x0f) as usize;

        // SAFETY: hi is four bits with a range [0, 16).
        let hi = unsafe { *self.encoder.get_unchecked(hi) };
        // SAFETY: lo is four bits with a range [0, 16).
        let lo = unsafe { *self.encoder.get_unchecked(lo) };

        (hi, lo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type EncodeBytes = fn(&[u8]) -> Box<[u8]>;
    type EncodeString = fn(&[u8]) -> String;

    #[test]
    fn byte_slices_encode_with_the_selected_case() {
        let vectors: &[(&[u8], &str, &str)] = &[
            (&[], "", ""),
            (&[0x00], "00", "00"),
            (&[0xff], "ff", "FF"),
            (&[0xde, 0xad, 0xbe, 0xef], "deadbeef", "DEADBEEF"),
            (
                &[0x00, 0x01, 0x0f, 0x10, 0xab, 0xff],
                "00010f10abff",
                "00010F10ABFF",
            ),
        ];

        for &(plain, lower, upper) in vectors {
            assert_eq!(encode_base16(plain).as_ref(), lower.as_bytes());
            assert_eq!(encode_base16_string(plain), lower);
            assert_eq!(encode_base16upper(plain).as_ref(), upper.as_bytes());
            assert_eq!(encode_base16upper_string(plain), upper);
        }
    }

    #[test]
    fn encoder_alphabets_preserve_unsafe_indexing_and_utf8_invariants() {
        fn assert_invariants(encoder: &Encoder<'_>) {
            assert_eq!(encoder.encoder.len(), 16);

            let mut seen = [false; 128];
            for &ascii in encoder.encoder {
                assert!(ascii.is_ascii());
                assert!(!seen[ascii as usize], "duplicate byte at ASCII {ascii}");
                seen[ascii as usize] = true;
            }
        }

        assert_invariants(&BASE16_LOWER);
        assert_invariants(&BASE16_UPPER);
    }

    #[test]
    fn arbitrary_byte_slices_encode_to_twice_the_input_length() {
        let encoders: &[(&str, EncodeBytes, EncodeString, &[u8])] = &[
            (
                "lowercase",
                encode_base16,
                encode_base16_string,
                BASE16_LOWER.encoder,
            ),
            (
                "uppercase",
                encode_base16upper,
                encode_base16upper_string,
                BASE16_UPPER.encoder,
            ),
        ];

        for len in 0usize..=64 {
            let input: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(73).wrapping_add(len * 19)) as u8)
                .collect();

            for &(name, encode, encode_string, alphabet) in encoders {
                let encoded = encode(&input);
                assert_eq!(encoded.len(), len * 2, "{name}, len {len}");
                assert_eq!(encode_string(&input).as_bytes(), encoded.as_ref());
                assert!(
                    encoded.iter().all(|byte| alphabet.contains(byte)),
                    "{name} emitted a byte outside its alphabet for len {len}"
                );
            }
        }
    }
}

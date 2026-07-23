// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Canonical padded Base32 and Base32Hex encoders.
//!
//! Both variants emit uppercase RFC 4648 alphabets and pad the final quantum
//! with `=` symbols.
//!
//! ```rust
//! use b2t_codecs::base32::{encode_base32_string, encode_base32hex_string};
//!
//! assert_eq!(encode_base32_string(b"foo"), "MZXW6===");
//! assert_eq!(encode_base32hex_string(b"foo"), "CPNMU===");
//! ```
use crate::base32::BASE32_PAD;

const BASE32_RFC: Encoder = const {
    use super::ENCODER;
    Encoder::from_alphabet(&ENCODER)
};
const BASE32_HEX: Encoder = const {
    use super::ENCODER_HEX;
    Encoder::from_alphabet(&ENCODER_HEX)
};

/// Encodes `bytes` as a canonical padded Base32 string.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base32_string(bytes: &[u8]) -> String {
    BASE32_RFC.encode_base32_string(bytes)
}

/// Encodes `bytes` as a canonical padded Base32Hex string.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base32hex_string(bytes: &[u8]) -> String {
    BASE32_HEX.encode_base32_string(bytes)
}

/// Encodes `bytes` as canonical padded Base32 ASCII bytes.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base32(bytes: &[u8]) -> Box<[u8]> {
    BASE32_RFC.encode_base32(bytes)
}

/// Encodes `bytes` as canonical padded Base32Hex ASCII bytes.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base32hex(bytes: &[u8]) -> Box<[u8]> {
    BASE32_HEX.encode_base32(bytes)
}

struct Encoder<'e> {
    encoder: &'e [u8],
}

impl<'e> Encoder<'e> {
    #[inline]
    const fn from_alphabet(encoder: &'e [u8]) -> Self {
        // INVARIANT: encoder table MUST be exactly 32.
        assert!(encoder.len() == 32);
        assert!(0x1f < encoder.len());
        Self { encoder }
    }

    #[inline]
    fn encode_base32_string(&self, bytes: &[u8]) -> String {
        let encoded = self.encode_base32(bytes);
        // SAFETY: base32 bytes are ASCII, therefore always valid UTF-8.
        unsafe { String::from_utf8_unchecked(encoded.into_vec()) }
    }

    fn encode_base32(&self, bytes: &[u8]) -> Box<[u8]> {
        if bytes.is_empty() {
            return Vec::<u8>::new().into_boxed_slice();
        }

        // base32 encodes 8 ASCII bytes per 5 byte chunk
        // and at most 8 extra bytes for a padded tail
        let cap = bytes
            .len()
            .checked_mul(8)
            .expect("base32 encoded length overflow")
            / 5
            + 8;

        let (chunks, rem) = bytes.as_chunks::<5>();
        let mut ret = Vec::<u8>::with_capacity(cap);

        for &chunk in chunks {
            ret.extend_from_slice(&self.encode_base32_full_chunk(chunk));
        }

        if !rem.is_empty() {
            let chunk = self.encode_base32_tail(rem);
            ret.extend_from_slice(&chunk);
        }

        ret.into_boxed_slice()
    }

    fn encode_base32_full_chunk(&self, chunk: [u8; 5]) -> [u8; 8] {
        // pack the 40 bits into a u64
        let n = u64::from_be_bytes([0, 0, 0, chunk[0], chunk[1], chunk[2], chunk[3], chunk[4]]);

        // the eight 5-bit pentads
        let on = n >> 35 & 0x1f;
        let tw = n >> 30 & 0x1f;
        let th = n >> 25 & 0x1f;
        let fo = n >> 20 & 0x1f;
        let fv = n >> 15 & 0x1f;
        let sx = n >> 10 & 0x1f;
        let sv = n >> 5 & 0x1f;
        let et = n & 0x1f;

        // the eight encoded bytes
        // SAFETY: five-bit pentad 1F is guaranteed to be on the range [0, 32)
        let on = unsafe { *self.encoder.get_unchecked(on as usize) };
        // SAFETY: five-bit pentad 1F is guaranteed to be on the range [0, 32)
        let tw = unsafe { *self.encoder.get_unchecked(tw as usize) };
        // SAFETY: five-bit pentad 1F is guaranteed to be on the range [0, 32)
        let th = unsafe { *self.encoder.get_unchecked(th as usize) };
        // SAFETY: five-bit pentad 1F is guaranteed to be on the range [0, 32)
        let fo = unsafe { *self.encoder.get_unchecked(fo as usize) };
        // SAFETY: five-bit pentad 1F is guaranteed to be on the range [0, 32)
        let fv = unsafe { *self.encoder.get_unchecked(fv as usize) };
        // SAFETY: five-bit pentad 1F is guaranteed to be on the range [0, 32)
        let sx = unsafe { *self.encoder.get_unchecked(sx as usize) };
        // SAFETY: five-bit pentad 1F is guaranteed to be on the range [0, 32)
        let sv = unsafe { *self.encoder.get_unchecked(sv as usize) };
        // SAFETY: five-bit pentad 1F is guaranteed to be on the range [0, 32)
        let et = unsafe { *self.encoder.get_unchecked(et as usize) };

        [on, tw, th, fo, fv, sx, sv, et]
    }

    fn encode_base32_tail(&self, tail: &[u8]) -> [u8; 8] {
        // must be 1, 2, 3, or 4
        let len = tail.len();

        // pad with null bytes for encoding
        // "When fewer than 40 input bits are available in an input group,
        // bits with value zero are added (on the right) to form an
        // integral number of 5-bit groups."
        let mut padded = [0u8; 5];
        padded[..len].copy_from_slice(tail);
        let mut encoded = self.encode_base32_full_chunk(padded);

        // replace unused encoded positions with b'=' based on tail length
        //  - 1 byte  => 2 encoded bytes and six pad
        //  - 2 bytes => 4 encoded bytes and four pad
        //  - 3 bytes => 5 encoded bytes and three pad
        //  - 4 bytes => 7 encoded bytes and one pad
        let pad_start = match len {
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            _ => unreachable!("len must be 1, 2, 3, or 4"),
        };
        encoded[pad_start..].fill(BASE32_PAD);

        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type EncodeBytes = fn(&[u8]) -> Box<[u8]>;
    type EncodeString = fn(&[u8]) -> String;

    #[test]
    fn rfc_4648_base32_test_vectors_pin_encoding() {
        let vectors: &[(&[u8], &str, &str)] = &[
            (b"", "", ""),
            (b"f", "MY======", "CO======"),
            (b"fo", "MZXQ====", "CPNG===="),
            (b"foo", "MZXW6===", "CPNMU==="),
            (b"foob", "MZXW6YQ=", "CPNMUOG="),
            (b"fooba", "MZXW6YTB", "CPNMUOJ1"),
            (b"foobar", "MZXW6YTBOI======", "CPNMUOJ1E8======"),
        ];

        for &(plain, base32, base32hex) in vectors {
            assert_eq!(encode_base32(plain).as_ref(), base32.as_bytes());
            assert_eq!(encode_base32_string(plain), base32);
            assert_eq!(encode_base32hex(plain).as_ref(), base32hex.as_bytes());
            assert_eq!(encode_base32hex_string(plain), base32hex);
        }
    }

    #[test]
    fn encoder_alphabets_preserve_unsafe_indexing_and_utf8_invariants() {
        fn assert_invariants(encoder: &Encoder<'_>) {
            assert_eq!(encoder.encoder.len(), 32);

            let mut seen = [false; 128];
            for &ascii in encoder.encoder {
                assert!(ascii.is_ascii());
                assert!(!seen[ascii as usize], "duplicate byte at ASCII {ascii}");
                seen[ascii as usize] = true;
            }
        }

        assert_invariants(&BASE32_RFC);
        assert_invariants(&BASE32_HEX);
    }

    #[test]
    fn byte_slices_of_arbitrary_lengths_encode_canonically() {
        let codecs: &[(&str, EncodeBytes, EncodeString, &[u8])] = &[
            (
                "Base32",
                encode_base32,
                encode_base32_string,
                BASE32_RFC.encoder,
            ),
            (
                "Base32Hex",
                encode_base32hex,
                encode_base32hex_string,
                BASE32_HEX.encoder,
            ),
        ];

        for len in 0usize..=64 {
            let input: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(73).wrapping_add(len * 19)) as u8)
                .collect();
            let padding = match len % 5 {
                0 => 0,
                1 => 6,
                2 => 4,
                3 => 3,
                4 => 1,
                _ => unreachable!(),
            };

            for &(name, encode, encode_string, alphabet) in codecs {
                let encoded = encode(&input);

                assert_eq!(encoded.len(), len.div_ceil(5) * 8, "{name}, len {len}");
                assert_eq!(encode_string(&input).as_bytes(), encoded.as_ref());
                assert!(
                    encoded[..encoded.len() - padding]
                        .iter()
                        .all(|byte| alphabet.contains(byte)),
                    "{name} emitted a byte outside its alphabet for len {len}"
                );
                assert!(
                    encoded[encoded.len() - padding..]
                        .iter()
                        .all(|&byte| byte == BASE32_PAD),
                    "{name} emitted malformed padding for len {len}"
                );
            }
        }
    }
}

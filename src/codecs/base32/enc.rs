// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Canonical padded Base32 and Base32Hex encoders.
//!
//! Both variants emit uppercase RFC 4648 alphabets and pad the final quantum
//! with `=` symbols.
//!
//! ```rust
//! use b2t_codecs::base32::{try_encode_into_base32, try_encode_into_base32hex};
//!
//! let mut base32 = [0; 8];
//! let mut base32hex = [0; 8];
//!
//! assert_eq!(try_encode_into_base32(b"foo", &mut base32), Some(b"MZXW6===".as_slice()));
//! assert_eq!(try_encode_into_base32hex(b"foo", &mut base32hex), Some(b"CPNMU===".as_slice()));
//! ```

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String, vec::Vec};

use crate::base32::BASE32_PAD;

pub(super) const BASE32_RFC: Encoder = const {
    use super::ENCODER;
    Encoder::from_alphabet(&ENCODER)
};
pub(super) const BASE32_HEX: Encoder = const {
    use super::ENCODER_HEX;
    Encoder::from_alphabet(&ENCODER_HEX)
};

// replace unused encoded positions with b'=' based on tail length
//  - 1 byte  => 2 encoded bytes and six pad
//  - 2 bytes => 4 encoded bytes and four pad
//  - 3 bytes => 5 encoded bytes and three pad
//  - 4 bytes => 7 encoded bytes and one pad
const BASE32_PADS: [usize; 5] = [0, 2, 4, 5, 7];

/// Encodes `bytes` as a canonical padded Base32 string.
#[cfg(feature = "alloc")]
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base32_string(bytes: &[u8]) -> String {
    BASE32_RFC.encode_string(bytes)
}

/// Encodes `bytes` as a canonical padded Base32Hex string.
#[cfg(feature = "alloc")]
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base32hex_string(bytes: &[u8]) -> String {
    BASE32_HEX.encode_string(bytes)
}

/// Encodes `bytes` as canonical padded Base32 ASCII bytes.
#[cfg(feature = "alloc")]
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base32(bytes: &[u8]) -> Box<[u8]> {
    BASE32_RFC.encode_boxed(bytes)
}

/// Encodes `bytes` as canonical padded Base32Hex ASCII bytes.
#[cfg(feature = "alloc")]
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base32hex(bytes: &[u8]) -> Box<[u8]> {
    BASE32_HEX.encode_boxed(bytes)
}

/// Returns the exact number of bytes needed to encode `bytes` as padded Base32.
///
/// Base32 emits eight ASCII bytes for every complete or partial five-byte
/// input quantum.
#[must_use = "the encoded size should be used"]
#[inline]
pub fn encoded_length_base32(bytes: &[u8]) -> usize {
    encoded_length(bytes)
}

#[inline]
fn encoded_length(bytes: &[u8]) -> usize {
    // A slice holds at most `isize::MAX` bytes, so this cannot overflow.
    bytes.len().div_ceil(5) * 8
}

/// Encodes `src` as canonical padded Base32 into the beginning of `dst`.
///
/// Returns the initialized prefix of `dst`, or [`None`] if `dst` is shorter
/// than [`encoded_length_base32(src)`](encoded_length_base32). A short
/// destination is left unchanged. Any bytes after the encoded prefix are also
/// left unchanged. This function does not allocate.
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_into_base32<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    BASE32_RFC.encode_into(src, dst)
}

/// Encodes `src` as canonical padded Base32Hex into the beginning of `dst`.
///
/// Returns the initialized prefix of `dst`, or [`None`] if `dst` is shorter
/// than [`encoded_length_base32(src)`](encoded_length_base32). A short
/// destination is left unchanged. Any bytes after the encoded prefix are also
/// left unchanged. This function does not allocate.
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_into_base32hex<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    BASE32_HEX.encode_into(src, dst)
}

pub(super) struct Encoder<'e> {
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

    #[cfg(feature = "alloc")]
    #[inline]
    fn encode_string(&self, bytes: &[u8]) -> String {
        let encoded = self.encode_boxed(bytes);
        // SAFETY: base32 bytes are ASCII, therefore always valid UTF-8.
        unsafe { String::from_utf8_unchecked(encoded.into_vec()) }
    }

    #[cfg(feature = "alloc")]
    pub(super) fn encode_boxed(&self, bytes: &[u8]) -> Box<[u8]> {
        if bytes.is_empty() {
            return Vec::<u8>::new().into_boxed_slice();
        }

        let payload_len = encoded_length(bytes);
        let mut dst = Box::<[u8]>::new_uninit_slice(payload_len);

        let (chunks, rem) = bytes.as_chunks::<5>();
        let mut written = 0usize;

        for &chunk in chunks {
            let chunk = self.encode_base32_full_chunk(chunk);
            dst[written..written + 8].write_copy_of_slice(&chunk);
            written += 8;
        }

        if !rem.is_empty() {
            let chunk = self.encode_base32_tail(rem);
            dst[written..written + 8].write_copy_of_slice(&chunk);
            written += 8;
        }

        // SAFETY:
        //  - `dst` contains `payload_len` consecutive `MaybeUninit<u8>` values.
        //  - A `MaybeUninit<u8>` pointer is valid for writes through a `u8`
        //    pointer.
        //  - initialized exactly `payload_len` bytes.
        unsafe {
            // INVARIANT: all allocated elements were initialized.
            // NOTE: dst.len() == payload_len
            assert!(written == dst.len());
            dst.assume_init()
        }
    }

    pub(super) fn encode_into<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
        if src.is_empty() {
            return Some(&dst[..0]);
        }

        let payload_len = encoded_length(src);
        if dst.len() < payload_len {
            return None;
        }

        let (chunks, rem) = src.as_chunks::<5>();
        let mut written = 0usize;

        for &chunk in chunks {
            let chunk = self.encode_base32_full_chunk(chunk);
            dst[written..written + 8].copy_from_slice(&chunk);
            written += 8;
        }

        if !rem.is_empty() {
            let chunk = self.encode_base32_tail(rem);
            dst[written..written + 8].copy_from_slice(&chunk);
            written += 8;
        }

        // INVARIANT: `written == encoded_length_base32(src)`, therefore
        // `written <= dst.len()`.
        assert!(written == payload_len);
        Some(&dst[..payload_len])
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

        let pad_start = BASE32_PADS[len];
        encoded[pad_start..].fill(BASE32_PAD);

        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::{BASE32_HEX, BASE32_RFC, Encoder, encoded_length};

    #[test]
    fn rfc_4648_base32_test_vectors_pin_encoding() {
        // Pentads 0..=31 packed MSB-first: encodes to each whole RFC 4648
        // alphabet (Tables 3 and 4) in order, pinning every symbol.
        const ALPHABET_DIGITS: [u8; 20] = [
            0x00, 0x44, 0x32, 0x14, 0xc7, 0x42, 0x54, 0xb6, 0x35, 0xcf, 0x84, 0x65, 0x3a, 0x56,
            0xd7, 0xc6, 0x75, 0xbe, 0x77, 0xdf,
        ];

        let vectors: &[(&[u8], &str, &str)] = &[
            (b"", "", ""),
            (b"f", "MY======", "CO======"),
            (b"fo", "MZXQ====", "CPNG===="),
            (b"foo", "MZXW6===", "CPNMU==="),
            (b"foob", "MZXW6YQ=", "CPNMUOG="),
            (b"fooba", "MZXW6YTB", "CPNMUOJ1"),
            (b"foobar", "MZXW6YTBOI======", "CPNMUOJ1E8======"),
            (
                &ALPHABET_DIGITS,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
                "0123456789ABCDEFGHIJKLMNOPQRSTUV",
            ),
        ];

        for &(plain, base32, base32hex) in vectors {
            let mut dst = [0u8; 32];
            assert_eq!(
                BASE32_RFC.encode_into(plain, &mut dst),
                Some(base32.as_bytes())
            );

            let mut dst = [0u8; 32];
            assert_eq!(
                BASE32_HEX.encode_into(plain, &mut dst),
                Some(base32hex.as_bytes())
            );

            #[cfg(feature = "alloc")]
            {
                assert_eq!(BASE32_RFC.encode_boxed(plain).as_ref(), base32.as_bytes());
                assert_eq!(BASE32_RFC.encode_string(plain), base32);
                assert_eq!(
                    BASE32_HEX.encode_boxed(plain).as_ref(),
                    base32hex.as_bytes()
                );
                assert_eq!(BASE32_HEX.encode_string(plain), base32hex);
            }
        }
    }

    #[test]
    fn encoded_lengths_are_exact() {
        assert_eq!(encoded_length(b""), 0);
        assert_eq!(encoded_length(&[0]), 8);
        assert_eq!(encoded_length(&[0; 4]), 8);
        assert_eq!(encoded_length(&[0; 5]), 8);
        assert_eq!(encoded_length(&[0; 6]), 16);
        assert_eq!(encoded_length(&[0; 32]), 56);
    }

    #[test]
    fn slice_encoders_preserve_destination_bounds() {
        let codecs: [(&str, &Encoder<'_>, &[u8], u8); 2] = [
            ("Base32", &BASE32_RFC, b"MZXW6YTBOI======", b'!'),
            ("Base32Hex", &BASE32_HEX, b"CPNMUOJ1E8======", b'?'),
        ];

        for (name, encoder, expected, sentinel) in codecs {
            let mut oversized = [sentinel; 18];
            assert_eq!(
                encoder.encode_into(b"foobar", &mut oversized),
                Some(expected),
                "{name}"
            );
            assert_eq!(
                &oversized[expected.len()..],
                &[sentinel; 2],
                "{name} modified the destination suffix"
            );

            let mut short = [sentinel; 15];
            assert_eq!(encoder.encode_into(b"foobar", &mut short), None, "{name}");
            assert_eq!(short, [sentinel; 15], "{name} modified a short destination");

            let mut empty = [sentinel; 1];
            assert_eq!(
                encoder.encode_into(b"", &mut empty),
                Some([].as_slice()),
                "{name}"
            );
            assert_eq!(
                empty,
                [sentinel],
                "{name} modified the destination for empty input"
            );
        }
    }
}

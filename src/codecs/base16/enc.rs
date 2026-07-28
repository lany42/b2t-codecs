// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Base16 encoders for lowercase and uppercase ASCII output.
//!
//! Each input byte is represented by exactly two hexadecimal symbols.
//!
//! ```rust
//! use b2t_codecs::base16::{try_encode_into_base16, try_encode_into_base16upper};
//!
//! let mut lower = [0; 4];
//! let mut upper = [0; 4];
//! let lower = try_encode_into_base16(&[0xab, 0xcd], &mut lower).unwrap();
//! let upper = try_encode_into_base16upper(&[0xab, 0xcd], &mut upper).unwrap();
//!
//! assert_eq!(lower, b"abcd");
//! assert_eq!(upper, b"ABCD");
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
#[cfg(feature = "alloc")]
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base16_string(bytes: &[u8]) -> String {
    BASE16_LOWER.encode_string(bytes)
}

/// Encodes `bytes` as an uppercase Base16 string.
///
/// The output contains exactly two ASCII symbols per input byte.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[cfg(feature = "alloc")]
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base16upper_string(bytes: &[u8]) -> String {
    BASE16_UPPER.encode_string(bytes)
}

/// Encodes `bytes` as lowercase Base16 ASCII bytes.
///
/// The output contains exactly two ASCII symbols per input byte.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[cfg(feature = "alloc")]
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base16(bytes: &[u8]) -> Box<[u8]> {
    BASE16_LOWER.encode_boxed(bytes)
}

/// Encodes `bytes` as uppercase Base16 ASCII bytes.
///
/// The output contains exactly two ASCII symbols per input byte.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[cfg(feature = "alloc")]
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base16upper(bytes: &[u8]) -> Box<[u8]> {
    BASE16_UPPER.encode_boxed(bytes)
}

/// Returns the exact number of bytes needed to encode `bytes` as Base16.
///
/// Base16 emits two ASCII bytes for every input byte.
///
/// # Panics
///
/// Panics if twice the input length cannot be represented as a [`usize`].
#[must_use = "the encoded size should be used"]
#[inline]
pub fn encoded_length_base16(bytes: &[u8]) -> usize {
    bytes
        .len()
        .checked_mul(2)
        .expect("base16 encoded length overflow")
}

/// Encodes `src` as lowercase Base16 into the beginning of `dst`.
///
/// Returns the initialized prefix of `dst`, or [`None`] if `dst` is shorter
/// than [`encoded_length_base16(src)`](encoded_length_base16). A short
/// destination is left unchanged. Any bytes after the encoded prefix are also
/// left unchanged. This function does not allocate.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_into_base16<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    BASE16_LOWER.encode_into(src, dst)
}

/// Encodes `src` as uppercase Base16 into the beginning of `dst`.
///
/// Returns the initialized prefix of `dst`, or [`None`] if `dst` is shorter
/// than [`encoded_length_base16(src)`](encoded_length_base16). A short
/// destination is left unchanged. Any bytes after the encoded prefix are also
/// left unchanged. This function does not allocate.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_into_base16upper<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    BASE16_UPPER.encode_into(src, dst)
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

    #[cfg(feature = "alloc")]
    #[inline]
    fn encode_string(&self, bytes: &[u8]) -> String {
        let encoded = self.encode_boxed(bytes);
        // SAFETY: base16 bytes are ASCII, therefore always valid UTF-8.
        unsafe { String::from_utf8_unchecked(encoded.into_vec()) }
    }

    #[cfg(feature = "alloc")]
    fn encode_boxed(&self, bytes: &[u8]) -> Box<[u8]> {
        if bytes.is_empty() {
            return Vec::<u8>::new().into_boxed_slice();
        }
        let payload_len = encoded_length_base16(bytes);
        let mut dst = Box::<[u8]>::new_uninit_slice(payload_len);

        // SAFETY:
        //  - `dst` contains `payload_len` consecutive `MaybeUninit<u8>` values.
        //  - A `MaybeUninit<u8>` pointer is valid for writes through a `u8`
        //    pointer.
        //  - `encode_base16_payload` initializes exactly `payload_len` bytes.
        unsafe {
            let written = self.encode_base16_payload(bytes, dst.as_mut_ptr().cast::<u8>());

            // INVARIANT: all allocated elements were initialized.
            assert!(written == dst.len());
            dst.assume_init()
        }
    }

    fn encode_into<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
        if src.is_empty() {
            return Some(&dst[..0]);
        }

        let payload_len = encoded_length_base16(src);
        if dst.len() < payload_len {
            return None;
        }

        // SAFETY: `dst` has at least `payload_len`, or `2 * src.len()`, bytes.
        let written = unsafe { self.encode_base16_payload(src, dst.as_mut_ptr()) };

        // INVARIANT: `written == encoded_length_base16(src)`, therefore
        // `written <= dst.len()`.
        assert!(written == payload_len);
        Some(&dst[..written])
    }

    // SAFETY: `dst` must point to at least `encoded_length_base16(src)`
    // consecutive, writable bytes.
    //
    // Returns the number of bytes written to `dst`.
    #[inline]
    unsafe fn encode_base16_payload(&self, src: &[u8], dst: *mut u8) -> usize {
        let mut i = 0usize;

        // SAFETY:
        //  - The caller guarantees enough writable storage for every output
        //    pair.
        //  - `2 * i` and `2 * i + 1` address distinct, in-bounds bytes.
        unsafe {
            for &byte in src {
                let (hi, lo) = self.encode_base16_byte(byte);
                dst.add(2 * i).write(hi);
                dst.add(2 * i + 1).write(lo);
                i += 1;
            }
        }
        2 * i
    }

    #[inline]
    fn encode_base16_byte(&self, byte: u8) -> (u8, u8) {
        let hi = (byte >> 4) as usize;
        let lo = (byte & 0x0f) as usize;

        // SAFETY: hi is four bits with a range [0, 16).
        //         lo is four bits with a range [0, 16).
        unsafe {
            (
                *self.encoder.get_unchecked(hi),
                *self.encoder.get_unchecked(lo),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    type EncodeBytes = fn(&[u8]) -> Box<[u8]>;
    #[cfg(feature = "alloc")]
    type EncodeString = fn(&[u8]) -> String;

    #[cfg(feature = "alloc")]
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
    fn encoded_lengths_are_exact() {
        assert_eq!(encoded_length_base16(b""), 0);
        assert_eq!(encoded_length_base16(&[0]), 2);
        assert_eq!(encoded_length_base16(&[0; 32]), 64);
    }

    #[test]
    fn slice_encoders_write_only_the_returned_prefix() {
        let mut lower = [b'!'; 10];
        assert_eq!(
            try_encode_into_base16(&[0x00, 0xab, 0xff], &mut lower),
            Some(b"00abff".as_slice()),
        );
        assert_eq!(&lower[6..], b"!!!!");

        let mut upper = [b'?'; 10];
        assert_eq!(
            try_encode_into_base16upper(&[0x00, 0xab, 0xff], &mut upper),
            Some(b"00ABFF".as_slice()),
        );
        assert_eq!(&upper[6..], b"????");

        let mut untouched = [b'x'; 1];
        let dst_ptr = untouched.as_ptr();
        let encoded = try_encode_into_base16(b"", &mut untouched).unwrap();
        assert!(encoded.is_empty());
        assert_eq!(encoded.as_ptr(), dst_ptr);
        assert_eq!(untouched, [b'x']);
    }

    #[test]
    fn slice_encoders_cover_every_input_byte() {
        let mut input = [0u8; 256];
        for (byte, value) in input.iter_mut().zip(u8::MIN..=u8::MAX) {
            *byte = value;
        }

        let mut lower = [0u8; 512];
        let lower = try_encode_into_base16(&input, &mut lower).unwrap();
        assert_eq!(lower.len(), encoded_length_base16(&input));
        assert!(lower.iter().all(|byte| BASE16_LOWER.encoder.contains(byte)));

        let mut upper = [0u8; 512];
        let upper = try_encode_into_base16upper(&input, &mut upper).unwrap();
        assert_eq!(upper.len(), encoded_length_base16(&input));
        assert!(upper.iter().all(|byte| BASE16_UPPER.encoder.contains(byte)));
    }

    #[test]
    fn slice_encoders_return_none_for_a_short_destination() {
        let mut lower = [b'!'; 3];
        assert_eq!(try_encode_into_base16(&[0xab, 0xcd], &mut lower), None);
        assert_eq!(lower, [b'!'; 3]);

        let mut upper = [b'?'; 3];
        assert_eq!(try_encode_into_base16upper(&[0xab, 0xcd], &mut upper), None);
        assert_eq!(upper, [b'?'; 3]);
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

    #[cfg(feature = "alloc")]
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

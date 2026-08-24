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
//! use b2t_codecs::base85::{try_encode_into_adobe85, try_encode_into_z85};
//!
//! let mut adobe85 = [0; 5];
//! let mut z85 = [0; 5];
//!
//! assert_eq!(
//!     try_encode_into_adobe85(&[0, 0, 0, 0], &mut adobe85),
//!     Some(b"z".as_slice()),
//! );
//! assert_eq!(
//!     try_encode_into_z85(&[0x86, 0x4f, 0xd2, 0x6f], &mut z85),
//!     Some(b"Hello".as_slice()),
//! );
//! ```
pub(super) const ASCII85: Encoder = const {
    use super::ENCODER_ASCII85;
    Encoder::from_alphabet(&ENCODER_ASCII85)
};
pub(super) const Z85: Encoder = const {
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
#[cfg(feature = "alloc")]
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_adobe85_string(bytes: &[u8]) -> String {
    ASCII85.encode_adobe85_string(bytes)
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
#[cfg(feature = "alloc")]
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_adobe85(bytes: &[u8]) -> Box<[u8]> {
    ASCII85.encode_adobe85_boxed(bytes)
}

/// Encodes complete four-byte quanta as a strict Ascii85 string.
///
/// Returns [`None`] if `bytes.len()` is not divisible by four or the encoded
/// length cannot be represented as a [`usize`].
#[cfg(feature = "alloc")]
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_ascii85_string(bytes: &[u8]) -> Option<String> {
    ASCII85.try_encode_base85_string(bytes)
}

/// Encodes complete four-byte quanta as strict Ascii85 bytes.
///
/// Returns [`None`] if `bytes.len()` is not divisible by four or the encoded
/// length cannot be represented as a [`usize`].
#[cfg(feature = "alloc")]
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_ascii85(bytes: &[u8]) -> Option<Box<[u8]>> {
    ASCII85.try_encode_base85_boxed(bytes)
}

/// Encodes complete four-byte quanta as a ZeroMQ Z85 string.
///
/// Returns [`None`] if `bytes.len()` is not divisible by four or the encoded
/// length cannot be represented as a [`usize`].
#[cfg(feature = "alloc")]
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_z85_string(bytes: &[u8]) -> Option<String> {
    Z85.try_encode_base85_string(bytes)
}

/// Encodes complete four-byte quanta as ZeroMQ Z85 bytes.
///
/// Returns [`None`] if `bytes.len()` is not divisible by four or the encoded
/// length cannot be represented as a [`usize`].
#[cfg(feature = "alloc")]
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_z85(bytes: &[u8]) -> Option<Box<[u8]>> {
    Z85.try_encode_base85_boxed(bytes)
}

/// Returns the exact encoded length of strict Ascii85 or Z85 input.
///
/// Strict Base85 emits five ASCII symbols for every complete four-byte input
/// quantum. Returns [`None`] unless `src.len()` is divisible by four or if the
/// encoded length cannot be represented as a [`usize`]. This function does
/// not inspect the contents of `src`.
#[must_use = "the encoded size should be used"]
#[inline]
pub fn encoded_length_base85(src: &[u8]) -> Option<usize> {
    encoded_length(src)
}

#[inline]
fn encoded_length(src: &[u8]) -> Option<usize> {
    // INVARIANT: strict base85 does not handle padding automatically
    // "The binary frame SHALL have a length that is divisible by 4 with no remainder."
    if !src.len().is_multiple_of(4) {
        return None;
    }

    // INVARIANT: base85 encodes five ASCII bytes per four input bytes
    // "The string frame SHALL have a length that is divisible by 5 with no remainder."
    (src.len() / 4).checked_mul(5)
}

/// Returns the destination capacity required to encode `src` as Adobe85.
///
/// The returned value is the uncompressed upper bound: five ASCII symbols for
/// every complete four-byte input quantum, plus two to four symbols for a
/// partial final quantum. It does not inspect `src` or account for `z`
/// compression, so the initialized prefix returned by
/// [`try_encode_into_adobe85`] can be shorter. Callers must nevertheless
/// provide this full capacity.
///
/// # Panics
///
/// Panics if the upper bound cannot be represented as a [`usize`].
#[must_use = "the encoded capacity should be used"]
#[inline]
pub fn encoded_length_adobe85(src: &[u8]) -> usize {
    let tail_len = match src.len() % 4 {
        0 => 0,
        len => len + 1,
    };

    (src.len() / 4)
        .checked_mul(5)
        .and_then(|len| len.checked_add(tail_len))
        .expect("base85 encoded length overflow")
}

/// Encodes `src` as raw Adobe85 into the beginning of `dst`.
///
/// `dst` must contain at least
/// [`encoded_length_adobe85(src)`](encoded_length_adobe85) bytes even when zero
/// compression makes the actual output shorter. Returns the initialized prefix
/// of `dst`, including `Some(&dst[..0])` for empty input. A short destination is
/// left unchanged, and bytes after a successful returned prefix are also left
/// unchanged. This function does not allocate.
///
/// # Panics
///
/// Panics if the Adobe85 encoded-length upper bound cannot be represented as a
/// [`usize`].
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_into_adobe85<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    ASCII85.encode_adobe85_into(src, dst)
}

/// Encodes complete four-byte `src` quanta as strict Ascii85 into `dst`.
///
/// Returns the initialized prefix of `dst`, including `Some(&dst[..0])` for
/// empty input, or [`None`] if `src` is not four-byte aligned, the encoded
/// length overflows, or `dst` is too short. Alignment and capacity failures
/// leave `dst` unchanged. Bytes after a successful returned prefix are also
/// left unchanged. This function does not allocate.
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_into_ascii85<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    ASCII85.try_encode_base85_into(src, dst)
}

/// Encodes complete four-byte `src` quanta as ZeroMQ Z85 into `dst`.
///
/// Returns the initialized prefix of `dst`, including `Some(&dst[..0])` for
/// empty input, or [`None`] if `src` is not four-byte aligned, the encoded
/// length overflows, or `dst` is too short. Alignment and capacity failures
/// leave `dst` unchanged. Bytes after a successful returned prefix are also
/// left unchanged. This function does not allocate.
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_into_z85<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    Z85.try_encode_base85_into(src, dst)
}

pub(super) struct Encoder<'e> {
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

    #[cfg(feature = "alloc")]
    #[inline]
    fn try_encode_base85_string(&self, bytes: &[u8]) -> Option<String> {
        let encoded = self.try_encode_base85_boxed(bytes)?;
        // SAFETY: base85 bytes are ASCII, therefore always valid UTF-8.
        unsafe { Some(String::from_utf8_unchecked(encoded.into_vec())) }
    }

    #[cfg(feature = "alloc")]
    #[inline]
    fn encode_adobe85_string(&self, bytes: &[u8]) -> String {
        let encoded = self.encode_adobe85_boxed(bytes);
        // SAFETY: base85 bytes are ASCII, therefore always valid UTF-8.
        unsafe { String::from_utf8_unchecked(encoded.into_vec()) }
    }

    #[cfg(feature = "alloc")]
    pub(super) fn try_encode_base85_boxed(&self, bytes: &[u8]) -> Option<Box<[u8]>> {
        if bytes.is_empty() {
            return Some(Vec::<u8>::new().into_boxed_slice());
        }

        let payload_len = encoded_length(bytes)?;
        let (chunks, []) = bytes.as_chunks::<4>() else {
            unreachable!("encoded_length_base85 requires complete four-byte quanta")
        };
        let mut dst = Box::<[u8]>::new_uninit_slice(payload_len);
        let mut written = 0usize;

        for &chunk in chunks {
            let chunk = self.encode_base85_chunk(chunk);
            dst[written..written + 5].write_copy_of_slice(&chunk);
            written += 5;
        }

        // SAFETY:
        //  - `dst` contains `payload_len` consecutive `MaybeUninit<u8>` values.
        //  - Every encoded chunk writes five bytes into distinct, in-bounds
        //    elements of `dst`.
        //  - `written == dst.len()` verifies that every element was initialized.
        unsafe {
            // INVARIANT: every four-byte quantum emits exactly five symbols, so
            // all allocated elements were initialized.
            assert!(written == dst.len());
            Some(dst.assume_init())
        }
    }

    #[cfg(feature = "alloc")]
    pub(super) fn encode_adobe85_boxed(&self, bytes: &[u8]) -> Box<[u8]> {
        let payload_capacity = encoded_length_adobe85(bytes);
        let mut ret = Vec::<u8>::with_capacity(payload_capacity);
        let (chunks, remainder) = bytes.as_chunks::<4>();

        for &chunk in chunks {
            if chunk == [0; 4] {
                ret.push(super::ADOBE85_ZEROS);
            } else {
                ret.extend_from_slice(&self.encode_base85_chunk(chunk));
            }
        }

        if !remainder.is_empty() {
            let (encoded, len) = self.encode_adobe85_tail(remainder);
            ret.extend_from_slice(&encoded[..len]);
        }

        // INVARIANT: compression only reduces the content-independent bound.
        assert!(ret.len() <= payload_capacity);
        ret.into_boxed_slice()
    }

    pub(super) fn try_encode_base85_into<'a>(
        &self,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        let payload_len = encoded_length(src)?;
        if dst.len() < payload_len {
            return None;
        }

        let (chunks, []) = src.as_chunks::<4>() else {
            unreachable!("encoded_length_base85 requires complete four-byte quanta")
        };
        let mut written = 0usize;

        for &chunk in chunks {
            let encoded = self.encode_base85_chunk(chunk);
            dst[written..written + 5].copy_from_slice(&encoded);
            written += 5;
        }

        // INVARIANT: every four-byte quantum emits exactly five symbols.
        assert!(written == payload_len);
        Some(&dst[..written])
    }

    pub(super) fn encode_adobe85_into<'a>(
        &self,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        let payload_capacity = encoded_length_adobe85(src);
        if dst.len() < payload_capacity {
            return None;
        }

        let (chunks, remainder) = src.as_chunks::<4>();
        let mut written = 0usize;

        for &chunk in chunks {
            if chunk == [0; 4] {
                dst[written] = super::ADOBE85_ZEROS;
                written += 1;
            } else {
                let encoded = self.encode_base85_chunk(chunk);
                dst[written..written + 5].copy_from_slice(&encoded);
                written += 5;
            }
        }

        if !remainder.is_empty() {
            let (encoded, len) = self.encode_adobe85_tail(remainder);
            dst[written..written + len].copy_from_slice(&encoded[..len]);
            written += len;
        }

        // INVARIANT: zero compression only reduces the upper bound.
        assert!(written <= payload_capacity);
        Some(&dst[..written])
    }

    fn encode_base85_chunk(&self, chunk: [u8; 4]) -> [u8; 5] {
        let mut buf = [0u8; 5];

        // "To encode a frame, an implementation SHALL take four octets at a time from
        // the binary frame and convert them into five printable characters"

        // "The four octets SHALL be treated as an
        // unsigned 32-bit integer in network byte order (big endian)."
        let n = u32::from_be_bytes(chunk);

        // "The five characters SHALL be output from most significant to least significant (big endian)."
        let mut d = 85u32.pow(4);
        for b in &mut buf {
            let i = ((n / d) % 85) as usize;

            // SAFETY: modulo 85 guarantees safe encoder indexing.
            *b = unsafe { *self.encoder.get_unchecked(i) };
            d /= 85;
        }

        buf
    }

    #[inline]
    fn encode_adobe85_tail(&self, tail: &[u8]) -> ([u8; 5], usize) {
        // Adobe85 implicit tails contain one, two, or three source bytes.
        let len = tail.len();
        assert!((1..=3).contains(&len));

        let mut padded = [0; 4];
        padded[..len].copy_from_slice(tail);

        // the number of padding null bytes added are equal to the amount
        // of bytes stripped from the encoded chunk (length 5)
        //      - 1 byte  => 3 '0' bytes => 2 bytes output
        //      - 2 bytes => 2 '0' bytes => 3 bytes output
        //      - 3 bytes => 1 '0' byte  => 4 bytes output
        //
        // that is, bytes kept: remainder.len() + 1
        (self.encode_base85_chunk(padded), len + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::{ASCII85, Z85, encoded_length, encoded_length_adobe85};

    #[test]
    fn strict_length_helper_requires_complete_quanta() {
        assert_eq!(encoded_length(b""), Some(0));
        assert_eq!(encoded_length(&[0; 4]), Some(5));
        assert_eq!(encoded_length(&[0; 8]), Some(10));

        for len in [1, 2, 3, 5, 6, 7] {
            let input = [0u8; 7];
            assert_eq!(encoded_length(&input[..len]), None);
        }
    }

    #[test]
    fn adobe85_length_helper_is_an_uncompressed_upper_bound() {
        let expected = [0, 2, 3, 4, 5, 7, 8, 9, 10];
        let input = [0u8; 8];

        for (len, expected) in expected.into_iter().enumerate() {
            assert_eq!(encoded_length_adobe85(&input[..len]), expected);
        }

        let mut dst = [0xa5; 10];
        let encoded = ASCII85.encode_adobe85_into(&input, &mut dst).unwrap();
        assert_eq!(encoded, b"zz");
        assert_eq!(encoded.len() + 8, encoded_length_adobe85(&input));
        assert_eq!(&dst[2..], &[0xa5; 8]);

        let nonzero = [1u8; 8];
        let encoded = ASCII85.encode_adobe85_into(&nonzero, &mut dst).unwrap();
        assert_eq!(encoded.len(), encoded_length_adobe85(&nonzero));

        let mixed = [0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0];
        let mut mixed_dst = [0; 15];
        let encoded = ASCII85.encode_adobe85_into(&mixed, &mut mixed_dst).unwrap();
        assert_eq!(encoded.len() + 8, encoded_length_adobe85(&mixed));
    }

    #[test]
    fn known_vectors_select_the_requested_alphabet() {
        let input = [0x86u8, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b];
        let mut ascii85 = [0; 10];
        let mut z85 = [0; 10];
        let mut adobe85 = [0; 10];

        assert_eq!(
            ASCII85.try_encode_base85_into(&input, &mut ascii85),
            Some(b"L/669[9<6.".as_slice())
        );
        assert_eq!(
            Z85.try_encode_base85_into(&input, &mut z85),
            Some(b"HelloWorld".as_slice())
        );
        assert_eq!(
            ASCII85.encode_adobe85_into(&input, &mut adobe85),
            Some(b"L/669[9<6.".as_slice())
        );
    }

    #[test]
    fn empty_input_returns_an_empty_prefix_for_every_destination() {
        let mut empty = [];
        assert_eq!(
            ASCII85.try_encode_base85_into(b"", &mut empty),
            Some(&[][..])
        );
        assert_eq!(Z85.try_encode_base85_into(b"", &mut empty), Some(&[][..]));
        assert_eq!(ASCII85.encode_adobe85_into(b"", &mut empty), Some(&[][..]));

        let mut dst = [0xa5; 1];
        assert_eq!(ASCII85.try_encode_base85_into(b"", &mut dst), Some(&[][..]));
        assert_eq!(Z85.try_encode_base85_into(b"", &mut dst), Some(&[][..]));
        assert_eq!(ASCII85.encode_adobe85_into(b"", &mut dst), Some(&[][..]));
        assert_eq!(dst, [0xa5]);
    }

    #[test]
    fn strict_preflight_failures_leave_destinations_unchanged() {
        for encoder in [&ASCII85, &Z85] {
            let mut short = [0xa5; 4];
            assert_eq!(encoder.try_encode_base85_into(&[0; 4], &mut short), None);
            assert_eq!(short, [0xa5; 4]);

            let mut unaligned = [0xa5; 5];
            assert_eq!(
                encoder.try_encode_base85_into(&[0; 3], &mut unaligned),
                None
            );
            assert_eq!(unaligned, [0xa5; 5]);

            let mut oversized = [0xa5; 6];
            assert_eq!(
                encoder
                    .try_encode_base85_into(&[0; 4], &mut oversized)
                    .unwrap()
                    .len(),
                5
            );
            assert_eq!(oversized[5], 0xa5);
        }
    }

    #[test]
    fn adobe85_requires_the_full_bound_and_preserves_zero_tails() {
        let cases: &[(&[u8], &[u8])] = &[
            (&[0], b"!!"),
            (&[0, 0], b"!!!"),
            (&[0, 0, 0], b"!!!!"),
            (&[0, 0, 0, 0], b"z"),
            (&[0, 0, 0, 1], b"!!!!\""),
            (b"M", b"9`"),
            (b"Ma", b"9jn"),
            (b"Man", b"9jqo"),
            (b"Man s", b"9jqo^Er"),
        ];

        for &(input, expected) in cases {
            let mut dst = [0xa5; 10];
            let encoded = ASCII85.encode_adobe85_into(input, &mut dst).unwrap();
            assert_eq!(encoded, expected);
            let encoded_len = encoded.len();
            assert!(encoded_len <= encoded_length_adobe85(input));
            assert!(dst[encoded_len..].iter().all(|&byte| byte == 0xa5));
        }

        let mut compressed_but_short = [0xa5; 4];
        assert_eq!(
            ASCII85.encode_adobe85_into(&[0; 4], &mut compressed_but_short),
            None
        );
        assert_eq!(compressed_but_short, [0xa5; 4]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn allocating_encoders_match_slice_encoders() {
        let input = [0u8, 0, 0, 0, 0x86, 0x4f, 0xd2, 0x6f];
        let adobe85_inputs: &[&[u8]] = &[
            b"",
            &[0],
            &[0, 0],
            &[0, 0, 0],
            &[0, 0, 0, 0],
            b"M",
            b"Ma",
            b"Man",
            b"Man s",
            &input,
        ];

        for &adobe85_input in adobe85_inputs {
            let mut dst = [0; 16];
            let adobe85 = ASCII85
                .encode_adobe85_into(adobe85_input, &mut dst)
                .unwrap();
            assert_eq!(
                ASCII85.encode_adobe85_boxed(adobe85_input).as_ref(),
                adobe85
            );
            assert_eq!(
                ASCII85.encode_adobe85_string(adobe85_input).as_bytes(),
                adobe85
            );
        }

        let mut dst = [0; 10];

        let ascii85 = ASCII85.try_encode_base85_into(&input, &mut dst).unwrap();
        assert_eq!(
            ASCII85.try_encode_base85_boxed(&input).as_deref(),
            Some(ascii85)
        );
        assert_eq!(
            ASCII85.try_encode_base85_string(&input).as_deref(),
            core::str::from_utf8(ascii85).ok()
        );

        let z85 = Z85.try_encode_base85_into(&input, &mut dst).unwrap();
        assert_eq!(Z85.try_encode_base85_boxed(&input).as_deref(), Some(z85));
        assert_eq!(
            Z85.try_encode_base85_string(&input).as_deref(),
            core::str::from_utf8(z85).ok()
        );
    }
}

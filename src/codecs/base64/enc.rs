// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Canonical padded Base64 and Base64URL encoders.
//!
//! The Base64URL variant substitutes `-` and `_` for the standard alphabet's
//! `+` and `/`; both variants retain RFC 4648 end padding.
//!
//! ```rust
//! use b2t_codecs::base64::{try_encode_into_base64, try_encode_into_base64url};
//!
//! let mut base64 = [0; 4];
//! let mut base64url = [0; 4];
//!
//! assert_eq!(try_encode_into_base64(&[0xfb, 0xff], &mut base64), Some(b"+/8=".as_slice()));
//! assert_eq!(try_encode_into_base64url(&[0xfb, 0xff], &mut base64url), Some(b"-_8=".as_slice()));
//! ```
use super::BASE64_PAD;

pub(super) const BASE64_RFC: Encoder = const {
    use super::ENCODER;
    Encoder::from_alphabet(&ENCODER)
};
pub(super) const BASE64_URL: Encoder = const {
    use super::ENCODER_URL;
    Encoder::from_alphabet(&ENCODER_URL)
};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String, vec::Vec};

/// Encodes `bytes` as a canonical padded Base64 string.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[cfg(feature = "alloc")]
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base64_string(bytes: &[u8]) -> String {
    BASE64_RFC.encode_string(bytes)
}

/// Encodes `bytes` as a canonical padded Base64URL string.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[cfg(feature = "alloc")]
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base64url_string(bytes: &[u8]) -> String {
    BASE64_URL.encode_string(bytes)
}

/// Encodes `bytes` as canonical padded Base64 ASCII bytes.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[cfg(feature = "alloc")]
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base64(bytes: &[u8]) -> Box<[u8]> {
    BASE64_RFC.encode_boxed(bytes)
}

/// Encodes `bytes` as canonical padded Base64URL ASCII bytes.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[cfg(feature = "alloc")]
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base64url(bytes: &[u8]) -> Box<[u8]> {
    BASE64_URL.encode_boxed(bytes)
}

/// Returns the exact number of bytes needed to encode `bytes` as padded Base64.
///
/// Base64 emits four ASCII bytes for every complete or partial three-byte
/// input quantum.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoded size should be used"]
#[inline]
pub fn encoded_length_base64(bytes: &[u8]) -> usize {
    encoded_length(bytes)
}

#[inline]
fn encoded_length(bytes: &[u8]) -> usize {
    bytes
        .len()
        .div_ceil(3)
        .checked_mul(4)
        .expect("base64 encoded length overflow")
}

/// Encodes `src` as canonical padded Base64 into the beginning of `dst`.
///
/// Returns the initialized prefix of `dst`, or [`None`] if `dst` is shorter
/// than [`encoded_length_base64(src)`](encoded_length_base64). A short
/// destination is left unchanged. Any bytes after the encoded prefix are also
/// left unchanged. This function does not allocate.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_into_base64<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    BASE64_RFC.encode_into(src, dst)
}

/// Encodes `src` as canonical padded Base64URL into the beginning of `dst`.
///
/// Returns the initialized prefix of `dst`, or [`None`] if `dst` is shorter
/// than [`encoded_length_base64(src)`](encoded_length_base64). A short
/// destination is left unchanged. Any bytes after the encoded prefix are also
/// left unchanged. This function does not allocate.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoding result should be handled"]
#[inline]
pub fn try_encode_into_base64url<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    BASE64_URL.encode_into(src, dst)
}

pub(super) struct Encoder<'e> {
    encoder: &'e [u8],
}

impl<'e> Encoder<'e> {
    #[inline]
    const fn from_alphabet(encoder: &'e [u8]) -> Self {
        // INVARIANT: encoder table MUST be exactly 64
        assert!(encoder.len() == 64);
        assert!(0x3f < encoder.len());
        Self { encoder }
    }

    #[cfg(feature = "alloc")]
    #[inline]
    fn encode_string(&self, bytes: &[u8]) -> String {
        let encoded = self.encode_boxed(bytes);
        // SAFETY: base64 bytes are ASCII, therefore always valid UTF-8.
        unsafe { String::from_utf8_unchecked(encoded.into_vec()) }
    }

    #[cfg(feature = "alloc")]
    pub(super) fn encode_boxed(&self, bytes: &[u8]) -> Box<[u8]> {
        if bytes.is_empty() {
            return Vec::<u8>::new().into_boxed_slice();
        }

        let payload_len = encoded_length(bytes);
        let mut dst = Box::<[u8]>::new_uninit_slice(payload_len);

        let (chunks, rem) = bytes.as_chunks::<3>();
        let mut written = 0usize;

        for &chunk in chunks {
            let chunk = self.encode_base64_full_chunk(chunk);
            dst[written..written + 4].write_copy_of_slice(&chunk);
            written += 4;
        }

        if !rem.is_empty() {
            let chunk = self.encode_base64_tail(rem);
            dst[written..written + 4].write_copy_of_slice(&chunk);
            written += 4;
        }

        // SAFETY:
        //  - `dst` contains `payload_len` consecutive `MaybeUninit<u8>` values.
        //  - A `MaybeUninit<u8>` pointer is valid for writes through a `u8`
        //    pointer.
        //  - initialized exactly `payload_len` bytes.
        unsafe {
            // INVARIANT: all allocated elements were initialized.
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

        let (chunks, rem) = src.as_chunks::<3>();
        let mut written = 0usize;

        for &chunk in chunks {
            let chunk = self.encode_base64_full_chunk(chunk);
            dst[written..written + 4].copy_from_slice(&chunk);
            written += 4;
        }

        if !rem.is_empty() {
            let chunk = self.encode_base64_tail(rem);
            dst[written..written + 4].copy_from_slice(&chunk);
            written += 4;
        }

        // INVARIANT: `written == encoded_length_base64(src)`, therefore
        // `written <= dst.len()`.
        assert!(written == payload_len);
        Some(&dst[..payload_len])
    }

    fn encode_base64_full_chunk(&self, chunk: [u8; 3]) -> [u8; 4] {
        // pack each byte into a u32
        let n = u32::from_be_bytes([0, chunk[0], chunk[1], chunk[2]]);

        // the four 6-bit hexads
        let on = n >> 18 & 0x3f; // Not required, but ensures safe indexing if n isn't initialized to zero.
        let tw = n >> 12 & 0x3f;
        let th = n >> 6 & 0x3f;
        let fo = n & 0x3f;

        // the four encoded bytes
        // SAFETY: six-bit hexad 3F is guaranteed to be on the range [0, 64)
        let on = unsafe { *self.encoder.get_unchecked(on as usize) };
        // SAFETY: six-bit hexad 3F is guaranteed to be on the range [0, 64)
        let tw = unsafe { *self.encoder.get_unchecked(tw as usize) };
        // SAFETY: six-bit hexad 3F is guaranteed to be on the range [0, 64)
        let th = unsafe { *self.encoder.get_unchecked(th as usize) };
        // SAFETY: six-bit hexad 3F is guaranteed to be on the range [0, 64)
        let fo = unsafe { *self.encoder.get_unchecked(fo as usize) };

        [on, tw, th, fo]
    }

    fn encode_base64_tail(&self, tail: &[u8]) -> [u8; 4] {
        // must be 1 or 2
        let len = tail.len();

        // pad with null bytes for encoding
        // "These pad bits MUST be set to zero by conforming encoders..."
        let mut padded = [0u8; 3];
        padded[..len].copy_from_slice(tail);
        let mut encoded = self.encode_base64_full_chunk(padded);

        // replace bytes in the encoded position with b'=' based on tail length
        //      - 1 byte  => two encoded bytes and two pad bytes
        //      - 2 bytes => three encoded bytes and single pad byte
        // That is, N_PAD_START = len + 1
        encoded[len + 1..].fill(BASE64_PAD);

        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::{BASE64_RFC, BASE64_URL, Encoder, encoded_length};

    #[cfg(feature = "alloc")]
    use super::BASE64_PAD;

    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;

    #[test]
    fn rfc_4648_base64_test_vectors_pin_encoding() {
        let vectors: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];

        for &(plain, base64) in vectors {
            let mut dst = [0u8; 8];
            assert_eq!(
                BASE64_RFC.encode_into(plain, &mut dst),
                Some(base64.as_bytes())
            );

            // These RFC vectors do not use alphabet digits 62 or 63, so their
            // Base64 and Base64URL encodings are identical.
            let mut dst = [0u8; 8];
            assert_eq!(
                BASE64_URL.encode_into(plain, &mut dst),
                Some(base64.as_bytes())
            );

            #[cfg(feature = "alloc")]
            {
                assert_eq!(BASE64_RFC.encode_boxed(plain).as_ref(), base64.as_bytes());
                assert_eq!(BASE64_RFC.encode_string(plain), base64);
                assert_eq!(BASE64_URL.encode_boxed(plain).as_ref(), base64.as_bytes());
                assert_eq!(BASE64_URL.encode_string(plain), base64);
            }
        }
    }

    #[test]
    fn base64url_encoding_uses_url_safe_alphabet() {
        let vectors: &[(&[u8], &str, &str)] = &[
            (&[0xfb], "+w==", "-w=="),
            (&[0xfb, 0xff], "+/8=", "-_8="),
            (&[0xfb, 0xff, 0xff], "+///", "-___"),
        ];

        for &(plain, base64, base64url) in vectors {
            let mut dst = [0u8; 4];
            assert_eq!(
                BASE64_RFC.encode_into(plain, &mut dst),
                Some(base64.as_bytes())
            );

            let mut dst = [0u8; 4];
            assert_eq!(
                BASE64_URL.encode_into(plain, &mut dst),
                Some(base64url.as_bytes())
            );

            #[cfg(feature = "alloc")]
            {
                assert_eq!(BASE64_RFC.encode_boxed(plain).as_ref(), base64.as_bytes());
                assert_eq!(BASE64_RFC.encode_string(plain), base64);
                assert_eq!(
                    BASE64_URL.encode_boxed(plain).as_ref(),
                    base64url.as_bytes()
                );
                assert_eq!(BASE64_URL.encode_string(plain), base64url);
            }
        }
    }

    #[test]
    fn encoded_lengths_are_exact() {
        assert_eq!(encoded_length(b""), 0);
        assert_eq!(encoded_length(&[0]), 4);
        assert_eq!(encoded_length(&[0; 2]), 4);
        assert_eq!(encoded_length(&[0; 3]), 4);
        assert_eq!(encoded_length(&[0; 4]), 8);
        assert_eq!(encoded_length(&[0; 32]), 44);
    }

    #[test]
    fn slice_encoders_write_only_the_returned_prefix() {
        let mut base64 = [b'!'; 6];
        assert_eq!(
            BASE64_RFC.encode_into(&[0xfb, 0xff], &mut base64),
            Some(b"+/8=".as_slice()),
        );
        assert_eq!(&base64[4..], b"!!");

        let mut base64url = [b'?'; 6];
        assert_eq!(
            BASE64_URL.encode_into(&[0xfb, 0xff], &mut base64url),
            Some(b"-_8=".as_slice()),
        );
        assert_eq!(&base64url[4..], b"??");

        let mut untouched = [b'x'; 1];
        let dst_ptr = untouched.as_ptr();
        let encoded = BASE64_RFC.encode_into(b"", &mut untouched).unwrap();
        assert!(encoded.is_empty());
        assert_eq!(encoded.as_ptr(), dst_ptr);
        assert_eq!(untouched, [b'x']);
    }

    #[test]
    fn slice_encoders_return_none_for_a_short_destination() {
        let mut base64 = [b'!'; 3];
        assert_eq!(BASE64_RFC.encode_into(&[0xfb, 0xff], &mut base64), None);
        assert_eq!(base64, [b'!'; 3]);

        let mut base64url = [b'?'; 3];
        assert_eq!(BASE64_URL.encode_into(&[0xfb, 0xff], &mut base64url), None,);
        assert_eq!(base64url, [b'?'; 3]);
    }

    #[test]
    fn encoder_alphabets_preserve_unsafe_indexing_and_utf8_invariants() {
        fn assert_invariants(encoder: &Encoder<'_>) {
            assert_eq!(encoder.encoder.len(), 64);

            let mut seen = [false; 128];
            for &ascii in encoder.encoder {
                assert!(ascii.is_ascii());
                assert!(!seen[ascii as usize], "duplicate byte at ASCII {ascii}");
                seen[ascii as usize] = true;
            }
        }

        assert_invariants(&BASE64_RFC);
        assert_invariants(&BASE64_URL);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn byte_slices_of_arbitrary_lengths_encode_canonically() {
        let codecs: &[(&str, &Encoder<'_>, &[u8])] = &[
            ("Base64", &BASE64_RFC, BASE64_RFC.encoder),
            ("Base64URL", &BASE64_URL, BASE64_URL.encoder),
        ];

        for len in 0usize..=64 {
            let input: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(73).wrapping_add(len * 19)) as u8)
                .collect();
            let padding = match len % 3 {
                0 => 0,
                1 => 2,
                2 => 1,
                _ => unreachable!(),
            };

            for &(name, encode, alphabet) in codecs {
                let encoded = encode.encode_boxed(&input);

                assert_eq!(encoded.len(), len.div_ceil(3) * 4, "{name}, len {len}");
                assert_eq!(encode.encode_string(&input).as_bytes(), encoded.as_ref());
                assert!(
                    encoded[..encoded.len() - padding]
                        .iter()
                        .all(|byte| alphabet.contains(byte)),
                    "{name} emitted a byte outside its alphabet for len {len}"
                );
                assert!(
                    encoded[encoded.len() - padding..]
                        .iter()
                        .all(|&byte| byte == BASE64_PAD),
                    "{name} emitted malformed padding for len {len}"
                );
            }
        }
    }
}

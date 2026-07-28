// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Canonical padded Base64 and Base64URL encoders.
//!
//! The Base64URL variant substitutes `-` and `_` for the standard alphabet's
//! `+` and `/`; both variants retain RFC 4648 end padding.
//!
//! ```rust
//! use b2t_codecs::base64::{encode_base64_string, encode_base64url_string};
//!
//! assert_eq!(encode_base64_string(&[0xfb, 0xff]), "+/8=");
//! assert_eq!(encode_base64url_string(&[0xfb, 0xff]), "-_8=");
//! ```
use super::BASE64_PAD;

const BASE64_RFC: Encoder = const {
    use super::ENCODER;
    Encoder::from_alphabet(&ENCODER)
};
const BASE64_URL: Encoder = const {
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
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base64_string(bytes: &[u8]) -> String {
    BASE64_RFC.encode_base64_string(bytes)
}

/// Encodes `bytes` as a canonical padded Base64URL string.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base64url_string(bytes: &[u8]) -> String {
    BASE64_URL.encode_base64_string(bytes)
}

/// Encodes `bytes` as canonical padded Base64 ASCII bytes.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base64(bytes: &[u8]) -> Box<[u8]> {
    BASE64_RFC.encode_base64(bytes)
}

/// Encodes `bytes` as canonical padded Base64URL ASCII bytes.
///
/// # Panics
///
/// Panics if the encoded length cannot be represented as a [`usize`].
#[must_use = "the encoded value should be used"]
#[inline]
pub fn encode_base64url(bytes: &[u8]) -> Box<[u8]> {
    BASE64_URL.encode_base64(bytes)
}

struct Encoder<'e> {
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

    #[inline]
    fn encode_base64_string(&self, bytes: &[u8]) -> String {
        let enc = self.encode_base64(bytes);
        // SAFETY: base64 bytes are ASCII, therefore always valid UTF-8
        unsafe { String::from_utf8_unchecked(enc.into_vec()) }
    }

    fn encode_base64(&self, bytes: &[u8]) -> Box<[u8]> {
        if bytes.is_empty() {
            return Vec::<u8>::new().into_boxed_slice();
        }

        // base64 encodes four ASCII bytes per three byte chunks
        // and at most four extra bytes for a padded tail
        let capacity = bytes
            .len()
            .checked_mul(4)
            .expect("base64 encoded length overflow")
            / 3
            + 4;

        let (chunks, remainder) = bytes.as_chunks::<3>();
        let mut ret = Vec::<u8>::with_capacity(capacity);

        for &chunk in chunks {
            ret.extend_from_slice(&self.encode_base64_full_chunk(chunk));
        }

        if !remainder.is_empty() {
            let chunk = self.encode_base64_tail(remainder);
            ret.extend_from_slice(&chunk);
        }

        ret.into_boxed_slice()
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
    use super::*;

    type EncodeBytes = fn(&[u8]) -> Box<[u8]>;
    type EncodeString = fn(&[u8]) -> String;

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
            assert_eq!(encode_base64(plain).as_ref(), base64.as_bytes());
            assert_eq!(encode_base64_string(plain), base64);

            // These RFC vectors do not use alphabet digits 62 or 63, so their
            // Base64 and Base64URL encodings are identical.
            assert_eq!(encode_base64url(plain).as_ref(), base64.as_bytes());
            assert_eq!(encode_base64url_string(plain), base64);
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
            assert_eq!(encode_base64(plain).as_ref(), base64.as_bytes());
            assert_eq!(encode_base64_string(plain), base64);
            assert_eq!(encode_base64url(plain).as_ref(), base64url.as_bytes());
            assert_eq!(encode_base64url_string(plain), base64url);
        }
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

    #[test]
    fn byte_slices_of_arbitrary_lengths_encode_canonically() {
        let codecs: &[(&str, EncodeBytes, EncodeString, &[u8])] = &[
            (
                "Base64",
                encode_base64,
                encode_base64_string,
                BASE64_RFC.encoder,
            ),
            (
                "Base64URL",
                encode_base64url,
                encode_base64url_string,
                BASE64_URL.encoder,
            ),
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

            for &(name, encode, encode_string, alphabet) in codecs {
                let encoded = encode(&input);

                assert_eq!(encoded.len(), len.div_ceil(3) * 4, "{name}, len {len}");
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
                        .all(|&byte| byte == BASE64_PAD),
                    "{name} emitted malformed padding for len {len}"
                );
            }
        }
    }
}

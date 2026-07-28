// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Canonical RFC 4648 Base64 and Base64URL codecs.
//!
//! Encoders emit padded ASCII. Strict decoders require complete quanta and
//! terminal canonical padding; extended decoders additionally accept unpadded
//! tails, concatenated padded values, and padding-only quanta.
//!
//! ```rust
//! use b2t_codecs::base64::{encode_base64url_string, try_decode_base64url_string};
//!
//! let encoded = encode_base64url_string(b"Hello,World!");
//! assert_eq!(encoded, "SGVsbG8sV29ybGQh");
//!
//! let decoded = &*try_decode_base64url_string(&encoded).unwrap();
//! assert_eq!(decoded, b"Hello,World!");
//! ```
// BASE64 CODEC
// Canonical RFC 4648 Base64 and Base64URL codecs. Strict decoders reject
// non-zero pad-bit aliases, missing padding, and malformed inputs; extended
// decoders additionally support unpadded tails and concatenated padded values.
// https://www.rfc-editor.org/rfc/rfc4648.html

mod dec;
mod enc;

pub use dec::{
    try_decode_base64, try_decode_base64_string, try_decode_base64ext, try_decode_base64ext_string,
    try_decode_base64url, try_decode_base64url_string, try_decode_base64urlext,
    try_decode_base64urlext_string,
};
pub use enc::{encode_base64, encode_base64_string, encode_base64url, encode_base64url_string};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String, vec::Vec};

const ENCODER: [u8; 64] = [
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
    89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
    115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 43, 47,
];

// ASCII-ordered decoding table on the range [MIN_ASCII, MAX_ASCII)
// INVARIANT: non-base64 ASCII values MUST be marked with the sentinel 255
// INVARIANT: base64 ASCII values MUST be marked with their location in the encoder alphabet
const DECODER: [u8; 80] = [
    62, 255, 255, 255, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 255, 255, 255,
    255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    25, 255, 255, 255, 255, 255, 255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
];

// INVARIANT: base64 bytes MUST fall within the range [MIN_ASCII, MAX_ASCII)
// INVARIANT: MAX_ASCII - MIN_ASCII == DECODER.len()
const MIN_ASCII: usize = 43;
const MAX_ASCII: usize = 122 + 1; // Exclusive; one past the end.

// url-safe base64
const ENCODER_URL: [u8; 64] = [
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
    89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
    115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95,
];

const DECODER_URL: [u8; 78] = [
    62, 255, 255, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 255, 255, 255, 255, 0, 1,
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255,
    255, 255, 255, 63, 255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
    44, 45, 46, 47, 48, 49, 50, 51,
];

const MIN_ASCII_URL: usize = 45;
const MAX_ASCII_URL: usize = 122 + 1; // Exclusive; one past the end.

const BASE64_PAD: u8 = b'=';

/// Removes every trailing Base64 padding byte (`=`).
///
/// This function does not validate the input and leaves non-trailing bytes
/// unchanged.
#[must_use = "the unpadded value should be used"]
#[inline]
pub fn trim_base64_end_padding(bytes: Box<[u8]>) -> Box<[u8]> {
    let mut bytes = bytes.into_vec();
    while let Some(&c) = bytes.last() {
        if c != BASE64_PAD {
            break;
        }
        bytes.pop();
    }

    bytes.into_boxed_slice()
}

mod sealed {
    /// Prevents downstream implementations of the public conversion traits.
    pub trait Sealed {}
}

/// Converts fixed-width integers to and from canonical RFC 4648 Base64.
///
/// This sealed trait is implemented for all fixed-width signed and unsigned
/// primitive integer types. Values are encoded from their big-endian bytes at
/// their full type width.
pub trait Base64: sealed::Sealed + Copy {
    /// Returns the padded Base64 encoding of this value.
    #[must_use = "the encoded value should be used"]
    fn as_base64_string(&self) -> String;

    /// Returns the padded Base64 ASCII bytes for this value.
    #[must_use = "the encoded value should be used"]
    fn as_base64(&self) -> Box<[u8]>;

    /// Decodes a canonical Base64 string into a value of exactly this type's width.
    ///
    /// Returns [`None`] if `base64_str` is malformed, non-canonical, or decodes
    /// to the wrong number of bytes.
    #[must_use = "the decoding result should be handled"]
    fn try_from_base64_string(base64_str: &str) -> Option<Self>;

    /// Decodes canonical Base64 ASCII into a value of exactly this type's width.
    ///
    /// Returns [`None`] if `base64` is malformed, non-canonical, or decodes to
    /// the wrong number of bytes.
    #[must_use = "the decoding result should be handled"]
    fn try_from_base64(base64: &[u8]) -> Option<Self>;
}

/// Converts fixed-width integers to and from canonical RFC 4648 Base64URL.
///
/// This sealed trait is implemented for all fixed-width signed and unsigned
/// primitive integer types. Values are encoded from their big-endian bytes at
/// their full type width.
pub trait Base64Url: sealed::Sealed + Copy {
    /// Returns the padded Base64URL encoding of this value.
    #[must_use = "the encoded value should be used"]
    fn as_base64url_string(&self) -> String;

    /// Returns the padded Base64URL ASCII bytes for this value.
    #[must_use = "the encoded value should be used"]
    fn as_base64url(&self) -> Box<[u8]>;

    /// Decodes a canonical Base64URL string into a value of this type's width.
    ///
    /// Returns [`None`] if `base64_str` is malformed, non-canonical, or decodes
    /// to the wrong number of bytes.
    #[must_use = "the decoding result should be handled"]
    fn try_from_base64url_string(base64_str: &str) -> Option<Self>;

    /// Decodes canonical Base64URL ASCII into a value of this type's width.
    ///
    /// Returns [`None`] if `base64` is malformed, non-canonical, or decodes to
    /// the wrong number of bytes.
    #[must_use = "the decoding result should be handled"]
    fn try_from_base64url(base64: &[u8]) -> Option<Self>;
}

macro_rules! impl_base64 {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl sealed::Sealed for $ty {}

            impl Base64 for $ty {
                #[inline]
                fn as_base64_string(&self) -> String {
                    encode_base64_string(&self.to_be_bytes())
                }

                #[inline]
                fn as_base64(&self) -> Box<[u8]> {
                    encode_base64(&self.to_be_bytes())
                }

                #[inline]
                fn try_from_base64_string(base64_str: &str) -> Option<Self> {
                    Self::try_from_base64(base64_str.as_bytes())
                }

                #[inline]
                fn try_from_base64(base64: &[u8]) -> Option<Self> {
                    if let Some(bytes) = try_decode_base64(base64) {
                        const SIZE: usize = core::mem::size_of::<$ty>();
                        if bytes.len() != SIZE {
                            return None;
                        }

                        let bytes = bytes.as_ref().try_into().ok()?;
                        return Some(Self::from_be_bytes(bytes));
                    }

                    None
                }
            }

            impl Base64Url for $ty {
                #[inline]
                fn as_base64url_string(&self) -> String {
                    encode_base64url_string(&self.to_be_bytes())
                }

                #[inline]
                fn as_base64url(&self) -> Box<[u8]> {
                    encode_base64url(&self.to_be_bytes())
                }

                #[inline]
                fn try_from_base64url_string(base64_str: &str) -> Option<Self> {
                    Self::try_from_base64url(base64_str.as_bytes())
                }

                #[inline]
                fn try_from_base64url(base64: &[u8]) -> Option<Self> {
                    if let Some(bytes) = try_decode_base64url(base64) {
                        const SIZE: usize = core::mem::size_of::<$ty>();
                        if bytes.len() != SIZE {
                            return None;
                        }

                        let bytes = bytes.as_ref().try_into().ok()?;
                        return Some(Self::from_be_bytes(bytes));
                    }

                    None
                }
            }
        )+
    };
}

impl_base64!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::fmt::Debug;

    fn assert_primitive_encoding<T>(value: T, expected: &str)
    where
        T: Base64 + Base64Url + Copy + Debug + Eq,
    {
        let encoded_string = value.as_base64_string();
        let encoded = value.as_base64();

        assert_eq!(encoded_string, expected);
        assert_eq!(encoded.as_ref(), expected.as_bytes());
        assert_eq!(T::try_from_base64_string(&encoded_string), Some(value));
        assert_eq!(T::try_from_base64(&encoded), Some(value));

        let expected_url = expected.replace('+', "-").replace('/', "_");
        let encoded_url_string = value.as_base64url_string();
        let encoded_url = value.as_base64url();

        assert_eq!(encoded_url_string, expected_url);
        assert_eq!(encoded_url.as_ref(), expected_url.as_bytes());
        assert_eq!(
            T::try_from_base64url_string(&encoded_url_string),
            Some(value)
        );
        assert_eq!(T::try_from_base64url(&encoded_url), Some(value));
    }

    #[test]
    fn integer_primitive_encodings_are_pinned() {
        macro_rules! assert_min_and_max_encoding {
            ($ty:ty, $min:literal, $max:literal) => {
                assert_primitive_encoding(<$ty>::MIN, $min);
                assert_primitive_encoding(<$ty>::MAX, $max);
            };
        }

        assert_min_and_max_encoding!(u8, "AA==", "/w==");
        assert_min_and_max_encoding!(u16, "AAA=", "//8=");
        assert_min_and_max_encoding!(u32, "AAAAAA==", "/////w==");
        assert_min_and_max_encoding!(u64, "AAAAAAAAAAA=", "//////////8=");
        assert_min_and_max_encoding!(u128, "AAAAAAAAAAAAAAAAAAAAAA==", "/////////////////////w==");

        assert_min_and_max_encoding!(i8, "gA==", "fw==");
        assert_min_and_max_encoding!(i16, "gAA=", "f/8=");
        assert_min_and_max_encoding!(i32, "gAAAAA==", "f////w==");
        assert_min_and_max_encoding!(i64, "gAAAAAAAAAA=", "f/////////8=");
        assert_min_and_max_encoding!(i128, "gAAAAAAAAAAAAAAAAAAAAA==", "f////////////////////w==");

        // Exercise alphabet digit 62 as well as the digit-63 cases above.
        assert_primitive_encoding(0xfbu8, "+w==");
    }

    #[test]
    fn integer_primitive_decoding_requires_the_exact_data_width() {
        assert_eq!(u32::try_from_base64(b"AAA="), None);
        assert_eq!(u32::try_from_base64(b"AAAAAA=="), Some(0));
        assert_eq!(u32::try_from_base64(b"AAAAAAAAAAA="), None);

        assert_eq!(u32::try_from_base64url(b"AAA="), None);
        assert_eq!(u32::try_from_base64url(b"AAAAAA=="), Some(0));
        assert_eq!(u32::try_from_base64url(b"AAAAAAAAAAA="), None);
    }

    #[test]
    fn primitive_decoders_do_not_mix_base64_alphabets() {
        assert_eq!(u8::try_from_base64(b"+w=="), Some(0xfb));
        assert_eq!(u8::try_from_base64(b"-w=="), None);
        assert_eq!(u8::try_from_base64url(b"-w=="), Some(0xfb));
        assert_eq!(u8::try_from_base64url(b"+w=="), None);

        assert_eq!(u8::try_from_base64(b"/w=="), Some(u8::MAX));
        assert_eq!(u8::try_from_base64(b"_w=="), None);
        assert_eq!(u8::try_from_base64url(b"_w=="), Some(u8::MAX));
        assert_eq!(u8::try_from_base64url(b"/w=="), None);
    }

    #[test]
    fn trim_base64_end_padding_removes_only_trailing_padding() {
        assert_eq!(
            trim_base64_end_padding(Box::from(b"".as_slice())).as_ref(),
            b""
        );
        assert_eq!(
            trim_base64_end_padding(Box::from(b"Zg==".as_slice())).as_ref(),
            b"Zg"
        );
        assert_eq!(
            trim_base64_end_padding(Box::from(b"Zm8=".as_slice())).as_ref(),
            b"Zm8"
        );
        assert_eq!(
            trim_base64_end_padding(Box::from(b"=Zm9v".as_slice())).as_ref(),
            b"=Zm9v"
        );
    }
}

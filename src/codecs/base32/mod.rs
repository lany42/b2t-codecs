// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Canonical RFC 4648 Base32 and Base32Hex codecs.
//!
//! Encoders emit uppercase ASCII with required end padding. Decoders require
//! complete eight-symbol quanta, canonical zero pad bits, and padding only in
//! the final quantum.
//!
//! ```rust
//! use b2t_codecs::base32::{encode_base32_string, try_decode_base32_string};
//!
//! let encoded = encode_base32_string(b"Hello,World!");
//! assert_eq!(encoded, "JBSWY3DPFRLW64TMMQQQ====");
//!
//! let decoded = &*try_decode_base32_string(&encoded).unwrap();
//! assert_eq!(decoded, b"Hello,World!");
//! ```
// BASE32 CODEC
// Canonical RFC 4648 Base32 and Base32Hex codecs. Strict decoders reject
// non-zero pad-bit aliases, missing padding, and malformed inputs.
// https://www.rfc-editor.org/rfc/rfc4648.html

mod dec;
mod enc;

pub use dec::{
    try_decode_base32, try_decode_base32_string, try_decode_base32hex, try_decode_base32hex_string,
};
pub use enc::{encode_base32, encode_base32_string, encode_base32hex, encode_base32hex_string};

const ENCODER: [u8; 32] = [
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
    89, 90, 50, 51, 52, 53, 54, 55,
];

// ASCII-ordered decoding table on the range [MIN_ASCII, MAX_ASCII).
// INVARIANT: non-base32 ASCII values MUST be marked with the sentinel 255.
// INVARIANT: base32 ASCII values MUST contain their location in the encoder alphabet.
const DECODER: [u8; 41] = [
    26, 27, 28, 29, 30, 31, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
];

// INVARIANT: base32 bytes MUST fall within the range [MIN_ASCII, MAX_ASCII).
// INVARIANT: MAX_ASCII - MIN_ASCII == DECODER.len().
const MIN_ASCII: usize = 50;
const MAX_ASCII: usize = 90 + 1; // Exclusive; one past the end.

const ENCODER_HEX: [u8; 32] = [
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78,
    79, 80, 81, 82, 83, 84, 85, 86,
];

// ASCII-ordered decoding table on the range [MIN_ASCII_HEX, MAX_ASCII_HEX).
// INVARIANT: non-base32hex ASCII values MUST be marked with the sentinel 255.
// INVARIANT: base32hex ASCII values MUST contain their location in the encoder alphabet.
const DECODER_HEX: [u8; 39] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255, 255, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];

// INVARIANT: base32hex bytes MUST fall within the range [MIN_ASCII_HEX, MAX_ASCII_HEX).
// INVARIANT: MAX_ASCII_HEX - MIN_ASCII_HEX == DECODER_HEX.len().
const MIN_ASCII_HEX: usize = 48;
const MAX_ASCII_HEX: usize = 86 + 1; // Exclusive; one past the end.

const BASE32_PAD: u8 = b'=';

mod sealed {
    /// Prevents downstream implementations of the public conversion traits.
    pub trait Sealed {}
}

/// Converts fixed-width integers to and from canonical RFC 4648 Base32.
///
/// This sealed trait is implemented for all fixed-width signed and unsigned
/// primitive integer types. Values are encoded from their big-endian bytes at
/// their full type width.
pub trait Base32: sealed::Sealed + Copy {
    /// Returns the padded Base32 encoding of this value.
    #[must_use = "the encoded value should be used"]
    fn as_base32_string(&self) -> String;

    /// Returns the padded Base32 ASCII bytes for this value.
    #[must_use = "the encoded value should be used"]
    fn as_base32(&self) -> Box<[u8]>;

    /// Decodes a canonical Base32 string into a value of exactly this type's width.
    ///
    /// Returns [`None`] if `base32_str` is malformed, non-canonical, or decodes
    /// to the wrong number of bytes.
    #[must_use = "the decoding result should be handled"]
    fn try_from_base32_string(base32_str: &str) -> Option<Self>;

    /// Decodes canonical Base32 ASCII into a value of exactly this type's width.
    ///
    /// Returns [`None`] if `base32` is malformed, non-canonical, or decodes to
    /// the wrong number of bytes.
    #[must_use = "the decoding result should be handled"]
    fn try_from_base32(base32: &[u8]) -> Option<Self>;
}

/// Converts fixed-width integers to and from canonical RFC 4648 Base32Hex.
///
/// This sealed trait is implemented for all fixed-width signed and unsigned
/// primitive integer types. Values are encoded from their big-endian bytes at
/// their full type width.
pub trait Base32Hex: sealed::Sealed + Copy {
    /// Returns the padded Base32Hex encoding of this value.
    #[must_use = "the encoded value should be used"]
    fn as_base32hex_string(&self) -> String;

    /// Returns the padded Base32Hex ASCII bytes for this value.
    #[must_use = "the encoded value should be used"]
    fn as_base32hex(&self) -> Box<[u8]>;

    /// Decodes a canonical Base32Hex string into a value of this type's width.
    ///
    /// Returns [`None`] if `base32hex_str` is malformed, non-canonical, or
    /// decodes to the wrong number of bytes.
    #[must_use = "the decoding result should be handled"]
    fn try_from_base32hex_string(base32hex_str: &str) -> Option<Self>;

    /// Decodes canonical Base32Hex ASCII into a value of this type's width.
    ///
    /// Returns [`None`] if `base32hex` is malformed, non-canonical, or decodes
    /// to the wrong number of bytes.
    #[must_use = "the decoding result should be handled"]
    fn try_from_base32hex(base32hex: &[u8]) -> Option<Self>;
}

macro_rules! impl_base32 {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl sealed::Sealed for $ty {}

            impl Base32 for $ty {
                #[inline]
                fn as_base32_string(&self) -> String {
                    encode_base32_string(&self.to_be_bytes())
                }

                #[inline]
                fn as_base32(&self) -> Box<[u8]> {
                    encode_base32(&self.to_be_bytes())
                }

                #[inline]
                fn try_from_base32_string(base32_str: &str) -> Option<Self> {
                    Self::try_from_base32(base32_str.as_bytes())
                }

                #[inline]
                fn try_from_base32(base32: &[u8]) -> Option<Self> {
                    if let Some(bytes) = try_decode_base32(base32) {
                        const SIZE: usize = std::mem::size_of::<$ty>();
                        if bytes.len() != SIZE {
                            return None;
                        }

                        let bytes = bytes.as_ref().try_into().ok()?;
                        return Some(Self::from_be_bytes(bytes));
                    }

                    None
                }
            }

            impl Base32Hex for $ty {
                #[inline]
                fn as_base32hex_string(&self) -> String {
                    encode_base32hex_string(&self.to_be_bytes())
                }

                #[inline]
                fn as_base32hex(&self) -> Box<[u8]> {
                    encode_base32hex(&self.to_be_bytes())
                }

                #[inline]
                fn try_from_base32hex_string(base32hex_str: &str) -> Option<Self> {
                    Self::try_from_base32hex(base32hex_str.as_bytes())
                }

                #[inline]
                fn try_from_base32hex(base32hex: &[u8]) -> Option<Self> {
                    if let Some(bytes) = try_decode_base32hex(base32hex) {
                        const SIZE: usize = std::mem::size_of::<$ty>();
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

impl_base32!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Debug;

    fn assert_primitive_encoding<T>(value: T, expected: &str, expected_hex: &str)
    where
        T: Base32 + Base32Hex + Copy + Debug + Eq,
    {
        let encoded_string = value.as_base32_string();
        let encoded = value.as_base32();

        assert_eq!(encoded_string, expected);
        assert_eq!(encoded.as_ref(), expected.as_bytes());
        assert_eq!(T::try_from_base32_string(&encoded_string), Some(value));
        assert_eq!(T::try_from_base32(&encoded), Some(value));

        let encoded_hex_string = value.as_base32hex_string();
        let encoded_hex = value.as_base32hex();

        assert_eq!(encoded_hex_string, expected_hex);
        assert_eq!(encoded_hex.as_ref(), expected_hex.as_bytes());
        assert_eq!(
            T::try_from_base32hex_string(&encoded_hex_string),
            Some(value)
        );
        assert_eq!(T::try_from_base32hex(&encoded_hex), Some(value));
    }

    #[test]
    fn integer_primitive_encodings_are_pinned() {
        macro_rules! assert_min_and_max_encoding {
            ($ty:ty, $min:literal, $max:literal, $min_hex:literal, $max_hex:literal) => {
                assert_primitive_encoding(<$ty>::MIN, $min, $min_hex);
                assert_primitive_encoding(<$ty>::MAX, $max, $max_hex);
            };
        }

        assert_min_and_max_encoding!(u8, "AA======", "74======", "00======", "VS======");
        assert_min_and_max_encoding!(u16, "AAAA====", "777Q====", "0000====", "VVVG====");
        assert_min_and_max_encoding!(u32, "AAAAAAA=", "777777Y=", "0000000=", "VVVVVVO=");
        assert_min_and_max_encoding!(
            u64,
            "AAAAAAAAAAAAA===",
            "7777777777776===",
            "0000000000000===",
            "VVVVVVVVVVVVU==="
        );
        assert_min_and_max_encoding!(
            u128,
            "AAAAAAAAAAAAAAAAAAAAAAAAAA======",
            "77777777777777777777777774======",
            "00000000000000000000000000======",
            "VVVVVVVVVVVVVVVVVVVVVVVVVS======"
        );

        assert_min_and_max_encoding!(i8, "QA======", "P4======", "G0======", "FS======");
        assert_min_and_max_encoding!(i16, "QAAA====", "P77Q====", "G000====", "FVVG====");
        assert_min_and_max_encoding!(i32, "QAAAAAA=", "P77777Y=", "G000000=", "FVVVVVO=");
        assert_min_and_max_encoding!(
            i64,
            "QAAAAAAAAAAAA===",
            "P777777777776===",
            "G000000000000===",
            "FVVVVVVVVVVVU==="
        );
        assert_min_and_max_encoding!(
            i128,
            "QAAAAAAAAAAAAAAAAAAAAAAAAA======",
            "P7777777777777777777777774======",
            "G0000000000000000000000000======",
            "FVVVVVVVVVVVVVVVVVVVVVVVVS======"
        );

        assert_primitive_encoding(0xb0u8, "WA======", "M0======");
    }

    #[test]
    fn integer_primitive_decoding_requires_the_exact_data_width() {
        assert_eq!(u32::try_from_base32(b"AAAA===="), None);
        assert_eq!(u32::try_from_base32(b"AAAAAAA="), Some(0));
        assert_eq!(u32::try_from_base32(b"AAAAAAAAAAAAA==="), None);

        assert_eq!(u32::try_from_base32hex(b"0000===="), None);
        assert_eq!(u32::try_from_base32hex(b"0000000="), Some(0));
        assert_eq!(u32::try_from_base32hex(b"0000000000000==="), None);
    }

    #[test]
    fn primitive_decoders_do_not_mix_base32_alphabets() {
        assert_eq!(u8::try_from_base32(b"WA======"), Some(0xb0));
        assert_eq!(u8::try_from_base32(b"M0======"), None);
        assert_eq!(u8::try_from_base32hex(b"M0======"), Some(0xb0));
        assert_eq!(u8::try_from_base32hex(b"WA======"), None);
    }
}

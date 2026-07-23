// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Base16 encoding, decoding, and fixed-width integer conversions.
//!
//! The default encoder emits lowercase ASCII. The general decoder accepts
//! lowercase, uppercase, or mixed-case input, while the case-specific decoders
//! accept only their selected letter case.
//!
//! ```rust
//! use b2t_codecs::base16::{encode_base16_string, try_decode_base16_string};
//!
//! let encoded = encode_base16_string(b"\xde\xad\xbe\xef");
//! assert_eq!(encoded, "deadbeef");
//! assert_eq!(
//!     try_decode_base16_string("dEaDbEeF").as_deref(),
//!     Some([0xde, 0xad, 0xbe, 0xef].as_slice()),
//! );
//! ```
// BASE16 CODEC
// The default encoder emits lowercase ASCII, while the default decoder accepts
// lowercase, uppercase, or mixed-case input. Case-specific decoders are strict.

mod dec;
mod enc;

pub use dec::{
    try_decode_base16, try_decode_base16_string, try_decode_base16lower,
    try_decode_base16lower_string, try_decode_base16upper, try_decode_base16upper_string,
};
pub use enc::{encode_base16, encode_base16_string, encode_base16upper, encode_base16upper_string};

// Any 4-bit nibble can index these encoder arrays.
// b0000 == 0, b1111 == 15
// INVARIANT: nibbles are, by definition, bounded on [0, 16).
const ENCODER_LOWER: [u8; 16] = [
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102,
];

const ENCODER_UPPER: [u8; 16] = [
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70,
];

// ASCII-ordered decoding tables on their respective [MIN_ASCII, MAX_ASCII) ranges.
// INVARIANT: non-base16 ASCII values MUST be marked with the sentinel 255.
// INVARIANT: base16 ASCII values MUST contain their location in the encoder alphabet.
const DECODER: [u8; 55] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255, 255, 10, 11, 12, 13, 14, 15, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 10, 11, 12, 13, 14, 15,
];

const DECODER_LOWER: [u8; 55] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 10, 11, 12, 13, 14, 15,
];

const DECODER_UPPER: [u8; 23] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255, 255, 10, 11, 12, 13, 14, 15,
];

// INVARIANT: base16 bytes MUST fall within the range [MIN_ASCII, MAX_ASCII).
// INVARIANT: MAX_ASCII - MIN_ASCII == DECODER.len().
const MIN_ASCII: usize = 48;
const MAX_ASCII: usize = 102 + 1; // Exclusive; one past the end.

const MIN_ASCII_LOWER: usize = 48;
const MAX_ASCII_LOWER: usize = 102 + 1; // Exclusive; one past the end.

const MIN_ASCII_UPPER: usize = 48;
const MAX_ASCII_UPPER: usize = 70 + 1; // Exclusive; one past the end.

mod sealed {
    /// Prevents downstream implementations of the public conversion trait.
    pub trait Sealed {}
}

/// Converts fixed-width integers to and from Base16.
///
/// This sealed trait is implemented for every signed and unsigned primitive
/// integer type. Values are encoded from their big-endian bytes at their full
/// type width.
pub trait Base16: sealed::Sealed + Copy {
    /// Returns the lowercase Base16 encoding of this value.
    #[must_use = "the encoded value should be used"]
    fn as_base16_string(&self) -> String;

    /// Returns the lowercase Base16 ASCII bytes for this value.
    #[must_use = "the encoded value should be used"]
    fn as_base16(&self) -> Box<[u8]>;

    /// Decodes a mixed-case Base16 string into a value of exactly this type's width.
    ///
    /// Returns [`None`] if `base16_str` is malformed or has the wrong encoded
    /// width.
    #[must_use = "the decoding result should be handled"]
    fn try_from_base16_string(base16_str: &str) -> Option<Self>;

    /// Decodes mixed-case Base16 ASCII into a value of exactly this type's width.
    ///
    /// Returns [`None`] if `base16` is malformed or has the wrong encoded width.
    #[must_use = "the decoding result should be handled"]
    fn try_from_base16(base16: &[u8]) -> Option<Self>;
}

macro_rules! impl_base16 {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl sealed::Sealed for $ty {}

            impl Base16 for $ty {
                #[inline]
                fn as_base16_string(&self) -> String {
                    encode_base16_string(&self.to_be_bytes())
                }

                #[inline]
                fn as_base16(&self) -> Box<[u8]> {
                    encode_base16(&self.to_be_bytes())
                }

                #[inline]
                fn try_from_base16_string(base16_str: &str) -> Option<Self> {
                    Self::try_from_base16(base16_str.as_bytes())
                }

                #[inline]
                fn try_from_base16(base16: &[u8]) -> Option<Self> {
                    const SIZE: usize = std::mem::size_of::<$ty>() * 2;
                    if base16.len() != SIZE {
                        return None;
                    }

                    if let Some(bytes) = try_decode_base16(base16) {
                        let bytes = bytes.as_ref().try_into().ok()?;
                        return Some(Self::from_be_bytes(bytes));
                    }

                    None
                }
            }
        )+
    };
}

impl_base16!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Debug;

    fn assert_primitive_encoding<T>(value: T, expected: &str)
    where
        T: Base16 + Debug + Eq,
    {
        let base16_string = value.as_base16_string();
        let base16 = value.as_base16();

        assert_eq!(base16_string, expected);
        assert_eq!(base16.as_ref(), expected.as_bytes());
        assert_eq!(T::try_from_base16_string(&base16_string), Some(value));
        assert_eq!(T::try_from_base16(&base16), Some(value));
        assert_eq!(T::try_from_base16(&base16[..base16.len() - 1]), None);
    }

    #[test]
    fn integer_primitive_encodings_are_pinned() {
        macro_rules! assert_min_and_max_encoding {
            ($ty:ty, $min:literal, $max:literal) => {
                assert_primitive_encoding(<$ty>::MIN, $min);
                assert_primitive_encoding(<$ty>::MAX, $max);
            };
        }

        assert_min_and_max_encoding!(u8, "00", "ff");
        assert_min_and_max_encoding!(u16, "0000", "ffff");
        assert_min_and_max_encoding!(u32, "00000000", "ffffffff");
        assert_min_and_max_encoding!(u64, "0000000000000000", "ffffffffffffffff");
        assert_min_and_max_encoding!(
            u128,
            "00000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffff"
        );

        assert_min_and_max_encoding!(i8, "80", "7f");
        assert_min_and_max_encoding!(i16, "8000", "7fff");
        assert_min_and_max_encoding!(i32, "80000000", "7fffffff");
        assert_min_and_max_encoding!(i64, "8000000000000000", "7fffffffffffffff");
        assert_min_and_max_encoding!(
            i128,
            "80000000000000000000000000000000",
            "7fffffffffffffffffffffffffffffff"
        );

        #[cfg(target_pointer_width = "16")]
        {
            assert_min_and_max_encoding!(usize, "0000", "ffff");
            assert_min_and_max_encoding!(isize, "8000", "7fff");
        }

        #[cfg(target_pointer_width = "32")]
        {
            assert_min_and_max_encoding!(usize, "00000000", "ffffffff");
            assert_min_and_max_encoding!(isize, "80000000", "7fffffff");
        }

        #[cfg(target_pointer_width = "64")]
        {
            assert_min_and_max_encoding!(usize, "0000000000000000", "ffffffffffffffff");
            assert_min_and_max_encoding!(isize, "8000000000000000", "7fffffffffffffff");
        }
    }

    #[test]
    fn integer_primitive_decoding_accepts_mixed_case_and_requires_exact_width() {
        assert_eq!(u32::try_from_base16(b"dEaDbEeF"), Some(0xdead_beef));
        assert_eq!(u32::try_from_base16(b"0000"), None);
        assert_eq!(u32::try_from_base16(b"00000000"), Some(0));
        assert_eq!(u32::try_from_base16(b"0000000000000000"), None);
    }
}

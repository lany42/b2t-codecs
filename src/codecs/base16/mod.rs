// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Base16 encoding, decoding, and fixed-width integer conversions.
//!
//! The default encoder emits lowercase ASCII. The general decoder accepts
//! lowercase, uppercase, or mixed-case input, while the case-specific decoders
//! accept only their selected letter case.
//!
//! ```rust
//! use b2t_codecs::base16::{try_decode_from_base16, try_encode_into_base16};
//!
//! let mut encoded = [0; 64];
//! let mut decoded = [0; 64];
//! let encoded = try_encode_into_base16(b"Hello,World!", &mut encoded).unwrap();
//! let decoded = try_decode_from_base16(encoded, &mut decoded);
//!
//! assert_eq!(encoded, b"48656c6c6f2c576f726c6421");
//! assert_eq!(decoded, Some(b"Hello,World!".as_slice()));
//! ```
// BASE16 CODEC
// The default encoder emits lowercase ASCII, while the default decoder accepts
// lowercase, uppercase, or mixed-case input. Case-specific decoders are strict.

mod dec;
mod enc;

pub use dec::{
    decoded_length_base16, try_decode_from_base16, try_decode_from_base16lower,
    try_decode_from_base16upper,
};

#[cfg(feature = "alloc")]
pub use dec::{
    try_decode_base16, try_decode_base16_string, try_decode_base16lower,
    try_decode_base16lower_string, try_decode_base16upper, try_decode_base16upper_string,
};

#[cfg(feature = "alloc")]
pub use enc::{encode_base16, encode_base16_string, encode_base16upper, encode_base16upper_string};
pub use enc::{encoded_length_base16, try_encode_into_base16, try_encode_into_base16upper};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String};

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
/// This sealed trait is implemented for all fixed-width signed and unsigned
/// primitive integer types. Values are encoded from their big-endian bytes at
/// their full type width.
pub trait Base16: sealed::Sealed + Copy {
    /// The fixed width of this integer type in decoded bytes.
    ///
    /// Its full-width Base16 representation contains exactly `Self::SIZE * 2`
    /// ASCII bytes.
    const SIZE: usize;

    /// Returns the lowercase Base16 encoding of this value.
    #[cfg(feature = "alloc")]
    #[must_use = "the encoded value should be used"]
    fn as_base16_string(&self) -> String;

    /// Returns the lowercase Base16 ASCII bytes for this value.
    #[cfg(feature = "alloc")]
    #[must_use = "the encoded value should be used"]
    fn as_base16(&self) -> Box<[u8]>;

    /// Encodes this value as full-width, lowercase Base16 into `dst`.
    ///
    /// Returns the initialized prefix of `dst`, or [`None`] if `dst` is shorter
    /// than `Self::SIZE * 2`. A short destination is left unchanged. Any bytes
    /// after the encoded prefix are also left unchanged. This method does not
    /// allocate.
    #[must_use = "the encoding result should be handled"]
    fn try_as_base16_into<'a>(&self, dst: &'a mut [u8]) -> Option<&'a [u8]>;

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
                const SIZE: usize = core::mem::size_of::<$ty>();

                #[cfg(feature = "alloc")]
                #[inline]
                fn as_base16_string(&self) -> String {
                    encode_base16_string(&self.to_be_bytes())
                }

                #[cfg(feature = "alloc")]
                #[inline]
                fn as_base16(&self) -> Box<[u8]> {
                    encode_base16(&self.to_be_bytes())
                }

                #[inline]
                fn try_as_base16_into<'a>(&self, dst: &'a mut [u8]) -> Option<&'a [u8]> {
                    try_encode_into_base16(&self.to_be_bytes(), dst)
                }

                #[inline]
                fn try_from_base16_string(base16_str: &str) -> Option<Self> {
                    Self::try_from_base16(base16_str.as_bytes())
                }

                #[inline]
                fn try_from_base16(base16: &[u8]) -> Option<Self> {
                    if decoded_length_base16(base16)? != Self::SIZE {
                        return None;
                    }

                    let mut dst = [0u8; Self::SIZE];
                    if let Some(bytes) = try_decode_from_base16(base16, &mut dst) {
                        if bytes.len() != Self::SIZE {
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

impl_base16!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use core::fmt::Debug;

    #[cfg(feature = "alloc")]
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

    #[cfg(feature = "alloc")]
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
    }

    #[test]
    fn integer_primitive_decoding_accepts_mixed_case_and_requires_exact_width() {
        assert_eq!(u32::try_from_base16(b"dEaDbEeF"), Some(0xdead_beef));
        assert_eq!(u32::try_from_base16_string("dEaDbEeF"), Some(0xdead_beef));
        assert_eq!(u32::try_from_base16(b"0000"), None);
        assert_eq!(u32::try_from_base16(b"00000000"), Some(0));
        assert_eq!(u32::try_from_base16(b"0000000000000000"), None);
    }

    #[test]
    fn no_alloc_integer_encoding_is_full_width_and_preserves_the_tail() {
        let mut dst = [b'!'; 10];
        assert_eq!(
            0xdead_beefu32.try_as_base16_into(&mut dst),
            Some(b"deadbeef".as_slice()),
        );
        assert_eq!(&dst[8..], b"!!");
    }

    #[test]
    fn no_alloc_integer_encoding_returns_none_for_a_short_destination() {
        let mut dst = [b'!'; 7];
        assert_eq!(0xdead_beefu32.try_as_base16_into(&mut dst), None);
        assert_eq!(dst, [b'!'; 7]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn allocating_api_is_reexported_and_wired_to_the_right_alphabet() {
        // Covers every symbol of both alphabets. Only the mixed-case decoders
        // accept `mixed`; each strict decoder accepts only its own case.
        let plain: &[u8] = &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let lower = "0123456789abcdef";
        let upper = "0123456789ABCDEF";
        let mixed = "0123456789aBcDeF";

        assert_eq!(crate::encode_base16(plain).as_ref(), lower.as_bytes());
        assert_eq!(crate::encode_base16_string(plain), lower);
        assert_eq!(crate::encode_base16upper(plain).as_ref(), upper.as_bytes());
        assert_eq!(crate::encode_base16upper_string(plain), upper);

        assert_eq!(
            crate::try_decode_base16(mixed.as_bytes()).as_deref(),
            Some(plain)
        );
        assert_eq!(
            crate::try_decode_base16_string(mixed).as_deref(),
            Some(plain)
        );

        assert_eq!(
            crate::try_decode_base16lower(lower.as_bytes()).as_deref(),
            Some(plain)
        );
        assert_eq!(
            crate::try_decode_base16lower_string(lower).as_deref(),
            Some(plain)
        );
        assert_eq!(crate::try_decode_base16lower(mixed.as_bytes()), None);
        assert_eq!(crate::try_decode_base16lower_string(mixed), None);

        assert_eq!(
            crate::try_decode_base16upper(upper.as_bytes()).as_deref(),
            Some(plain)
        );
        assert_eq!(
            crate::try_decode_base16upper_string(upper).as_deref(),
            Some(plain)
        );
        assert_eq!(crate::try_decode_base16upper(mixed.as_bytes()), None);
        assert_eq!(crate::try_decode_base16upper_string(mixed), None);
    }
}

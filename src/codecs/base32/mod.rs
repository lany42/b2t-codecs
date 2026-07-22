// BASE32 CODEC
// Canonical RFC 4648 Base32 and Base32Hex codecs.
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

#[allow(dead_code)] // Used by the pending encoder and decoder implementations.
const BASE32_PAD: u8 = b'=';

mod sealed {
    pub trait Sealed {}
}

pub trait Base32: sealed::Sealed + Copy {
    fn as_base32_string(&self) -> String;

    fn as_base32(&self) -> Box<[u8]>;

    fn try_from_base32_string(base32_str: &str) -> Option<Self>;
    fn try_from_base32(base32: &[u8]) -> Option<Self>;
}

pub trait Base32Hex: sealed::Sealed + Copy {
    fn as_base32hex_string(&self) -> String;

    fn as_base32hex(&self) -> Box<[u8]>;

    fn try_from_base32hex_string(base32hex_str: &str) -> Option<Self>;
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

impl_base32!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
);

// BASE64 CODEC
// Canonical RFC 4648 Base64, rejecting non-zero pad-bit aliases, missing padding, and malformed inputs.
// https://www.rfc-editor.org/rfc/rfc4648.html

mod dec;
mod enc;

pub use dec::{try_decode_base64, try_decode_base64url};
pub use enc::{encode_base64, encode_base64_string, encode_base64url, encode_base64url_string};

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

#[inline]
pub fn trim_end_padding(bytes: Box<[u8]>) -> Box<[u8]> {
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
    pub trait Sealed {}
}

pub trait Base64: sealed::Sealed + Copy {
    fn as_base64_string(&self) -> String;

    fn as_base64(&self) -> Box<[u8]>;

    fn try_from_base64_string(base64_str: &str) -> Option<Self>;
    fn try_from_base64(base64: &[u8]) -> Option<Self>;
}

pub trait Base64Url: sealed::Sealed + Copy {
    fn as_base64url_string(&self) -> String;

    fn as_base64url(&self) -> Box<[u8]>;

    fn try_from_base64url_string(base64_str: &str) -> Option<Self>;
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

impl_base64!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
);

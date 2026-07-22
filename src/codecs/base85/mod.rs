// BASE85 CODEC
// Base85 encoding and decoding shared by the ASCII85, Adobe85, and Z85 APIs.
// ASCII85 and Z85 use the strict path; Adobe85 adds zero compression and implicit tails.
// The Z85 specification describes the common framing and transformation:
// https://rfc.zeromq.org/spec/32/
// "A Z85 implementation takes a binary frame and encodes it as a printable ASCII string,
// or takes an ASCII encoded string and decodes it into a binary frame."

mod dec;
mod enc;

pub use dec::{
    try_decode_adobe85, try_decode_adobe85_string, try_decode_ascii85, try_decode_ascii85_string,
    try_decode_z85, try_decode_z85_string,
};
pub use enc::{
    encode_adobe85, encode_adobe85_string, try_encode_ascii85, try_encode_ascii85_string,
    try_encode_z85, try_encode_z85_string,
};

const ENCODER_Z85: [u8; 85] = [
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
    108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 65, 66, 67, 68, 69,
    70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 46, 45, 58,
    43, 61, 94, 33, 47, 42, 63, 38, 60, 62, 40, 41, 91, 93, 123, 125, 64, 37, 36, 35,
];

// ASCII-ordered decoding table on the range [MIN_ASCII_Z85, MAX_ASCII_Z85)
// INVARIANT: non-z85 ASCII values MUST be marked with the sentinel 255
// INVARIANT: z85 ASCII values MUST be marked with their location in the encoder alphabet
const DECODER_Z85: [u8; 93] = [
    68, 255, 84, 83, 82, 72, 255, 75, 76, 70, 65, 255, 63, 62, 69, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    64, 255, 73, 66, 74, 71, 81, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 255, 78, 67, 255, 255, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 79, 255, 80,
];

// INVARIANT: z85 bytes MUST fall within the range [MIN_ASCII_Z85, MAX_ASCII_Z85)
// INVARIANT: MAX_ASCII_Z85 - MIN_ASCII_Z85 == DECODER_Z85.len()
const MIN_ASCII_Z85: usize = 33;
const MAX_ASCII_Z85: usize = 125 + 1; // One past the end

const ENCODER_ASCII85: [u8; 85] = [
    33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
    57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
    81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103,
    104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
];

// ASCII-ordered decoding table on the range [MIN_ASCII_ASCII85, MAX_ASCII_ASCII85)
// INVARIANT: non-ASCII85 values MUST be marked with the sentinel 255
// INVARIANT: ASCII85 values MUST be marked with their location in the encoder alphabet
const DECODER_ASCII85: [u8; 85] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
    74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
];

// INVARIANT: ASCII85 bytes MUST fall within the range
// [MIN_ASCII_ASCII85, MAX_ASCII_ASCII85)
// INVARIANT: MAX_ASCII_ASCII85 - MIN_ASCII_ASCII85 == DECODER_ASCII85.len()
const MIN_ASCII_ASCII85: usize = 33;
const MAX_ASCII_ASCII85: usize = 117 + 1; // One past the end

// Adobe85 uses the ASCII85 alphabet with a shorthand for an all-zero chunk and
// the final alphabet byte as implicit tail padding during decoding.
const ADOBE85_ZEROS: u8 = b'z';
const ADOBE85_DEC_PAD: u8 = b'u';

mod sealed {
    pub trait Sealed {}
}

pub trait Adobe85: sealed::Sealed + Copy {
    fn as_adobe85_string(&self) -> String;

    fn as_adobe85(&self) -> Box<[u8]>;

    fn try_from_adobe85_string(adobe85_str: &str) -> Option<Self>;
    fn try_from_adobe85(adobe85: &[u8]) -> Option<Self>;
}

pub trait Z85: sealed::Sealed + Copy {
    fn as_z85_string(&self) -> Option<String>;

    fn as_z85(&self) -> Option<Box<[u8]>>;

    fn try_from_z85_string(z85_str: &str) -> Option<Self>;
    fn try_from_z85(z85: &[u8]) -> Option<Self>;
}

pub trait Base85: sealed::Sealed + Copy {
    fn as_base85_string(&self) -> Option<String>;

    fn as_base85(&self) -> Option<Box<[u8]>>;

    fn try_from_base85_string(base85_str: &str) -> Option<Self>;
    fn try_from_base85(base85: &[u8]) -> Option<Self>;
}

macro_rules! impl_base85 {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl Base85 for $ty {
                #[inline]
                fn as_base85_string(&self) -> Option<String> {
                    try_encode_ascii85_string(&self.to_be_bytes())
                }

                #[inline]
                fn as_base85(&self) -> Option<Box<[u8]>> {
                    try_encode_ascii85(&self.to_be_bytes())
                }

                #[inline]
                fn try_from_base85_string(base85_str: &str) -> Option<Self> {
                    Self::try_from_base85(base85_str.as_bytes())
                }

                #[inline]
                fn try_from_base85(base85: &[u8]) -> Option<Self> {
                    // INVARIANT: base85 encodes five ASCII per four bytes
                    // ex.  u32/i32     -> 5 ASCII
                    //      u64/i64     -> 10 ASCII
                    //      u128/i128   -> 20 ASCII
                    const SIZE: usize = std::mem::size_of::<$ty>() * 5 / 4;
                    if base85.len() != SIZE {
                        return None;
                    }

                    if let Some(bytes) = try_decode_ascii85(base85) {
                        let bytes = bytes.as_ref().try_into().ok()?;
                        return Some(Self::from_be_bytes(bytes));
                    }

                    None
                }
            }

            impl Z85 for $ty {
                #[inline]
                fn as_z85_string(&self) -> Option<String> {
                    try_encode_z85_string(&self.to_be_bytes())
                }

                #[inline]
                fn as_z85(&self) -> Option<Box<[u8]>> {
                    try_encode_z85(&self.to_be_bytes())
                }

                #[inline]
                fn try_from_z85_string(z85_str: &str) -> Option<Self> {
                    Self::try_from_z85(z85_str.as_bytes())
                }

                #[inline]
                fn try_from_z85(z85: &[u8]) -> Option<Self> {
                    // INVARIANT: base85 encodes five ASCII per four bytes
                    // ex.  u32/i32     -> 5 ASCII
                    //      u64/i64     -> 10 ASCII
                    //      u128/i128   -> 20 ASCII
                    const SIZE: usize = std::mem::size_of::<$ty>() * 5 / 4;
                    if z85.len() != SIZE {
                        return None;
                    }

                    if let Some(bytes) = try_decode_z85(z85) {
                        let bytes = bytes.as_ref().try_into().ok()?;
                        return Some(Self::from_be_bytes(bytes));
                    }

                    None
                }
            }
        )+
    };
}

macro_rules! impl_adobe85 {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl sealed::Sealed for $ty {}

            impl Adobe85 for $ty {
                #[inline]
                fn as_adobe85_string(&self) -> String {
                    encode_adobe85_string(&self.to_be_bytes())
                }

                #[inline]
                fn as_adobe85(&self) -> Box<[u8]> {
                    encode_adobe85(&self.to_be_bytes())
                }

                #[inline]
                fn try_from_adobe85_string(adobe85_str: &str) -> Option<Self> {
                    Self::try_from_adobe85(adobe85_str.as_bytes())
                }

                #[inline]
                fn try_from_adobe85(adobe85: &[u8]) -> Option<Self> {
                    if let Some(bytes) = try_decode_adobe85(adobe85) {
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

impl_adobe85!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
);

// INVARIANT: the strict base85 codec cannot encode anything less than 4 bytes
// u8, u16, i8, i16 cannot be encoded without caller-provided padding
// "It is up to the application to ensure that frames and strings are padded if necessary."
impl_base85!(u32, u64, u128, i32, i64, i128);

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Debug;

    fn assert_primitive_roundtrip<T>(value: T)
    where
        T: Base85 + Z85 + Debug + Eq,
    {
        let ascii85_string = value
            .as_base85_string()
            .expect("primitive must be ASCII85 encodable");
        let ascii85 = value
            .as_base85()
            .expect("primitive must be ASCII85 encodable");

        assert_eq!(ascii85_string.as_bytes(), ascii85.as_ref());
        assert_eq!(ascii85.len(), std::mem::size_of::<T>() * 5 / 4);
        assert_eq!(T::try_from_base85_string(&ascii85_string), Some(value));
        assert_eq!(T::try_from_base85(&ascii85), Some(value));

        let z85_string = value
            .as_z85_string()
            .expect("primitive must be Z85 encodable");
        let z85 = value.as_z85().expect("primitive must be Z85 encodable");

        assert_eq!(z85_string.as_bytes(), z85.as_ref());
        assert_eq!(z85.len(), std::mem::size_of::<T>() * 5 / 4);
        assert_eq!(T::try_from_z85_string(&z85_string), Some(value));
        assert_eq!(T::try_from_z85(&z85), Some(value));
    }

    #[test]
    fn integer_primitive_encodings_roundtrip() {
        macro_rules! assert_min_and_max_roundtrip {
            ($ty:ty) => {
                assert_primitive_roundtrip(<$ty>::MIN);
                assert_primitive_roundtrip(<$ty>::MAX);
            };
        }

        assert_min_and_max_roundtrip!(u32);
        assert_min_and_max_roundtrip!(u64);
        assert_min_and_max_roundtrip!(u128);
        assert_min_and_max_roundtrip!(i32);
        assert_min_and_max_roundtrip!(i64);
        assert_min_and_max_roundtrip!(i128);

        assert_eq!(0u32.as_base85_string().as_deref(), Some("!!!!!"));
        assert_eq!(u32::MAX.as_base85_string().as_deref(), Some("s8W-!"));
    }

    #[test]
    fn integer_primitive_decoding_requires_the_exact_data_width() {
        assert_eq!(u64::try_from_base85(b"!!!!!"), None);
        assert_eq!(u64::try_from_base85(b"!!!!!!!!!!"), Some(0));
        assert_eq!(u64::try_from_base85(b"!!!!!!!!!!!!!!!"), None);

        assert_eq!(u64::try_from_z85(b"00000"), None);
        assert_eq!(u64::try_from_z85(b"0000000000"), Some(0));
        assert_eq!(u64::try_from_z85(b"000000000000000"), None);
    }

    mod adobe85 {
        use super::*;

        fn assert_primitive_encoding<T>(value: T, expected: &str)
        where
            T: Adobe85 + Debug + Eq,
        {
            let encoded_string = value.as_adobe85_string();
            let encoded = value.as_adobe85();

            assert_eq!(encoded_string, expected);
            assert_eq!(encoded.as_ref(), expected.as_bytes());
            assert_eq!(T::try_from_adobe85_string(&encoded_string), Some(value));
            assert_eq!(T::try_from_adobe85(&encoded), Some(value));
        }

        #[test]
        fn integer_primitive_encodings_are_pinned() {
            macro_rules! assert_min_and_max_encoding {
                ($ty:ty, $min:literal, $max:literal) => {
                    assert_primitive_encoding(<$ty>::MIN, $min);
                    assert_primitive_encoding(<$ty>::MAX, $max);
                };
            }

            assert_min_and_max_encoding!(u8, "!!", "rr");
            assert_min_and_max_encoding!(u16, "!!!", "s8N");
            assert_min_and_max_encoding!(u32, "z", "s8W-!");
            assert_min_and_max_encoding!(u64, "zz", "s8W-!s8W-!");
            assert_min_and_max_encoding!(u128, "zzzz", "s8W-!s8W-!s8W-!s8W-!");

            assert_min_and_max_encoding!(i8, "J,", "If");
            assert_min_and_max_encoding!(i16, "J,f", "J,]");
            assert_min_and_max_encoding!(i32, "J,fQL", "J,fQK");
            assert_min_and_max_encoding!(i64, "J,fQLz", "J,fQKs8W-!");
            assert_min_and_max_encoding!(i128, "J,fQLzzz", "J,fQKs8W-!s8W-!s8W-!");

            #[cfg(target_pointer_width = "16")]
            {
                assert_min_and_max_encoding!(usize, "!!!", "s8N");
                assert_min_and_max_encoding!(isize, "J,f", "J,]");
            }

            #[cfg(target_pointer_width = "32")]
            {
                assert_min_and_max_encoding!(usize, "z", "s8W-!");
                assert_min_and_max_encoding!(isize, "J,fQL", "J,fQK");
            }

            #[cfg(target_pointer_width = "64")]
            {
                assert_min_and_max_encoding!(usize, "zz", "s8W-!s8W-!");
                assert_min_and_max_encoding!(isize, "J,fQLz", "J,fQKs8W-!");
            }
        }

        #[test]
        fn integer_primitive_decoding_requires_the_exact_data_width() {
            assert_eq!(u32::try_from_adobe85(b"!!!"), None);
            assert_eq!(u32::try_from_adobe85(b"z"), Some(0));
            assert_eq!(u32::try_from_adobe85(b"zz"), None);
        }
    }
}

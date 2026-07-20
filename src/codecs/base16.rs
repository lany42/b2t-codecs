// BASE16 CODEC

// Any 4-bit nibble can index these encoder arrays.
// b0000 == 0, b1111 == 15
// INVARIANT: nibbles are, by definition, bounded on [0, 16).
const ENCODER_LOWER: [u8; 16] = [
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102,
];

// ASCII-ordered decoding table on the range [MIN_ASCII, MAX_ASCII)
// INVARIANT: non-base16 ASCII values MUST be marked with the sentinel 255
// INVARIANT: base16 ASCII values MUST be marked with their location in the encoder alphabet
const DECODER: [u8; 55] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255, 255, 10, 11, 12, 13, 14, 15, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 10, 11, 12, 13, 14, 15,
];

// INVARIANT: base16 bytes MUST fall within the range [MIN_ASCII, MAX_ASCII)
// INVARIANT: MAX_ASCII - MIN_ASCII == DECODER.len()
const MIN_ASCII: usize = 48;
const MAX_ASCII: usize = 102 + 1; // One past the end

mod sealed {
    pub trait Sealed {}
}

pub trait Base16: sealed::Sealed + Copy {
    fn as_base16_string(&self) -> String;

    fn as_base16(&self) -> Box<[u8]>;

    fn try_from_base16_string(base16_str: &str) -> Option<Self>;
    fn try_from_base16(base16: &[u8]) -> Option<Self>;
}

macro_rules! impl_base16 {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl sealed::Sealed for $ty {}

            impl Base16 for $ty {
                #[inline]
                fn as_base16_string(&self) -> String {
                    as_base16_string(&self.to_be_bytes(), &ENCODER_LOWER)
                }

                #[inline]
                fn as_base16(&self) -> Box<[u8]> {
                    as_base16(&self.to_be_bytes(), &ENCODER_LOWER)
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

#[inline]
pub fn encode_base16_string(bytes: &[u8]) -> String {
    as_base16_string(bytes, &ENCODER_LOWER)
}

#[inline]
pub fn encode_base16(bytes: &[u8]) -> Box<[u8]> {
    as_base16(bytes, &ENCODER_LOWER)
}

#[inline]
fn as_base16_string(bytes: &[u8], encoder: &[u8; 16]) -> String {
    let base16_bytes = as_base16(bytes, encoder);
    // SAFETY: base16 bytes are ASCII, therefore always valid UTF-8
    unsafe { String::from_utf8_unchecked(base16_bytes.into_vec()) }
}

#[inline]
fn as_base16(bytes: &[u8], encoder: &[u8; 16]) -> Box<[u8]> {
    if bytes.is_empty() {
        return Vec::<u8>::new().into_boxed_slice();
    }

    let mut ret = Vec::<u8>::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let hi = (b >> 4) as usize;
        let lo = (b & 0x0f) as usize;

        // SAFETY: hi is four bits with a range [0, 16)
        let hi = unsafe { *encoder.get_unchecked(hi) };
        // SAFETY: lo is four bits with a range [0, 16)
        let lo = unsafe { *encoder.get_unchecked(lo) };

        ret.push(hi);
        ret.push(lo);
    }

    ret.into_boxed_slice()
}

#[inline]
pub fn try_decode_base16_string(base16: &str) -> Option<Box<[u8]>> {
    try_decode_base16(base16.as_bytes())
}

#[inline]
pub fn try_decode_base16(base16: &[u8]) -> Option<Box<[u8]>> {
    // INVARIANT: MAX_ASCII must always be larger than MIN_ASCII
    const { assert!(MAX_ASCII > MIN_ASCII) }

    // INVARIANT: the decoder must be sized on the range [MIN_ASCII, MAX_ASCII)
    const { assert!(MAX_ASCII - MIN_ASCII == DECODER.len()) }

    // empty inputs result in empty outputs
    if base16.is_empty() {
        return Some(Vec::<u8>::new().into_boxed_slice());
    }

    // INVARIANT: input length must be a multiple of two
    if !base16.len().is_multiple_of(2) {
        return None;
    }

    let mut ret = Vec::<u8>::with_capacity(base16.len() / 2);
    let (pairs, []) = base16.as_chunks::<2>() else {
        unreachable!("base16 slice always a multiple of 2")
    };

    for pair in pairs {
        let hi = pair[0] as usize;
        if !(MIN_ASCII..MAX_ASCII).contains(&hi) {
            // hi byte out of base16 ASCII range
            return None;
        }
        let lo = pair[1] as usize;
        if !(MIN_ASCII..MAX_ASCII).contains(&lo) {
            // lo byte out of base16 ASCII range
            return None;
        }

        // SAFETY: hi - MIN_ASCII guarenteed to fall within [0, MAX_ASCII - MIN_ASCII)
        let hi = unsafe { *DECODER.get_unchecked(hi - MIN_ASCII) };
        if hi == 255 {
            // hi byte is not encoded base16
            return None;
        }

        // SAFETY: lo - MIN_ASCII guarenteed to fall within [0, MAX_ASCII - MIN_ASCII)
        let lo = unsafe { *DECODER.get_unchecked(lo - MIN_ASCII) };
        if lo == 255 {
            // lo byte is not encoded base16
            return None;
        }

        ret.push(hi * 16 + lo);
    }

    Some(ret.into_boxed_slice())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fmt::Debug;

    #[test]
    fn decode_valid_base16() {
        assert_eq!(*try_decode_base16(b"FF").unwrap(), [0xFF]);
        assert_eq!(*try_decode_base16(b"00").unwrap(), [0x00]);
        assert_eq!(*try_decode_base16(b"0A").unwrap(), [0x0A]);
        assert_eq!(*try_decode_base16(b"A0").unwrap(), [0xA0]);
        assert_eq!(
            *try_decode_base16(b"deadBEEF").unwrap(),
            [0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert_eq!(&*try_decode_base16(b"").unwrap(), b"");
    }

    #[test]
    fn decode_rejects_invalid_base16() {
        assert_eq!(try_decode_base16(b"0"), None);

        for invalid in [u8::MIN, b'/', b'g', u8::MAX] {
            assert_eq!(try_decode_base16(&[invalid, b'0']), None);
            assert_eq!(try_decode_base16(&[b'0', invalid]), None);
        }

        assert_eq!(try_decode_base16(b":0"), None);
        assert_eq!(try_decode_base16(b"0:"), None);
    }

    #[test]
    fn encode_bytes_as_lowercase_base16() {
        let cases: &[(&[u8], &str)] = &[
            (&[], ""),
            (&[0x00], "00"),
            (&[0xFF], "ff"),
            (&[0xDE, 0xAD, 0xBE, 0xEF], "deadbeef"),
            (&[0x00, 0x01, 0x0F, 0x10, 0xAB, 0xFF], "00010f10abff"),
        ];

        for &(bytes, expected) in cases {
            assert_eq!(encode_base16(bytes).as_ref(), expected.as_bytes());
            assert_eq!(encode_base16_string(bytes), expected);
        }
    }

    #[test]
    fn base16_strings_roundtrip_as_lowercase() {
        for (base16, canonical) in [
            ("", ""),
            ("00", "00"),
            ("deadbeef", "deadbeef"),
            ("DEADBEEF", "deadbeef"),
            ("0123456789aBcDeF", "0123456789abcdef"),
        ] {
            let bytes = try_decode_base16_string(base16).unwrap();
            assert_eq!(encode_base16_string(&bytes), canonical);
        }
    }

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
}

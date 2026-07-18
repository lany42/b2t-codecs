// BASE16 CODEC

// Any 4-bit nibble can index these encoder arrays.
// b0000 == 0, b1111 == 15
// INVARIANT: nibbles are, by definition, bounded on [0, 16).
pub const ENCODER_LOWER: [u8; 16] = [
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102,
];
pub const ENCODER_UPPER: [u8; 16] = [
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70,
];

// ASCII-ordered decoding table on the range [MIN_ASCII, MAX_ASCII)
// INVARIANT: non-base16 ASCII values MUST be marked with the sentinel 255
// INVARIANT: base16 ASCII values MUST be marked with their location in the encoder alphabet
pub const DECODER: [u8; 55] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255, 255, 10, 11, 12, 13, 14, 15, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 10, 11, 12, 13, 14, 15,
];

// INVARIANT: base16 bytes MUST fall within the range [MIN_ASCII, MAX_ASCII)
// INVARIANT: MAX_ASCII - MIN_ASCII == DECODER.len()
pub const MIN_ASCII: usize = 48;
pub const MAX_ASCII: usize = 102 + 1; // One past the end

mod sealed {
    pub trait Sealed {}
}

pub trait Base16: sealed::Sealed + Copy {
    fn as_base16_string(&self) -> String;
    fn as_base16_string_upper(&self) -> String;

    fn as_base16(&self) -> Box<[u8]>;
    fn as_base16_upper(&self) -> Box<[u8]>;

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
                    as_base16_string(&self.as_base16())
                }

                #[inline]
                fn as_base16_string_upper(&self) -> String {
                    as_base16_string_upper(&self.as_base16_upper())
                }

                #[inline]
                fn as_base16(&self) -> Box<[u8]> {
                    as_base16(&self.to_be_bytes(), &ENCODER_LOWER)
                }

                #[inline]
                fn as_base16_upper(&self) -> Box<[u8]> {
                    as_base16(&self.to_be_bytes(), &ENCODER_UPPER)
                }

                #[inline]
                fn try_from_base16_string(base16_str: &str) -> Option<Self> {
                    Self::try_from_base16(base16_str.as_bytes())
                }

                #[inline]
                fn try_from_base16(base16: &[u8]) -> Option<Self> {
                    const SIZE: usize = std::mem::size_of::<$ty>();
                    if base16.len() != SIZE {
                        return None;
                    }

                    if let Some(bytes) = try_from_base16(base16) {
                        let bytes = <[u8; SIZE]>::try_from(&bytes[..SIZE]).unwrap();
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
pub fn as_base16_string(bytes: &[u8]) -> String {
    let base16_bytes = as_base16(bytes, &ENCODER_LOWER);
    // SAFETY: base16 bytes are ASCII, therefore always valid UTF-8
    unsafe { String::from_utf8_unchecked(base16_bytes.into_vec()) }
}

#[inline]
pub fn as_base16_string_upper(bytes: &[u8]) -> String {
    let base16_bytes = as_base16(bytes, &ENCODER_UPPER);
    // SAFETY: base16 bytes are ASCII, therefore always valid UTF-8
    unsafe { String::from_utf8_unchecked(base16_bytes.into_vec()) }
}

#[inline]
pub fn as_base16(bytes: &[u8], encoder: &[u8; 16]) -> Box<[u8]> {
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
pub fn try_from_base16_str(base16: &str) -> Option<Box<[u8]>> {
    try_from_base16(base16.as_bytes())
}

#[inline]
pub fn try_from_base16(base16: &[u8]) -> Option<Box<[u8]>> {
    // INVARIANT: MAX_ASCII must always be larger than MIN_ASCII
    const { assert!(MAX_ASCII > MIN_ASCII) }

    // INVARIANT: the decoder must be sized on the range [MIN_ASCII, MAX_ASCII)
    const { assert!(MAX_ASCII - MIN_ASCII == DECODER.len()) }

    // empty inputs result in empty outputs
    if base16.is_empty() {
        return Some(Vec::<u8>::new().into_boxed_slice());
    }

    // input length must be a multiple of two
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

    #[test]
    fn decode_hex() {
        assert_eq!(*try_from_base16(b"FF").unwrap(), [0xFF]);
        assert_eq!(*try_from_base16(b"00").unwrap(), [0x00]);
        assert_eq!(*try_from_base16(b"0A").unwrap(), [0x0A]);
        assert_eq!(*try_from_base16(b"A0").unwrap(), [0xA0]);
    }
}

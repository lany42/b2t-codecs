// Z85 CODEC
// https://rfc.zeromq.org/spec/32/
// "A Z85 implementation takes a binary frame and encodes it as a printable ASCII string,
// or takes an ASCII encoded string and decodes it into a binary frame."

const ENCODER: [u8; 85] = [
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
    108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 65, 66, 67, 68, 69,
    70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 46, 45, 58,
    43, 61, 94, 33, 47, 42, 63, 38, 60, 62, 40, 41, 91, 93, 123, 125, 64, 37, 36, 35,
];

// ASCII-ordered decoding table on the range [MIN_ASCII, MAX_ASCII)
// INVARIANT: non-z85 ASCII values MUST be marked with the sentinel 255
// INVARIANT: z85 ASCII values MUST be marked with their location in the encoder alphabet
const DECODER: [u8; 93] = [
    68, 255, 84, 83, 82, 72, 255, 75, 76, 70, 65, 255, 63, 62, 69, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    64, 255, 73, 66, 74, 71, 81, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 255, 78, 67, 255, 255, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 79, 255, 80,
];

// INVARIANT: z85 bytes MUST fall within the range [MIN_ASCII, MAX_ASCII)
// INVARIANT: MAX_ASCII - MIN_ASCII == DECODER.len()
const MIN_ASCII: usize = 33;
const MAX_ASCII: usize = 125 + 1; // One past the end

mod sealed {
    pub trait Sealed {}
}

pub trait Z85: sealed::Sealed + Copy {
    fn as_z85_string(&self) -> Option<String>;

    fn as_z85(&self) -> Option<Box<[u8]>>;

    fn try_from_z85_string(z85_str: &str) -> Option<Self>;
    fn try_from_z85(z85: &[u8]) -> Option<Self>;
}

macro_rules! impl_z85 {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl sealed::Sealed for $ty {}

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
                    // INVARIANT: z85 encodes five ASCII per four bytes
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

// INVARIANT: the core z85 codec cannot encode anything less than 4 bytes
// u8, u16, i8, i16 cannot be encoded without caller-provided padding
// "It is up to the application to ensure that frames and strings are padded if necessary."
impl_z85!(u32, u64, u128, i32, i64, i128);

// TODO: Convenience impls for u8, u16, usize, i8, i16, and isize. Where padding is
// needed, they will perform the caller-side pack/pad/extract operations around this
// strict core codec; try_encode_z85 and try_decode_z85 remain unpadded.

#[inline]
pub fn try_encode_z85_string(bytes: &[u8]) -> Option<String> {
    if let Some(z85_bytes) = try_encode_z85(bytes) {
        // SAFETY: z85 bytes are ASCII, therefore always valid UTF-8
        return unsafe { Some(String::from_utf8_unchecked(z85_bytes.into_vec())) };
    }
    None
}

#[inline]
pub fn try_encode_z85(bytes: &[u8]) -> Option<Box<[u8]>> {
    // INVARIANT: encoder table MUST be exactly 85
    const { assert!(ENCODER.len() == 85) }

    if bytes.is_empty() {
        return Some(Vec::<u8>::new().into_boxed_slice());
    }

    // INVARIANT: z85 does not handle padding automatically
    // "The binary frame SHALL have a length that is divisible by 4 with no remainder."
    if !bytes.len().is_multiple_of(4) {
        return None;
    }

    // INVARIANT: z85 encodes five ASCII bytes per four input bytes
    // "The string frame SHALL have a length that is divisible by 5 with no remainder."
    let capacity = bytes.len().checked_mul(5)? / 4;
    let mut ret = Vec::<u8>::with_capacity(capacity);
    let (chunks, []) = bytes.as_chunks::<4>() else {
        unreachable!("bytes slice always a multiple of 4")
    };

    // "To encode a frame, an implementation SHALL take four octets at a time from
    // the binary frame and convert them into five printable characters"
    for &chunk in chunks {
        let mut buf = [0u8; 5];

        // "The four octets SHALL be treated as an
        // unsigned 32-bit integer in network byte order (big endian)."
        let n = u32::from_be_bytes(chunk);

        // "The five characters SHALL be output from most significant to least significant (big endian)."
        let mut d = 85u32.pow(4);
        for b in buf.iter_mut() {
            let i = ((n / d) % 85) as usize;

            // SAFETY: mod 85 gaurentees safe encoder indexing
            *b = unsafe { *ENCODER.get_unchecked(i) };
            d /= 85;
        }
        ret.extend_from_slice(&buf);
    }

    Some(ret.into_boxed_slice())
}

#[inline]
pub fn try_decode_z85_string(z85: &str) -> Option<Box<[u8]>> {
    try_decode_z85(z85.as_bytes())
}

#[inline]
pub fn try_decode_z85(z85: &[u8]) -> Option<Box<[u8]>> {
    // INVARIANT: MAX_ASCII must always be larger than MIN_ASCII
    const { assert!(MAX_ASCII > MIN_ASCII) }

    // INVARIANT: the decoder must be sized on the range [MIN_ASCII, MAX_ASCII)
    const { assert!(MAX_ASCII - MIN_ASCII == DECODER.len()) }

    // empty inputs result in empty outputs
    if z85.is_empty() {
        return Some(Vec::<u8>::new().into_boxed_slice());
    }

    // INVARIANT: z85 does not handle padding automatically
    // "The string frame SHALL have a length that is divisible by 5 with no remainder."
    if !z85.len().is_multiple_of(5) {
        return None;
    }

    // INVARIANT: z85 encodes five ASCII bytes per four input bytes
    // "The binary frame SHALL have a length that is divisible by 4 with no remainder."
    let capacity = z85.len().checked_mul(4)? / 5;
    let mut ret = Vec::<u8>::with_capacity(capacity);
    let (chunks, []) = z85.as_chunks::<5>() else {
        unreachable!("z85 slice always a multiple of 5")
    };

    // "To decode a string, an implementation SHALL take five characters at a time
    // from the string and convert them into four octets of data representing a
    // 32-bit unsigned integer in network byte order."
    for &chunk in chunks {
        // "The five characters SHALL each be converted into a value 0 to 84,
        // and accumulated by multiplication by 85, from most to least significant."
        let mut acc = 0u32;
        for c in chunk {
            let i = c as usize;
            if !(MIN_ASCII..MAX_ASCII).contains(&i) {
                // byte out of z85 ASCII range
                return None;
            }

            // SAFETY: i - MIN_ASCII guarenteed to fall within [0, MAX_ASCII - MIN_ASCII)
            let d = unsafe { *DECODER.get_unchecked(i - MIN_ASCII) } as u32;
            if d == 255 {
                // byte is not encoded z85
                return None;
            }

            acc = acc.checked_mul(85)?.checked_add(d)?;
        }

        ret.extend_from_slice(&acc.to_be_bytes());
    }

    Some(ret.into_boxed_slice())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fmt::Debug;

    #[test]
    fn encode_valid_z85() {
        let input = [0x86u8, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b];
        let expected = b"HelloWorld";

        assert_eq!(&*try_encode_z85(&input).unwrap(), expected);
        assert_eq!(try_encode_z85_string(&input).as_deref(), Some("HelloWorld"));
    }

    #[test]
    fn decode_valid_z85() {
        let input = b"HelloWorld";
        let expected = [0x86u8, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b];

        assert_eq!(&*try_decode_z85(input).unwrap(), expected);
        assert_eq!(
            try_decode_z85_string("HelloWorld").as_deref(),
            Some(expected.as_slice())
        );
    }

    #[test]
    fn empty_input_roundtrips() {
        assert_eq!(try_encode_z85(b"").as_deref(), Some(b"".as_slice()));
        assert_eq!(try_encode_z85_string(b"").as_deref(), Some(""));
        assert_eq!(try_decode_z85(b"").as_deref(), Some(b"".as_slice()));
        assert_eq!(try_decode_z85_string("").as_deref(), Some(b"".as_slice()));
    }

    #[test]
    fn tables_preserve_unsafe_indexing_and_utf8_invariants() {
        let mut seen = [false; DECODER.len()];

        for (digit, &ascii) in ENCODER.iter().enumerate() {
            assert!(ascii.is_ascii());

            let ascii = ascii as usize;
            assert!((MIN_ASCII..MAX_ASCII).contains(&ascii));

            let offset = ascii - MIN_ASCII;
            assert!(!seen[offset], "duplicate Z85 byte at ASCII {ascii}");
            seen[offset] = true;
            assert_eq!(DECODER[offset], digit as u8);
        }

        for (offset, &digit) in DECODER.iter().enumerate() {
            if digit == 255 {
                continue;
            }

            assert!((digit as usize) < ENCODER.len());
            assert_eq!(ENCODER[digit as usize] as usize, MIN_ASCII + offset);
        }
    }

    #[test]
    fn encode_rejects_unpadded_lengths() {
        for len in 1..=15 {
            if len % 4 == 0 {
                continue;
            }

            let input = vec![0u8; len];
            assert_eq!(try_encode_z85(&input), None, "accepted {len} bytes");
            assert_eq!(
                try_encode_z85_string(&input),
                None,
                "accepted {len} bytes as a string"
            );
        }
    }

    #[test]
    fn decode_rejects_unpadded_lengths() {
        for len in 1..=19 {
            if len % 5 == 0 {
                continue;
            }

            let input = vec![b'0'; len];
            assert_eq!(try_decode_z85(&input), None, "accepted {len} bytes");
        }
    }

    #[test]
    fn decode_rejects_out_of_range_bytes_in_every_position() {
        for invalid in [u8::MIN, (MIN_ASCII - 1) as u8, MAX_ASCII as u8, u8::MAX] {
            for position in 0..5 {
                let mut input = *b"00000";
                input[position] = invalid;
                assert_eq!(
                    try_decode_z85(&input),
                    None,
                    "accepted byte {invalid:#04x} at position {position}"
                );
            }
        }

        // Three ASCII bytes plus one two-byte UTF-8 scalar still form a five-byte frame.
        assert_eq!(try_decode_z85_string("000é"), None);
    }

    #[test]
    fn decode_rejects_non_alphabet_ascii_in_every_position() {
        for (offset, &digit) in DECODER.iter().enumerate() {
            if digit != 255 {
                continue;
            }

            let invalid = (MIN_ASCII + offset) as u8;
            for position in 0..5 {
                let mut input = *b"00000";
                input[position] = invalid;
                assert_eq!(
                    try_decode_z85(&input),
                    None,
                    "accepted byte {invalid:#04x} at position {position}"
                );
            }
        }
    }

    #[test]
    fn decode_rejects_invalid_second_frame() {
        for invalid in [u8::MIN, b'"', b'~', u8::MAX] {
            let mut input = *b"0000000000";
            input[7] = invalid;
            assert_eq!(try_decode_z85(&input), None);
        }
    }

    #[test]
    fn decode_rejects_value_just_above_u32_max() {
        assert_eq!(
            try_decode_z85(b"%nSc0").as_deref(),
            Some([u8::MAX; 4].as_slice())
        );
        assert_eq!(try_decode_z85(b"%nSc1"), None);
    }

    #[test]
    fn decode_rejects_maximum_base85_value() {
        assert_eq!(try_decode_z85(b"#####"), None);
    }

    fn assert_primitive_roundtrip<T>(value: T)
    where
        T: Z85 + Debug + Eq,
    {
        let encoded_string = value.as_z85_string().expect("primitive must be encodable");
        let encoded = value.as_z85().expect("primitive must be encodable");

        assert_eq!(encoded_string.as_bytes(), encoded.as_ref());
        assert_eq!(encoded.len(), std::mem::size_of::<T>() * 5 / 4);
        assert_eq!(T::try_from_z85_string(&encoded_string), Some(value));
        assert_eq!(T::try_from_z85(&encoded), Some(value));
        assert_eq!(T::try_from_z85(&encoded[..encoded.len() - 1]), None);

        let mut invalid = encoded.into_vec();
        invalid[0] = b'"';
        assert_eq!(T::try_from_z85(&invalid), None);
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
    }
}

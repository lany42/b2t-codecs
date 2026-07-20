// BASE85 CODEC
// base85 converts four binary octets into five printable ASCII characters.

const ENCODER: [u8; 85] = [
    33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
    57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
    81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103,
    104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
];

// ASCII-ordered decoding table on the range [MIN_ASCII, MAX_ASCII)
// INVARIANT: non-base85 ASCII values MUST be marked with the sentinel 255
// INVARIANT: base85 ASCII values MUST be marked with their location in the encoder alphabet
const DECODER: [u8; 85] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
    74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
];

// INVARIANT: base85 bytes MUST fall within the range [MIN_ASCII, MAX_ASCII)
// INVARIANT: MAX_ASCII - MIN_ASCII == DECODER.len()
const MIN_ASCII: usize = 33;
const MAX_ASCII: usize = 117 + 1; // One past the end

const BASE85_ZEROS: u8 = b'z';
const BASE85_ENC_PAD: u8 = 0;
const BASE85_DEC_PAD: u8 = b'u';

mod sealed {
    pub trait Sealed {}
}

pub trait Base85: sealed::Sealed + Copy {
    fn as_base85_string(&self) -> String;

    fn as_base85(&self) -> Box<[u8]>;

    fn try_from_base85_string(base85_str: &str) -> Option<Self>;
    fn try_from_base85(base85: &[u8]) -> Option<Self>;
}

macro_rules! impl_base85 {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl sealed::Sealed for $ty {}

            impl Base85 for $ty {
                #[inline]
                fn as_base85_string(&self) -> String {
                    encode_base85_string(&self.to_be_bytes())
                }

                #[inline]
                fn as_base85(&self) -> Box<[u8]> {
                    encode_base85(&self.to_be_bytes())
                }

                #[inline]
                fn try_from_base85_string(base85_str: &str) -> Option<Self> {
                    Self::try_from_base85(base85_str.as_bytes())
                }

                #[inline]
                fn try_from_base85(base85: &[u8]) -> Option<Self> {
                    if let Some(bytes) = try_decode_base85(base85) {
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

impl_base85!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
);

#[inline]
pub fn encode_base85_string(bytes: &[u8]) -> String {
    let base85_bytes = encode_base85(bytes);
    // SAFETY: base85 bytes are ASCII, therefore always valid UTF-8
    unsafe { String::from_utf8_unchecked(base85_bytes.into_vec()) }
}

#[inline]
pub fn encode_base85(bytes: &[u8]) -> Box<[u8]> {
    // INVARIANT: encoder table MUST be exactly 85
    const { assert!(ENCODER.len() == 85) }

    if bytes.is_empty() {
        return Vec::<u8>::new().into_boxed_slice();
    }

    // base85 encodes five bytes per full chunk and at most four bytes for a tail.
    let capacity = bytes
        .len()
        .checked_mul(5)
        .expect("base85 encoded length overflow")
        / 4
        + 4;

    let mut ret = Vec::<u8>::with_capacity(capacity);
    let (chunks, remainder) = bytes.as_chunks::<4>();

    for n in chunks.iter().map(|c| u32::from_be_bytes(*c)) {
        if n > 0 {
            ret.extend_from_slice(&encode_base85_chunk(n));
        } else {
            ret.push(BASE85_ZEROS);
        }
    }

    if !remainder.is_empty() {
        encode_base85_tail(remainder, &mut ret);
    }

    ret.into_boxed_slice()
}

#[inline]
fn encode_base85_tail(tail: &[u8], ret: &mut Vec<u8>) {
    // must be 1, 2, or 3
    let len = tail.len();

    // pad with '0' bytes
    let mut padded = [BASE85_ENC_PAD; 4];
    padded[..len].copy_from_slice(tail);

    // the number of padding null bytes added are equal to the amount
    // of bytes stripped from the encoded chunk (length 5)
    //      - 1 byte  => 3 '0' bytes => 2 bytes output
    //      - 2 bytes => 2 '0' bytes => 3 bytes output
    //      - 3 bytes => 1 '0' byte  => 4 bytes output
    //
    // that is, bytes kept: remainder.len() + 1
    let encoded = encode_base85_chunk(u32::from_be_bytes(padded));
    ret.extend_from_slice(&encoded[..len + 1]);
}

#[inline]
fn encode_base85_chunk(n: u32) -> [u8; 5] {
    let mut buf = [0u8; 5];

    // Output the five characters from most significant to least significant.
    let mut d = 85u32.pow(4);
    for b in buf.iter_mut() {
        let i = ((n / d) % 85) as usize;

        // SAFETY: mod 85 guarantees safe encoder indexing
        *b = unsafe { *ENCODER.get_unchecked(i) };
        d /= 85;
    }

    buf
}

#[inline]
pub fn try_decode_base85_string(base85: &str) -> Option<Box<[u8]>> {
    try_decode_base85(base85.as_bytes())
}

#[inline]
pub fn try_decode_base85(base85: &[u8]) -> Option<Box<[u8]>> {
    // INVARIANT: MAX_ASCII must always be larger than MIN_ASCII
    const { assert!(MAX_ASCII > MIN_ASCII) }

    // INVARIANT: the decoder must be sized on the range [MIN_ASCII, MAX_ASCII)
    const { assert!(MAX_ASCII - MIN_ASCII == DECODER.len()) }

    // empty inputs result in empty outputs
    if base85.is_empty() {
        return Some(Vec::<u8>::new().into_boxed_slice());
    }

    // INVARIANT: base85 encodes five ASCII bytes per four input bytes
    // A remainder tail will decode up to 3 extra output bytes:
    let capacity = base85.len().checked_mul(4)? / 5 + 3;
    let mut ret = Vec::<u8>::with_capacity(capacity);

    let mut r = 0usize;
    while r < base85.len() {
        // SAFETY: r less than slice length
        let c = unsafe { *base85.get_unchecked(r) };

        // decompress zeros and continue
        if c == BASE85_ZEROS {
            ret.extend_from_slice(&[0u8; 4]);
            r += 1;
        }
        // try to pull a whole chunk
        // NOTE: 'z' in a chunk results in None
        else if r + 5 <= base85.len() {
            let chunk: [u8; 5] = base85[r..r + 5].try_into().ok()?;
            ret.extend_from_slice(&decode_base85_chunk(chunk)?);
            r += 5;
        }
        // tail section
        else {
            // must be 2, 3, or 4; a single trailing ASCII byte cannot be
            // produced by the canonical encoder
            let rem = base85.len() - r;
            if rem == 1 {
                return None;
            }

            // pad with 'u' bytes to reverse encoding padding
            let mut padded = [BASE85_DEC_PAD; 5];
            padded[..rem].copy_from_slice(&base85[r..]);

            // NOTE: Returns None if padded chunk is malformed
            let decoded = decode_base85_chunk(padded)?;

            // the number of padding 'u' bytes added are equal to the amount
            // of bytes stripped from the decoded buffer
            //      - 2 ASCII => 3 'u' bytes => 1 byte output
            //      - 3 ASCII => 2 'u' bytes => 2 bytes output
            //      - 4 ASCII => 1 'u' byte  => 3 bytes output
            //
            // that is, bytes kept: remainder - 1
            ret.extend_from_slice(&decoded[..rem - 1]);

            break;
        }
    }

    Some(ret.into_boxed_slice())
}

#[inline]
fn decode_base85_chunk(chunk: [u8; 5]) -> Option<[u8; 4]> {
    // Convert each character to a value from 0 to 84 and accumulate it in
    // most-significant-to-least-significant order.
    let mut acc = 0u32;
    for c in chunk {
        let i = c as usize;
        if !(MIN_ASCII..MAX_ASCII).contains(&i) {
            // byte out of base85 ASCII range
            return None;
        }

        // SAFETY: i - MIN_ASCII is guaranteed to fall within
        // [0, MAX_ASCII - MIN_ASCII)
        let d = unsafe { *DECODER.get_unchecked(i - MIN_ASCII) } as u32;
        if d == 255 {
            // byte is not encoded base85
            return None;
        }

        acc = acc.checked_mul(85)?.checked_add(d)?;
    }

    Some(acc.to_be_bytes())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fmt::Debug;

    #[test]
    fn known_vector_roundtrips_through_byte_and_string_apis() {
        let input = [0x86u8, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b];
        let expected = b"L/669[9<6.";

        assert_eq!(&*encode_base85(&input), expected);
        assert_eq!(encode_base85_string(&input), "L/669[9<6.");
        assert_eq!(
            try_decode_base85(expected).as_deref(),
            Some(input.as_slice())
        );
        assert_eq!(
            try_decode_base85_string("L/669[9<6.").as_deref(),
            Some(input.as_slice())
        );
    }

    #[test]
    fn empty_input_roundtrips() {
        assert_eq!(&*encode_base85(b""), b"");
        assert_eq!(encode_base85_string(b""), "");
        assert_eq!(try_decode_base85(b"").as_deref(), Some(b"".as_slice()));
        assert_eq!(
            try_decode_base85_string("").as_deref(),
            Some(b"".as_slice())
        );
    }

    #[test]
    fn tables_preserve_unsafe_indexing_and_utf8_invariants() {
        let mut seen = [false; DECODER.len()];

        for (digit, &ascii) in ENCODER.iter().enumerate() {
            assert!(ascii.is_ascii());

            let ascii = ascii as usize;
            assert!((MIN_ASCII..MAX_ASCII).contains(&ascii));

            let offset = ascii - MIN_ASCII;
            assert!(!seen[offset], "duplicate base85 byte at ASCII {ascii}");
            seen[offset] = true;
            assert_eq!(DECODER[offset], digit as u8);
        }
    }

    #[test]
    fn encode_handles_tail_chunks() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"M", b"9`"),
            (b"Ma", b"9jn"),
            (b"Man", b"9jqo"),
            (b"Man s", b"9jqo^Er"),
        ];

        for &(input, expected) in cases {
            assert_eq!(encode_base85(input).as_ref(), expected);
        }
    }

    #[test]
    fn encode_compresses_full_zero_chunks_but_not_zero_tails() {
        let cases: &[(&[u8], &[u8])] = &[
            (&[0], b"!!"),
            (&[0, 0], b"!!!"),
            (&[0, 0, 0], b"!!!!"),
            (&[0, 0, 0, 0], b"z"),
            (&[0, 0, 0, 1], b"!!!!\""),
        ];

        for &(input, expected) in cases {
            assert_eq!(encode_base85(input).as_ref(), expected);
        }
    }

    #[test]
    fn byte_slices_of_arbitrary_lengths_roundtrip() {
        for len in 0usize..=64 {
            let input: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(73).wrapping_add(len * 19)) as u8)
                .collect();
            let encoded = encode_base85(&input);

            assert_eq!(
                try_decode_base85(&encoded).as_deref(),
                Some(input.as_slice()),
                "failed to roundtrip {len} data bytes"
            );
        }
    }

    #[test]
    fn decode_rejects_single_ascii_tails() {
        for input in [b"!".as_slice(), b"!!!!!!".as_slice(), b"z!".as_slice()] {
            assert_eq!(try_decode_base85(input), None, "accepted {input:?}");
        }
    }

    #[test]
    fn decode_accepts_compressed_and_uncompressed_zero_chunks() {
        for input in [b"z".as_slice(), b"!!!!!".as_slice()] {
            assert_eq!(try_decode_base85(input).as_deref(), Some([0; 4].as_slice()));
        }

        for input in [b"z!!!!!".as_slice(), b"!!!!!z".as_slice()] {
            assert_eq!(try_decode_base85(input).as_deref(), Some([0; 8].as_slice()));
        }
    }

    #[test]
    fn decode_rejects_invalid_bytes_in_any_frame() {
        for invalid in [(MIN_ASCII - 1) as u8, MAX_ASCII as u8] {
            for position in 0..5 {
                let mut input = *b"!!!!!";
                input[position] = invalid;
                assert_eq!(
                    try_decode_base85(&input),
                    None,
                    "accepted byte {invalid:#04x} at position {position}"
                );
            }
        }

        let mut second_frame = *b"!!!!!!!!!!";
        second_frame[7] = BASE85_ZEROS;
        assert_eq!(try_decode_base85(&second_frame), None);
    }

    #[test]
    fn decode_rejects_value_just_above_u32_max() {
        assert_eq!(
            try_decode_base85(b"s8W-!").as_deref(),
            Some([u8::MAX; 4].as_slice())
        );
        assert_eq!(try_decode_base85(b"s8W-\""), None);
    }

    fn assert_primitive_encoding<T>(value: T, expected: &str)
    where
        T: Base85 + Debug + Eq,
    {
        let encoded_string = value.as_base85_string();
        let encoded = value.as_base85();

        assert_eq!(encoded_string, expected);
        assert_eq!(encoded.as_ref(), expected.as_bytes());
        assert_eq!(T::try_from_base85_string(&encoded_string), Some(value));
        assert_eq!(T::try_from_base85(&encoded), Some(value));
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
        assert_eq!(u32::try_from_base85(b"!!!"), None);
        assert_eq!(u32::try_from_base85(b"z"), Some(0));
        assert_eq!(u32::try_from_base85(b"zz"), None);
    }
}

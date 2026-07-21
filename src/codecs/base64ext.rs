// BASE64 CODEC
// Strictly emits canonical RFC 4648 Base64 and rejects non-zero pad-bit aliases.
// Decoding is extended to accept omitted final padding, treat independently padded
// quanta as concatenated Base64 values, and ignore all-padding quanta.
// https://www.rfc-editor.org/rfc/rfc4648.html

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

const BASE64_PAD: u8 = b'=';

mod sealed {
    pub trait Sealed {}
}

pub trait Base64: sealed::Sealed + Copy {
    fn as_base64_string(&self) -> String;

    fn as_base64(&self) -> Box<[u8]>;

    fn try_from_base64_string(base64_str: &str) -> Option<Self>;
    fn try_from_base64(base64: &[u8]) -> Option<Self>;
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
        )+
    };
}

impl_base64!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
);

#[inline]
pub fn encode_base64_string(bytes: &[u8]) -> String {
    let base64_bytes = encode_base64(bytes);
    // SAFETY: base64 bytes are ASCII, therefore always valid UTF-8
    unsafe { String::from_utf8_unchecked(base64_bytes.into_vec()) }
}

#[inline]
pub fn encode_base64(bytes: &[u8]) -> Box<[u8]> {
    // INVARIANT: encoder table MUST be exactly 64
    const { assert!(ENCODER.len() == 64) }

    if bytes.is_empty() {
        return Vec::<u8>::new().into_boxed_slice();
    }

    // base64 encodes four ASCII bytes per three byte chunks
    // and at most four extra bytes for a padded tail
    let capacity = bytes
        .len()
        .checked_mul(4)
        .expect("base64 encoded length overflow")
        / 3
        + 4;

    let (chunks, remainder) = bytes.as_chunks::<3>();
    let mut ret = Vec::<u8>::with_capacity(capacity);

    for &chunk in chunks {
        let encoded = encode_base64_full_chunk(chunk);
        ret.extend_from_slice(&encoded);
    }

    if !remainder.is_empty() {
        ret.extend_from_slice(&encode_base64_tail(remainder));
    }

    ret.into_boxed_slice()
}

#[inline]
fn encode_base64_full_chunk(chunk: [u8; 3]) -> [u8; 4] {
    // pack each byte into a u32
    let n = u32::from_be_bytes([0, chunk[0], chunk[1], chunk[2]]);

    // the four 6-bit sextets
    const { assert!(0x3f < ENCODER.len()) }
    let on = n >> 18 & 0x3f; // Not required, but ensures safe indexing if n isn't initialized to zero.
    let tw = n >> 12 & 0x3f;
    let th = n >> 6 & 0x3f;
    let fo = n & 0x3f;

    // the four encoded bytes
    // SAFETY: six-bit sextet 3F is guaranteed to be on the range [0, 64)
    let on = unsafe { *ENCODER.get_unchecked(on as usize) };
    // SAFETY: six-bit sextet 3F is guaranteed to be on the range [0, 64)
    let tw = unsafe { *ENCODER.get_unchecked(tw as usize) };
    // SAFETY: six-bit sextet 3F is guaranteed to be on the range [0, 64)
    let th = unsafe { *ENCODER.get_unchecked(th as usize) };
    // SAFETY: six-bit sextet 3F is guaranteed to be on the range [0, 64)
    let fo = unsafe { *ENCODER.get_unchecked(fo as usize) };

    [on, tw, th, fo]
}

#[inline]
fn encode_base64_tail(tail: &[u8]) -> [u8; 4] {
    // must be 1 or 2
    let len = tail.len();

    // pad with null bytes for encoding
    // "These pad bits MUST be set to zero by conforming encoders..."
    let mut padded = [0u8; 3];
    padded[..len].copy_from_slice(tail);
    let mut encoded = encode_base64_full_chunk(padded);

    // replace bytes in the encoded position with b'=' based on tail length
    //      - 1 byte  => two encoded bytes and two b'=' bytes
    //      - 2 bytes => three encoded bytes and one b'=' byte
    match len {
        1 => {
            encoded[2] = BASE64_PAD;
            encoded[3] = BASE64_PAD;
        }
        2 => encoded[3] = BASE64_PAD,
        _ => unreachable!("tail length must be one or two"),
    }

    encoded
}

#[inline]
pub fn try_decode_base64_string(base64: &str) -> Option<Box<[u8]>> {
    try_decode_base64(base64.as_bytes())
}

#[inline]
pub fn try_decode_base64(base64: &[u8]) -> Option<Box<[u8]>> {
    // INVARIANT: MAX_ASCII must always be larger than MIN_ASCII
    const { assert!(MAX_ASCII > MIN_ASCII) }

    // INVARIANT: the decoder must be sized on the range [MIN_ASCII, MAX_ASCII)
    const { assert!(MAX_ASCII - MIN_ASCII == DECODER.len()) }

    // empty inputs result in empty outputs
    if base64.is_empty() {
        return Some(Vec::<u8>::new().into_boxed_slice());
    }

    // base64 encodes four ASCII bytes per three byte chunks
    // an unpadded tail implies up to two extra bytes
    let capacity = base64.len().checked_mul(3)? / 4 + 2;

    // ideally, every input base64 evenly divides into chunks of 4
    // but we gracefully handle implied padding.
    // all-padding chunks DO NOT contribute to the byte stream
    // NOTE: the consequence of this is two concatenated base64 strings
    // will round-trip as an entirely different base64 string if they have padding
    let (chunks, remainder) = base64.as_chunks::<4>();
    let mut ret = Vec::<u8>::with_capacity(capacity);

    for &chunk in chunks {
        // possibly a valid chunk
        // malformed chunks return immediately
        match chunk {
            // skip chunks with only padding
            [BASE64_PAD, BASE64_PAD, BASE64_PAD, BASE64_PAD] => {}
            [_, _, BASE64_PAD, BASE64_PAD] => ret.push(decode_base64_two_pads(chunk)?),
            [_, _, _, BASE64_PAD] => ret.extend_from_slice(&decode_base64_one_pad(chunk)?),
            _ => ret.extend_from_slice(&decode_base64_full_chunk(chunk)?),
        }
    }

    // handle a tail with implied padding, if any
    if !remainder.is_empty() {
        // malformed if one ASCII character
        if remainder.len() == 1 {
            return None;
        }

        // [x, x] OR [x, x, x]
        decode_base64_tail(remainder, &mut ret)?;
    }

    Some(ret.into_boxed_slice())
}

#[inline]
fn decode_base64_full_chunk(chunk: [u8; 4]) -> Option<[u8; 3]> {
    let [on, tw, th, fo] = chunk;

    let on = check_and_decode_b64_byte(on)?;
    let tw = check_and_decode_b64_byte(tw)?;
    let th = check_and_decode_b64_byte(th)?;
    let fo = check_and_decode_b64_byte(fo)?;

    // rehydrate chunk bytes into a u32
    // NOTE: each decoded byte is guaranteed [0, 64) from the decoding table
    let n = on << 18 | tw << 12 | th << 6 | fo;

    // strip off the top byte and return
    // [0, x, x, x]
    n.to_be_bytes()[1..].try_into().ok()
}

// Two ASCII and two pad, returns one decoded byte
#[inline]
fn decode_base64_two_pads(chunk: [u8; 4]) -> Option<u8> {
    let [on, tw, _, _] = chunk;

    let on = check_and_decode_b64_byte(on)?;
    let tw = check_and_decode_b64_byte(tw)?;

    // Only the top two bits of the second sextet carry data.
    if tw & 0x0f != 0 {
        return None;
    }

    let n = on << 18 | tw << 12;

    // return one byte only: [0, x, _, _]
    Some((n >> 16) as u8)
}

// Three ASCII and one pad, returns two decoded bytes
#[inline]
fn decode_base64_one_pad(chunk: [u8; 4]) -> Option<[u8; 2]> {
    let [on, tw, th, _] = chunk;

    let on = check_and_decode_b64_byte(on)?;
    let tw = check_and_decode_b64_byte(tw)?;
    let th = check_and_decode_b64_byte(th)?;

    // Only the top four bits of the third sextet carry data.
    if th & 0x03 != 0 {
        return None;
    }

    let n = on << 18 | tw << 12 | th << 6;

    // return two bytes only: [0, x, x, _]
    let bytes = n.to_be_bytes();
    Some([bytes[1], bytes[2]])
}

// tail length 2 OR 3
#[inline]
fn decode_base64_tail(tail: &[u8], ret: &mut Vec<u8>) -> Option<()> {
    let length = tail.len();
    assert!(length == 2 || length == 3);

    let mut buf = [BASE64_PAD; 4];
    buf[..length].copy_from_slice(tail);
    match length {
        2 => ret.push(decode_base64_two_pads(buf)?),
        3 => ret.extend_from_slice(&decode_base64_one_pad(buf)?),
        _ => unreachable!("tail length must be 2 or 3"),
    }

    Some(())
}

#[inline]
fn check_and_decode_b64_byte(byte: u8) -> Option<u32> {
    if !(MIN_ASCII..MAX_ASCII).contains(&(byte as usize)) {
        // byte out of base64 ASCII range
        return None;
    }

    // SAFETY: byte - MIN_ASCII within [0, MAX_ASCII - MIN_ASCII)
    let byte = unsafe { *DECODER.get_unchecked(byte as usize - MIN_ASCII) as u32 };
    if byte == 255 {
        // byte is not encoded base64
        return None;
    }

    Some(byte)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fmt::Debug;

    #[test]
    fn rfc_4648_base64_test_vectors_pin_encoding_and_decoding() {
        let vectors: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];

        for &(plain, base64) in vectors {
            assert_eq!(encode_base64(plain).as_ref(), base64.as_bytes());
            assert_eq!(encode_base64_string(plain), base64);
            assert_eq!(try_decode_base64(base64.as_bytes()).as_deref(), Some(plain));
            assert_eq!(try_decode_base64_string(base64).as_deref(), Some(plain));
        }
    }

    #[test]
    fn tables_preserve_unsafe_indexing_and_utf8_invariants() {
        let mut seen = [false; DECODER.len()];

        for (digit, &ascii) in ENCODER.iter().enumerate() {
            assert!(ascii.is_ascii());

            let ascii = ascii as usize;
            assert!((MIN_ASCII..MAX_ASCII).contains(&ascii));

            let offset = ascii - MIN_ASCII;
            assert!(!seen[offset], "duplicate base64 byte at ASCII {ascii}");
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
    fn byte_slices_of_arbitrary_lengths_roundtrip() {
        for len in 0usize..=64 {
            let input: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(73).wrapping_add(len * 19)) as u8)
                .collect();
            let encoded = encode_base64(&input);
            let padding = match len % 3 {
                0 => 0,
                1 => 2,
                2 => 1,
                _ => unreachable!(),
            };

            assert_eq!(encoded.len(), len.div_ceil(3) * 4);
            assert!(
                encoded[..encoded.len() - padding]
                    .iter()
                    .all(|byte| ENCODER.contains(byte))
            );
            assert!(
                encoded[encoded.len() - padding..]
                    .iter()
                    .all(|&byte| byte == BASE64_PAD)
            );

            assert_eq!(
                try_decode_base64(&encoded).as_deref(),
                Some(input.as_slice()),
                "failed to roundtrip {len} data bytes"
            );
        }
    }

    #[test]
    fn decode_accepts_unpadded_final_quantum() {
        for (input, expected) in [("Zg", b"f".as_slice()), ("Zm8", b"fo".as_slice())] {
            assert_eq!(try_decode_base64_string(input).as_deref(), Some(expected));
        }
    }

    #[test]
    fn decode_rejects_alias_with_two_padding_characters() {
        assert_eq!(
            try_decode_base64_string("TQ==").as_deref(),
            Some(b"M".as_slice())
        );
        assert_eq!(try_decode_base64_string("TR=="), None);
    }

    #[test]
    fn decode_rejects_alias_with_one_padding_character() {
        assert_eq!(
            try_decode_base64_string("TWE=").as_deref(),
            Some(b"Ma".as_slice())
        );
        assert_eq!(try_decode_base64_string("TWF="), None);
    }

    #[test]
    fn decode_accepts_padding_only_chunks() {
        for input in [b"====".as_slice(), b"========".as_slice()] {
            assert_eq!(try_decode_base64(input).as_deref(), Some(b"".as_slice()));
        }
    }

    #[test]
    fn decode_treats_padded_quanta_as_concatenated_values() {
        assert_eq!(
            try_decode_base64_string("TQ==TQ==").as_deref(),
            Some(b"MM".as_slice())
        );
    }

    #[test]
    fn decode_rejects_single_ascii_tails() {
        for input in [
            b"A".as_slice(),
            b"AAAAA".as_slice(),
            b"AAAAAAAAA".as_slice(),
        ] {
            assert_eq!(try_decode_base64(input), None, "accepted {input:?}");
        }
    }

    #[test]
    fn decode_rejects_misplaced_or_partial_padding() {
        for input in [
            b"=AAA".as_slice(),
            b"A=AA".as_slice(),
            b"AA=A".as_slice(),
            b"A===".as_slice(),
            b"===A".as_slice(),
            b"===".as_slice(),
            b"AA=".as_slice(),
            b"A==".as_slice(),
        ] {
            assert_eq!(try_decode_base64(input), None, "accepted {input:?}");
        }
    }

    #[test]
    fn decode_rejects_invalid_bytes_in_any_frame() {
        for invalid in [
            u8::MIN,
            (MIN_ASCII - 1) as u8,
            b',',
            b':',
            b'@',
            b'[',
            b'`',
            MAX_ASCII as u8,
            u8::MAX,
        ] {
            for position in 0..4 {
                let mut input = *b"AAAA";
                input[position] = invalid;
                assert_eq!(
                    try_decode_base64(&input),
                    None,
                    "accepted byte {invalid:#04x} at position {position}"
                );
            }
        }

        let mut second_frame = *b"AAAAAAAA";
        second_frame[6] = b',';
        assert_eq!(try_decode_base64(&second_frame), None);
    }

    fn assert_primitive_encoding<T>(value: T, expected: &str)
    where
        T: Base64 + Debug + Eq,
    {
        let encoded_string = value.as_base64_string();
        let encoded = value.as_base64();

        assert_eq!(encoded_string, expected);
        assert_eq!(encoded.as_ref(), expected.as_bytes());
        assert_eq!(T::try_from_base64_string(&encoded_string), Some(value));
        assert_eq!(T::try_from_base64(&encoded), Some(value));
    }

    #[test]
    fn integer_primitive_encodings_are_pinned() {
        macro_rules! assert_min_and_max_encoding {
            ($ty:ty, $min:literal, $max:literal) => {
                assert_primitive_encoding(<$ty>::MIN, $min);
                assert_primitive_encoding(<$ty>::MAX, $max);
            };
        }

        assert_min_and_max_encoding!(u8, "AA==", "/w==");
        assert_min_and_max_encoding!(u16, "AAA=", "//8=");
        assert_min_and_max_encoding!(u32, "AAAAAA==", "/////w==");
        assert_min_and_max_encoding!(u64, "AAAAAAAAAAA=", "//////////8=");
        assert_min_and_max_encoding!(u128, "AAAAAAAAAAAAAAAAAAAAAA==", "/////////////////////w==");

        assert_min_and_max_encoding!(i8, "gA==", "fw==");
        assert_min_and_max_encoding!(i16, "gAA=", "f/8=");
        assert_min_and_max_encoding!(i32, "gAAAAA==", "f////w==");
        assert_min_and_max_encoding!(i64, "gAAAAAAAAAA=", "f/////////8=");
        assert_min_and_max_encoding!(i128, "gAAAAAAAAAAAAAAAAAAAAA==", "f////////////////////w==");

        #[cfg(target_pointer_width = "16")]
        {
            assert_min_and_max_encoding!(usize, "AAA=", "//8=");
            assert_min_and_max_encoding!(isize, "gAA=", "f/8=");
        }

        #[cfg(target_pointer_width = "32")]
        {
            assert_min_and_max_encoding!(usize, "AAAAAA==", "/////w==");
            assert_min_and_max_encoding!(isize, "gAAAAA==", "f////w==");
        }

        #[cfg(target_pointer_width = "64")]
        {
            assert_min_and_max_encoding!(usize, "AAAAAAAAAAA=", "//////////8=");
            assert_min_and_max_encoding!(isize, "gAAAAAAAAAA=", "f/////////8=");
        }
    }

    #[test]
    fn integer_primitive_decoding_requires_the_exact_data_width() {
        assert_eq!(u32::try_from_base64(b"AAA="), None);
        assert_eq!(u32::try_from_base64(b"AAAAAA=="), Some(0));
        assert_eq!(u32::try_from_base64(b"AAAAAAAAAAA="), None);
    }
}

const BASE16_MIXED: Decoder = const {
    use super::{DECODER, MAX_ASCII, MIN_ASCII};
    Decoder::from_table(&DECODER, MIN_ASCII, MAX_ASCII)
};
const BASE16_LOWER: Decoder = const {
    use super::{DECODER_LOWER, MAX_ASCII_LOWER, MIN_ASCII_LOWER};
    Decoder::from_table(&DECODER_LOWER, MIN_ASCII_LOWER, MAX_ASCII_LOWER)
};
const BASE16_UPPER: Decoder = const {
    use super::{DECODER_UPPER, MAX_ASCII_UPPER, MIN_ASCII_UPPER};
    Decoder::from_table(&DECODER_UPPER, MIN_ASCII_UPPER, MAX_ASCII_UPPER)
};

#[inline]
pub fn try_decode_base16_string(base16: &str) -> Option<Box<[u8]>> {
    BASE16_MIXED.try_decode_base16_string(base16)
}

#[inline]
pub fn try_decode_base16lower_string(base16: &str) -> Option<Box<[u8]>> {
    BASE16_LOWER.try_decode_base16_string(base16)
}

#[inline]
pub fn try_decode_base16upper_string(base16: &str) -> Option<Box<[u8]>> {
    BASE16_UPPER.try_decode_base16_string(base16)
}

#[inline]
pub fn try_decode_base16(base16: &[u8]) -> Option<Box<[u8]>> {
    BASE16_MIXED.try_decode_base16(base16)
}

#[inline]
pub fn try_decode_base16lower(base16: &[u8]) -> Option<Box<[u8]>> {
    BASE16_LOWER.try_decode_base16(base16)
}

#[inline]
pub fn try_decode_base16upper(base16: &[u8]) -> Option<Box<[u8]>> {
    BASE16_UPPER.try_decode_base16(base16)
}

struct Decoder<'d> {
    decoder: &'d [u8],
    min_ascii: usize,
    max_ascii: usize,
}

impl<'d> Decoder<'d> {
    #[inline]
    const fn from_table(decoder: &'d [u8], min_ascii: usize, max_ascii: usize) -> Self {
        // INVARIANT: MAX_ASCII must always be larger than MIN_ASCII.
        assert!(max_ascii > min_ascii);

        // INVARIANT: the decoder must be sized on the range [MIN_ASCII, MAX_ASCII).
        assert!(max_ascii - min_ascii == decoder.len());

        Self {
            decoder,
            min_ascii,
            max_ascii,
        }
    }

    #[inline]
    fn try_decode_base16_string(&self, base16: &str) -> Option<Box<[u8]>> {
        self.try_decode_base16(base16.as_bytes())
    }

    fn try_decode_base16(&self, base16: &[u8]) -> Option<Box<[u8]>> {
        // Empty inputs result in empty outputs.
        if base16.is_empty() {
            return Some(Vec::<u8>::new().into_boxed_slice());
        }

        // INVARIANT: input length must be a multiple of two.
        if !base16.len().is_multiple_of(2) {
            return None;
        }

        let mut ret = Vec::<u8>::with_capacity(base16.len() / 2);
        let (pairs, []) = base16.as_chunks::<2>() else {
            unreachable!("base16 slice always a multiple of two")
        };

        for &[hi, lo] in pairs {
            let hi = self.check_and_decode_base16_byte(hi)?;
            let lo = self.check_and_decode_base16_byte(lo)?;
            ret.push(hi << 4 | lo);
        }

        Some(ret.into_boxed_slice())
    }

    #[inline]
    fn check_and_decode_base16_byte(&self, byte: u8) -> Option<u8> {
        if !(self.min_ascii..self.max_ascii).contains(&(byte as usize)) {
            // Byte is outside this base16 decoder's ASCII range.
            return None;
        }

        let i = byte as usize - self.min_ascii;

        // SAFETY: byte - MIN_ASCII is within [0, MAX_ASCII - MIN_ASCII).
        let byte = unsafe { *self.decoder.get_unchecked(i) };
        if byte == 255 {
            // Byte is not part of this base16 alphabet.
            return None;
        }

        Some(byte)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ENCODER_LOWER, ENCODER_UPPER};
    use super::*;

    type Decode = fn(&[u8]) -> Option<Box<[u8]>>;

    #[test]
    fn mixed_case_decoder_accepts_lowercase_uppercase_and_mixed_input() {
        for encoded in ["deadbeef", "DEADBEEF", "dEaDbEeF"] {
            assert_eq!(
                try_decode_base16(encoded.as_bytes()).as_deref(),
                Some([0xde, 0xad, 0xbe, 0xef].as_slice())
            );
            assert_eq!(
                try_decode_base16_string(encoded).as_deref(),
                Some([0xde, 0xad, 0xbe, 0xef].as_slice())
            );
        }
    }

    #[test]
    fn strict_decoders_accept_only_their_selected_case() {
        let expected = Some([0xde, 0xad, 0xbe, 0xef].as_slice());

        assert_eq!(try_decode_base16lower(b"deadbeef").as_deref(), expected);
        assert_eq!(
            try_decode_base16lower_string("deadbeef").as_deref(),
            expected
        );
        assert_eq!(try_decode_base16lower(b"DEADBEEF"), None);
        assert_eq!(try_decode_base16lower(b"dEaDbEeF"), None);

        assert_eq!(try_decode_base16upper(b"DEADBEEF").as_deref(), expected);
        assert_eq!(
            try_decode_base16upper_string("DEADBEEF").as_deref(),
            expected
        );
        assert_eq!(try_decode_base16upper(b"deadbeef"), None);
        assert_eq!(try_decode_base16upper(b"dEaDbEeF"), None);

        assert_eq!(
            try_decode_base16lower(b"0123456789").as_deref(),
            Some([0x01, 0x23, 0x45, 0x67, 0x89].as_slice())
        );
        assert_eq!(
            try_decode_base16upper(b"0123456789").as_deref(),
            Some([0x01, 0x23, 0x45, 0x67, 0x89].as_slice())
        );
    }

    #[test]
    fn every_decoder_rejects_malformed_input() {
        let decoders: &[(&str, Decode)] = &[
            ("mixed-case", try_decode_base16),
            ("lowercase", try_decode_base16lower),
            ("uppercase", try_decode_base16upper),
        ];

        for &(name, decode) in decoders {
            assert_eq!(decode(b"0"), None, "{name} accepted an odd-length input");

            for invalid in [u8::MIN, b'/', b':', b'G', b'g', u8::MAX] {
                assert_eq!(decode(&[invalid, b'0']), None, "{name}, high nibble");
                assert_eq!(decode(&[b'0', invalid]), None, "{name}, low nibble");
            }
        }
    }

    #[test]
    fn tables_preserve_unsafe_indexing_invariants() {
        fn assert_invariants(decoder: &Decoder<'_>, alphabets: &[&[u8]]) {
            assert!(decoder.max_ascii > decoder.min_ascii);
            assert_eq!(decoder.max_ascii - decoder.min_ascii, decoder.decoder.len());

            let mut seen = vec![false; decoder.decoder.len()];
            for alphabet in alphabets {
                for (digit, &ascii) in alphabet.iter().enumerate() {
                    let ascii = ascii as usize;
                    assert!((decoder.min_ascii..decoder.max_ascii).contains(&ascii));

                    let offset = ascii - decoder.min_ascii;
                    // Decimal digits are intentionally shared by the lowercase
                    // and uppercase alphabets.
                    if seen[offset] {
                        assert!((ascii as u8).is_ascii_digit());
                    } else {
                        seen[offset] = true;
                    }
                    assert_eq!(decoder.decoder[offset], digit as u8);
                }
            }

            for (offset, &digit) in decoder.decoder.iter().enumerate() {
                if digit == 255 {
                    continue;
                }

                let ascii = (decoder.min_ascii + offset) as u8;
                assert!(
                    alphabets
                        .iter()
                        .any(|alphabet| alphabet[digit as usize] == ascii)
                );
            }
        }

        assert_invariants(&BASE16_MIXED, &[&ENCODER_LOWER, &ENCODER_UPPER]);
        assert_invariants(&BASE16_LOWER, &[&ENCODER_LOWER]);
        assert_invariants(&BASE16_UPPER, &[&ENCODER_UPPER]);
    }

    #[test]
    fn arbitrary_byte_slices_roundtrip_through_the_matching_decoders() {
        for len in 0usize..=64 {
            let input: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(73).wrapping_add(len * 19)) as u8)
                .collect();

            let lower = super::super::encode_base16(&input);
            assert_eq!(try_decode_base16(&lower).as_deref(), Some(input.as_slice()));
            assert_eq!(
                try_decode_base16lower(&lower).as_deref(),
                Some(input.as_slice())
            );

            let upper = super::super::encode_base16upper(&input);
            assert_eq!(try_decode_base16(&upper).as_deref(), Some(input.as_slice()));
            assert_eq!(
                try_decode_base16upper(&upper).as_deref(),
                Some(input.as_slice())
            );
        }
    }
}

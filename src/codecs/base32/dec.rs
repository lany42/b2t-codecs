// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Strict canonical Base32 and Base32Hex decoders.
//!
//! Inputs must use the selected uppercase alphabet, consist of complete
//! eight-symbol quanta, and use canonical terminal padding with zero pad bits.
//!
//! ```rust
//! use b2t_codecs::base32::{try_decode_base32_string, try_decode_base32hex_string};
//!
//! assert_eq!(
//!     try_decode_base32_string("MZXW6===").as_deref(),
//!     Some(b"foo".as_slice()),
//! );
//! assert_eq!(
//!     try_decode_base32hex_string("CPNMU===").as_deref(),
//!     Some(b"foo".as_slice()),
//! );
//! ```
use crate::base32::BASE32_PAD;

const BASE32_RFC: Decoder = const {
    use super::{DECODER, MAX_ASCII, MIN_ASCII};
    Decoder::from_table(&DECODER, MIN_ASCII, MAX_ASCII)
};
const BASE32_HEX: Decoder = const {
    use super::{DECODER_HEX, MAX_ASCII_HEX, MIN_ASCII_HEX};
    Decoder::from_table(&DECODER_HEX, MIN_ASCII_HEX, MAX_ASCII_HEX)
};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec};

/// Decodes a canonical padded Base32 string.
///
/// Returns [`None`] unless `base32` uses the RFC 4648 Base32 alphabet, complete
/// eight-symbol quanta, terminal padding, and zero pad bits.
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base32_string(base32: &str) -> Option<Box<[u8]>> {
    BASE32_RFC.try_decode_base32_string(base32)
}

/// Decodes canonical padded Base32 ASCII bytes.
///
/// Returns [`None`] unless `base32` uses the RFC 4648 Base32 alphabet, complete
/// eight-symbol quanta, terminal padding, and zero pad bits.
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base32(base32: &[u8]) -> Option<Box<[u8]>> {
    BASE32_RFC.try_decode_base32(base32)
}

/// Decodes a canonical padded Base32Hex string.
///
/// Returns [`None`] unless `base32hex` uses the RFC 4648 Base32Hex alphabet,
/// complete eight-symbol quanta, terminal padding, and zero pad bits.
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base32hex_string(base32hex: &str) -> Option<Box<[u8]>> {
    BASE32_HEX.try_decode_base32_string(base32hex)
}

/// Decodes canonical padded Base32Hex ASCII bytes.
///
/// Returns [`None`] unless `base32hex` uses the RFC 4648 Base32Hex alphabet,
/// complete eight-symbol quanta, terminal padding, and zero pad bits.
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base32hex(base32hex: &[u8]) -> Option<Box<[u8]>> {
    BASE32_HEX.try_decode_base32(base32hex)
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
    fn try_decode_base32_string(&self, base32: &str) -> Option<Box<[u8]>> {
        self.try_decode_base32(base32.as_bytes())
    }

    fn try_decode_base32(&self, base32: &[u8]) -> Option<Box<[u8]>> {
        // empty inputs result in empty outputs
        if base32.is_empty() {
            return Some(Vec::<u8>::new().into_boxed_slice());
        }

        // INVARIANT: strict base32 encodes eight ASCII per five bytes
        if !base32.len().is_multiple_of(8) {
            return None;
        }

        let cap = base32.len().checked_mul(5)? / 8;
        let mut ret = Vec::<u8>::with_capacity(cap);

        let (chunks, []) = base32.as_chunks::<8>() else {
            unreachable!("base32 slice always a multiple of eight")
        };
        let (tail, chunks) = chunks.split_last().unwrap();

        // whole chunks
        // padding characters are malformed here
        for &chunk in chunks {
            ret.extend_from_slice(&self.decode_base32_full_chunk(chunk)?);
        }

        // handle padding at the tail
        match tail {
            [
                _,
                _,
                BASE32_PAD,
                BASE32_PAD,
                BASE32_PAD,
                BASE32_PAD,
                BASE32_PAD,
                BASE32_PAD,
            ] => {
                let byte = self.decode_base32_six_pads(*tail)?;
                ret.push(byte);
            }
            [_, _, _, _, BASE32_PAD, BASE32_PAD, BASE32_PAD, BASE32_PAD] => {
                let chunk = self.decode_base32_four_pads(*tail)?;
                ret.extend_from_slice(&chunk);
            }
            [_, _, _, _, _, BASE32_PAD, BASE32_PAD, BASE32_PAD] => {
                let chunk = self.decode_base32_three_pads(*tail)?;
                ret.extend_from_slice(&chunk);
            }
            [_, _, _, _, _, _, _, BASE32_PAD] => {
                let chunk = self.decode_base32_one_pad(*tail)?;
                ret.extend_from_slice(&chunk);
            }
            _ => {
                let chunk = self.decode_base32_full_chunk(*tail)?;
                ret.extend_from_slice(&chunk);
            }
        }

        Some(ret.into_boxed_slice())
    }

    fn decode_base32_full_chunk(&self, chunk: [u8; 8]) -> Option<[u8; 5]> {
        let [on, tw, th, fo, fv, sx, sv, et] = chunk;

        let on = self.check_and_decode_b32_byte(on)?;
        let tw = self.check_and_decode_b32_byte(tw)?;
        let th = self.check_and_decode_b32_byte(th)?;
        let fo = self.check_and_decode_b32_byte(fo)?;
        let fv = self.check_and_decode_b32_byte(fv)?;
        let sx = self.check_and_decode_b32_byte(sx)?;
        let sv = self.check_and_decode_b32_byte(sv)?;
        let et = self.check_and_decode_b32_byte(et)?;

        // rehydrate chunk bytes into a u64
        // NOTE: each decoded byte is guaranteed [0, 32) from the decoding table
        let n = on << 35 | tw << 30 | th << 25 | fo << 20 | fv << 15 | sx << 10 | sv << 5 | et;

        // strip off the top 3 bytes and return
        // [0, 0, 0, x, x, x, x, x]
        n.to_be_bytes()[3..].try_into().ok()
    }

    // two encoded ascii and six pad, returns one decoded byte
    fn decode_base32_six_pads(&self, chunk: [u8; 8]) -> Option<u8> {
        let [on, tw, _, _, _, _, _, _] = chunk;

        let on = self.check_and_decode_b32_byte(on)?;
        let tw = self.check_and_decode_b32_byte(tw)?;

        // Only the top three bits of the second pentad carry data
        // on => 5 bits
        // tw => 3 bits
        //      --------
        //       8 bits == 1 byte
        // The bottom two bits of the second pentad
        // MUST be zero to gate canonical encodings
        if tw & 0x03 != 0 {
            return None;
        }

        let n = on << 35 | tw << 30;

        // return one byte only: [0, 0, 0, x, _, _, _, _]
        #[allow(clippy::cast_possible_truncation)]
        Some((n >> 32) as u8)
    }

    // four encoded ascii and four pad, returns two bytes
    fn decode_base32_four_pads(&self, chunk: [u8; 8]) -> Option<[u8; 2]> {
        let [on, tw, th, fo, _, _, _, _] = chunk;

        let on = self.check_and_decode_b32_byte(on)?;
        let tw = self.check_and_decode_b32_byte(tw)?;
        let th = self.check_and_decode_b32_byte(th)?;
        let fo = self.check_and_decode_b32_byte(fo)?;

        // Only the top bit of the fourth pentad carries data
        // on => 5 bits
        // tw => 5 bits
        // th => 5 bits
        // fo => 1 bit
        //      --------
        //       16 bits == 2 bytes
        // The bottom four bits of the fourth pentad
        // MUST be zero to gate canonical encodings
        if fo & 0x0f != 0 {
            return None;
        }

        let n = on << 35 | tw << 30 | th << 25 | fo << 20;

        // return two bytes: [0, 0, 0, x, x, _, _, _]
        let bytes = n.to_be_bytes();
        Some([bytes[3], bytes[4]])
    }

    // five encoded ascii and three pad, returns three bytes
    fn decode_base32_three_pads(&self, chunk: [u8; 8]) -> Option<[u8; 3]> {
        let [on, tw, th, fo, fv, _, _, _] = chunk;

        let on = self.check_and_decode_b32_byte(on)?;
        let tw = self.check_and_decode_b32_byte(tw)?;
        let th = self.check_and_decode_b32_byte(th)?;
        let fo = self.check_and_decode_b32_byte(fo)?;
        let fv = self.check_and_decode_b32_byte(fv)?;

        // Only the top four bits of the fifth pentad carry data
        // on => 5 bits
        // tw => 5 bits
        // th => 5 bits
        // fo => 5 bits
        // fv => 4 bits
        //      --------
        //       24 bits == 3 bytes
        // The bottom bit of the fifth pentad
        // MUST be zero to gate canonical encodings
        if fv & 0x01 != 0 {
            return None;
        }

        let n = on << 35 | tw << 30 | th << 25 | fo << 20 | fv << 15;

        // return three bytes: [0, 0, 0, x, x, x, _, _]
        let bytes = n.to_be_bytes();
        Some([bytes[3], bytes[4], bytes[5]])
    }

    // seven encoded ascii and one pad, returns four bytes
    fn decode_base32_one_pad(&self, chunk: [u8; 8]) -> Option<[u8; 4]> {
        let [on, tw, th, fo, fv, sx, sv, _] = chunk;

        let on = self.check_and_decode_b32_byte(on)?;
        let tw = self.check_and_decode_b32_byte(tw)?;
        let th = self.check_and_decode_b32_byte(th)?;
        let fo = self.check_and_decode_b32_byte(fo)?;
        let fv = self.check_and_decode_b32_byte(fv)?;
        let sx = self.check_and_decode_b32_byte(sx)?;
        let sv = self.check_and_decode_b32_byte(sv)?;

        // Only the top two bits of the seventh pentad carry data
        // on => 5 bits
        // tw => 5 bits
        // th => 5 bits
        // fo => 5 bits
        // fv => 5 bits
        // sx => 5 bits
        // sv => 2 bits
        //      --------
        //       32 bits == 4 bytes
        // The bottom three bits of the seventh pentad
        // MUST be zero to gate canonical encodings
        if sv & 0x07 != 0 {
            return None;
        }

        let n = on << 35 | tw << 30 | th << 25 | fo << 20 | fv << 15 | sx << 10 | sv << 5;

        // return four bytes: [0, 0, 0, x, x, x, x, _]
        let bytes = n.to_be_bytes();
        Some([bytes[3], bytes[4], bytes[5], bytes[6]])
    }

    fn check_and_decode_b32_byte(&self, byte: u8) -> Option<u64> {
        if !(self.min_ascii..self.max_ascii).contains(&(byte as usize)) {
            // byte out of base32 ASCII range
            return None;
        }

        let i = byte as usize - self.min_ascii;

        // SAFETY: byte - MIN_ASCII within [0, MAX_ASCII - MIN_ASCII)
        let byte = unsafe { *self.decoder.get_unchecked(i) };

        if byte == 255 {
            // byte is not encoded base32
            return None;
        }
        Some(u64::from(byte))
    }
}

#[cfg(test)]
mod tests {
    use super::super::enc::{encode_base32, encode_base32hex};
    use super::super::{ENCODER, ENCODER_HEX};
    use super::*;

    use alloc::vec;

    type Encode = fn(&[u8]) -> Box<[u8]>;
    type Decode = fn(&[u8]) -> Option<Box<[u8]>>;

    fn codecs() -> [(&'static str, Encode, Decode, &'static [u8]); 2] {
        [
            ("Base32", encode_base32, try_decode_base32, &ENCODER),
            (
                "Base32Hex",
                encode_base32hex,
                try_decode_base32hex,
                &ENCODER_HEX,
            ),
        ]
    }

    #[test]
    fn rfc_4648_base32_test_vectors_pin_decoding() {
        let vectors: &[(&[u8], &str, &str)] = &[
            (b"", "", ""),
            (b"f", "MY======", "CO======"),
            (b"fo", "MZXQ====", "CPNG===="),
            (b"foo", "MZXW6===", "CPNMU==="),
            (b"foob", "MZXW6YQ=", "CPNMUOG="),
            (b"fooba", "MZXW6YTB", "CPNMUOJ1"),
            (b"foobar", "MZXW6YTBOI======", "CPNMUOJ1E8======"),
        ];

        for &(plain, base32, base32hex) in vectors {
            assert_eq!(try_decode_base32(base32.as_bytes()).as_deref(), Some(plain));
            assert_eq!(try_decode_base32_string(base32).as_deref(), Some(plain));
            assert_eq!(
                try_decode_base32hex(base32hex.as_bytes()).as_deref(),
                Some(plain)
            );
            assert_eq!(
                try_decode_base32hex_string(base32hex).as_deref(),
                Some(plain)
            );
        }
    }

    #[test]
    fn three_pad_tail_decoding_preserves_all_three_bytes() {
        assert_eq!(
            try_decode_base32(b"MZXW6===").as_deref(),
            Some(b"foo".as_slice())
        );
        assert_eq!(
            try_decode_base32hex(b"CPNMU===").as_deref(),
            Some(b"foo".as_slice())
        );
    }

    #[test]
    fn decoders_select_the_requested_alphabet() {
        assert_eq!(
            try_decode_base32(b"WA======").as_deref(),
            Some([0xb0].as_slice())
        );
        assert_eq!(
            try_decode_base32hex(b"M0======").as_deref(),
            Some([0xb0].as_slice())
        );

        assert_eq!(try_decode_base32(b"M0======"), None);
        assert_eq!(try_decode_base32hex(b"WA======"), None);
    }

    #[test]
    fn tables_preserve_unsafe_indexing_invariants() {
        fn assert_invariants(decoder: &Decoder<'_>, encoder: &[u8]) {
            assert!(decoder.max_ascii > decoder.min_ascii);
            assert_eq!(decoder.max_ascii - decoder.min_ascii, decoder.decoder.len());

            let mut seen = vec![false; decoder.decoder.len()];
            for (digit, &ascii) in encoder.iter().enumerate() {
                let ascii = ascii as usize;
                assert!((decoder.min_ascii..decoder.max_ascii).contains(&ascii));

                let offset = ascii - decoder.min_ascii;
                assert!(!seen[offset], "duplicate base32 byte at ASCII {ascii}");
                seen[offset] = true;
                assert_eq!(decoder.decoder[offset], digit as u8);
            }

            for (offset, &digit) in decoder.decoder.iter().enumerate() {
                if digit == 255 {
                    continue;
                }

                assert!((digit as usize) < encoder.len());
                assert_eq!(encoder[digit as usize] as usize, decoder.min_ascii + offset);
            }
        }

        assert_invariants(&BASE32_RFC, &ENCODER);
        assert_invariants(&BASE32_HEX, &ENCODER_HEX);
    }

    #[test]
    fn byte_slices_of_arbitrary_lengths_roundtrip_through_matching_decoders() {
        for len in 0usize..=64 {
            let input: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(73).wrapping_add(len * 19)) as u8)
                .collect();

            for (name, encode, decode, _) in codecs() {
                let encoded = encode(&input);
                assert_eq!(
                    decode(&encoded).as_deref(),
                    Some(input.as_slice()),
                    "{name} failed to roundtrip {len} data bytes"
                );
            }
        }
    }

    #[test]
    fn strict_decode_requires_complete_quanta() {
        for (name, _, decode, alphabet) in codecs() {
            for len in 1usize..16 {
                if len.is_multiple_of(8) {
                    continue;
                }

                let input = vec![alphabet[0]; len];
                assert_eq!(decode(&input), None, "{name} accepted {len} symbols");
            }
        }
    }

    #[test]
    fn decoders_reject_every_non_zero_pad_bit_alias() {
        // (input bytes, last data-symbol position, unused low-bit mask)
        let tails = [
            (1usize, 1usize, 0x03u8),
            (2, 3, 0x0f),
            (3, 4, 0x01),
            (4, 6, 0x07),
        ];

        for (name, encode, decode, alphabet) in codecs() {
            for (len, symbol, pad_bit_mask) in tails {
                let input: Vec<u8> = (0..len)
                    .map(|i| (i.wrapping_mul(83).wrapping_add(0x5b)) as u8)
                    .collect();
                let canonical = encode(&input);
                assert_eq!(
                    decode(&canonical).as_deref(),
                    Some(input.as_slice()),
                    "{name} rejected its canonical {len}-byte tail"
                );

                let digit = alphabet
                    .iter()
                    .position(|&byte| byte == canonical[symbol])
                    .expect("encoded symbol must be in the selected alphabet")
                    as u8;
                assert_eq!(digit & pad_bit_mask, 0);

                for pad_bits in 1..=pad_bit_mask {
                    let mut alias = canonical.to_vec();
                    alias[symbol] = alphabet[(digit | pad_bits) as usize];
                    assert_eq!(
                        decode(&alias),
                        None,
                        "{name} accepted non-zero pad bits {pad_bits:#04x} \
                         for a {len}-byte tail: {alias:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn strict_decode_rejects_non_terminal_or_malformed_padding() {
        for (name, encode, decode, _) in codecs() {
            for len in 1usize..=4 {
                let mut non_terminal = encode(&vec![0x5a; len]).into_vec();
                non_terminal.extend_from_slice(&encode(b"abcde"));
                assert_eq!(
                    decode(&non_terminal),
                    None,
                    "{name} accepted padding before the final quantum"
                );
            }

            for input in [
                b"========".as_slice(),
                b"================".as_slice(),
                b"=AAAAAAA".as_slice(),
                b"A=AAAAAA".as_slice(),
                b"AA=AAAAA".as_slice(),
                b"AAA=AAAA".as_slice(),
                b"AAAA=AAA".as_slice(),
                b"AAAAA=AA".as_slice(),
                b"AAAAAA=A".as_slice(),
                b"A=======".as_slice(),
                b"AAA=====".as_slice(),
                b"AAAAAA==".as_slice(),
            ] {
                assert_eq!(decode(input), None, "{name} accepted {input:?}");
            }
        }
    }

    #[test]
    fn decoders_reject_every_non_alphabet_byte_in_any_frame() {
        fn assert_invalid_bytes_rejected(name: &str, decode: Decode, alphabet: &[u8]) {
            for invalid in u8::MIN..=u8::MAX {
                if invalid == BASE32_PAD || alphabet.contains(&invalid) {
                    continue;
                }

                for position in 0..8 {
                    let mut input = [alphabet[0]; 8];
                    input[position] = invalid;
                    assert_eq!(
                        decode(&input),
                        None,
                        "{name} accepted byte {invalid:#04x} at position {position}"
                    );
                }

                let mut second_frame = [alphabet[0]; 16];
                second_frame[14] = invalid;
                assert_eq!(
                    decode(&second_frame),
                    None,
                    "{name} accepted byte {invalid:#04x} in a later frame"
                );
            }
        }

        assert_invalid_bytes_rejected("Base32", try_decode_base32, &ENCODER);
        assert_invalid_bytes_rejected("Base32Hex", try_decode_base32hex, &ENCODER_HEX);
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Decoders for strict Ascii85, Adobe85, and ZeroMQ Z85.
//!
//! Strict Ascii85 and Z85 require complete five-symbol input quanta. Adobe85
//! additionally recognizes `z` as a compressed zero quantum and decodes
//! two-to-four-symbol final quanta using implicit padding. Adobe85 decoders
//! accept raw payloads without `<~` and `~>` delimiters and ignore ASCII
//! whitespace within payloads.
//!
//! ```rust
//! use b2t_codecs::base85::{try_decode_adobe85_string, try_decode_z85_string};
//!
//! assert_eq!(
//!     try_decode_adobe85_string("z").as_deref(),
//!     Some([0, 0, 0, 0].as_slice()),
//! );
//! assert_eq!(
//!     try_decode_z85_string("Hello").as_deref(),
//!     Some([0x86, 0x4f, 0xd2, 0x6f].as_slice()),
//! );
//! ```
const ASCII85: Decoder = const {
    use super::{DECODER_ASCII85, MAX_ASCII_ASCII85, MIN_ASCII_ASCII85};
    Decoder::from_table(&DECODER_ASCII85, MIN_ASCII_ASCII85, MAX_ASCII_ASCII85)
};
const Z85: Decoder = const {
    use super::{DECODER_Z85, MAX_ASCII_Z85, MIN_ASCII_Z85};
    Decoder::from_table(&DECODER_Z85, MIN_ASCII_Z85, MAX_ASCII_Z85)
};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec};

/// Decodes a raw Adobe85 string.
///
/// The decoder accepts compressed zero quanta and implicit final padding,
/// ignores ASCII whitespace, and does not accept `<~` and `~>` delimiters.
/// Returns [`None`] if the input is malformed or a decoded quantum exceeds
/// [`u32::MAX`].
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_adobe85_string(adobe85: &str) -> Option<Box<[u8]>> {
    ASCII85.try_decode_base85ext_string(adobe85, super::ADOBE85_ZEROS, super::ADOBE85_DEC_PAD)
}

/// Decodes raw Adobe85 ASCII bytes.
///
/// The decoder accepts compressed zero quanta and implicit final padding,
/// ignores ASCII whitespace, and does not accept `<~` and `~>` delimiters.
/// Returns [`None`] if the input is malformed or a decoded quantum exceeds
/// [`u32::MAX`].
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_adobe85(adobe85: &[u8]) -> Option<Box<[u8]>> {
    ASCII85.try_decode_base85ext(adobe85, super::ADOBE85_ZEROS, super::ADOBE85_DEC_PAD)
}

/// Decodes a strict Ascii85 string.
///
/// Returns [`None`] unless `ascii85` consists of complete five-symbol Ascii85
/// quanta whose decoded values fit in a [`u32`].
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_ascii85_string(ascii85: &str) -> Option<Box<[u8]>> {
    ASCII85.try_decode_base85_string(ascii85)
}

/// Decodes strict Ascii85 bytes.
///
/// Returns [`None`] unless `ascii85` consists of complete five-symbol Ascii85
/// quanta whose decoded values fit in a [`u32`].
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_ascii85(ascii85: &[u8]) -> Option<Box<[u8]>> {
    ASCII85.try_decode_base85(ascii85)
}

/// Decodes a ZeroMQ Z85 string.
///
/// Returns [`None`] unless `z85` consists of complete five-symbol Z85 quanta
/// whose decoded values fit in a [`u32`].
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_z85_string(z85: &str) -> Option<Box<[u8]>> {
    Z85.try_decode_base85_string(z85)
}

/// Decodes ZeroMQ Z85 bytes.
///
/// Returns [`None`] unless `z85` consists of complete five-symbol Z85 quanta
/// whose decoded values fit in a [`u32`].
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_z85(z85: &[u8]) -> Option<Box<[u8]>> {
    Z85.try_decode_base85(z85)
}

struct Decoder<'d> {
    decoder: &'d [u8],
    min_ascii: usize,
    max_ascii: usize,
}

impl<'d> Decoder<'d> {
    #[inline]
    const fn from_table(decoder: &'d [u8], min_ascii: usize, max_ascii: usize) -> Self {
        // INVARIANT: MAX_ASCII must always be larger than MIN_ASCII
        assert!(max_ascii > min_ascii);

        // INVARIANT: the decoder must be sized on the range [MIN_ASCII, MAX_ASCII)
        assert!(max_ascii - min_ascii == decoder.len());

        Self {
            decoder,
            min_ascii,
            max_ascii,
        }
    }

    #[inline]
    fn try_decode_base85_string(&self, base85: &str) -> Option<Box<[u8]>> {
        self.try_decode_base85(base85.as_bytes())
    }

    #[inline]
    fn try_decode_base85ext_string(
        &self,
        base85: &str,
        zeros_byte: u8,
        tail_pad: u8,
    ) -> Option<Box<[u8]>> {
        self.try_decode_base85ext(base85.as_bytes(), zeros_byte, tail_pad)
    }

    fn try_decode_base85(&self, base85: &[u8]) -> Option<Box<[u8]>> {
        // empty inputs result in empty outputs
        if base85.is_empty() {
            return Some(Vec::<u8>::new().into_boxed_slice());
        }

        // INVARIANT: strict base85 does not handle padding automatically
        // "The string frame SHALL have a length that is divisible by 5 with no remainder."
        if !base85.len().is_multiple_of(5) {
            return None;
        }

        // INVARIANT: base85 encodes five ASCII bytes per four input bytes
        // "The binary frame SHALL have a length that is divisible by 4 with no remainder."
        let capacity = base85.len().checked_mul(4)? / 5;
        let mut ret = Vec::<u8>::with_capacity(capacity);
        let (chunks, []) = base85.as_chunks::<5>() else {
            unreachable!("base85 slice always a multiple of 5")
        };

        // "To decode a string, an implementation SHALL take five characters at a time
        // from the string and convert them into four octets of data representing a
        // 32-bit unsigned integer in network byte order."
        for &chunk in chunks {
            ret.extend_from_slice(&self.decode_base85_chunk(chunk)?);
        }

        Some(ret.into_boxed_slice())
    }

    fn try_decode_base85ext(
        &self,
        base85: &[u8],
        zeros_byte: u8,
        tail_pad: u8,
    ) -> Option<Box<[u8]>> {
        // empty inputs result in empty outputs
        if base85.is_empty() {
            return Some(Vec::<u8>::new().into_boxed_slice());
        }

        // INVARIANT: base85ext encodes five ASCII bytes per four input bytes
        // A remainder tail will decode up to 3 extra output bytes:
        let capacity = base85.len().checked_mul(4)? / 5 + 3;
        let mut ret = Vec::<u8>::with_capacity(capacity);

        let mut r = 0usize;
        let mut p = 0usize;
        let mut chunk = [tail_pad; 5];
        while r < base85.len() {
            // SAFETY: r less than slice length
            let c = unsafe { *base85.get_unchecked(r) };

            // decompress zeros and continue
            if c == zeros_byte {
                if p != 0 {
                    return None;
                }
                ret.extend_from_slice(&[0u8; 4]);
                r += 1;
            } else if c.is_ascii_whitespace() || c == b'\x0b' {
                r += 1;
            } else {
                chunk[p] = c;
                p += 1;
                r += 1;
            }

            if p == 5 {
                ret.extend_from_slice(&self.decode_base85_chunk(chunk)?);
                chunk.fill(tail_pad);
                p = 0;
            }
        }

        // tail handling
        match p {
            0 => {}
            1 => return None,
            _ => {
                let decoded = self.decode_base85_chunk(chunk)?;
                ret.extend_from_slice(&decoded[..p - 1]);
            }
        }

        Some(ret.into_boxed_slice())
    }

    fn decode_base85_chunk(&self, chunk: [u8; 5]) -> Option<[u8; 4]> {
        // "The five characters SHALL each be converted into a value 0 to 84,
        // and accumulated by multiplication by 85, from most to least significant."
        let mut acc = 0u32;
        for byte in chunk {
            let digit = self.check_and_decode_base85_byte(byte)?;
            acc = acc.checked_mul(85)?.checked_add(digit)?;
        }

        Some(acc.to_be_bytes())
    }

    #[inline]
    fn check_and_decode_base85_byte(&self, byte: u8) -> Option<u32> {
        let i = byte as usize;
        if !(self.min_ascii..self.max_ascii).contains(&i) {
            // byte is outside the selected base85 ASCII range
            return None;
        }

        // SAFETY: i - min_ascii is guaranteed to fall within
        // [0, max_ascii - min_ascii)
        let digit = unsafe { *self.decoder.get_unchecked(i - self.min_ascii) };
        if digit == 255 {
            // byte is not part of the selected base85 alphabet
            return None;
        }

        Some(u32::from(digit))
    }
}

#[cfg(test)]
mod tests {
    use super::super::enc::{ASCII85 as ASCII85_ENCODER, Z85 as Z85_ENCODER};
    use super::super::{
        ADOBE85_DEC_PAD, ADOBE85_ZEROS, ENCODER_ASCII85, ENCODER_Z85, MAX_ASCII_ASCII85,
        MAX_ASCII_Z85, MIN_ASCII_ASCII85, MIN_ASCII_Z85,
    };
    use super::{ASCII85, Decoder, Z85};

    use alloc::{vec, vec::Vec};

    #[test]
    fn z85_known_vector_decodes_through_byte_and_string_apis() {
        let input = [0x86u8, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b];
        let expected = b"HelloWorld";

        assert_eq!(
            Z85.try_decode_base85(expected).as_deref(),
            Some(input.as_slice())
        );
        assert_eq!(
            Z85.try_decode_base85_string("HelloWorld").as_deref(),
            Some(input.as_slice())
        );
    }

    #[test]
    fn ascii85_known_vector_decodes_through_byte_and_string_apis() {
        let input = [0x86u8, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b];
        let expected = b"L/669[9<6.";

        assert_eq!(
            ASCII85.try_decode_base85(expected).as_deref(),
            Some(input.as_slice())
        );
        assert_eq!(
            ASCII85.try_decode_base85_string("L/669[9<6.").as_deref(),
            Some(input.as_slice())
        );
    }

    #[test]
    fn empty_input_decodes_through_all_apis() {
        assert_eq!(
            ASCII85.try_decode_base85(b"").as_deref(),
            Some(b"".as_slice())
        );
        assert_eq!(
            ASCII85.try_decode_base85_string("").as_deref(),
            Some(b"".as_slice())
        );
        assert_eq!(Z85.try_decode_base85(b"").as_deref(), Some(b"".as_slice()));
        assert_eq!(
            Z85.try_decode_base85_string("").as_deref(),
            Some(b"".as_slice())
        );
        assert_eq!(
            ASCII85
                .try_decode_base85ext(b"", ADOBE85_ZEROS, ADOBE85_DEC_PAD)
                .as_deref(),
            Some(b"".as_slice())
        );
        assert_eq!(
            ASCII85
                .try_decode_base85ext_string("", ADOBE85_ZEROS, ADOBE85_DEC_PAD)
                .as_deref(),
            Some(b"".as_slice())
        );
    }

    #[test]
    fn decoders_select_the_requested_alphabet() {
        let ascii85_only = b"\"!!!!";
        assert!(ASCII85.try_decode_base85(ascii85_only).is_some());
        assert_eq!(Z85.try_decode_base85(ascii85_only), None);

        let z85_only = b"0000{";
        assert!(Z85.try_decode_base85(z85_only).is_some());
        assert_eq!(ASCII85.try_decode_base85(z85_only), None);
        assert_eq!(ASCII85.try_decode_base85(b"!!!!z"), None);
    }

    #[test]
    fn complete_byte_quanta_roundtrip_through_both_alphabets() {
        let codecs = &[
            ("ASCII85", &ASCII85_ENCODER, &ASCII85),
            ("Z85", &Z85_ENCODER, &Z85),
        ];

        for len in (0usize..=64).step_by(4) {
            let input: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(73).wrapping_add(len * 19)) as u8)
                .collect();

            for &(name, encoder, decoder) in codecs {
                let encoded = encoder
                    .try_encode_base85(&input)
                    .expect("complete byte quanta must encode");
                assert_eq!(encoded.len(), len * 5 / 4, "{name}, len {len}");
                assert_eq!(
                    decoder.try_decode_base85(&encoded).as_deref(),
                    Some(input.as_slice()),
                    "{name} failed to roundtrip {len} bytes"
                );
            }
        }
    }

    #[test]
    fn tables_preserve_unsafe_indexing_invariants() {
        fn assert_invariants(name: &str, decoder: &Decoder<'_>, encoder: &[u8]) {
            assert_eq!(encoder.len(), 85);
            assert!(decoder.max_ascii > decoder.min_ascii);
            assert_eq!(decoder.max_ascii - decoder.min_ascii, decoder.decoder.len());

            let mut seen = vec![false; decoder.decoder.len()];

            for (digit, &ascii) in encoder.iter().enumerate() {
                assert!(ascii.is_ascii());

                let ascii = ascii as usize;
                assert!((decoder.min_ascii..decoder.max_ascii).contains(&ascii));

                let offset = ascii - decoder.min_ascii;
                assert!(!seen[offset], "duplicate {name} byte at ASCII {ascii}");
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

        assert_invariants("ASCII85", &ASCII85, &ENCODER_ASCII85);
        assert_invariants("Z85", &Z85, &ENCODER_Z85);
    }

    #[test]
    fn decode_rejects_unpadded_lengths() {
        let decoders = &[("ASCII85", &ASCII85), ("Z85", &Z85)];

        for len in (1..=9).filter(|len| len % 5 != 0) {
            let input = vec![b'0'; len];
            for &(name, decoder) in decoders {
                assert_eq!(
                    decoder.try_decode_base85(&input),
                    None,
                    "{name} accepted {len} bytes"
                );
            }
        }
    }

    #[test]
    fn decode_rejects_invalid_bytes_in_any_frame() {
        let decoders = &[
            (
                "ASCII85",
                &ASCII85,
                b'!',
                [
                    (MIN_ASCII_ASCII85 - 1) as u8,
                    MAX_ASCII_ASCII85 as u8,
                    u8::MAX,
                ],
            ),
            (
                "Z85",
                &Z85,
                b'0',
                [(MIN_ASCII_Z85 - 1) as u8, b'"', MAX_ASCII_Z85 as u8],
            ),
        ];

        for &(name, decoder, fill, invalids) in decoders {
            for invalid in invalids {
                for position in 0..5 {
                    let mut input = [fill; 5];
                    input[position] = invalid;
                    assert_eq!(
                        decoder.try_decode_base85(&input),
                        None,
                        "{name} accepted byte {invalid:#04x} at position {position}"
                    );
                }

                let mut second_frame = [fill; 10];
                second_frame[7] = invalid;
                assert_eq!(
                    decoder.try_decode_base85(&second_frame),
                    None,
                    "{name} accepted {invalid:#04x}"
                );
            }
        }
    }

    #[test]
    fn decoders_reject_value_just_above_u32_max() {
        let codecs = &[
            (
                "ASCII85",
                &ASCII85,
                None,
                b"s8W-!".as_slice(),
                b"s8W-\"".as_slice(),
            ),
            ("Z85", &Z85, None, b"%nSc0".as_slice(), b"%nSc1".as_slice()),
            (
                "Adobe85",
                &ASCII85,
                Some((ADOBE85_ZEROS, ADOBE85_DEC_PAD)),
                b"s8W-!".as_slice(),
                b"s8W-\"".as_slice(),
            ),
        ];
        let expected = [u8::MAX; 4];

        for &(name, decoder, extension, max, overflow) in codecs {
            let decoded_max = match extension {
                Some((zeros_byte, tail_pad)) => {
                    decoder.try_decode_base85ext(max, zeros_byte, tail_pad)
                }
                None => decoder.try_decode_base85(max),
            };
            assert_eq!(
                decoded_max.as_deref(),
                Some(expected.as_slice()),
                "{name} rejected u32::MAX"
            );
            let decoded_overflow = match extension {
                Some((zeros_byte, tail_pad)) => {
                    decoder.try_decode_base85ext(overflow, zeros_byte, tail_pad)
                }
                None => decoder.try_decode_base85(overflow),
            };
            assert_eq!(decoded_overflow, None, "{name} accepted u32::MAX + 1");
        }
    }

    #[test]
    fn adobe85_known_vector_decodes_through_byte_and_string_apis() {
        let input = [0x86u8, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b];
        let expected = b"L/669[9<6.";

        assert_eq!(
            ASCII85
                .try_decode_base85ext(expected, ADOBE85_ZEROS, ADOBE85_DEC_PAD)
                .as_deref(),
            Some(input.as_slice())
        );
        assert_eq!(
            ASCII85
                .try_decode_base85ext_string("L/669[9<6.", ADOBE85_ZEROS, ADOBE85_DEC_PAD)
                .as_deref(),
            Some(input.as_slice())
        );
    }

    #[test]
    fn adobe85_byte_slices_of_arbitrary_lengths_roundtrip() {
        for len in 0usize..=64 {
            let input: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(73).wrapping_add(len * 19)) as u8)
                .collect();
            let encoded = ASCII85_ENCODER.encode_base85ext(&input, ADOBE85_ZEROS);

            assert_eq!(
                ASCII85
                    .try_decode_base85ext(&encoded, ADOBE85_ZEROS, ADOBE85_DEC_PAD)
                    .as_deref(),
                Some(input.as_slice()),
                "failed to roundtrip {len} data bytes"
            );
        }
    }

    #[test]
    fn adobe85_decode_ignores_ascii_whitespace_at_every_position() {
        const ASCII_WHITESPACE: [u8; 6] = *b"\t\n\x0b\x0c\r ";
        let inputs: &[&[u8]] = &[
            b"",
            b"\0\0\0\0",
            b"A",
            b"AB",
            b"ABC",
            b"ABCD",
            b"ABCDE",
            b"ABCDEF",
            b"ABCDEFG",
            b"\0\0\0\0ABC",
        ];

        for &input in inputs {
            let encoded = ASCII85_ENCODER.encode_base85ext(input, ADOBE85_ZEROS);

            for position in 0..=encoded.len() {
                for whitespace in ASCII_WHITESPACE {
                    let mut with_whitespace = encoded.to_vec();
                    with_whitespace.insert(position, whitespace);

                    assert_eq!(
                        ASCII85
                            .try_decode_base85ext(&with_whitespace, ADOBE85_ZEROS, ADOBE85_DEC_PAD,)
                            .as_deref(),
                        Some(input),
                        "byte API changed {encoded:?} with whitespace {whitespace:#04x} \
                         at position {position}"
                    );

                    let with_whitespace =
                        alloc::str::from_utf8(&with_whitespace).expect("input remains ASCII");
                    assert_eq!(
                        ASCII85
                            .try_decode_base85ext_string(
                                with_whitespace,
                                ADOBE85_ZEROS,
                                ADOBE85_DEC_PAD,
                            )
                            .as_deref(),
                        Some(input),
                        "string API changed {encoded:?} with whitespace {whitespace:#04x} \
                         at position {position}"
                    );
                }
            }
        }
    }

    #[test]
    fn adobe85_decode_ignores_dense_ascii_whitespace_within_tails() {
        const ASCII_WHITESPACE: &[u8] = b"\t\n\x0b\x0c\r ";

        for input in [b"A".as_slice(), b"AB".as_slice(), b"ABC".as_slice()] {
            let encoded = ASCII85_ENCODER.encode_base85ext(input, ADOBE85_ZEROS);
            let mut with_whitespace =
                Vec::with_capacity(encoded.len() * (ASCII_WHITESPACE.len() + 1));

            for byte in encoded.iter().copied() {
                with_whitespace.extend_from_slice(ASCII_WHITESPACE);
                with_whitespace.push(byte);
            }
            with_whitespace.extend_from_slice(ASCII_WHITESPACE);

            assert_eq!(
                ASCII85
                    .try_decode_base85ext(&with_whitespace, ADOBE85_ZEROS, ADOBE85_DEC_PAD)
                    .as_deref(),
                Some(input),
                "dense whitespace changed tail {encoded:?}"
            );
        }
    }

    #[test]
    fn adobe85_decode_rejects_single_ascii_tails() {
        for input in [b"!".as_slice(), b"!!!!!!".as_slice(), b"z!".as_slice()] {
            assert_eq!(
                ASCII85.try_decode_base85ext(input, ADOBE85_ZEROS, ADOBE85_DEC_PAD),
                None,
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn adobe85_decode_accepts_compressed_and_uncompressed_zero_chunks() {
        for input in [b"z".as_slice(), b"!!!!!".as_slice()] {
            assert_eq!(
                ASCII85
                    .try_decode_base85ext(input, ADOBE85_ZEROS, ADOBE85_DEC_PAD)
                    .as_deref(),
                Some([0; 4].as_slice())
            );
        }

        for input in [b"z!!!!!".as_slice(), b"!!!!!z".as_slice()] {
            assert_eq!(
                ASCII85
                    .try_decode_base85ext(input, ADOBE85_ZEROS, ADOBE85_DEC_PAD)
                    .as_deref(),
                Some([0; 8].as_slice())
            );
        }
    }

    #[test]
    fn adobe85_decode_rejects_invalid_bytes_in_any_frame() {
        for invalid in [b'\0', MAX_ASCII_ASCII85 as u8] {
            for position in 0..5 {
                let mut input = *b"!!!!!";
                input[position] = invalid;
                assert_eq!(
                    ASCII85.try_decode_base85ext(&input, ADOBE85_ZEROS, ADOBE85_DEC_PAD),
                    None,
                    "accepted byte {invalid:#04x} at position {position}"
                );
            }
        }

        let mut second_frame = *b"!!!!!!!!!!";
        second_frame[7] = ADOBE85_ZEROS;
        assert_eq!(
            ASCII85.try_decode_base85ext(&second_frame, ADOBE85_ZEROS, ADOBE85_DEC_PAD),
            None
        );
    }
}

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
//! use b2t_codecs::base85::{try_decode_from_adobe85, try_decode_from_z85};
//!
//! let mut decoded = [0; 4];
//! assert_eq!(
//!     try_decode_from_adobe85(b"z", &mut decoded),
//!     Some([0, 0, 0, 0].as_slice()),
//! );
//! assert_eq!(
//!     try_decode_from_z85(b"Hello", &mut decoded),
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
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_adobe85_string(adobe85: &str) -> Option<Box<[u8]>> {
    ASCII85.try_decode_adobe85_string(adobe85)
}

/// Decodes raw Adobe85 ASCII bytes.
///
/// The decoder accepts compressed zero quanta and implicit final padding,
/// ignores ASCII whitespace, and does not accept `<~` and `~>` delimiters.
/// Returns [`None`] if the input is malformed or a decoded quantum exceeds
/// [`u32::MAX`].
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_adobe85(adobe85: &[u8]) -> Option<Box<[u8]>> {
    ASCII85.try_decode_adobe85_boxed(adobe85)
}

/// Decodes a strict Ascii85 string.
///
/// Returns [`None`] unless `ascii85` consists of complete five-symbol Ascii85
/// quanta whose decoded values fit in a [`u32`].
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_ascii85_string(ascii85: &str) -> Option<Box<[u8]>> {
    ASCII85.try_decode_base85_string(ascii85)
}

/// Decodes strict Ascii85 bytes.
///
/// Returns [`None`] unless `ascii85` consists of complete five-symbol Ascii85
/// quanta whose decoded values fit in a [`u32`].
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_ascii85(ascii85: &[u8]) -> Option<Box<[u8]>> {
    ASCII85.try_decode_base85_boxed(ascii85)
}

/// Decodes a ZeroMQ Z85 string.
///
/// Returns [`None`] unless `z85` consists of complete five-symbol Z85 quanta
/// whose decoded values fit in a [`u32`].
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_z85_string(z85: &str) -> Option<Box<[u8]>> {
    Z85.try_decode_base85_string(z85)
}

/// Decodes ZeroMQ Z85 bytes.
///
/// Returns [`None`] unless `z85` consists of complete five-symbol Z85 quanta
/// whose decoded values fit in a [`u32`].
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_z85(z85: &[u8]) -> Option<Box<[u8]>> {
    Z85.try_decode_base85_boxed(z85)
}

/// Returns the exact decoded length of structurally valid strict Base85.
///
/// Every complete five-symbol Ascii85 or Z85 quantum decodes to four bytes.
/// Returns [`None`] unless `src.len()` is divisible by five or if the decoded
/// length cannot be represented as a [`usize`]. This function does not
/// validate the selected alphabet or whether quantum values fit in a [`u32`].
#[must_use = "the decoded size should be used"]
#[inline]
pub fn decoded_length_base85(src: &[u8]) -> Option<usize> {
    decoded_length(src)
}

#[inline]
fn decoded_length(src: &[u8]) -> Option<usize> {
    // INVARIANT: strict base85 does not handle padding automatically
    // "The string frame SHALL have a length that is divisible by 5 with no remainder."
    if !src.len().is_multiple_of(5) {
        return None;
    }

    // INVARIANT: base85 encodes five ASCII bytes per four input bytes
    // "The binary frame SHALL have a length that is divisible by 4 with no remainder."
    (src.len() / 5).checked_mul(4)
}

/// Decodes raw Adobe85 from `src` into the beginning of `dst` in one pass.
///
/// The decoder accepts `z` only between ordinary quanta, accepts implicit
/// two-to-four-symbol tails, ignores tab, line feed, vertical tab, form feed,
/// carriage return, and space, and rejects `<~`/`~>` delimiters. Returns the
/// initialized prefix of `dst`, including `Some(&dst[..0])` for empty or
/// whitespace-only input.
///
/// This function checks capacity as output is emitted and returns [`None`]
/// immediately on malformed input or insufficient remaining space. After any
/// failure, all contents of `dst` are indeterminate and must be discarded. On
/// success, bytes after the returned prefix remain unchanged. This function
/// never truncates output and does not allocate.
#[must_use = "the decoded slice should be used"]
#[inline]
pub fn try_decode_from_adobe85<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    ASCII85.try_decode_adobe85_into(src, dst)
}

/// Decodes complete strict Ascii85 quanta from `src` into `dst`.
///
/// Returns the initialized prefix of `dst`, including `Some(&dst[..0])` for
/// empty input, or [`None`] if `src` is not five-symbol aligned, contains an
/// invalid quantum, or `dst` is too short. Alignment and capacity failures
/// leave `dst` unchanged. Invalid input may partially modify a sufficiently
/// large destination. Bytes after a successful returned prefix remain
/// unchanged. This function does not allocate.
#[must_use = "the decoded slice should be used"]
#[inline]
pub fn try_decode_from_ascii85<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    ASCII85.try_decode_base85_into(src, dst)
}

/// Decodes complete ZeroMQ Z85 quanta from `src` into `dst`.
///
/// Returns the initialized prefix of `dst`, including `Some(&dst[..0])` for
/// empty input, or [`None`] if `src` is not five-symbol aligned, contains an
/// invalid quantum, or `dst` is too short. Alignment and capacity failures
/// leave `dst` unchanged. Invalid input may partially modify a sufficiently
/// large destination. Bytes after a successful returned prefix remain
/// unchanged. This function does not allocate.
#[must_use = "the decoded slice should be used"]
#[inline]
pub fn try_decode_from_z85<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    Z85.try_decode_base85_into(src, dst)
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

    #[cfg(feature = "alloc")]
    #[inline]
    fn try_decode_base85_string(&self, base85: &str) -> Option<Box<[u8]>> {
        self.try_decode_base85_boxed(base85.as_bytes())
    }

    #[cfg(feature = "alloc")]
    #[inline]
    fn try_decode_adobe85_string(&self, adobe85: &str) -> Option<Box<[u8]>> {
        self.try_decode_adobe85_boxed(adobe85.as_bytes())
    }

    #[cfg(feature = "alloc")]
    fn try_decode_base85_boxed(&self, base85: &[u8]) -> Option<Box<[u8]>> {
        if base85.is_empty() {
            return Some(Vec::<u8>::new().into_boxed_slice());
        }

        let payload_len = decoded_length(base85)?;
        let (chunks, []) = base85.as_chunks::<5>() else {
            unreachable!("decoded_length_base85 requires complete five-symbol quanta")
        };

        let mut dst = Box::<[u8]>::new_uninit_slice(payload_len);
        let mut written = 0usize;

        for &chunk in chunks {
            let chunk = self.decode_base85_chunk(chunk)?;
            dst[written..written + 4].write_copy_of_slice(&chunk);
            written += 4;
        }

        // SAFETY:
        //  - `dst` contains `payload_len` consecutive `MaybeUninit<u8>` values.
        //  - Successful chunk decoding writes every output byte into distinct,
        //    in-bounds elements of `dst`.
        //  - `written == dst.len()` verifies that every element was initialized.
        unsafe {
            // INVARIANT: every complete quantum emits exactly four bytes, so all
            // allocated elements were initialized.
            assert!(written == dst.len());
            Some(dst.assume_init())
        }
    }

    #[cfg(feature = "alloc")]
    fn try_decode_adobe85_boxed(&self, adobe85: &[u8]) -> Option<Box<[u8]>> {
        if adobe85.is_empty() {
            return Some(Vec::<u8>::new().into_boxed_slice());
        }

        // Adobe85 emits four bytes per complete five-symbol quantum. A final
        // implicit tail can emit up to three additional bytes. Whitespace can
        // reduce this estimate and repeated `z` symbols can make the Vec grow.
        let capacity = adobe85.len().checked_mul(4)? / 5 + 3;
        let mut ret = Vec::<u8>::with_capacity(capacity);

        let mut source = 0usize;
        let mut symbols = 0usize;
        let mut chunk = [super::ADOBE85_DEC_PAD; 5];

        while source < adobe85.len() {
            // SAFETY: the loop condition proves `source < adobe85.len()`.
            let byte = unsafe { *adobe85.get_unchecked(source) };
            source += 1;

            if byte == super::ADOBE85_ZEROS {
                if symbols != 0 {
                    return None;
                }
                ret.extend_from_slice(&[0; 4]);
            } else if byte.is_ascii_whitespace() || byte == b'\x0b' {
                continue;
            } else {
                chunk[symbols] = byte;
                symbols += 1;

                if symbols == chunk.len() {
                    ret.extend_from_slice(&self.decode_base85_chunk(chunk)?);
                    chunk.fill(super::ADOBE85_DEC_PAD);
                    symbols = 0;
                }
            }
        }

        match symbols {
            0 => {}
            1 => return None,
            2..=4 => {
                let decoded = self.decode_base85_chunk(chunk)?;
                ret.extend_from_slice(&decoded[..symbols - 1]);
            }
            _ => unreachable!("complete quanta are emitted immediately"),
        }

        Some(ret.into_boxed_slice())
    }

    fn try_decode_base85_into<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
        let payload_len = decoded_length(src)?;
        if dst.len() < payload_len {
            return None;
        }

        let (chunks, []) = src.as_chunks::<5>() else {
            unreachable!("decoded_length_base85 requires complete five-symbol quanta")
        };
        let mut written = 0usize;

        for &chunk in chunks {
            let decoded = self.decode_base85_chunk(chunk)?;
            dst[written..written + 4].copy_from_slice(&decoded);
            written += 4;
        }

        // INVARIANT: every complete quantum emits exactly four bytes.
        assert!(written == payload_len);
        Some(&dst[..written])
    }

    fn try_decode_adobe85_into<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
        let mut source = 0usize;
        let mut symbols = 0usize;
        let mut written = 0usize;
        let mut chunk = [super::ADOBE85_DEC_PAD; 5];

        while source < src.len() {
            // SAFETY: the loop condition proves `source < src.len()`.
            let byte = unsafe { *src.get_unchecked(source) };
            source += 1;

            if byte == super::ADOBE85_ZEROS {
                if symbols != 0 {
                    return None;
                }

                let end = written.checked_add(4)?;
                dst.get_mut(written..end)?.copy_from_slice(&[0; 4]);
                written = end;
            } else if byte.is_ascii_whitespace() || byte == b'\x0b' {
                continue;
            } else {
                chunk[symbols] = byte;
                symbols += 1;

                if symbols == chunk.len() {
                    let decoded = self.decode_base85_chunk(chunk)?;
                    let end = written.checked_add(decoded.len())?;
                    dst.get_mut(written..end)?.copy_from_slice(&decoded);
                    written = end;
                    chunk.fill(super::ADOBE85_DEC_PAD);
                    symbols = 0;
                }
            }
        }

        match symbols {
            0 => {}
            1 => return None,
            2..=4 => {
                let decoded = self.decode_base85_chunk(chunk)?;
                let decoded = &decoded[..symbols - 1];
                let end = written.checked_add(decoded.len())?;
                dst.get_mut(written..end)?.copy_from_slice(decoded);
                written = end;
            }
            _ => unreachable!("complete quanta are emitted immediately"),
        }

        Some(&dst[..written])
    }

    fn decode_base85_chunk(&self, chunk: [u8; 5]) -> Option<[u8; 4]> {
        // "To decode a string, an implementation SHALL take five characters at a time
        // from the string and convert them into four octets of data representing a
        // 32-bit unsigned integer in network byte order."

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

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::super::enc::{ASCII85 as ASCII85_ENCODER, Z85 as Z85_ENCODER};
    use super::super::{
        ENCODER_ASCII85, ENCODER_Z85, MAX_ASCII_ASCII85, MAX_ASCII_Z85, MIN_ASCII_ASCII85,
        MIN_ASCII_Z85,
    };
    use super::{ASCII85, Decoder, Z85};

    use alloc::{vec, vec::Vec};

    #[test]
    fn z85_known_vector_decodes_through_byte_and_string_apis() {
        let input = [0x86u8, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b];
        let expected = b"HelloWorld";

        assert_eq!(
            Z85.try_decode_base85_boxed(expected).as_deref(),
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
            ASCII85.try_decode_base85_boxed(expected).as_deref(),
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
            ASCII85.try_decode_base85_boxed(b"").as_deref(),
            Some(b"".as_slice())
        );
        assert_eq!(
            ASCII85.try_decode_base85_string("").as_deref(),
            Some(b"".as_slice())
        );
        assert_eq!(
            Z85.try_decode_base85_boxed(b"").as_deref(),
            Some(b"".as_slice())
        );
        assert_eq!(
            Z85.try_decode_base85_string("").as_deref(),
            Some(b"".as_slice())
        );
        assert_eq!(
            ASCII85.try_decode_adobe85_boxed(b"").as_deref(),
            Some(b"".as_slice())
        );
        assert_eq!(
            ASCII85.try_decode_adobe85_string("").as_deref(),
            Some(b"".as_slice())
        );
    }

    #[test]
    fn decoders_select_the_requested_alphabet() {
        let ascii85_only = b"\"!!!!";
        assert!(ASCII85.try_decode_base85_boxed(ascii85_only).is_some());
        assert_eq!(Z85.try_decode_base85_boxed(ascii85_only), None);

        let z85_only = b"0000{";
        assert!(Z85.try_decode_base85_boxed(z85_only).is_some());
        assert_eq!(ASCII85.try_decode_base85_boxed(z85_only), None);
        assert_eq!(ASCII85.try_decode_base85_boxed(b"!!!!z"), None);
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
                    .try_encode_base85_boxed(&input)
                    .expect("complete byte quanta must encode");
                assert_eq!(encoded.len(), len * 5 / 4, "{name}, len {len}");
                assert_eq!(
                    decoder.try_decode_base85_boxed(&encoded).as_deref(),
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
                    decoder.try_decode_base85_boxed(&input),
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
                        decoder.try_decode_base85_boxed(&input),
                        None,
                        "{name} accepted byte {invalid:#04x} at position {position}"
                    );
                }

                let mut second_frame = [fill; 10];
                second_frame[7] = invalid;
                assert_eq!(
                    decoder.try_decode_base85_boxed(&second_frame),
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
                b"s8W-!".as_slice(),
                b"s8W-\"".as_slice(),
            ),
            ("Z85", &Z85, b"%nSc0".as_slice(), b"%nSc1".as_slice()),
        ];
        let expected = [u8::MAX; 4];

        for &(name, decoder, max, overflow) in codecs {
            let decoded_max = decoder.try_decode_base85_boxed(max);
            assert_eq!(
                decoded_max.as_deref(),
                Some(expected.as_slice()),
                "{name} rejected u32::MAX"
            );
            let decoded_overflow = decoder.try_decode_base85_boxed(overflow);
            assert_eq!(decoded_overflow, None, "{name} accepted u32::MAX + 1");
        }

        assert_eq!(
            ASCII85.try_decode_adobe85_boxed(b"s8W-!").as_deref(),
            Some(expected.as_slice())
        );
        assert_eq!(ASCII85.try_decode_adobe85_boxed(b"s8W-\""), None);
    }

    #[test]
    fn adobe85_known_vector_decodes_through_byte_and_string_apis() {
        let input = [0x86u8, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b];
        let expected = b"L/669[9<6.";

        assert_eq!(
            ASCII85.try_decode_adobe85_boxed(expected).as_deref(),
            Some(input.as_slice())
        );
        assert_eq!(
            ASCII85.try_decode_adobe85_string("L/669[9<6.").as_deref(),
            Some(input.as_slice())
        );
    }

    #[test]
    fn adobe85_byte_slices_of_arbitrary_lengths_roundtrip() {
        for len in 0usize..=64 {
            let input: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(73).wrapping_add(len * 19)) as u8)
                .collect();
            let encoded = ASCII85_ENCODER.encode_adobe85_boxed(&input);

            assert_eq!(
                ASCII85.try_decode_adobe85_boxed(&encoded).as_deref(),
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
            let encoded = ASCII85_ENCODER.encode_adobe85_boxed(input);

            for position in 0..=encoded.len() {
                for whitespace in ASCII_WHITESPACE {
                    let mut with_whitespace = encoded.to_vec();
                    with_whitespace.insert(position, whitespace);

                    assert_eq!(
                        ASCII85
                            .try_decode_adobe85_boxed(&with_whitespace)
                            .as_deref(),
                        Some(input),
                        "byte API changed {encoded:?} with whitespace {whitespace:#04x} \
                         at position {position}"
                    );

                    let with_whitespace =
                        alloc::str::from_utf8(&with_whitespace).expect("input remains ASCII");
                    assert_eq!(
                        ASCII85
                            .try_decode_adobe85_string(with_whitespace)
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
            let encoded = ASCII85_ENCODER.encode_adobe85_boxed(input);
            let mut with_whitespace =
                Vec::with_capacity(encoded.len() * (ASCII_WHITESPACE.len() + 1));

            for byte in encoded.iter().copied() {
                with_whitespace.extend_from_slice(ASCII_WHITESPACE);
                with_whitespace.push(byte);
            }
            with_whitespace.extend_from_slice(ASCII_WHITESPACE);

            assert_eq!(
                ASCII85
                    .try_decode_adobe85_boxed(&with_whitespace)
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
                ASCII85.try_decode_adobe85_boxed(input),
                None,
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn adobe85_decode_accepts_compressed_and_uncompressed_zero_chunks() {
        for input in [b"z".as_slice(), b"!!!!!".as_slice()] {
            assert_eq!(
                ASCII85.try_decode_adobe85_boxed(input).as_deref(),
                Some([0; 4].as_slice())
            );
        }

        for input in [b"z!!!!!".as_slice(), b"!!!!!z".as_slice()] {
            assert_eq!(
                ASCII85.try_decode_adobe85_boxed(input).as_deref(),
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
                    ASCII85.try_decode_adobe85_boxed(&input),
                    None,
                    "accepted byte {invalid:#04x} at position {position}"
                );
            }
        }

        let mut second_frame = *b"!!!!!!!!!!";
        second_frame[7] = b'z';
        assert_eq!(ASCII85.try_decode_adobe85_boxed(&second_frame), None);
    }

    #[test]
    fn allocating_decoders_match_slice_decoders() {
        let mut dst = [0u8; 12];

        let ascii85 = b"L/669[9<6.";
        let decoded = ASCII85.try_decode_base85_into(ascii85, &mut dst).unwrap();
        assert_eq!(
            ASCII85.try_decode_base85_boxed(ascii85).as_deref(),
            Some(decoded)
        );
        assert_eq!(
            ASCII85
                .try_decode_base85_string(core::str::from_utf8(ascii85).unwrap())
                .as_deref(),
            Some(decoded)
        );

        let z85 = b"HelloWorld";
        let decoded = Z85.try_decode_base85_into(z85, &mut dst).unwrap();
        assert_eq!(Z85.try_decode_base85_boxed(z85).as_deref(), Some(decoded));
        assert_eq!(
            Z85.try_decode_base85_string(core::str::from_utf8(z85).unwrap())
                .as_deref(),
            Some(decoded)
        );

        for adobe85 in [
            b"".as_slice(),
            b"\t\n\x0b\x0c\r ",
            b"z",
            b"!!!!!",
            b"!!",
            b"!!!",
            b"!!!!",
            b"s8W-!",
            b"z L/669",
            b"L/66\t9[9<6.",
        ] {
            let allocating = ASCII85.try_decode_adobe85_boxed(adobe85);
            let string = ASCII85.try_decode_adobe85_string(
                core::str::from_utf8(adobe85).expect("Adobe85 cases are ASCII"),
            );
            let mut dst = [0u8; 32];
            let slice = ASCII85.try_decode_adobe85_into(adobe85, &mut dst);

            assert_eq!(
                allocating.as_deref(),
                slice,
                "byte mismatch for {adobe85:?}"
            );
            assert_eq!(string.as_deref(), slice, "string mismatch for {adobe85:?}");
        }

        for malformed in [
            b"!".as_slice(),
            b"z!",
            b"!z!!!",
            b"!!!!z",
            b"<~z~>",
            b"\0!!!!",
            b"s8W-\"",
        ] {
            let mut dst = [0u8; 32];
            assert_eq!(ASCII85.try_decode_adobe85_boxed(malformed), None);
            assert_eq!(
                ASCII85.try_decode_adobe85_string(
                    core::str::from_utf8(malformed).expect("Adobe85 cases are ASCII"),
                ),
                None
            );
            assert_eq!(ASCII85.try_decode_adobe85_into(malformed, &mut dst), None);
        }
    }
}

#[cfg(test)]
mod non_alloc_tests {
    use super::super::enc::{ASCII85 as ASCII85_ENCODER, Z85 as Z85_ENCODER};
    use super::super::{
        ENCODER_ASCII85, ENCODER_Z85, MAX_ASCII_ASCII85, MAX_ASCII_Z85, MIN_ASCII_ASCII85,
        MIN_ASCII_Z85,
    };
    use super::{ASCII85, Decoder, Z85, decoded_length};

    type EncodeFn = for<'a> fn(&[u8], &'a mut [u8]) -> Option<&'a [u8]>;
    type DecodeFn = for<'a> fn(&[u8], &'a mut [u8]) -> Option<&'a [u8]>;

    fn encode_ascii85<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
        ASCII85_ENCODER.try_encode_base85_into(src, dst)
    }

    fn encode_z85<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
        Z85_ENCODER.try_encode_base85_into(src, dst)
    }

    fn encode_adobe85<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
        ASCII85_ENCODER.encode_adobe85_into(src, dst)
    }

    fn decode_ascii85<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
        ASCII85.try_decode_base85_into(src, dst)
    }

    fn decode_z85<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
        Z85.try_decode_base85_into(src, dst)
    }

    fn decode_adobe85<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
        ASCII85.try_decode_adobe85_into(src, dst)
    }

    #[test]
    fn strict_length_helper_requires_complete_quanta() {
        assert_eq!(decoded_length(b""), Some(0));
        assert_eq!(decoded_length(b"!!!!!"), Some(4));
        assert_eq!(decoded_length(b"!!!!!!!!!!"), Some(8));

        let input = [b'!'; 9];
        for len in [1, 2, 3, 4, 6, 7, 8, 9] {
            assert_eq!(decoded_length(&input[..len]), None);
        }
    }

    #[test]
    fn strict_known_vectors_and_alphabets_are_distinct() {
        let expected = [0x86u8, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b];
        let mut ascii85 = [0; 8];
        let mut z85 = [0; 8];

        assert_eq!(
            decode_ascii85(b"L/669[9<6.", &mut ascii85),
            Some(expected.as_slice())
        );
        assert_eq!(
            decode_z85(b"HelloWorld", &mut z85),
            Some(expected.as_slice())
        );

        let mut dst = [0; 4];
        assert_eq!(decode_z85(b"\"!!!!", &mut dst), None);
        assert_eq!(decode_ascii85(b"0000{", &mut dst), None);
        assert_eq!(decode_ascii85(b"!!!!z", &mut dst), None);
    }

    #[test]
    fn empty_strict_and_adobe_inputs_return_empty_prefixes() {
        let mut empty = [];
        assert_eq!(decode_ascii85(b"", &mut empty), Some(&[][..]));
        assert_eq!(decode_z85(b"", &mut empty), Some(&[][..]));
        assert_eq!(decode_adobe85(b"", &mut empty), Some(&[][..]));
        assert_eq!(
            decode_adobe85(b"\t\n\x0b\x0c\r ", &mut empty),
            Some(&[][..])
        );

        let mut dst = [0xa5; 1];
        assert_eq!(decode_ascii85(b"", &mut dst), Some(&[][..]));
        assert_eq!(decode_z85(b"", &mut dst), Some(&[][..]));
        assert_eq!(decode_adobe85(b"", &mut dst), Some(&[][..]));
        assert_eq!(dst, [0xa5]);
    }

    #[test]
    fn strict_preflight_and_success_destination_contracts_hold() {
        for (decode, zero) in [
            (decode_ascii85 as DecodeFn, b"!!!!!".as_slice()),
            (decode_z85 as DecodeFn, b"00000".as_slice()),
        ] {
            let mut unaligned = [0xa5; 4];
            assert_eq!(decode(b"!!!!", &mut unaligned), None);
            assert_eq!(unaligned, [0xa5; 4]);

            let mut short = [0xa5; 3];
            assert_eq!(decode(zero, &mut short), None);
            assert_eq!(short, [0xa5; 3]);

            let mut oversized = [0xa5; 5];
            assert_eq!(decode(zero, &mut oversized).unwrap(), &[0; 4]);
            assert_eq!(oversized[4], 0xa5);
        }
    }

    #[test]
    fn invalid_strict_input_can_leave_a_partially_decoded_destination() {
        for (decode, input) in [
            (decode_ascii85 as DecodeFn, b"!!!!!!!!!z".as_slice()),
            (decode_z85 as DecodeFn, b"000000000\"".as_slice()),
        ] {
            let mut dst = [0xa5; 8];
            assert_eq!(decode(input, &mut dst), None);
            assert_eq!(&dst[..4], &[0; 4]);
            assert_eq!(&dst[4..], &[0xa5; 4]);
        }
    }

    #[test]
    fn strict_aligned_lengths_roundtrip_on_stack() {
        let codecs: [(EncodeFn, DecodeFn); 2] =
            [(encode_ascii85, decode_ascii85), (encode_z85, decode_z85)];

        for len in (0usize..=64).step_by(4) {
            let mut input = [0u8; 64];
            for (index, byte) in input[..len].iter_mut().enumerate() {
                *byte = index.wrapping_mul(73).wrapping_add(len * 19) as u8;
            }

            for (encode, decode) in codecs {
                let mut encoded = [0u8; 80];
                let encoded = encode(&input[..len], &mut encoded).unwrap();
                assert_eq!(encoded.len(), len / 4 * 5);

                let mut decoded = [0u8; 64];
                assert_eq!(decode(encoded, &mut decoded), Some(&input[..len]));
            }
        }
    }

    #[test]
    fn decoder_tables_preserve_unsafe_indexing_invariants() {
        fn assert_invariants(name: &str, decoder: &Decoder<'_>, encoder: &[u8]) {
            assert_eq!(encoder.len(), 85);
            assert!(decoder.max_ascii > decoder.min_ascii);
            assert_eq!(decoder.max_ascii - decoder.min_ascii, decoder.decoder.len());

            let mut seen = [false; 93];
            for (digit, &ascii) in encoder.iter().enumerate() {
                let ascii = usize::from(ascii);
                assert!((decoder.min_ascii..decoder.max_ascii).contains(&ascii));
                let offset = ascii - decoder.min_ascii;
                assert!(!seen[offset], "duplicate {name} byte at ASCII {ascii}");
                seen[offset] = true;
                assert_eq!(decoder.decoder[offset], digit as u8);
            }

            for (offset, &digit) in decoder.decoder.iter().enumerate() {
                if digit != 255 {
                    assert!((digit as usize) < encoder.len());
                    assert_eq!(encoder[digit as usize] as usize, decoder.min_ascii + offset);
                }
            }
        }

        assert_invariants("ASCII85", &ASCII85, &ENCODER_ASCII85);
        assert_invariants("Z85", &Z85, &ENCODER_Z85);
    }

    #[test]
    fn strict_decoders_reject_invalid_symbols_and_overflow_values() {
        let cases = [
            (
                decode_ascii85 as DecodeFn,
                b'!',
                [
                    (MIN_ASCII_ASCII85 - 1) as u8,
                    MAX_ASCII_ASCII85 as u8,
                    u8::MAX,
                ],
            ),
            (
                decode_z85 as DecodeFn,
                b'0',
                [(MIN_ASCII_Z85 - 1) as u8, b'\"', MAX_ASCII_Z85 as u8],
            ),
        ];

        for (decode, fill, invalids) in cases {
            for invalid in invalids {
                for position in 0..5 {
                    let mut input = [fill; 5];
                    input[position] = invalid;
                    let mut dst = [0; 4];
                    assert_eq!(decode(&input, &mut dst), None);
                }
            }
        }

        let mut dst = [0; 4];
        assert_eq!(
            decode_ascii85(b"s8W-!", &mut dst),
            Some([u8::MAX; 4].as_slice())
        );
        assert_eq!(decode_ascii85(b"s8W-\"", &mut dst), None);
        assert_eq!(
            decode_z85(b"%nSc0", &mut dst),
            Some([u8::MAX; 4].as_slice())
        );
        assert_eq!(decode_z85(b"%nSc1", &mut dst), None);
    }

    #[test]
    fn adobe85_arbitrary_lengths_and_zero_quanta_roundtrip_on_stack() {
        for len in 0usize..=64 {
            let mut input = [0u8; 64];
            for (index, byte) in input[..len].iter_mut().enumerate() {
                *byte = index.wrapping_mul(73).wrapping_add(len * 19) as u8;
            }
            if len >= 4 {
                input[..4].fill(0);
            }

            let mut encoded = [0u8; 80];
            let encoded = encode_adobe85(&input[..len], &mut encoded).unwrap();
            let mut decoded = [0u8; 64];
            assert_eq!(
                decode_adobe85(encoded, &mut decoded),
                Some(&input[..len]),
                "failed to roundtrip {len} bytes"
            );
        }
    }

    #[test]
    fn adobe85_accepts_whitespace_at_every_position() {
        const WHITESPACE: [u8; 6] = *b"\t\n\x0b\x0c\r ";
        let inputs: &[&[u8]] = &[b"", b"A", b"AB", b"ABC", b"ABCD", b"\0\0\0\0ABC"];

        for &input in inputs {
            let mut encoded_storage = [0u8; 16];
            let encoded = encode_adobe85(input, &mut encoded_storage).unwrap();

            for position in 0..=encoded.len() {
                for whitespace in WHITESPACE {
                    let mut spaced = [0u8; 17];
                    spaced[..position].copy_from_slice(&encoded[..position]);
                    spaced[position] = whitespace;
                    spaced[position + 1..encoded.len() + 1].copy_from_slice(&encoded[position..]);

                    let mut decoded = [0u8; 8];
                    assert_eq!(
                        decode_adobe85(&spaced[..encoded.len() + 1], &mut decoded),
                        Some(input)
                    );
                }
            }
        }
    }

    #[test]
    fn adobe85_accepts_dense_whitespace_and_all_tail_widths() {
        const WHITESPACE: &[u8] = b"\t\n\x0b\x0c\r ";

        for input in [b"A".as_slice(), b"AB".as_slice(), b"ABC".as_slice()] {
            let mut encoded_storage = [0u8; 4];
            let encoded = encode_adobe85(input, &mut encoded_storage).unwrap();
            let mut spaced = [0u8; 35];
            let mut written = 0usize;

            for &byte in encoded {
                spaced[written..written + WHITESPACE.len()].copy_from_slice(WHITESPACE);
                written += WHITESPACE.len();
                spaced[written] = byte;
                written += 1;
            }
            spaced[written..written + WHITESPACE.len()].copy_from_slice(WHITESPACE);
            written += WHITESPACE.len();

            let mut decoded = [0u8; 3];
            assert_eq!(
                decode_adobe85(&spaced[..written], &mut decoded),
                Some(input)
            );
        }
    }

    #[test]
    fn adobe85_zero_compression_and_structure_rules_are_preserved() {
        let mut dst = [0xa5; 13];
        assert_eq!(
            decode_adobe85(b"z!!!!!z", &mut dst),
            Some([0; 12].as_slice())
        );
        assert_eq!(dst[12], 0xa5);

        for malformed in [
            b"!".as_slice(),
            b"!!!!!!".as_slice(),
            b"z!".as_slice(),
            b"!z!!!".as_slice(),
            b"!!!!z".as_slice(),
            b"<~z~>".as_slice(),
        ] {
            let mut dst = [0; 16];
            assert_eq!(decode_adobe85(malformed, &mut dst), None);
        }

        let expected: &[&[u8]] = &[&[0], &[0, 0], &[0, 0, 0], &[0, 0, 0, 0]];
        for (encoded, expected) in [b"!!".as_slice(), b"!!!", b"!!!!", b"!!!!!"]
            .into_iter()
            .zip(expected)
        {
            let mut dst = [0; 4];
            assert_eq!(decode_adobe85(encoded, &mut dst), Some(*expected));
        }
    }

    #[test]
    fn adobe85_checks_capacity_while_emitting_without_touching_guards() {
        let mut exact = [0xa5; 4];
        assert_eq!(decode_adobe85(b"z", &mut exact), Some([0; 4].as_slice()));

        let mut oversized = [0xa5; 5];
        assert_eq!(decode_adobe85(b"z", &mut oversized).unwrap(), &[0; 4]);
        assert_eq!(oversized[4], 0xa5);

        let mut guarded = [0xa5; 10];
        assert_eq!(decode_adobe85(b"zz", &mut guarded[1..8]), None);
        assert_eq!(guarded[0], 0xa5);
        assert_eq!(guarded[8..], [0xa5; 2]);
    }

    #[test]
    fn adobe85_rejects_invalid_symbols_and_overflow_values() {
        for invalid in [b'\0', MAX_ASCII_ASCII85 as u8] {
            for position in 0..5 {
                let mut input = *b"!!!!!";
                input[position] = invalid;
                let mut dst = [0; 4];
                assert_eq!(decode_adobe85(&input, &mut dst), None);
            }
        }

        let mut dst = [0; 4];
        assert_eq!(
            decode_adobe85(b"s8W-!", &mut dst),
            Some([u8::MAX; 4].as_slice())
        );
        assert_eq!(decode_adobe85(b"s8W-\"", &mut dst), None);
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Strict canonical Base32 and Base32Hex decoders.
//!
//! Inputs must use the selected uppercase alphabet, consist of complete
//! eight-symbol quanta, and use canonical terminal padding with zero pad bits.
//!
//! ```rust
//! use b2t_codecs::base32::{try_decode_from_base32, try_decode_from_base32hex};
//!
//! let mut base32 = [0; 3];
//! let mut base32hex = [0; 3];
//!
//! assert_eq!(
//!     try_decode_from_base32(b"MZXW6===", &mut base32),
//!     Some(b"foo".as_slice()),
//! );
//! assert_eq!(
//!     try_decode_from_base32hex(b"CPNMU===", &mut base32hex),
//!     Some(b"foo".as_slice()),
//! );
//! ```

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec};

use crate::base32::BASE32_PAD;

const BASE32_RFC: Decoder = const {
    use super::{DECODER, MAX_ASCII, MIN_ASCII};
    Decoder::from_table(&DECODER, MIN_ASCII, MAX_ASCII)
};
const BASE32_HEX: Decoder = const {
    use super::{DECODER_HEX, MAX_ASCII_HEX, MIN_ASCII_HEX};
    Decoder::from_table(&DECODER_HEX, MIN_ASCII_HEX, MAX_ASCII_HEX)
};

/// Decodes a canonical padded Base32 string.
///
/// Returns [`None`] unless `base32` uses the RFC 4648 Base32 alphabet, complete
/// eight-symbol quanta, terminal padding, and zero pad bits.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base32_string(base32: &str) -> Option<Box<[u8]>> {
    BASE32_RFC.try_decode_string(base32)
}

/// Decodes canonical padded Base32 ASCII bytes.
///
/// Returns [`None`] unless `base32` uses the RFC 4648 Base32 alphabet, complete
/// eight-symbol quanta, terminal padding, and zero pad bits.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base32(base32: &[u8]) -> Option<Box<[u8]>> {
    BASE32_RFC.try_decode_boxed(base32)
}

/// Decodes a canonical padded Base32Hex string.
///
/// Returns [`None`] unless `base32hex` uses the RFC 4648 Base32Hex alphabet,
/// complete eight-symbol quanta, terminal padding, and zero pad bits.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base32hex_string(base32hex: &str) -> Option<Box<[u8]>> {
    BASE32_HEX.try_decode_string(base32hex)
}

/// Decodes canonical padded Base32Hex ASCII bytes.
///
/// Returns [`None`] unless `base32hex` uses the RFC 4648 Base32Hex alphabet,
/// complete eight-symbol quanta, terminal padding, and zero pad bits.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base32hex(base32hex: &[u8]) -> Option<Box<[u8]>> {
    BASE32_HEX.try_decode_boxed(base32hex)
}

/// Decodes canonical padded Base32 ASCII from `src` into the beginning of
/// `dst`.
///
/// Returns the initialized prefix of `dst`, or [`None`] if `src` is malformed,
/// non-canonical, or `dst` is shorter than
/// [`decoded_length_base32(src)`](decoded_length_base32). A short destination
/// is left unchanged. This function does not allocate.
///
/// If decoding returns [`None`] because of invalid input, `dst` may have been
/// partially modified.
#[must_use = "the decoded slice should be used"]
#[inline]
pub fn try_decode_from_base32<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    BASE32_RFC.try_decode_into(src, dst)
}

/// Decodes canonical padded Base32Hex ASCII from `src` into the beginning of
/// `dst`.
///
/// Returns the initialized prefix of `dst`, or [`None`] if `src` is malformed,
/// non-canonical, or `dst` is shorter than
/// [`decoded_length_base32(src)`](decoded_length_base32). A short destination
/// is left unchanged. This function does not allocate.
///
/// If decoding returns [`None`] because of invalid input, `dst` may have been
/// partially modified.
#[must_use = "the decoded slice should be used"]
#[inline]
pub fn try_decode_from_base32hex<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    BASE32_HEX.try_decode_into(src, dst)
}

/// Returns the exact decoded length of a padded Base32 slice.
///
/// Returns [`None`] unless `src` contains complete eight-symbol quanta and its
/// trailing padding length is valid for canonical Base32. This function does
/// not validate the alphabet, pad bits, or padding outside the final quantum.
#[must_use = "the decoded size should be used"]
#[inline]
pub fn decoded_length_base32(src: &[u8]) -> Option<usize> {
    let len = src.len();
    if !len.is_multiple_of(8) {
        return None;
    }

    let decoded_len = (len / 8) * 5;

    let tail_shortfall = match count_tail_padding(src) {
        0 => 0,
        1 => 1,
        3 => 2,
        4 => 3,
        6 => 4,
        _ => return None,
    };

    Some(decoded_len - tail_shortfall)
}

#[inline]
fn count_tail_padding(src: &[u8]) -> usize {
    src.iter()
        .rev()
        .take(8)
        .take_while(|&&byte| byte == BASE32_PAD)
        .count()
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

    #[cfg(feature = "alloc")]
    #[inline]
    fn try_decode_string(&self, base32: &str) -> Option<Box<[u8]>> {
        self.try_decode_boxed(base32.as_bytes())
    }

    #[cfg(feature = "alloc")]
    fn try_decode_boxed(&self, base32: &[u8]) -> Option<Box<[u8]>> {
        // empty inputs result in empty outputs
        if base32.is_empty() {
            return Some(Vec::<u8>::new().into_boxed_slice());
        }

        let payload_len = decoded_length_base32(base32)?;

        let (chunks, []) = base32.as_chunks::<8>() else {
            unreachable!("decoded_length_base32 requires complete eight-symbol quanta")
        };
        let (tail, chunks) = chunks.split_last().unwrap();

        let mut dst = Box::<[u8]>::new_uninit_slice(payload_len);
        let mut written = 0usize;

        // whole chunks
        // padding characters are malformed here
        for &chunk in chunks {
            let chunk = self.decode_base32_full_chunk(chunk)?;
            dst[written..written + 5].write_copy_of_slice(&chunk);
            written += 5;
        }

        // handle padding at the tail
        match count_tail_padding(tail) {
            6 => {
                let byte = self.decode_base32_six_pads(*tail)?;
                dst[written].write(byte);
                written += 1;
            }
            4 => {
                let chunk = self.decode_base32_four_pads(*tail)?;
                dst[written..written + 2].write_copy_of_slice(&chunk);
                written += 2;
            }
            3 => {
                let chunk = self.decode_base32_three_pads(*tail)?;
                dst[written..written + 3].write_copy_of_slice(&chunk);
                written += 3;
            }
            1 => {
                let chunk = self.decode_base32_one_pad(*tail)?;
                dst[written..written + 4].write_copy_of_slice(&chunk);
                written += 4;
            }
            0 => {
                let chunk = self.decode_base32_full_chunk(*tail)?;
                dst[written..written + 5].write_copy_of_slice(&chunk);
                written += 5;
            }
            _ => unreachable!("the padding length was validated before allocation"),
        }

        // SAFETY:
        //  - `dst` contains `payload_len` consecutive `MaybeUninit<u8>` values.
        //  - Successful chunk decoding writes every output byte into distinct,
        //    in-bounds elements of `dst`.
        //  - `written == dst.len()` verifies that every element was initialized.
        unsafe {
            // INVARIANT: all allocated elements were initialized.
            assert!(written == dst.len());
            Some(dst.assume_init())
        }
    }

    #[inline]
    fn try_decode_into<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
        if src.is_empty() {
            return Some(&dst[..0]);
        }

        let payload_len = decoded_length_base32(src)?;
        if dst.len() < payload_len {
            return None;
        }

        let (chunks, []) = src.as_chunks::<8>() else {
            unreachable!("decoded_length_base32 requires complete eight-symbol quanta")
        };
        let (tail, chunks) = chunks.split_last().unwrap();

        let mut written = 0usize;

        // whole chunks
        // padding characters are malformed here
        for &chunk in chunks {
            let chunk = self.decode_base32_full_chunk(chunk)?;
            dst[written..written + 5].copy_from_slice(&chunk);
            written += 5;
        }

        // handle padding at the tail
        match count_tail_padding(tail) {
            6 => {
                let byte = self.decode_base32_six_pads(*tail)?;
                dst[written] = byte;
                written += 1;
            }
            4 => {
                let chunk = self.decode_base32_four_pads(*tail)?;
                dst[written..written + 2].copy_from_slice(&chunk);
                written += 2;
            }
            3 => {
                let chunk = self.decode_base32_three_pads(*tail)?;
                dst[written..written + 3].copy_from_slice(&chunk);
                written += 3;
            }
            1 => {
                let chunk = self.decode_base32_one_pad(*tail)?;
                dst[written..written + 4].copy_from_slice(&chunk);
                written += 4;
            }
            0 => {
                let chunk = self.decode_base32_full_chunk(*tail)?;
                dst[written..written + 5].copy_from_slice(&chunk);
                written += 5;
            }
            _ => unreachable!("the padding length was validated before decoding"),
        }

        // INVARIANT: successful decoding writes exactly `payload_len` bytes.
        assert!(written == payload_len);
        Some(&dst[..written])
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
    #[cfg(feature = "alloc")]
    use super::super::enc::{encode_base32, encode_base32hex};
    use super::super::enc::{try_encode_into_base32, try_encode_into_base32hex};
    use super::super::{ENCODER, ENCODER_HEX};
    use super::*;

    #[cfg(feature = "alloc")]
    use alloc::vec;

    #[cfg(feature = "alloc")]
    type Encode = fn(&[u8]) -> Box<[u8]>;
    #[cfg(feature = "alloc")]
    type Decode = fn(&[u8]) -> Option<Box<[u8]>>;
    type EncodeInto = for<'a> fn(&[u8], &'a mut [u8]) -> Option<&'a [u8]>;
    type DecodeInto = for<'a> fn(&[u8], &'a mut [u8]) -> Option<&'a [u8]>;

    #[cfg(feature = "alloc")]
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
    fn decoded_lengths_are_exact_and_require_complete_quanta() {
        assert_eq!(decoded_length_base32(b""), Some(0));
        assert_eq!(decoded_length_base32(b"A"), None);
        assert_eq!(decoded_length_base32(b"AAAAAAA"), None);
        assert_eq!(decoded_length_base32(b"AAAAAAAA"), Some(5));
        assert_eq!(decoded_length_base32(b"MY======"), Some(1));
        assert_eq!(decoded_length_base32(b"MZXQ===="), Some(2));
        assert_eq!(decoded_length_base32(b"MZXW6==="), Some(3));
        assert_eq!(decoded_length_base32(b"MZXW6YQ="), Some(4));
        assert_eq!(decoded_length_base32(b"MZXW6YTB"), Some(5));
        assert_eq!(decoded_length_base32(b"MZXW6YTBOI======"), Some(6));
        assert_eq!(decoded_length_base32(b"AAAAAAAAAAAAAAAA"), Some(10));
        assert_eq!(decoded_length_base32(b"AAAAAA=="), None);
        assert_eq!(decoded_length_base32(b"AAA====="), None);
        assert_eq!(decoded_length_base32(b"A======="), None);
        assert_eq!(decoded_length_base32(b"========"), None);
        // Length calculation deliberately leaves non-terminal padding validation to decoding.
        assert_eq!(decoded_length_base32(b"A===A==="), Some(3));
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
            #[cfg(feature = "alloc")]
            {
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

            let mut dst = [0u8; 6];
            assert_eq!(
                try_decode_from_base32(base32.as_bytes(), &mut dst),
                Some(plain)
            );

            let mut dst = [0u8; 6];
            assert_eq!(
                try_decode_from_base32hex(base32hex.as_bytes(), &mut dst),
                Some(plain)
            );
        }
    }

    #[test]
    fn non_allocating_decoders_preserve_destination_bounds() {
        let codecs: [(&str, DecodeInto, &[u8]); 2] = [
            ("Base32", try_decode_from_base32, b"MZXW6YTBOI======"),
            ("Base32Hex", try_decode_from_base32hex, b"CPNMUOJ1E8======"),
        ];

        for (name, decode, encoded) in codecs {
            let mut short = [0xa5; 5];
            assert_eq!(decode(encoded, &mut short), None, "{name}");
            assert_eq!(short, [0xa5; 5], "{name} modified a short destination");

            let mut oversized = [0xa5; 8];
            assert_eq!(
                decode(encoded, &mut oversized),
                Some(b"foobar".as_slice()),
                "{name}"
            );
            assert_eq!(
                &oversized[6..],
                &[0xa5; 2],
                "{name} modified the destination suffix"
            );
        }
    }

    #[test]
    fn non_allocating_decoders_reject_noncanonical_inputs() {
        let codecs: [(&str, DecodeInto, &[u8]); 2] = [
            ("Base32", try_decode_from_base32, b"MZ======"),
            ("Base32Hex", try_decode_from_base32hex, b"CP======"),
        ];

        for (name, decode, non_zero_pad_bits) in codecs {
            let mut dst = [0u8; 10];
            for input in [
                b"A".as_slice(),
                b"!!!!!!!!".as_slice(),
                b"AAAAAA==".as_slice(),
                b"AA======AAAAAAAA".as_slice(),
                non_zero_pad_bits,
            ] {
                assert_eq!(decode(input, &mut dst), None, "{name} accepted {input:?}");
            }
        }
    }

    #[test]
    fn three_pad_tail_decoding_preserves_all_three_bytes() {
        let mut dst = [0; 3];
        assert_eq!(
            try_decode_from_base32(b"MZXW6===", &mut dst),
            Some(b"foo".as_slice())
        );

        let mut dst = [0; 3];
        assert_eq!(
            try_decode_from_base32hex(b"CPNMU===", &mut dst),
            Some(b"foo".as_slice())
        );
    }

    #[test]
    fn decoders_select_the_requested_alphabet() {
        let mut dst = [0; 1];
        assert_eq!(
            try_decode_from_base32(b"WA======", &mut dst),
            Some([0xb0].as_slice())
        );

        let mut dst = [0; 1];
        assert_eq!(
            try_decode_from_base32hex(b"M0======", &mut dst),
            Some([0xb0].as_slice())
        );

        assert_eq!(try_decode_from_base32(b"M0======", &mut dst), None);
        assert_eq!(try_decode_from_base32hex(b"WA======", &mut dst), None);
    }

    #[test]
    fn tables_preserve_unsafe_indexing_invariants() {
        fn assert_invariants(decoder: &Decoder<'_>, encoder: &[u8]) {
            assert!(decoder.max_ascii > decoder.min_ascii);
            assert_eq!(decoder.max_ascii - decoder.min_ascii, decoder.decoder.len());

            let mut seen = [false; 41];
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
    fn arbitrary_byte_slices_roundtrip_through_non_allocating_codecs() {
        let codecs: [(&str, EncodeInto, DecodeInto); 2] = [
            ("Base32", try_encode_into_base32, try_decode_from_base32),
            (
                "Base32Hex",
                try_encode_into_base32hex,
                try_decode_from_base32hex,
            ),
        ];

        let mut input = [0u8; 64];
        let mut encoded = [0u8; 104];
        let mut decoded = [0u8; 64];

        for len in 0usize..=input.len() {
            for (i, byte) in input[..len].iter_mut().enumerate() {
                *byte = (i.wrapping_mul(73).wrapping_add(len * 19)) as u8;
            }

            for (name, encode, decode) in codecs {
                let encoded = encode(&input[..len], &mut encoded).unwrap();
                assert_eq!(
                    decode(encoded, &mut decoded),
                    Some(&input[..len]),
                    "{name} failed to roundtrip {len} data bytes"
                );
            }
        }
    }

    #[cfg(feature = "alloc")]
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

    #[cfg(feature = "alloc")]
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

    #[cfg(feature = "alloc")]
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

    #[cfg(feature = "alloc")]
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

    #[cfg(feature = "alloc")]
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

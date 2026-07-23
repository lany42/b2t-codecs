// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Strict and extended Base64 and Base64URL decoders.
//!
//! Strict decoding accepts one canonical padded value. Extended decoding also
//! accepts canonical unpadded final quanta, concatenated padded values, and
//! padding-only quanta.
//!
//! ```rust
//! use b2t_codecs::base64::{try_decode_base64_string, try_decode_base64ext_string};
//!
//! assert_eq!(
//!     try_decode_base64_string("Zg==").as_deref(),
//!     Some(b"f".as_slice()),
//! );
//! assert_eq!(
//!     try_decode_base64ext_string("Zg").as_deref(),
//!     Some(b"f".as_slice()),
//! );
//! ```
use super::BASE64_PAD;

const BASE64_RFC: Decoder = const {
    use super::{DECODER, MAX_ASCII, MIN_ASCII};
    Decoder::from_table(&DECODER, MIN_ASCII, MAX_ASCII)
};
const BASE64_URL: Decoder = const {
    use super::{DECODER_URL, MAX_ASCII_URL, MIN_ASCII_URL};
    Decoder::from_table(&DECODER_URL, MIN_ASCII_URL, MAX_ASCII_URL)
};

/// Decodes a canonical padded Base64 string.
///
/// Returns [`None`] unless `base64` uses the standard RFC 4648 alphabet,
/// complete four-symbol quanta, terminal padding, and zero pad bits.
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base64_string(base64: &str) -> Option<Box<[u8]>> {
    BASE64_RFC.try_decode_base64_string(base64)
}

/// Decodes a Base64 string using extended framing.
///
/// Padded quanta may be concatenated, padding-only quanta are ignored, and the
/// final quantum may omit padding. Returns [`None`] for an invalid alphabet,
/// malformed padding, non-zero pad bits, or a one-symbol tail.
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base64ext_string(base64: &str) -> Option<Box<[u8]>> {
    BASE64_RFC.try_decode_base64ext_string(base64)
}

/// Decodes canonical padded Base64 ASCII bytes.
///
/// Returns [`None`] unless `base64` uses the standard RFC 4648 alphabet,
/// complete four-symbol quanta, terminal padding, and zero pad bits.
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base64(base64: &[u8]) -> Option<Box<[u8]>> {
    BASE64_RFC.try_decode_base64(base64)
}

/// Decodes Base64 ASCII bytes using extended framing.
///
/// Padded quanta may be concatenated, padding-only quanta are ignored, and the
/// final quantum may omit padding. Returns [`None`] for an invalid alphabet,
/// malformed padding, non-zero pad bits, or a one-symbol tail.
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base64ext(base64: &[u8]) -> Option<Box<[u8]>> {
    BASE64_RFC.try_decode_base64ext(base64)
}

/// Decodes a canonical padded Base64URL string.
///
/// Returns [`None`] unless `base64` uses the RFC 4648 URL-safe alphabet,
/// complete four-symbol quanta, terminal padding, and zero pad bits.
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base64url_string(base64: &str) -> Option<Box<[u8]>> {
    BASE64_URL.try_decode_base64_string(base64)
}

/// Decodes a Base64URL string using extended framing.
///
/// Padded quanta may be concatenated, padding-only quanta are ignored, and the
/// final quantum may omit padding. Returns [`None`] for an invalid URL-safe
/// alphabet, malformed padding, non-zero pad bits, or a one-symbol tail.
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base64urlext_string(base64: &str) -> Option<Box<[u8]>> {
    BASE64_URL.try_decode_base64ext_string(base64)
}

/// Decodes canonical padded Base64URL ASCII bytes.
///
/// Returns [`None`] unless `base64` uses the RFC 4648 URL-safe alphabet,
/// complete four-symbol quanta, terminal padding, and zero pad bits.
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base64url(base64: &[u8]) -> Option<Box<[u8]>> {
    BASE64_URL.try_decode_base64(base64)
}

/// Decodes Base64URL ASCII bytes using extended framing.
///
/// Padded quanta may be concatenated, padding-only quanta are ignored, and the
/// final quantum may omit padding. Returns [`None`] for an invalid URL-safe
/// alphabet, malformed padding, non-zero pad bits, or a one-symbol tail.
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base64urlext(base64: &[u8]) -> Option<Box<[u8]>> {
    BASE64_URL.try_decode_base64ext(base64)
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
    fn try_decode_base64ext_string(&self, base64: &str) -> Option<Box<[u8]>> {
        self.try_decode_base64ext(base64.as_bytes())
    }

    #[inline]
    fn try_decode_base64_string(&self, base64: &str) -> Option<Box<[u8]>> {
        self.try_decode_base64(base64.as_bytes())
    }

    // extended decoder supports:
    //  - unpadded tails
    //  - concatenated base64 strings
    //  - skips all-padding chunks
    fn try_decode_base64ext(&self, base64: &[u8]) -> Option<Box<[u8]>> {
        // empty inputs result in empty outputs
        if base64.is_empty() {
            return Some(Vec::<u8>::new().into_boxed_slice());
        }

        // unpadded tail implies up to two extra bytes
        let cap = base64.len().checked_mul(3)? / 4 + 2;

        let (chunks, remainder) = base64.as_chunks::<4>();
        let mut ret = Vec::<u8>::with_capacity(cap);

        for &chunk in chunks {
            match chunk {
                // skip chunks with only padding
                [BASE64_PAD, BASE64_PAD, BASE64_PAD, BASE64_PAD] => {}
                [_, _, BASE64_PAD, BASE64_PAD] => {
                    let byte = self.decode_base64_two_pads(chunk)?;
                    ret.push(byte);
                }
                [_, _, _, BASE64_PAD] => {
                    let chunk = self.decode_base64_one_pad(chunk)?;
                    ret.extend_from_slice(&chunk);
                }
                _ => {
                    let chunk = self.decode_base64_full_chunk(chunk)?;
                    ret.extend_from_slice(&chunk);
                }
            }
        }

        // handle a tail with implied padding, if any
        if !remainder.is_empty() {
            // malformed if one ASCII character
            if remainder.len() == 1 {
                return None;
            }

            // [x, x] OR [x, x, x]
            self.decode_base64_tail(remainder, &mut ret)?;
        }

        Some(ret.into_boxed_slice())
    }

    fn try_decode_base64(&self, base64: &[u8]) -> Option<Box<[u8]>> {
        // empty inputs result in empty outputs
        if base64.is_empty() {
            return Some(Vec::<u8>::new().into_boxed_slice());
        }

        // INVARIANT: strict base64 encodes four ASCII per three bytes
        if !base64.len().is_multiple_of(4) {
            return None;
        }

        let cap = base64.len().checked_mul(3)? / 4;
        let mut ret = Vec::<u8>::with_capacity(cap);

        let (chunks, []) = base64.as_chunks::<4>() else {
            unreachable!("base64 slice always a multiple of four")
        };
        let (tail, chunks) = chunks.split_last().unwrap();

        // whole chunks
        // padding characters are malformed here
        for &chunk in chunks {
            ret.extend_from_slice(&self.decode_base64_full_chunk(chunk)?);
        }

        // handle padding at the tail
        match tail {
            [_, _, BASE64_PAD, BASE64_PAD] => {
                let byte = self.decode_base64_two_pads(*tail)?;
                ret.push(byte);
            }
            [_, _, _, BASE64_PAD] => {
                let chunk = self.decode_base64_one_pad(*tail)?;
                ret.extend_from_slice(&chunk);
            }
            _ => {
                let chunk = self.decode_base64_full_chunk(*tail)?;
                ret.extend_from_slice(&chunk);
            }
        }

        Some(ret.into_boxed_slice())
    }

    fn decode_base64_full_chunk(&self, chunk: [u8; 4]) -> Option<[u8; 3]> {
        let [on, tw, th, fo] = chunk;

        let on = self.check_and_decode_b64_byte(on)?;
        let tw = self.check_and_decode_b64_byte(tw)?;
        let th = self.check_and_decode_b64_byte(th)?;
        let fo = self.check_and_decode_b64_byte(fo)?;

        // rehydrate chunk bytes into a u32
        // NOTE: each decoded byte is guaranteed [0, 64) from the decoding table
        let n = on << 18 | tw << 12 | th << 6 | fo;

        // strip off the top byte and return
        // [0, x, x, x]
        n.to_be_bytes()[1..].try_into().ok()
    }

    // Two ASCII and two pad, returns one decoded byte
    fn decode_base64_two_pads(&self, chunk: [u8; 4]) -> Option<u8> {
        let [on, tw, _, _] = chunk;

        let on = self.check_and_decode_b64_byte(on)?;
        let tw = self.check_and_decode_b64_byte(tw)?;

        // Only the top two bits of the second hexad carry data.
        if tw & 0x0f != 0 {
            return None;
        }

        let n = on << 18 | tw << 12;

        // return one byte only: [0, x, _, _]
        #[allow(clippy::cast_possible_truncation)]
        Some((n >> 16) as u8)
    }

    // Three ASCII and one pad, returns two decoded bytes
    fn decode_base64_one_pad(&self, chunk: [u8; 4]) -> Option<[u8; 2]> {
        let [on, tw, th, _] = chunk;

        let on = self.check_and_decode_b64_byte(on)?;
        let tw = self.check_and_decode_b64_byte(tw)?;
        let th = self.check_and_decode_b64_byte(th)?;

        // Only the top four bits of the third hexad carry data.
        if th & 0x03 != 0 {
            return None;
        }

        let n = on << 18 | tw << 12 | th << 6;

        // return two bytes only: [0, x, x, _]
        let bytes = n.to_be_bytes();
        Some([bytes[1], bytes[2]])
    }

    // tail length 2 OR 3
    fn decode_base64_tail(&self, tail: &[u8], ret: &mut Vec<u8>) -> Option<()> {
        let length = tail.len();

        let mut buf = [BASE64_PAD; 4];
        buf[..length].copy_from_slice(tail);
        match length {
            2 => ret.push(self.decode_base64_two_pads(buf)?),
            3 => ret.extend_from_slice(&self.decode_base64_one_pad(buf)?),
            _ => unreachable!("tail length must be 2 or 3"),
        }

        Some(())
    }

    fn check_and_decode_b64_byte(&self, byte: u8) -> Option<u32> {
        if !(self.min_ascii..self.max_ascii).contains(&(byte as usize)) {
            // byte out of base64 ASCII range
            return None;
        }

        let i = byte as usize - self.min_ascii;

        // SAFETY: byte - MIN_ASCII within [0, MAX_ASCII - MIN_ASCII)
        let byte = unsafe { *self.decoder.get_unchecked(i) };

        if byte == 255 {
            // byte is not encoded base64
            return None;
        }
        Some(u32::from(byte))
    }
}

#[cfg(test)]
mod tests {
    use super::super::enc::{encode_base64, encode_base64url};
    use super::super::{ENCODER, ENCODER_URL};
    use super::*;

    type Decode = fn(&[u8]) -> Option<Box<[u8]>>;

    fn strict_decoders() -> [(&'static str, Decode); 2] {
        [
            ("Base64 strict", try_decode_base64),
            ("Base64URL strict", try_decode_base64url),
        ]
    }

    fn extended_decoders() -> [(&'static str, Decode); 2] {
        [
            ("Base64 extended", try_decode_base64ext),
            ("Base64URL extended", try_decode_base64urlext),
        ]
    }

    fn all_decoders() -> [(&'static str, Decode); 4] {
        [
            ("Base64 strict", try_decode_base64),
            ("Base64 extended", try_decode_base64ext),
            ("Base64URL strict", try_decode_base64url),
            ("Base64URL extended", try_decode_base64urlext),
        ]
    }

    #[test]
    fn rfc_4648_base64_test_vectors_pin_decoding() {
        let vectors: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];

        for &(plain, encoded) in vectors {
            assert_eq!(
                try_decode_base64(encoded.as_bytes()).as_deref(),
                Some(plain)
            );
            assert_eq!(try_decode_base64_string(encoded).as_deref(), Some(plain));
            assert_eq!(
                try_decode_base64ext(encoded.as_bytes()).as_deref(),
                Some(plain)
            );
            assert_eq!(try_decode_base64ext_string(encoded).as_deref(), Some(plain));

            // These RFC vectors do not use alphabet digits 62 or 63, so they
            // are valid under the Base64URL alphabet as well.
            assert_eq!(
                try_decode_base64url(encoded.as_bytes()).as_deref(),
                Some(plain)
            );
            assert_eq!(try_decode_base64url_string(encoded).as_deref(), Some(plain));
            assert_eq!(
                try_decode_base64urlext(encoded.as_bytes()).as_deref(),
                Some(plain)
            );
            assert_eq!(
                try_decode_base64urlext_string(encoded).as_deref(),
                Some(plain)
            );
        }
    }

    #[test]
    fn base64url_decoding_uses_url_safe_alphabet() {
        let vectors: &[(&[u8], &str, &str)] = &[
            (&[0xfb], "+w==", "-w=="),
            (&[0xfb, 0xff], "+/8=", "-_8="),
            (&[0xfb, 0xff, 0xff], "+///", "-___"),
        ];

        for &(plain, base64, base64url) in vectors {
            assert_eq!(try_decode_base64_string(base64).as_deref(), Some(plain));
            assert_eq!(try_decode_base64ext_string(base64).as_deref(), Some(plain));
            assert_eq!(
                try_decode_base64url_string(base64url).as_deref(),
                Some(plain)
            );
            assert_eq!(
                try_decode_base64urlext_string(base64url).as_deref(),
                Some(plain)
            );

            assert_eq!(try_decode_base64(base64url.as_bytes()), None);
            assert_eq!(try_decode_base64ext(base64url.as_bytes()), None);
            assert_eq!(try_decode_base64url(base64.as_bytes()), None);
            assert_eq!(try_decode_base64urlext(base64.as_bytes()), None);
        }
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
                assert!(!seen[offset], "duplicate base64 byte at ASCII {ascii}");
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

        assert_invariants(&BASE64_RFC, &ENCODER);
        assert_invariants(&BASE64_URL, &ENCODER_URL);
    }

    #[test]
    fn byte_slices_of_arbitrary_lengths_roundtrip_through_every_decoder() {
        for len in 0usize..=64 {
            let input: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(73).wrapping_add(len * 19)) as u8)
                .collect();

            let base64 = encode_base64(&input);
            assert_eq!(
                try_decode_base64(&base64).as_deref(),
                Some(input.as_slice()),
                "Base64 strict failed to roundtrip {len} data bytes"
            );
            assert_eq!(
                try_decode_base64ext(&base64).as_deref(),
                Some(input.as_slice()),
                "Base64 extended failed to roundtrip {len} data bytes"
            );

            let base64url = encode_base64url(&input);
            assert_eq!(
                try_decode_base64url(&base64url).as_deref(),
                Some(input.as_slice()),
                "Base64URL strict failed to roundtrip {len} data bytes"
            );
            assert_eq!(
                try_decode_base64urlext(&base64url).as_deref(),
                Some(input.as_slice()),
                "Base64URL extended failed to roundtrip {len} data bytes"
            );
        }
    }

    #[test]
    fn strict_decode_requires_complete_quanta() {
        for (name, decode) in strict_decoders() {
            for input in [
                b"A".as_slice(),
                b"Zg".as_slice(),
                b"Zm8".as_slice(),
                b"AAAAA".as_slice(),
                b"AAAAAA".as_slice(),
                b"AAAAAAA".as_slice(),
            ] {
                assert_eq!(decode(input), None, "{name} accepted {input:?}");
            }
        }
    }

    #[test]
    fn every_decoder_rejects_non_zero_pad_bit_aliases() {
        let padded: &[(&str, &str, &[u8])] = &[("TQ==", "TR==", b"M"), ("TWE=", "TWF=", b"Ma")];

        for (name, decode) in all_decoders() {
            for &(canonical, alias, plain) in padded {
                assert_eq!(
                    decode(canonical.as_bytes()).as_deref(),
                    Some(plain),
                    "{name} rejected canonical {canonical:?}"
                );
                assert_eq!(
                    decode(alias.as_bytes()),
                    None,
                    "{name} accepted alias {alias:?}"
                );
            }
        }

        let unpadded: &[(&str, &str, &[u8])] = &[("TQ", "TR", b"M"), ("TWE", "TWF", b"Ma")];
        for (name, decode) in extended_decoders() {
            for &(canonical, alias, plain) in unpadded {
                assert_eq!(
                    decode(canonical.as_bytes()).as_deref(),
                    Some(plain),
                    "{name} rejected canonical {canonical:?}"
                );
                assert_eq!(
                    decode(alias.as_bytes()),
                    None,
                    "{name} accepted alias {alias:?}"
                );
            }
        }
    }

    #[test]
    fn strict_decode_rejects_non_terminal_or_malformed_padding() {
        for (name, decode) in strict_decoders() {
            for input in [
                b"====".as_slice(),
                b"========".as_slice(),
                b"TQ==TQ==".as_slice(),
                b"TWE=TWE=".as_slice(),
                b"=AAA".as_slice(),
                b"A=AA".as_slice(),
                b"AA=A".as_slice(),
                b"A===".as_slice(),
                b"===A".as_slice(),
            ] {
                assert_eq!(decode(input), None, "{name} accepted {input:?}");
            }
        }
    }

    #[test]
    fn extended_decode_accepts_unpadded_final_quantum() {
        for (name, decode) in extended_decoders() {
            for (input, expected) in [("Zg", b"f".as_slice()), ("Zm8", b"fo".as_slice())] {
                assert_eq!(
                    decode(input.as_bytes()).as_deref(),
                    Some(expected),
                    "{name} rejected {input:?}"
                );
            }
        }
    }

    #[test]
    fn extended_decode_accepts_padding_only_chunks() {
        for (name, decode) in extended_decoders() {
            for input in [b"====".as_slice(), b"========".as_slice()] {
                assert_eq!(
                    decode(input).as_deref(),
                    Some(b"".as_slice()),
                    "{name} rejected {input:?}"
                );
            }
        }
    }

    #[test]
    fn extended_decode_treats_padded_quanta_as_concatenated_values() {
        for (name, decode) in extended_decoders() {
            for (input, expected) in [
                ("TQ==TQ==", b"MM".as_slice()),
                ("TWE=TWE=", b"MaMa".as_slice()),
                ("TQ======TQ==", b"MM".as_slice()),
            ] {
                assert_eq!(
                    decode(input.as_bytes()).as_deref(),
                    Some(expected),
                    "{name} rejected {input:?}"
                );
            }
        }
    }

    #[test]
    fn extended_decode_rejects_single_ascii_tails() {
        for (name, decode) in extended_decoders() {
            for input in [
                b"A".as_slice(),
                b"AAAAA".as_slice(),
                b"AAAAAAAAA".as_slice(),
            ] {
                assert_eq!(decode(input), None, "{name} accepted {input:?}");
            }
        }
    }

    #[test]
    fn extended_decode_rejects_misplaced_or_partial_padding() {
        for (name, decode) in extended_decoders() {
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
                assert_eq!(decode(input), None, "{name} accepted {input:?}");
            }
        }
    }

    #[test]
    fn decoders_reject_every_non_alphabet_byte_in_any_frame() {
        fn assert_invalid_bytes_rejected(name: &str, decode: Decode, alphabet: &[u8]) {
            for invalid in u8::MIN..=u8::MAX {
                if invalid == BASE64_PAD || alphabet.contains(&invalid) {
                    continue;
                }

                for position in 0..4 {
                    let mut input = *b"AAAA";
                    input[position] = invalid;
                    assert_eq!(
                        decode(&input),
                        None,
                        "{name} accepted byte {invalid:#04x} at position {position}"
                    );
                }

                let mut second_frame = *b"AAAAAAAA";
                second_frame[6] = invalid;
                assert_eq!(
                    decode(&second_frame),
                    None,
                    "{name} accepted byte {invalid:#04x} in a later frame"
                );
            }
        }

        assert_invalid_bytes_rejected("Base64 strict", try_decode_base64, &ENCODER);
        assert_invalid_bytes_rejected("Base64 extended", try_decode_base64ext, &ENCODER);
        assert_invalid_bytes_rejected("Base64URL strict", try_decode_base64url, &ENCODER_URL);
        assert_invalid_bytes_rejected("Base64URL extended", try_decode_base64urlext, &ENCODER_URL);
    }
}

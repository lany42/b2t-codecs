// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Base16 decoders with mixed-case and case-selective validation.
//!
//! All decoders require an even number of symbols. The general decoder accepts
//! mixed case, while the lowercase and uppercase variants reject letters from
//! the other case.
//!
//! ```rust
//! use b2t_codecs::base16::{try_decode_from_base16, try_decode_from_base16upper};
//!
//! let mut mixed = [0; 2];
//! let mut upper = [0; 2];
//! let mixed = try_decode_from_base16(b"aBcD", &mut mixed);
//! let upper = try_decode_from_base16upper(b"aBcD", &mut upper);
//!
//! assert_eq!(mixed, Some([0xab, 0xcd].as_slice()));
//! assert_eq!(upper, None);
//! ```

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec};

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

/// Decodes a mixed-case Base16 string.
///
/// Returns [`None`] if the input has an odd length or contains a non-Base16
/// character.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base16_string(base16: &str) -> Option<Box<[u8]>> {
    BASE16_MIXED.try_decode_string(base16)
}

/// Decodes a lowercase Base16 string.
///
/// Returns [`None`] if the input has an odd length or contains any symbol
/// outside lowercase Base16, including an uppercase letter.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base16lower_string(base16: &str) -> Option<Box<[u8]>> {
    BASE16_LOWER.try_decode_string(base16)
}

/// Decodes an uppercase Base16 string.
///
/// Returns [`None`] if the input has an odd length or contains any symbol
/// outside uppercase Base16, including a lowercase letter.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base16upper_string(base16: &str) -> Option<Box<[u8]>> {
    BASE16_UPPER.try_decode_string(base16)
}

/// Decodes mixed-case Base16 ASCII bytes.
///
/// Returns [`None`] if the input has an odd length or contains a non-Base16
/// byte.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base16(base16: &[u8]) -> Option<Box<[u8]>> {
    BASE16_MIXED.try_decode_boxed(base16)
}

/// Decodes lowercase Base16 ASCII bytes.
///
/// Returns [`None`] if the input has an odd length or contains any byte outside
/// lowercase Base16, including an uppercase letter.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base16lower(base16: &[u8]) -> Option<Box<[u8]>> {
    BASE16_LOWER.try_decode_boxed(base16)
}

/// Decodes uppercase Base16 ASCII bytes.
///
/// Returns [`None`] if the input has an odd length or contains any byte outside
/// uppercase Base16, including a lowercase letter.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base16upper(base16: &[u8]) -> Option<Box<[u8]>> {
    BASE16_UPPER.try_decode_boxed(base16)
}

/// Returns the exact decoded length of a structurally valid Base16 slice.
///
/// Each pair of Base16 symbols decodes to one byte. This function returns
/// [`None`] for an odd input length, but does not validate that the bytes are
/// part of a Base16 alphabet.
#[must_use = "the decoded size should be used"]
#[inline]
pub fn decoded_length_base16(src: &[u8]) -> Option<usize> {
    decoded_length(src)
}

#[inline]
fn decoded_length(src: &[u8]) -> Option<usize> {
    let len = src.len();
    if len.is_multiple_of(2) {
        Some(len / 2)
    } else {
        None
    }
}

/// Decodes mixed-case Base16 ASCII from `src` into the beginning of `dst`.
///
/// Returns the initialized prefix of `dst`, or [`None`] if `src` has an odd
/// length, contains a non-Base16 byte, or `dst` is too short. The returned
/// slice has [`decoded_length_base16(src)`](decoded_length_base16) bytes. This
/// function does not allocate.
///
/// If decoding returns [`None`] because of an invalid byte, `dst` may have
/// been partially modified.
#[must_use = "the decoded slice should be used"]
#[inline]
pub fn try_decode_from_base16<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    BASE16_MIXED.try_decode_into(src, dst)
}

/// Decodes lowercase Base16 ASCII from `src` into the beginning of `dst`.
///
/// Returns the initialized prefix of `dst`, or [`None`] if `src` has an odd
/// length, contains a byte outside the lowercase Base16 alphabet, or `dst` is
/// too short. Decimal digits are accepted, but uppercase letters are rejected.
/// This function does not allocate.
///
/// If decoding returns [`None`] because of an invalid byte, `dst` may have
/// been partially modified.
#[must_use = "the decoded slice should be used"]
#[inline]
pub fn try_decode_from_base16lower<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    BASE16_LOWER.try_decode_into(src, dst)
}

/// Decodes uppercase Base16 ASCII from `src` into the beginning of `dst`.
///
/// Returns the initialized prefix of `dst`, or [`None`] if `src` has an odd
/// length, contains a byte outside the uppercase Base16 alphabet, or `dst` is
/// too short. Decimal digits are accepted, but lowercase letters are rejected.
/// This function does not allocate.
///
/// If decoding returns [`None`] because of an invalid byte, `dst` may have
/// been partially modified.
#[must_use = "the decoded slice should be used"]
#[inline]
pub fn try_decode_from_base16upper<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    BASE16_UPPER.try_decode_into(src, dst)
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
    fn try_decode_string(&self, base16: &str) -> Option<Box<[u8]>> {
        self.try_decode_boxed(base16.as_bytes())
    }

    #[cfg(feature = "alloc")]
    fn try_decode_boxed(&self, base16: &[u8]) -> Option<Box<[u8]>> {
        // Empty inputs result in empty outputs.
        if base16.is_empty() {
            return Some(Vec::<u8>::new().into_boxed_slice());
        }

        // INVARIANT: input length must be a multiple of two.
        if !base16.len().is_multiple_of(2) {
            return None;
        }

        let mut dst = Box::<[u8]>::new_uninit_slice(base16.len() / 2);

        // SAFETY:
        //  - `dst` contains `base16.len() / 2` consecutive
        //    `MaybeUninit<u8>` values.
        //  - A `MaybeUninit<u8>` pointer is valid for writes through a `u8`
        //    pointer.
        //  - `base16` has an even length.
        unsafe {
            let written = self.decode_base16_payload(base16, dst.as_mut_ptr().cast::<u8>())?;

            // INVARIANT: a successful decode initialized every element.
            assert!(written == dst.len());
            Some(dst.assume_init())
        }
    }

    #[inline]
    fn try_decode_into<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
        if src.is_empty() {
            return Some(&dst[..0]);
        }

        // INVARIANT: input length must be a multiple of 2
        if !src.len().is_multiple_of(2) {
            return None;
        }

        // INVARIANT: dst must be at least equal to src.len() / 2
        if dst.len() < src.len() / 2 {
            return None;
        }

        // SAFETY:
        //  - `dst.len() >= src.len() / 2`.
        //  - `src.len()` is evenly divisible by two.
        let written = unsafe { self.decode_base16_payload(src, dst.as_mut_ptr())? };

        // INVARIANT: the number of bytes written should be exactly src.len() / 2
        assert!(written == src.len() / 2);
        Some(&dst[..written])
    }

    // SAFETY:
    //  - `dst` must point to at least `src.len() / 2` consecutive, writable
    //    bytes.
    //  - `src.len()` must be evenly divisible by two.
    //
    // Returns the number of bytes written to `dst`.
    #[inline]
    unsafe fn decode_base16_payload(&self, src: &[u8], dst: *mut u8) -> Option<usize> {
        let mut i = 0usize;

        // SAFETY:
        //  - The caller guarantees `src` is a multiple of two.
        //  - The caller guarantees enough writable storage for one output byte
        //    per input pair.
        unsafe {
            for &[hi, lo] in src.as_chunks_unchecked::<2>() {
                let hi = self.check_and_decode_base16_byte(hi)?;
                let lo = self.check_and_decode_base16_byte(lo)?;
                dst.add(i).write(hi << 4 | lo);
                i += 1;
            }
        }
        Some(i)
    }

    #[inline]
    fn check_and_decode_base16_byte(&self, byte: u8) -> Option<u8> {
        let i = byte as usize;
        if !(self.min_ascii..self.max_ascii).contains(&i) {
            // Byte is outside this base16 decoder's ASCII range.
            return None;
        }

        let i = i - self.min_ascii;

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
    use super::{BASE16_LOWER, BASE16_MIXED, BASE16_UPPER, Decoder, decoded_length};

    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;

    #[cfg(feature = "alloc")]
    #[test]
    fn every_decoder_rejects_malformed_input() {
        let decoders: &[(&str, &Decoder<'_>)] = &[
            ("mixed-case", &BASE16_MIXED),
            ("lowercase", &BASE16_LOWER),
            ("uppercase", &BASE16_UPPER),
        ];

        for &(name, decode) in decoders {
            assert_eq!(
                decode.try_decode_boxed(b"0"),
                None,
                "{name} accepted an odd-length input"
            );

            for invalid in [u8::MIN, b'/', b':', b'G', b'g', u8::MAX] {
                assert_eq!(
                    decode.try_decode_boxed(&[invalid, b'0']),
                    None,
                    "{name}, high nibble"
                );
                assert_eq!(
                    decode.try_decode_boxed(&[b'0', invalid]),
                    None,
                    "{name}, low nibble"
                );
            }
        }
    }

    #[test]
    fn decoded_lengths_require_complete_symbol_pairs() {
        assert_eq!(decoded_length(b""), Some(0));
        assert_eq!(decoded_length(b"0"), None);
        assert_eq!(decoded_length(b"00"), Some(1));
        assert_eq!(decoded_length(b"001"), None);
        assert_eq!(decoded_length(b"0011"), Some(2));

        // Length calculation deliberately does not validate the alphabet.
        assert_eq!(decoded_length(b"zz"), Some(1));
    }

    #[test]
    fn slice_decoders_write_only_the_returned_prefix() {
        let decoders: &[(&str, &Decoder<'_>, &[u8])] = &[
            ("mixed lowercase", &BASE16_MIXED, b"deadbeef"),
            ("mixed uppercase", &BASE16_MIXED, b"DEADBEEF"),
            ("mixed case", &BASE16_MIXED, b"dEaDbEeF"),
            ("strict lowercase", &BASE16_LOWER, b"deadbeef"),
            ("strict uppercase", &BASE16_UPPER, b"DEADBEEF"),
        ];

        for &(name, decode, encoded) in decoders {
            let mut dst = [b'!'; 6];
            assert_eq!(
                decode.try_decode_into(encoded, &mut dst),
                Some([0xde, 0xad, 0xbe, 0xef].as_slice()),
                "{name}",
            );
            assert_eq!(&dst[4..], b"!!", "{name}");
        }

        let mut untouched = [b'x'; 1];
        let decoded = BASE16_MIXED.try_decode_into(b"", &mut untouched).unwrap();
        assert!(decoded.is_empty());
        assert_eq!(untouched, [b'x']);
    }

    #[test]
    fn slice_decoders_reject_bad_alignment_alphabet_case_and_capacity() {
        let mut dst = [0; 4];

        assert_eq!(BASE16_MIXED.try_decode_into(b"0", &mut dst), None);
        assert_eq!(BASE16_MIXED.try_decode_into(b"gg", &mut dst), None);
        assert_eq!(BASE16_LOWER.try_decode_into(b"FF", &mut dst), None);
        assert_eq!(BASE16_UPPER.try_decode_into(b"ff", &mut dst), None);

        let mut short = [0; 3];
        assert_eq!(BASE16_MIXED.try_decode_into(b"deadbeef", &mut short), None);
    }

    #[test]
    fn slice_decoders_cover_every_output_byte() {
        let mut input = [0u8; 256];
        for (byte, value) in input.iter_mut().zip(u8::MIN..=u8::MAX) {
            *byte = value;
        }

        let mut lower = [0; 512];
        let lower = super::super::enc::BASE16_LOWER
            .encode_into(&input, &mut lower)
            .unwrap();
        let mut decoded = [0; 256];
        assert_eq!(
            BASE16_MIXED.try_decode_into(lower, &mut decoded),
            Some(input.as_slice()),
        );
        assert_eq!(
            BASE16_LOWER.try_decode_into(lower, &mut decoded),
            Some(input.as_slice()),
        );

        let mut upper = [0; 512];
        let upper = super::super::enc::BASE16_UPPER
            .encode_into(&input, &mut upper)
            .unwrap();
        assert_eq!(
            BASE16_MIXED.try_decode_into(upper, &mut decoded),
            Some(input.as_slice()),
        );
        assert_eq!(
            BASE16_UPPER.try_decode_into(upper, &mut decoded),
            Some(input.as_slice()),
        );
    }

    #[test]
    fn tables_preserve_unsafe_indexing_invariants() {
        fn assert_invariants(decoder: &Decoder<'_>, alphabets: &[&[u8]]) {
            for alphabet in alphabets {
                for (digit, &ascii) in alphabet.iter().enumerate() {
                    let ascii = ascii as usize;
                    assert!((decoder.min_ascii..decoder.max_ascii).contains(&ascii));

                    let offset = ascii - decoder.min_ascii;
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

    #[cfg(feature = "alloc")]
    #[test]
    fn arbitrary_byte_slices_roundtrip_through_the_matching_decoders() {
        for len in 0usize..=64 {
            let input: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(73).wrapping_add(len * 19)) as u8)
                .collect();

            let lower = super::super::enc::BASE16_LOWER.encode_boxed(&input);
            assert_eq!(
                BASE16_MIXED.try_decode_boxed(&lower).as_deref(),
                Some(input.as_slice())
            );
            assert_eq!(
                BASE16_LOWER.try_decode_boxed(&lower).as_deref(),
                Some(input.as_slice())
            );

            let upper = super::super::enc::BASE16_UPPER.encode_boxed(&input);
            assert_eq!(
                BASE16_MIXED.try_decode_boxed(&upper).as_deref(),
                Some(input.as_slice())
            );
            assert_eq!(
                BASE16_UPPER.try_decode_boxed(&upper).as_deref(),
                Some(input.as_slice())
            );
        }
    }
}

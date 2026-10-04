// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
//! Strict and extended Base64 and Base64URL decoders.
//!
//! Strict decoding accepts one canonical padded value. Extended decoding also
//! accepts canonical unpadded final quanta, concatenated padded values, and
//! padding-only quanta.
//!
//! ```rust
//! use b2t_codecs::base64::{try_decode_from_base64, try_decode_from_base64ext};
//!
//! let mut strict = [0; 1];
//! let mut extended = [0; 1];
//!
//! assert_eq!(
//!     try_decode_from_base64(b"Zg==", &mut strict),
//!     Some(b"f".as_slice()),
//! );
//! assert_eq!(
//!     try_decode_from_base64ext(b"Zg", &mut extended),
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

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec};

/// Decodes a canonical padded Base64 string.
///
/// Returns [`None`] unless `base64` uses the standard RFC 4648 alphabet,
/// complete four-symbol quanta, terminal padding, and zero pad bits.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base64_string(base64: &str) -> Option<Box<[u8]>> {
    BASE64_RFC.try_decode_strict_string(base64)
}

/// Decodes a Base64 string using extended framing.
///
/// Padded quanta may be concatenated, padding-only quanta are ignored, and the
/// final quantum may omit padding. Returns [`None`] for an invalid alphabet,
/// malformed padding, non-zero pad bits, or a one-symbol tail.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base64ext_string(base64: &str) -> Option<Box<[u8]>> {
    BASE64_RFC.try_decode_extended_string(base64)
}

/// Decodes canonical padded Base64 ASCII bytes.
///
/// Returns [`None`] unless `base64` uses the standard RFC 4648 alphabet,
/// complete four-symbol quanta, terminal padding, and zero pad bits.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base64(base64: &[u8]) -> Option<Box<[u8]>> {
    BASE64_RFC.try_decode_strict_boxed(base64)
}

/// Decodes Base64 ASCII bytes using extended framing.
///
/// Padded quanta may be concatenated, padding-only quanta are ignored, and the
/// final quantum may omit padding. Returns [`None`] for an invalid alphabet,
/// malformed padding, non-zero pad bits, or a one-symbol tail.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base64ext(base64: &[u8]) -> Option<Box<[u8]>> {
    BASE64_RFC.try_decode_extended_boxed(base64)
}

/// Decodes a canonical padded Base64URL string.
///
/// Returns [`None`] unless `base64` uses the RFC 4648 URL-safe alphabet,
/// complete four-symbol quanta, terminal padding, and zero pad bits.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base64url_string(base64: &str) -> Option<Box<[u8]>> {
    BASE64_URL.try_decode_strict_string(base64)
}

/// Decodes a Base64URL string using extended framing.
///
/// Padded quanta may be concatenated, padding-only quanta are ignored, and the
/// final quantum may omit padding. Returns [`None`] for an invalid URL-safe
/// alphabet, malformed padding, non-zero pad bits, or a one-symbol tail.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base64urlext_string(base64: &str) -> Option<Box<[u8]>> {
    BASE64_URL.try_decode_extended_string(base64)
}

/// Decodes canonical padded Base64URL ASCII bytes.
///
/// Returns [`None`] unless `base64` uses the RFC 4648 URL-safe alphabet,
/// complete four-symbol quanta, terminal padding, and zero pad bits.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base64url(base64: &[u8]) -> Option<Box<[u8]>> {
    BASE64_URL.try_decode_strict_boxed(base64)
}

/// Decodes Base64URL ASCII bytes using extended framing.
///
/// Padded quanta may be concatenated, padding-only quanta are ignored, and the
/// final quantum may omit padding. Returns [`None`] for an invalid URL-safe
/// alphabet, malformed padding, non-zero pad bits, or a one-symbol tail.
#[cfg(feature = "alloc")]
#[must_use = "the decoding result should be handled"]
#[inline]
pub fn try_decode_base64urlext(base64: &[u8]) -> Option<Box<[u8]>> {
    BASE64_URL.try_decode_extended_boxed(base64)
}

/// Decodes canonical padded Base64 ASCII from `src` into the beginning of
/// `dst`.
///
/// Returns the initialized prefix of `dst`, or [`None`] if `src` is malformed,
/// non-canonical, or `dst` is shorter than
/// [`decoded_length_base64(src)`](decoded_length_base64). A short destination
/// is left unchanged. This function does not allocate.
///
/// If decoding returns [`None`] because of invalid input, `dst` may have been
/// partially modified.
#[must_use = "the decoded slice should be used"]
#[inline]
pub fn try_decode_from_base64<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    BASE64_RFC.try_decode_strict_into(src, dst)
}

/// Decodes canonical padded Base64URL ASCII from `src` into the beginning of
/// `dst`.
///
/// Returns the initialized prefix of `dst`, or [`None`] if `src` is malformed,
/// non-canonical, or `dst` is shorter than
/// [`decoded_length_base64(src)`](decoded_length_base64). A short destination
/// is left unchanged. This function does not allocate.
///
/// If decoding returns [`None`] because of invalid input, `dst` may have been
/// partially modified.
#[must_use = "the decoded slice should be used"]
#[inline]
pub fn try_decode_from_base64url<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    BASE64_URL.try_decode_strict_into(src, dst)
}

/// Decodes Base64 ASCII from `src` into `dst` using extended framing.
///
/// `dst` must be at least
/// [`decoded_length_base64ext(src)`](decoded_length_base64ext) bytes long, even
/// when the actual output is shorter; otherwise this returns [`None`] without
/// modifying `dst`.
///
/// Padded quanta may be concatenated, padding-only quanta are ignored, and the
/// final quantum may omit padding. Returns the initialized prefix of `dst`, or
/// [`None`] for invalid input. This function does not allocate.
///
/// If decoding returns [`None`] because of invalid input, `dst` may have been
/// partially modified.
#[must_use = "the decoded slice should be used"]
#[inline]
pub fn try_decode_from_base64ext<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    BASE64_RFC.try_decode_extended_into(src, dst)
}

/// Decodes Base64URL ASCII from `src` into `dst` using extended framing.
///
/// `dst` must be at least
/// [`decoded_length_base64ext(src)`](decoded_length_base64ext) bytes long, even
/// when the actual output is shorter; otherwise this returns [`None`] without
/// modifying `dst`.
///
/// Padded quanta may be concatenated, padding-only quanta are ignored, and the
/// final quantum may omit padding. Returns the initialized prefix of `dst`, or
/// [`None`] for invalid input. This function does not allocate.
///
/// If decoding returns [`None`] because of invalid input, `dst` may have been
/// partially modified.
#[must_use = "the decoded slice should be used"]
#[inline]
pub fn try_decode_from_base64urlext<'a>(src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
    BASE64_URL.try_decode_extended_into(src, dst)
}

/// Returns the exact decoded length of a padded Base64 slice.
///
/// Returns [`None`] unless `src` contains complete four-symbol quanta and its
/// trailing padding length is valid for canonical Base64. This function does
/// not validate the alphabet, pad bits, or padding outside the final quantum.
#[must_use = "the decoded size should be used"]
#[inline]
pub fn decoded_length_base64(src: &[u8]) -> Option<usize> {
    decoded_length(src)
}

#[inline]
fn decoded_length(src: &[u8]) -> Option<usize> {
    let len = src.len();
    if !len.is_multiple_of(4) {
        return None;
    }

    let decoded_len = (len / 4) * 3;
    let tail_shortfall = match count_tail_padding(src) {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => return None,
    };

    Some(decoded_len - tail_shortfall)
}

/// Returns the destination capacity required by the extended slice decoders.
///
/// Every complete four-symbol quantum is counted as three output bytes, while
/// a final unpadded two- or three-symbol quantum is counted as one or two bytes.
/// Returns [`None`] for a one-symbol final quantum. This constant-time upper
/// bound does not inspect `src`, so padded and padding-only quanta can make it
/// larger than the actual decoded output. It also does not validate the
/// alphabet, pad bits, or padding placement.
#[must_use = "the decoded size should be used"]
#[inline]
pub fn decoded_length_base64ext(src: &[u8]) -> Option<usize> {
    decoded_length_extended(src)
}

#[inline]
fn decoded_length_extended(src: &[u8]) -> Option<usize> {
    let tail_len = match src.len() % 4 {
        0 => 0,
        1 => return None,
        2 => 1,
        3 => 2,
        _ => unreachable!("a four-symbol remainder is impossible"),
    };

    Some(src.len() / 4 * 3 + tail_len)
}

#[inline]
fn count_tail_padding(src: &[u8]) -> usize {
    src.iter()
        .rev()
        .take(4)
        .take_while(|&&byte| byte == BASE64_PAD)
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
    fn try_decode_strict_string(&self, base64: &str) -> Option<Box<[u8]>> {
        self.try_decode_strict_boxed(base64.as_bytes())
    }

    #[cfg(feature = "alloc")]
    #[inline]
    fn try_decode_extended_string(&self, base64: &str) -> Option<Box<[u8]>> {
        self.try_decode_extended_boxed(base64.as_bytes())
    }

    #[cfg(feature = "alloc")]
    fn try_decode_strict_boxed(&self, base64: &[u8]) -> Option<Box<[u8]>> {
        if base64.is_empty() {
            return Some(Vec::<u8>::new().into_boxed_slice());
        }

        let payload_len = decoded_length(base64)?;
        let (chunks, []) = base64.as_chunks::<4>() else {
            unreachable!("decoded_length_base64 requires complete four-symbol quanta")
        };
        let (tail, chunks) = chunks.split_last().unwrap();

        let mut dst = Box::<[u8]>::new_uninit_slice(payload_len);
        let mut written = 0usize;

        // Padding characters are malformed before the final quantum.
        for &chunk in chunks {
            let chunk = self.decode_base64_full_chunk(chunk)?;
            dst[written..written + 3].write_copy_of_slice(&chunk);
            written += 3;
        }

        match count_tail_padding(tail) {
            2 => {
                let byte = self.decode_base64_two_pads(*tail)?;
                dst[written].write(byte);
                written += 1;
            }
            1 => {
                let chunk = self.decode_base64_one_pad(*tail)?;
                dst[written..written + 2].write_copy_of_slice(&chunk);
                written += 2;
            }
            0 => {
                let chunk = self.decode_base64_full_chunk(*tail)?;
                dst[written..written + 3].write_copy_of_slice(&chunk);
                written += 3;
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

    #[cfg(feature = "alloc")]
    fn try_decode_extended_boxed(&self, base64: &[u8]) -> Option<Box<[u8]>> {
        if base64.is_empty() {
            return Some(Vec::<u8>::new().into_boxed_slice());
        }

        let payload_capacity = decoded_length_extended(base64)?;
        let mut dst = Vec::<u8>::with_capacity(payload_capacity);
        let (chunks, rem) = base64.as_chunks::<4>();

        for &chunk in chunks {
            let (chunk, len) = self.decode_base64_extended_chunk(chunk)?;
            dst.extend_from_slice(&chunk[..len]);
        }

        if !rem.is_empty() {
            let (chunk, len) = self.decode_base64_unpadded_tail(rem)?;
            dst.extend_from_slice(&chunk[..len]);
        }

        // INVARIANT: every complete quantum emits at most three bytes and the
        // optional unpadded tail emits at most two bytes.
        assert!(dst.len() <= payload_capacity);
        Some(dst.into_boxed_slice())
    }

    fn try_decode_strict_into<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
        if src.is_empty() {
            return Some(&dst[..0]);
        }

        let payload_len = decoded_length(src)?;
        if dst.len() < payload_len {
            return None;
        }

        let (chunks, []) = src.as_chunks::<4>() else {
            unreachable!("decoded_length_base64 requires complete four-symbol quanta")
        };
        let (tail, chunks) = chunks.split_last().unwrap();
        let mut written = 0usize;

        // Padding characters are malformed before the final quantum.
        for &chunk in chunks {
            let chunk = self.decode_base64_full_chunk(chunk)?;
            dst[written..written + 3].copy_from_slice(&chunk);
            written += 3;
        }

        match count_tail_padding(tail) {
            2 => {
                dst[written] = self.decode_base64_two_pads(*tail)?;
                written += 1;
            }
            1 => {
                let chunk = self.decode_base64_one_pad(*tail)?;
                dst[written..written + 2].copy_from_slice(&chunk);
                written += 2;
            }
            0 => {
                let chunk = self.decode_base64_full_chunk(*tail)?;
                dst[written..written + 3].copy_from_slice(&chunk);
                written += 3;
            }
            _ => unreachable!("the padding length was validated before decoding"),
        }

        // INVARIANT: successful decoding writes exactly `payload_len` bytes.
        assert!(written == payload_len);
        Some(&dst[..written])
    }

    fn try_decode_extended_into<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> Option<&'a [u8]> {
        if src.is_empty() {
            return Some(&dst[..0]);
        }

        let payload_capacity = decoded_length_extended(src)?;
        if dst.len() < payload_capacity {
            return None;
        }

        let (chunks, rem) = src.as_chunks::<4>();
        let mut written = 0usize;

        for &chunk in chunks {
            let (chunk, len) = self.decode_base64_extended_chunk(chunk)?;
            dst[written..written + len].copy_from_slice(&chunk[..len]);
            written += len;
        }

        if !rem.is_empty() {
            let (chunk, len) = self.decode_base64_unpadded_tail(rem)?;
            dst[written..written + len].copy_from_slice(&chunk[..len]);
            written += len;
        }

        // INVARIANT: every complete quantum emits at most three bytes and the
        // optional unpadded tail emits at most two bytes.
        assert!(written <= payload_capacity);
        Some(&dst[..written])
    }

    fn decode_base64_extended_chunk(&self, chunk: [u8; 4]) -> Option<([u8; 3], usize)> {
        match count_tail_padding(&chunk) {
            4 => Some(([0; 3], 0)),
            2 => {
                let byte = self.decode_base64_two_pads(chunk)?;
                Some(([byte, 0, 0], 1))
            }
            1 => {
                let [on, tw] = self.decode_base64_one_pad(chunk)?;
                Some(([on, tw, 0], 2))
            }
            0 => Some((self.decode_base64_full_chunk(chunk)?, 3)),
            _ => None,
        }
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

    // Unpadded tail length 2 OR 3, returning a fixed buffer and used length.
    fn decode_base64_unpadded_tail(&self, tail: &[u8]) -> Option<([u8; 2], usize)> {
        let mut buf = [BASE64_PAD; 4];
        buf[..tail.len()].copy_from_slice(tail);
        match tail.len() {
            2 => Some(([self.decode_base64_two_pads(buf)?, 0], 1)),
            3 => Some((self.decode_base64_one_pad(buf)?, 2)),
            _ => unreachable!("tail length must be 2 or 3"),
        }
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
    use super::super::enc;
    use super::super::{ENCODER, ENCODER_URL};
    use super::{BASE64_RFC, BASE64_URL, Decoder, decoded_length, decoded_length_extended};

    #[cfg(feature = "alloc")]
    use super::BASE64_PAD;

    #[cfg(feature = "alloc")]
    use alloc::{boxed::Box, vec::Vec};

    #[cfg(feature = "alloc")]
    type Decode = fn(&Decoder<'static>, &[u8]) -> Option<Box<[u8]>>;
    type DecodeInto = for<'a> fn(&Decoder<'static>, &[u8], &'a mut [u8]) -> Option<&'a [u8]>;

    const RFC_4648_VECTORS: &[(&[u8], &str)] = &[
        (b"", ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
    ];

    const ALPHABET_VECTORS: &[(&[u8], &str, &str)] = &[
        (&[0xfb], "+w==", "-w=="),
        (&[0xfb, 0xff], "+/8=", "-_8="),
        (&[0xfb, 0xff, 0xff], "+///", "-___"),
    ];

    #[cfg(feature = "alloc")]
    fn strict_decoders() -> [(&'static str, &'static Decoder<'static>); 2] {
        [
            ("Base64 strict", &BASE64_RFC),
            ("Base64URL strict", &BASE64_URL),
        ]
    }

    #[cfg(feature = "alloc")]
    fn extended_decoders() -> [(&'static str, &'static Decoder<'static>); 2] {
        [
            ("Base64 extended", &BASE64_RFC),
            ("Base64URL extended", &BASE64_URL),
        ]
    }

    #[cfg(feature = "alloc")]
    fn all_decoders() -> [(&'static str, &'static Decoder<'static>, Decode); 4] {
        [
            (
                "Base64 strict",
                &BASE64_RFC,
                Decoder::try_decode_strict_boxed,
            ),
            (
                "Base64 extended",
                &BASE64_RFC,
                Decoder::try_decode_extended_boxed,
            ),
            (
                "Base64URL strict",
                &BASE64_URL,
                Decoder::try_decode_strict_boxed,
            ),
            (
                "Base64URL extended",
                &BASE64_URL,
                Decoder::try_decode_extended_boxed,
            ),
        ]
    }

    fn strict_decoders_into() -> [(&'static str, &'static Decoder<'static>); 2] {
        [
            ("Base64 strict", &BASE64_RFC),
            ("Base64URL strict", &BASE64_URL),
        ]
    }

    fn extended_decoders_into() -> [(&'static str, &'static Decoder<'static>); 2] {
        [
            ("Base64 extended", &BASE64_RFC),
            ("Base64URL extended", &BASE64_URL),
        ]
    }

    fn all_decoders_into() -> [(&'static str, &'static Decoder<'static>, DecodeInto); 4] {
        [
            (
                "Base64 strict",
                &BASE64_RFC,
                Decoder::try_decode_strict_into,
            ),
            (
                "Base64 extended",
                &BASE64_RFC,
                Decoder::try_decode_extended_into,
            ),
            (
                "Base64URL strict",
                &BASE64_URL,
                Decoder::try_decode_strict_into,
            ),
            (
                "Base64URL extended",
                &BASE64_URL,
                Decoder::try_decode_extended_into,
            ),
        ]
    }

    #[test]
    fn decoded_lengths_are_exact_for_strict_framing() {
        assert_eq!(decoded_length(b""), Some(0));
        assert_eq!(decoded_length(b"A"), None);
        assert_eq!(decoded_length(b"AAA"), None);
        assert_eq!(decoded_length(b"AAAA"), Some(3));
        assert_eq!(decoded_length(b"Zg=="), Some(1));
        assert_eq!(decoded_length(b"Zm8="), Some(2));
        assert_eq!(decoded_length(b"Zm9v"), Some(3));
        assert_eq!(decoded_length(b"Zm9vYg=="), Some(4));
        assert_eq!(decoded_length(b"A==="), None);
        assert_eq!(decoded_length(b"===="), None);
    }

    #[test]
    fn decoded_lengths_are_upper_bounds_for_extended_framing() {
        assert_eq!(decoded_length_extended(b""), Some(0));
        assert_eq!(decoded_length_extended(b"A"), None);
        assert_eq!(decoded_length_extended(b"AA"), Some(1));
        assert_eq!(decoded_length_extended(b"AAA"), Some(2));
        assert_eq!(decoded_length_extended(b"AAAA"), Some(3));
        assert_eq!(decoded_length_extended(b"Zg=="), Some(3));
        assert_eq!(decoded_length_extended(b"Zm8="), Some(3));
        assert_eq!(decoded_length_extended(b"===="), Some(3));
        assert_eq!(decoded_length_extended(b"TQ==TWE="), Some(6));
        assert_eq!(decoded_length_extended(b"TQ======TQ=="), Some(9));
        assert_eq!(decoded_length_extended(b"AAAAAA"), Some(4));
        assert_eq!(decoded_length_extended(b"AAAAAAA"), Some(5));
        assert_eq!(decoded_length_extended(b"AAAAA"), None);
    }

    #[test]
    fn rfc_vectors_decode_through_non_allocating_paths() {
        for &(plain, encoded) in RFC_4648_VECTORS {
            let mut dst = [0u8; 6];
            assert_eq!(
                BASE64_RFC.try_decode_strict_into(encoded.as_bytes(), &mut dst),
                Some(plain),
            );

            let mut dst = [0u8; 6];
            assert_eq!(
                BASE64_RFC.try_decode_extended_into(encoded.as_bytes(), &mut dst),
                Some(plain),
            );

            let mut dst = [0u8; 6];
            assert_eq!(
                BASE64_URL.try_decode_strict_into(encoded.as_bytes(), &mut dst),
                Some(plain),
            );

            let mut dst = [0u8; 6];
            assert_eq!(
                BASE64_URL.try_decode_extended_into(encoded.as_bytes(), &mut dst),
                Some(plain),
            );
        }
    }

    #[test]
    fn non_allocating_decoders_select_the_requested_alphabet() {
        for &(plain, base64, base64url) in ALPHABET_VECTORS {
            let mut dst = [0u8; 3];
            assert_eq!(
                BASE64_RFC.try_decode_strict_into(base64.as_bytes(), &mut dst),
                Some(plain),
            );
            assert_eq!(
                BASE64_RFC.try_decode_strict_into(base64url.as_bytes(), &mut dst),
                None,
            );

            let mut dst = [0u8; 3];
            assert_eq!(
                BASE64_URL.try_decode_strict_into(base64url.as_bytes(), &mut dst),
                Some(plain),
            );
            assert_eq!(
                BASE64_URL.try_decode_strict_into(base64.as_bytes(), &mut dst),
                None,
            );

            let mut dst = [0u8; 3];
            assert_eq!(
                BASE64_RFC.try_decode_extended_into(base64.as_bytes(), &mut dst),
                Some(plain),
            );
            assert_eq!(
                BASE64_RFC.try_decode_extended_into(base64url.as_bytes(), &mut dst),
                None,
            );

            let mut dst = [0u8; 3];
            assert_eq!(
                BASE64_URL.try_decode_extended_into(base64url.as_bytes(), &mut dst),
                Some(plain),
            );
            assert_eq!(
                BASE64_URL.try_decode_extended_into(base64.as_bytes(), &mut dst),
                None,
            );
        }
    }

    #[test]
    fn non_allocating_decoders_preserve_destination_bounds() {
        for (name, decoder, decode) in all_decoders_into() {
            let mut short = [0xa5; 5];
            assert_eq!(decode(decoder, b"Zm9vYmFy", &mut short), None, "{name}");
            assert_eq!(short, [0xa5; 5], "{name} modified a short destination");

            let mut oversized = [0xa5; 8];
            assert_eq!(
                decode(decoder, b"Zm9vYmFy", &mut oversized),
                Some(b"foobar".as_slice()),
                "{name}",
            );
            assert_eq!(
                &oversized[6..],
                &[0xa5; 2],
                "{name} modified the destination suffix",
            );

            assert_eq!(
                decode(decoder, b"", &mut oversized),
                Some([].as_slice()),
                "{name}"
            );
        }

        for (name, decoder) in extended_decoders_into() {
            let mut padded_exact = [0xa5; 1];
            assert_eq!(
                decoder.try_decode_extended_into(b"TQ==", &mut padded_exact),
                None,
                "{name}"
            );
            assert_eq!(
                padded_exact, [0xa5; 1],
                "{name} modified a destination shorter than the upper bound",
            );

            let mut padding_only_exact = [0u8; 0];
            assert_eq!(
                decoder.try_decode_extended_into(b"====", &mut padding_only_exact),
                None,
                "{name}"
            );

            let mut exact = [0xa5; 2];
            assert_eq!(
                decoder.try_decode_extended_into(b"TQ==TQ==", &mut exact),
                None,
                "{name}"
            );
            assert_eq!(
                exact, [0xa5; 2],
                "{name} modified a destination shorter than the upper bound",
            );

            let mut upper_bound = [0xa5; 6];
            assert_eq!(
                decoder.try_decode_extended_into(b"TQ==TQ==", &mut upper_bound),
                Some(b"MM".as_slice()),
                "{name}",
            );
            assert_eq!(&upper_bound[2..], &[0xa5; 4]);
        }
    }

    #[test]
    fn non_allocating_decoders_reject_noncanonical_inputs() {
        for (name, decoder, decode) in all_decoders_into() {
            let mut dst = [0u8; 3];
            assert_eq!(
                decode(decoder, b"TQ==", &mut dst),
                Some(b"M".as_slice()),
                "{name}"
            );
            assert_eq!(
                decode(decoder, b"TR==", &mut dst),
                None,
                "{name} accepted pad bits"
            );
            assert_eq!(
                decode(decoder, b"TWE=", &mut dst),
                Some(b"Ma".as_slice()),
                "{name}"
            );
            assert_eq!(
                decode(decoder, b"TWF=", &mut dst),
                None,
                "{name} accepted pad bits"
            );
        }

        // Six bytes satisfies `decoded_length` for each padded input below
        // (4, 5, 4 and 6), so only strict framing can reject them; extended
        // framing would decode them as "MM", "MaMa", "M" and "M\0\0\0".
        for (name, decoder) in strict_decoders_into() {
            let mut dst = [0u8; 6];
            for input in [
                b"A".as_slice(),
                b"Zg".as_slice(),
                b"Zm8".as_slice(),
                b"TQ==TQ==".as_slice(),
                b"TWE=TWE=".as_slice(),
                b"====TQ==".as_slice(),
                b"TQ==AAAA".as_slice(),
            ] {
                assert_eq!(
                    decoder.try_decode_strict_into(input, &mut dst),
                    None,
                    "{name} accepted {input:?}"
                );
            }
        }

        for (name, decoder) in extended_decoders_into() {
            let mut dst = [0u8; 3];
            assert_eq!(
                decoder.try_decode_extended_into(b"TQ", &mut dst),
                Some(b"M".as_slice()),
                "{name}"
            );
            assert_eq!(
                decoder.try_decode_extended_into(b"TR", &mut dst),
                None,
                "{name} accepted pad bits"
            );
            assert_eq!(
                decoder.try_decode_extended_into(b"TWE", &mut dst),
                Some(b"Ma".as_slice()),
                "{name}"
            );
            assert_eq!(
                decoder.try_decode_extended_into(b"TWF", &mut dst),
                None,
                "{name} accepted pad bits"
            );
        }
    }

    #[test]
    fn extended_slice_decoders_preserve_extended_framing() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"Zg", b"f"),
            (b"Zm8", b"fo"),
            (b"====", b""),
            (b"========", b""),
            (b"TQ==TWE=", b"MMa"),
            (b"TQ======TQ==", b"MM"),
            (b"Zm9vYg", b"foob"),
            (b"Zm9vYmE", b"fooba"),
            (b"TQ==Zg", b"Mf"),
            (b"====Zm8", b"fo"),
        ];

        for (name, decoder) in extended_decoders_into() {
            for &(input, expected) in cases {
                let mut dst = [0xa5; 9];
                assert_eq!(
                    decoder.try_decode_extended_into(input, &mut dst),
                    Some(expected),
                    "{name}: {input:?}"
                );
                assert_eq!(
                    &dst[expected.len()..],
                    &[0xa5; 9][expected.len()..],
                    "{name} modified the suffix for {input:?}",
                );
            }

            let mut dst = [0u8; 4];
            for input in [
                b"A".as_slice(),
                b"AAAAA".as_slice(),
                b"=AAA".as_slice(),
                b"A=AA".as_slice(),
                b"AA=A".as_slice(),
                b"A===".as_slice(),
                b"===A".as_slice(),
                b"AA=".as_slice(),
                b"===".as_slice(),
                b"A==".as_slice(),
            ] {
                assert_eq!(
                    decoder.try_decode_extended_into(input, &mut dst),
                    None,
                    "{name} accepted {input:?}"
                );
            }
        }
    }

    #[test]
    fn arbitrary_byte_slices_roundtrip_through_non_allocating_codecs() {
        let codecs = [
            ("Base64", &enc::BASE64_RFC, &BASE64_RFC),
            ("Base64URL", &enc::BASE64_URL, &BASE64_URL),
        ];

        let mut input = [0u8; 64];
        let mut encoded = [0u8; 88];
        let mut decoded = [0u8; 66];

        for len in 0usize..=input.len() {
            for (i, byte) in input[..len].iter_mut().enumerate() {
                *byte = (i.wrapping_mul(73).wrapping_add(len * 19)) as u8;
            }

            for (name, encoder, decoder) in codecs {
                let encoded = encoder.encode_into(&input[..len], &mut encoded).unwrap();
                assert_eq!(
                    decoder.try_decode_strict_into(encoded, &mut decoded),
                    Some(&input[..len]),
                    "{name} strict failed to roundtrip {len} data bytes",
                );
                assert_eq!(
                    decoder.try_decode_extended_into(encoded, &mut decoded),
                    Some(&input[..len]),
                    "{name} extended failed to roundtrip {len} data bytes",
                );
            }
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn rfc_4648_base64_test_vectors_pin_decoding() {
        for &(plain, encoded) in RFC_4648_VECTORS {
            assert_eq!(
                BASE64_RFC
                    .try_decode_strict_boxed(encoded.as_bytes())
                    .as_deref(),
                Some(plain)
            );
            assert_eq!(
                BASE64_RFC
                    .try_decode_extended_boxed(encoded.as_bytes())
                    .as_deref(),
                Some(plain)
            );

            // These RFC vectors do not use alphabet digits 62 or 63, so they
            // are valid under the Base64URL alphabet as well.
            assert_eq!(
                BASE64_URL
                    .try_decode_strict_boxed(encoded.as_bytes())
                    .as_deref(),
                Some(plain)
            );
            assert_eq!(
                BASE64_URL
                    .try_decode_extended_boxed(encoded.as_bytes())
                    .as_deref(),
                Some(plain)
            );
        }
    }

    #[test]
    fn tables_preserve_unsafe_indexing_invariants() {
        fn assert_invariants(decoder: &Decoder<'_>, encoder: &[u8]) {
            let mut seen = [false; 80];
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

    #[cfg(feature = "alloc")]
    #[test]
    fn byte_slices_of_arbitrary_lengths_roundtrip_through_every_decoder() {
        for len in 0usize..=64 {
            let input: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(73).wrapping_add(len * 19)) as u8)
                .collect();

            let base64 = enc::BASE64_RFC.encode_boxed(&input);
            assert_eq!(
                BASE64_RFC.try_decode_strict_boxed(&base64).as_deref(),
                Some(input.as_slice()),
                "Base64 strict failed to roundtrip {len} data bytes"
            );
            assert_eq!(
                BASE64_RFC.try_decode_extended_boxed(&base64).as_deref(),
                Some(input.as_slice()),
                "Base64 extended failed to roundtrip {len} data bytes"
            );

            let base64url = enc::BASE64_URL.encode_boxed(&input);
            assert_eq!(
                BASE64_URL.try_decode_strict_boxed(&base64url).as_deref(),
                Some(input.as_slice()),
                "Base64URL strict failed to roundtrip {len} data bytes"
            );
            assert_eq!(
                BASE64_URL.try_decode_extended_boxed(&base64url).as_deref(),
                Some(input.as_slice()),
                "Base64URL extended failed to roundtrip {len} data bytes"
            );
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn strict_decode_requires_complete_quanta() {
        for (name, decoder) in strict_decoders() {
            for input in [
                b"A".as_slice(),
                b"Zg".as_slice(),
                b"Zm8".as_slice(),
                b"AAAAA".as_slice(),
                b"AAAAAA".as_slice(),
                b"AAAAAAA".as_slice(),
            ] {
                assert_eq!(
                    decoder.try_decode_strict_boxed(input),
                    None,
                    "{name} accepted {input:?}"
                );
            }
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn every_decoder_rejects_non_zero_pad_bit_aliases() {
        let padded: &[(&str, &str, &[u8])] = &[("TQ==", "TR==", b"M"), ("TWE=", "TWF=", b"Ma")];

        for (name, decoder, decode) in all_decoders() {
            for &(canonical, alias, plain) in padded {
                assert_eq!(
                    decode(decoder, canonical.as_bytes()).as_deref(),
                    Some(plain),
                    "{name} rejected canonical {canonical:?}"
                );
                assert_eq!(
                    decode(decoder, alias.as_bytes()),
                    None,
                    "{name} accepted alias {alias:?}"
                );
            }
        }

        let unpadded: &[(&str, &str, &[u8])] = &[("TQ", "TR", b"M"), ("TWE", "TWF", b"Ma")];
        for (name, decoder) in extended_decoders() {
            for &(canonical, alias, plain) in unpadded {
                assert_eq!(
                    decoder
                        .try_decode_extended_boxed(canonical.as_bytes())
                        .as_deref(),
                    Some(plain),
                    "{name} rejected canonical {canonical:?}"
                );
                assert_eq!(
                    decoder.try_decode_extended_boxed(alias.as_bytes()),
                    None,
                    "{name} accepted alias {alias:?}"
                );
            }
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn strict_decode_rejects_non_terminal_or_malformed_padding() {
        for (name, decoder) in strict_decoders() {
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
                assert_eq!(
                    decoder.try_decode_strict_boxed(input),
                    None,
                    "{name} accepted {input:?}"
                );
            }
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn extended_decode_accepts_supported_framing() {
        let cases: &[(&str, &[u8], &[u8])] = &[
            ("unpadded final quantum", b"Zg", b"f"),
            ("unpadded final quantum", b"Zm8", b"fo"),
            ("padding-only chunks", b"====", b""),
            ("padding-only chunks", b"========", b""),
            ("concatenated padded values", b"TQ==TQ==", b"MM"),
            ("concatenated padded values", b"TWE=TWE=", b"MaMa"),
            ("concatenated padded values", b"TQ======TQ==", b"MM"),
        ];

        for (name, decoder) in extended_decoders() {
            for &(category, input, expected) in cases {
                assert_eq!(
                    decoder.try_decode_extended_boxed(input).as_deref(),
                    Some(expected),
                    "{name} rejected {category} case {input:?}"
                );
            }
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn extended_decode_rejects_single_ascii_tails() {
        for (name, decoder) in extended_decoders() {
            for input in [
                b"A".as_slice(),
                b"AAAAA".as_slice(),
                b"AAAAAAAAA".as_slice(),
            ] {
                assert_eq!(
                    decoder.try_decode_extended_boxed(input),
                    None,
                    "{name} accepted {input:?}"
                );
            }
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn decoders_reject_every_non_alphabet_byte_in_any_frame() {
        fn assert_invalid_bytes_rejected(
            name: &str,
            decoder: &Decoder<'static>,
            decode: Decode,
            alphabet: &[u8],
        ) {
            for invalid in u8::MIN..=u8::MAX {
                if invalid == BASE64_PAD || alphabet.contains(&invalid) {
                    continue;
                }

                for position in 0..4 {
                    let mut input = *b"AAAA";
                    input[position] = invalid;
                    assert_eq!(
                        decode(decoder, &input),
                        None,
                        "{name} accepted byte {invalid:#04x} at position {position}"
                    );
                }

                let mut second_frame = *b"AAAAAAAA";
                second_frame[6] = invalid;
                assert_eq!(
                    decode(decoder, &second_frame),
                    None,
                    "{name} accepted byte {invalid:#04x} in a later frame"
                );
            }
        }

        assert_invalid_bytes_rejected(
            "Base64 strict",
            &BASE64_RFC,
            Decoder::try_decode_strict_boxed,
            &ENCODER,
        );
        assert_invalid_bytes_rejected(
            "Base64 extended",
            &BASE64_RFC,
            Decoder::try_decode_extended_boxed,
            &ENCODER,
        );
        assert_invalid_bytes_rejected(
            "Base64URL strict",
            &BASE64_URL,
            Decoder::try_decode_strict_boxed,
            &ENCODER_URL,
        );
        assert_invalid_bytes_rejected(
            "Base64URL extended",
            &BASE64_URL,
            Decoder::try_decode_extended_boxed,
            &ENCODER_URL,
        );
    }
}

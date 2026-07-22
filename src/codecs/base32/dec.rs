const BASE32_RFC: Decoder = const {
    use super::{DECODER, MAX_ASCII, MIN_ASCII};
    Decoder::from_table(&DECODER, MIN_ASCII, MAX_ASCII)
};
const BASE32_HEX: Decoder = const {
    use super::{DECODER_HEX, MAX_ASCII_HEX, MIN_ASCII_HEX};
    Decoder::from_table(&DECODER_HEX, MIN_ASCII_HEX, MAX_ASCII_HEX)
};

#[inline]
pub fn try_decode_base32_string(base32: &str) -> Option<Box<[u8]>> {
    BASE32_RFC.try_decode_base32_string(base32)
}

#[inline]
pub fn try_decode_base32(base32: &[u8]) -> Option<Box<[u8]>> {
    BASE32_RFC.try_decode_base32(base32)
}

#[inline]
pub fn try_decode_base32hex_string(base32: &str) -> Option<Box<[u8]>> {
    BASE32_HEX.try_decode_base32_string(base32)
}

#[inline]
pub fn try_decode_base32hex(base32: &[u8]) -> Option<Box<[u8]>> {
    BASE32_HEX.try_decode_base32(base32)
}

#[allow(dead_code)] // Fields are used by the pending core implementation.
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

    fn try_decode_base32(&self, _base32: &[u8]) -> Option<Box<[u8]>> {
        todo!()
    }
}

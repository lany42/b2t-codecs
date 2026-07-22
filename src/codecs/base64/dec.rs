use super::BASE64_PAD;

const BASE64_RFC: Decoder = const {
    use super::{DECODER, MAX_ASCII, MIN_ASCII};
    Decoder::from_table(&DECODER, MIN_ASCII, MAX_ASCII)
};
const BASE64_URL: Decoder = const {
    use super::{DECODER_URL, MAX_ASCII_URL, MIN_ASCII_URL};
    Decoder::from_table(&DECODER_URL, MIN_ASCII_URL, MAX_ASCII_URL)
};

#[inline]
pub fn try_decode_base64_string(base64: &str) -> Option<Box<[u8]>> {
    BASE64_RFC.try_decode_base64_string(base64)
}

#[inline]
pub fn try_decode_base64ext_string(base64: &str) -> Option<Box<[u8]>> {
    BASE64_RFC.try_decode_base64ext_string(base64)
}

#[inline]
pub fn try_decode_base64(base64: &[u8]) -> Option<Box<[u8]>> {
    BASE64_RFC.try_decode_base64(base64)
}

#[inline]
pub fn try_decode_base64ext(base64: &[u8]) -> Option<Box<[u8]>> {
    BASE64_RFC.try_decode_base64ext(base64)
}

#[inline]
pub fn try_decode_base64url_string(base64: &str) -> Option<Box<[u8]>> {
    BASE64_URL.try_decode_base64_string(base64)
}

#[inline]
pub fn try_decode_base64urlext_string(base64: &str) -> Option<Box<[u8]>> {
    BASE64_URL.try_decode_base64ext_string(base64)
}

#[inline]
pub fn try_decode_base64url(base64: &[u8]) -> Option<Box<[u8]>> {
    BASE64_URL.try_decode_base64(base64)
}

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

    // extended deocder supports:
    //  - unpadded tails
    //  - concatenated base64 strings
    //  - skips all-padding chunkks
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
            ret.extend_from_slice(&self.decode_base64_full_chunk(chunk)?)
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

        // Only the top two bits of the second sextet carry data.
        if tw & 0x0f != 0 {
            return None;
        }

        let n = on << 18 | tw << 12;

        // return one byte only: [0, x, _, _]
        Some((n >> 16) as u8)
    }

    // Three ASCII and one pad, returns two decoded bytes
    fn decode_base64_one_pad(&self, chunk: [u8; 4]) -> Option<[u8; 2]> {
        let [on, tw, th, _] = chunk;

        let on = self.check_and_decode_b64_byte(on)?;
        let tw = self.check_and_decode_b64_byte(tw)?;
        let th = self.check_and_decode_b64_byte(th)?;

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
        Some(byte as u32)
    }
}

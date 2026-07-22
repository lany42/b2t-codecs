use super::BASE64_PAD;

const BASE64_RFC: Encoder = const {
    use super::ENCODER;
    Encoder::from_alphabet(&ENCODER)
};
const BASE64_URL: Encoder = const {
    use super::ENCODER_URL;
    Encoder::from_alphabet(&ENCODER_URL)
};

#[inline]
pub fn encode_base64_string(bytes: &[u8]) -> String {
    BASE64_RFC.encode_base64_string(bytes)
}

#[inline]
pub fn encode_base64url_string(bytes: &[u8]) -> String {
    BASE64_URL.encode_base64_string(bytes)
}

#[inline]
pub fn encode_base64(bytes: &[u8]) -> Box<[u8]> {
    BASE64_RFC.encode_base64(bytes)
}

#[inline]
pub fn encode_base64url(bytes: &[u8]) -> Box<[u8]> {
    BASE64_URL.encode_base64(bytes)
}

struct Encoder<'e> {
    encoder: &'e [u8],
}

impl<'e> Encoder<'e> {
    #[inline]
    const fn from_alphabet(encoder: &'e [u8]) -> Self {
        // INVARIANT: encoder table MUST be exactly 64
        assert!(encoder.len() == 64);
        assert!(0x3f < encoder.len());
        Self { encoder }
    }

    #[inline]
    fn encode_base64_string(&self, bytes: &[u8]) -> String {
        let enc = self.encode_base64(bytes);
        // SAFETY: base64 bytes are ASCII, therefore always valid UTF-8
        unsafe { String::from_utf8_unchecked(enc.into_vec()) }
    }

    fn encode_base64(&self, bytes: &[u8]) -> Box<[u8]> {
        if bytes.is_empty() {
            return Vec::<u8>::new().into_boxed_slice();
        }

        // base64 encodes four ASCII bytes per three byte chunks
        // and at most four extra bytes for a padded tail
        let capacity = bytes
            .len()
            .checked_mul(4)
            .expect("base64 encoded length overflow")
            / 3
            + 4;

        let (chunks, remainder) = bytes.as_chunks::<3>();
        let mut ret = Vec::<u8>::with_capacity(capacity);

        for &chunk in chunks {
            ret.extend_from_slice(&self.encode_base64_full_chunk(chunk));
        }

        if !remainder.is_empty() {
            let chunk = self.encode_base64_tail(remainder);
            ret.extend_from_slice(&chunk);
        }

        ret.into_boxed_slice()
    }

    fn encode_base64_full_chunk(&self, chunk: [u8; 3]) -> [u8; 4] {
        // pack each byte into a u32
        let n = u32::from_be_bytes([0, chunk[0], chunk[1], chunk[2]]);

        // the four 6-bit sextets
        let on = n >> 18 & 0x3f; // Not required, but ensures safe indexing if n isn't initialized to zero.
        let tw = n >> 12 & 0x3f;
        let th = n >> 6 & 0x3f;
        let fo = n & 0x3f;

        // the four encoded bytes
        // SAFETY: six-bit sextet 3F is guaranteed to be on the range [0, 64)
        let on = unsafe { *self.encoder.get_unchecked(on as usize) };
        // SAFETY: six-bit sextet 3F is guaranteed to be on the range [0, 64)
        let tw = unsafe { *self.encoder.get_unchecked(tw as usize) };
        // SAFETY: six-bit sextet 3F is guaranteed to be on the range [0, 64)
        let th = unsafe { *self.encoder.get_unchecked(th as usize) };
        // SAFETY: six-bit sextet 3F is guaranteed to be on the range [0, 64)
        let fo = unsafe { *self.encoder.get_unchecked(fo as usize) };

        [on, tw, th, fo]
    }

    fn encode_base64_tail(&self, tail: &[u8]) -> [u8; 4] {
        // must be 1 or 2
        let len = tail.len();

        // pad with null bytes for encoding
        // "These pad bits MUST be set to zero by conforming encoders..."
        let mut padded = [0u8; 3];
        padded[..len].copy_from_slice(tail);
        let mut encoded = self.encode_base64_full_chunk(padded);

        // replace bytes in the encoded position with b'=' based on tail length
        //      - 1 byte  => two encoded bytes and two pad bytes
        //      - 2 bytes => three encoded bytes and single pad byte
        // That is, N_PAD_START = len + 1
        for b in encoded[len + 1..].iter_mut() {
            *b = BASE64_PAD;
        }

        encoded
    }
}

const BASE32_RFC: Encoder = const {
    use super::ENCODER;
    Encoder::from_alphabet(&ENCODER)
};
const BASE32_HEX: Encoder = const {
    use super::ENCODER_HEX;
    Encoder::from_alphabet(&ENCODER_HEX)
};

#[inline]
pub fn encode_base32_string(bytes: &[u8]) -> String {
    BASE32_RFC.encode_base32_string(bytes)
}

#[inline]
pub fn encode_base32hex_string(bytes: &[u8]) -> String {
    BASE32_HEX.encode_base32_string(bytes)
}

#[inline]
pub fn encode_base32(bytes: &[u8]) -> Box<[u8]> {
    BASE32_RFC.encode_base32(bytes)
}

#[inline]
pub fn encode_base32hex(bytes: &[u8]) -> Box<[u8]> {
    BASE32_HEX.encode_base32(bytes)
}

#[allow(dead_code)] // Fields are used by the pending core implementation.
struct Encoder<'e> {
    encoder: &'e [u8],
}

impl<'e> Encoder<'e> {
    #[inline]
    const fn from_alphabet(encoder: &'e [u8]) -> Self {
        // INVARIANT: encoder table MUST be exactly 32.
        assert!(encoder.len() == 32);
        assert!(0x1f < encoder.len());
        Self { encoder }
    }

    #[inline]
    fn encode_base32_string(&self, bytes: &[u8]) -> String {
        let encoded = self.encode_base32(bytes);
        // SAFETY: base32 bytes are ASCII, therefore always valid UTF-8.
        unsafe { String::from_utf8_unchecked(encoded.into_vec()) }
    }

    fn encode_base32(&self, _bytes: &[u8]) -> Box<[u8]> {
        todo!()
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>

use b2t_codecs::{
    Base32, Base32Hex, decoded_length_base32, encoded_length_base32, try_decode_from_base32,
    try_decode_from_base32hex, try_encode_into_base32, try_encode_into_base32hex,
};

#[test]
fn non_allocating_base32_api_is_reexported_from_the_crate_root() {
    assert_eq!(encoded_length_base32(&[0xab, 0xcd]), 8);
    assert_eq!(decoded_length_base32(b"VPGQ===="), Some(2));

    let mut base32 = [0; 8];
    let mut base32hex = [0; 8];
    assert_eq!(
        try_encode_into_base32(&[0xab, 0xcd], &mut base32),
        Some(b"VPGQ====".as_slice()),
    );
    assert_eq!(
        try_encode_into_base32hex(&[0xab, 0xcd], &mut base32hex),
        Some(b"LF6G====".as_slice()),
    );

    let mut decoded = [0; 2];
    assert_eq!(
        try_decode_from_base32(b"VPGQ====", &mut decoded),
        Some([0xab, 0xcd].as_slice()),
    );
    assert_eq!(
        try_decode_from_base32hex(b"LF6G====", &mut decoded),
        Some([0xab, 0xcd].as_slice()),
    );

    let mut primitive = [0; 8];
    assert_eq!(
        0xabcd_u16.try_as_base32_into(&mut primitive),
        Some(b"VPGQ====".as_slice()),
    );
    assert_eq!(
        0xabcd_u16.try_as_base32hex_into(&mut primitive),
        Some(b"LF6G====".as_slice()),
    );
    assert_eq!(u16::try_from_base32(b"VPGQ===="), Some(0xabcd));
    assert_eq!(u16::try_from_base32_string("VPGQ===="), Some(0xabcd));
    assert_eq!(u16::try_from_base32hex(b"LF6G===="), Some(0xabcd));
    assert_eq!(u16::try_from_base32hex_string("LF6G===="), Some(0xabcd));
}

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>

use b2t_codecs::{
    Base64, Base64Url, decoded_length_base64, decoded_length_base64ext, encoded_length_base64,
    try_decode_from_base64, try_decode_from_base64ext, try_decode_from_base64url,
    try_decode_from_base64urlext, try_encode_into_base64, try_encode_into_base64url,
};

#[test]
fn non_allocating_base64_api_is_reexported_from_the_crate_root() {
    assert_eq!(encoded_length_base64(&[0xfb, 0xff]), 4);
    assert_eq!(decoded_length_base64(b"+/8="), Some(2));
    assert_eq!(decoded_length_base64ext(b"+w==/w=="), Some(6));

    let mut base64 = [0; 4];
    let mut base64url = [0; 4];
    assert_eq!(
        try_encode_into_base64(&[0xfb, 0xff], &mut base64),
        Some(b"+/8=".as_slice()),
    );
    assert_eq!(
        try_encode_into_base64url(&[0xfb, 0xff], &mut base64url),
        Some(b"-_8=".as_slice()),
    );

    let mut decoded = [0; 6];
    assert_eq!(
        try_decode_from_base64(b"+/8=", &mut decoded),
        Some([0xfb, 0xff].as_slice()),
    );
    assert_eq!(
        try_decode_from_base64url(b"-_8=", &mut decoded),
        Some([0xfb, 0xff].as_slice()),
    );
    assert_eq!(
        try_decode_from_base64ext(b"+w==/w==", &mut decoded),
        Some([0xfb, 0xff].as_slice()),
    );
    assert_eq!(
        try_decode_from_base64urlext(b"-w==_w==", &mut decoded),
        Some([0xfb, 0xff].as_slice()),
    );

    let mut primitive = [0; 4];
    assert_eq!(
        0xfbff_u16.try_as_base64_into(&mut primitive),
        Some(b"+/8=".as_slice()),
    );
    assert_eq!(
        0xfbff_u16.try_as_base64url_into(&mut primitive),
        Some(b"-_8=".as_slice()),
    );
    assert_eq!(u16::try_from_base64(b"+/8="), Some(0xfbff));
    assert_eq!(u16::try_from_base64_string("+/8="), Some(0xfbff));
    assert_eq!(u16::try_from_base64url(b"-_8="), Some(0xfbff));
    assert_eq!(u16::try_from_base64url_string("-_8="), Some(0xfbff));
}

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>

use b2t_codecs::{
    Base16, decoded_length_base16, encoded_length_base16, try_decode_from_base16,
    try_decode_from_base16lower, try_decode_from_base16upper, try_encode_into_base16,
    try_encode_into_base16upper,
};

#[test]
fn non_allocating_base16_api_is_reexported_from_the_crate_root() {
    assert_eq!(encoded_length_base16(&[0xab, 0xcd]), 4);
    assert_eq!(decoded_length_base16(b"aBcD"), Some(2));

    let mut lower = [0; 4];
    let mut upper = [0; 4];
    assert_eq!(
        try_encode_into_base16(&[0xab, 0xcd], &mut lower),
        Some(b"abcd".as_slice()),
    );
    assert_eq!(
        try_encode_into_base16upper(&[0xab, 0xcd], &mut upper),
        Some(b"ABCD".as_slice()),
    );

    let mut decoded = [0; 2];
    assert_eq!(
        try_decode_from_base16(b"aBcD", &mut decoded),
        Some([0xab, 0xcd].as_slice()),
    );
    assert_eq!(
        try_decode_from_base16lower(b"abcd", &mut decoded),
        Some([0xab, 0xcd].as_slice()),
    );
    assert_eq!(
        try_decode_from_base16upper(b"ABCD", &mut decoded),
        Some([0xab, 0xcd].as_slice()),
    );
    assert_eq!(try_decode_from_base16lower(b"ABCD", &mut decoded), None);

    let mut primitive = [0; 4];
    assert_eq!(
        0xabcd_u16.try_as_base16_into(&mut primitive),
        Some(b"abcd".as_slice()),
    );
    assert_eq!(u16::try_from_base16(b"aBcD"), Some(0xabcd));
}

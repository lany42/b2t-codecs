// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>

use b2t_codecs::{
    Adobe85, Base85, Z85, decoded_length_base85, encoded_length_adobe85, encoded_length_base85,
    try_decode_from_adobe85, try_decode_from_ascii85, try_decode_from_z85, try_encode_into_adobe85,
    try_encode_into_ascii85, try_encode_into_z85,
};

#[test]
fn non_allocating_base85_api_is_reexported_from_the_crate_root() {
    assert_eq!(b2t_codecs::base85::encoded_length_base85(&[0; 4]), Some(5));
    assert_eq!(encoded_length_base85(&[0; 4]), Some(5));
    assert_eq!(encoded_length_base85(&[0; 3]), None);
    assert_eq!(decoded_length_base85(b"Hello"), Some(4));
    assert_eq!(decoded_length_base85(b"Hell"), None);
    assert_eq!(encoded_length_adobe85(&[0; 7]), 9);

    let input = [0x86, 0x4f, 0xd2, 0x6f];
    let mut ascii85 = [0; 5];
    let mut z85 = [0; 5];
    let mut adobe85 = [0; 5];
    assert_eq!(
        try_encode_into_ascii85(&input, &mut ascii85),
        Some(b"L/669".as_slice())
    );
    assert_eq!(
        try_encode_into_z85(&input, &mut z85),
        Some(b"Hello".as_slice())
    );
    assert_eq!(
        try_encode_into_adobe85(&input, &mut adobe85),
        Some(b"L/669".as_slice())
    );

    let mut decoded = [0; 4];
    assert_eq!(
        try_decode_from_ascii85(b"L/669", &mut decoded),
        Some(input.as_slice())
    );
    assert_eq!(
        try_decode_from_z85(b"Hello", &mut decoded),
        Some(input.as_slice())
    );
    assert_eq!(
        try_decode_from_adobe85(b"L/669", &mut decoded),
        Some(input.as_slice())
    );
}

#[test]
fn public_slice_apis_enforce_their_destination_contracts() {
    let mut empty = [];
    assert_eq!(try_encode_into_ascii85(b"", &mut empty), Some(&[][..]));
    assert_eq!(try_encode_into_z85(b"", &mut empty), Some(&[][..]));
    assert_eq!(try_encode_into_adobe85(b"", &mut empty), Some(&[][..]));
    assert_eq!(try_decode_from_ascii85(b"", &mut empty), Some(&[][..]));
    assert_eq!(try_decode_from_z85(b"", &mut empty), Some(&[][..]));
    assert_eq!(try_decode_from_adobe85(b"", &mut empty), Some(&[][..]));

    let mut strict_short = [0xa5; 4];
    assert_eq!(try_encode_into_ascii85(&[0; 4], &mut strict_short), None);
    assert_eq!(strict_short, [0xa5; 4]);

    let mut adobe_short = [0xa5; 4];
    assert_eq!(try_encode_into_adobe85(&[0; 4], &mut adobe_short), None);
    assert_eq!(adobe_short, [0xa5; 4]);

    let mut adobe = [0xa5; 6];
    let encoded = try_encode_into_adobe85(&[0; 4], &mut adobe).unwrap();
    assert_eq!(encoded, b"z");
    assert_eq!(&adobe[1..], &[0xa5; 5]);

    let mut decoded = [0xa5; 5];
    assert_eq!(
        try_decode_from_adobe85(b"\t z\n", &mut decoded).unwrap(),
        &[0; 4]
    );
    assert_eq!(decoded[4], 0xa5);

    let mut guarded = [0xa5; 10];
    assert_eq!(try_decode_from_adobe85(b"zz", &mut guarded[1..8]), None);
    assert_eq!(guarded[0], 0xa5);
    assert_eq!(&guarded[8..], &[0xa5; 2]);
}

#[test]
fn fixed_width_traits_are_available_without_allocation() {
    macro_rules! assert_adobe85_size {
        ($($ty:ty),+ $(,)?) => {
            $(assert_eq!(<$ty as Adobe85>::SIZE, core::mem::size_of::<$ty>());)+
        };
    }
    macro_rules! assert_strict_sizes {
        ($($ty:ty),+ $(,)?) => {
            $(
                assert_eq!(<$ty as Base85>::SIZE, core::mem::size_of::<$ty>());
                assert_eq!(<$ty as Z85>::SIZE, core::mem::size_of::<$ty>());
            )+
        };
    }

    assert_adobe85_size!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);
    assert_strict_sizes!(u32, u64, u128, i32, i64, i128);

    let value = 0x864f_d26f_u32;
    let mut dst = [0xa5; 6];
    assert_eq!(
        value.try_as_base85_into(&mut dst),
        Some(b"L/669".as_slice())
    );
    assert_eq!(dst[5], 0xa5);
    assert_eq!(u32::try_from_base85(b"L/669"), Some(value));
    assert_eq!(u32::try_from_base85_string("L/669"), Some(value));

    assert_eq!(value.try_as_z85_into(&mut dst), Some(b"Hello".as_slice()));
    assert_eq!(dst[5], 0xa5);
    assert_eq!(u32::try_from_z85(b"Hello"), Some(value));
    assert_eq!(u32::try_from_z85_string("Hello"), Some(value));

    let mut strict_short = [0xa5; 4];
    assert_eq!(value.try_as_base85_into(&mut strict_short), None);
    assert_eq!(strict_short, [0xa5; 4]);
    assert_eq!(value.try_as_z85_into(&mut strict_short), None);
    assert_eq!(strict_short, [0xa5; 4]);

    let mut adobe = [0xa5; 6];
    assert_eq!(0_u32.try_as_adobe85_into(&mut adobe), Some(b"z".as_slice()));
    assert_eq!(&adobe[1..], &[0xa5; 5]);
    assert_eq!(u32::try_from_adobe85(b"z"), Some(0));
    assert_eq!(u32::try_from_adobe85_string("z"), Some(0));

    let mut short = [0xa5; 4];
    assert_eq!(0_u32.try_as_adobe85_into(&mut short), None);
    assert_eq!(short, [0xa5; 4]);

    assert_eq!(u64::try_from_base85(b"!!!!!"), None);
    assert_eq!(u64::try_from_base85(b"!!!!!!!!!!"), Some(0));
    assert_eq!(u64::try_from_z85(b"00000"), None);
    assert_eq!(u64::try_from_z85(b"0000000000"), Some(0));
    assert_eq!(u32::try_from_adobe85(b"!!!"), None);
    assert_eq!(u32::try_from_adobe85(b"zz"), None);

    let signed = i32::MIN;
    let mut signed_adobe = [0; 5];
    let signed_adobe = signed
        .try_as_adobe85_into(&mut signed_adobe)
        .expect("a five-byte destination fits an i32 Adobe85 upper bound");
    assert_eq!(i32::try_from_adobe85(signed_adobe), Some(signed));

    let mut signed_ascii85 = [0; 5];
    let signed_ascii85 = signed
        .try_as_base85_into(&mut signed_ascii85)
        .expect("a five-byte destination fits an i32 Ascii85 encoding");
    assert_eq!(i32::try_from_base85(signed_ascii85), Some(signed));

    let mut signed_z85 = [0; 5];
    let signed_z85 = signed
        .try_as_z85_into(&mut signed_z85)
        .expect("a five-byte destination fits an i32 Z85 encoding");
    assert_eq!(i32::try_from_z85(signed_z85), Some(signed));
}

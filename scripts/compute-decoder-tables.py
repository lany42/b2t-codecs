#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: 2026 Lany Atwood <lany@colorized.life>
"""Display the precomputed lookup tables used by the codecs.

The output is deliberately close to Rust syntax so that a table can be copied
into a codec implementation without first reformatting a Python list.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import dataclass


INVALID = 0xFF
DEFAULT_WIDTH = 100


@dataclass(frozen=True)
class Encoder:
    constant: str
    alphabet: str


@dataclass(frozen=True)
class Codec:
    key: str
    title: str
    radix: int
    encoders: tuple[Encoder, ...]
    decoder_constant: str = "DECODER"
    min_ascii_constant: str = "MIN_ASCII"
    max_ascii_constant: str = "MAX_ASCII"


@dataclass(frozen=True)
class CodecTables:
    codec: Codec
    decoder: tuple[int, ...]
    min_ascii: int
    max_ascii: int
    accepted_ascii: int


BASE85 = (
    "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
    "abcdefghijklmnopqrstu"
)
Z85 = (
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ".-:+=^!/*?&<>()[]{}@%$#"
)
BASE16_UPPER = "0123456789ABCDEF"
BASE16_LOWER = "0123456789abcdef"
BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
BASE32_HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
BASE64_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


# Keep this registry independent of CODECS so every literal is checked even
# when only one codec is selected on the command line.
ALPHABET_LENGTH_CHECKS = (
    ("BASE85", BASE85, 85),
    ("Z85", Z85, 85),
    ("BASE16_UPPER", BASE16_UPPER, 16),
    ("BASE16_LOWER", BASE16_LOWER, 16),
    ("BASE32", BASE32, 32),
    ("BASE32_HEX", BASE32_HEX, 32),
    ("BASE64", BASE64, 64),
    ("BASE64_URL", BASE64_URL, 64),
)


def check_alphabet_lengths(
    checks: Sequence[tuple[str, str, int]] = ALPHABET_LENGTH_CHECKS,
) -> None:
    """Catch malformed alphabet literals before generating any tables."""
    for name, alphabet, expected in checks:
        actual = len(alphabet)
        if actual != expected:
            raise ValueError(
                f"{name} alphabet has {actual} characters; expected {expected}. "
                "Check the string literal's escaping."
            )


check_alphabet_lengths()


CODECS = (
    Codec("base85", "Base85", 85, (Encoder("ENCODER", BASE85),)),
    Codec("z85", "Z85", 85, (Encoder("ENCODER", Z85),)),
    Codec("base32", "Base32", 32, (Encoder("ENCODER", BASE32),)),
    Codec(
        "base32hex",
        "Base32Hex",
        32,
        (Encoder("ENCODER", BASE32_HEX),),
    ),
    Codec("base64", "Base64", 64, (Encoder("ENCODER", BASE64),)),
    Codec(
        "base64-url",
        "Base64 URL-safe",
        64,
        (Encoder("ENCODER", BASE64_URL),),
    ),
    Codec(
        "base16",
        "Base16 mixed case",
        16,
        (
            Encoder("ENCODER_UPPER", BASE16_UPPER),
            Encoder("ENCODER_LOWER", BASE16_LOWER),
        ),
    ),
    Codec(
        "base16-lower",
        "Base16 lowercase",
        16,
        (Encoder("ENCODER_LOWER", BASE16_LOWER),),
        decoder_constant="DECODER_LOWER",
        min_ascii_constant="MIN_ASCII_LOWER",
        max_ascii_constant="MAX_ASCII_LOWER",
    ),
    Codec(
        "base16-upper",
        "Base16 uppercase",
        16,
        (Encoder("ENCODER_UPPER", BASE16_UPPER),),
        decoder_constant="DECODER_UPPER",
        min_ascii_constant="MIN_ASCII_UPPER",
        max_ascii_constant="MAX_ASCII_UPPER",
    ),
)


def build_tables(codec: Codec) -> CodecTables:
    """Build one decoder, accepting equivalent characters from every encoder."""
    if not 0 < codec.radix <= INVALID:
        raise ValueError(f"{codec.title}: radix must be between 1 and {INVALID}")
    if not codec.encoders:
        raise ValueError(f"{codec.title}: at least one encoder alphabet is required")

    decoded_values: dict[int, int] = {}
    for encoder in codec.encoders:
        if len(encoder.alphabet) != codec.radix:
            raise ValueError(
                f"{codec.title}: {encoder.constant} has {len(encoder.alphabet)} "
                f"characters; expected {codec.radix}"
            )
        if len(set(encoder.alphabet)) != codec.radix:
            raise ValueError(
                f"{codec.title}: {encoder.constant} contains duplicate characters"
            )

        for decoded, character in enumerate(encoder.alphabet):
            encoded = ord(character)
            if not 0x20 <= encoded <= 0x7E:
                raise ValueError(
                    f"{codec.title}: {character!r} is not printable ASCII"
                )

            previous = decoded_values.get(encoded)
            if previous is not None and previous != decoded:
                raise ValueError(
                    f"{codec.title}: {character!r} maps to both "
                    f"{previous} and {decoded}"
                )
            decoded_values[encoded] = decoded

    min_ascii = min(decoded_values)
    max_ascii = max(decoded_values) + 1
    decoder = tuple(
        decoded_values.get(encoded, INVALID)
        for encoded in range(min_ascii, max_ascii)
    )

    return CodecTables(
        codec=codec,
        decoder=decoder,
        min_ascii=min_ascii,
        max_ascii=max_ascii,
        accepted_ascii=len(decoded_values),
    )


def format_rust_array(name: str, values: Sequence[int], width: int) -> str:
    """Format a Rust u8 array without relying on rustfmt being installed."""
    lines = [f"const {name}: [u8; {len(values)}] = ["]
    line = "    "

    for value in values:
        item = f"{value},"
        separator = "" if line.isspace() else " "
        if len(line) + len(separator) + len(item) > width and not line.isspace():
            lines.append(line)
            line = f"    {item}"
        else:
            line += f"{separator}{item}"

    if not line.isspace():
        lines.append(line)
    lines.append("];")
    return "\n".join(lines)


def format_tables(tables: CodecTables, width: int) -> str:
    codec = tables.codec
    heading = f"{codec.title} (radix {codec.radix})"
    invalid_ascii = len(tables.decoder) - tables.accepted_ascii
    max_inclusive = tables.max_ascii - 1

    lines = [heading, "=" * len(heading)]
    for encoder in codec.encoders:
        alphabet = json.dumps(encoder.alphabet, ensure_ascii=True)
        lines.append(f"{encoder.constant} alphabet: {alphabet}")

    lines.extend(
        (
            f"Accepted ASCII: {tables.accepted_ascii} characters",
            (
                f"Lookup range:  {tables.min_ascii} ({chr(tables.min_ascii)!r}) "
                f"..= {max_inclusive} ({chr(max_inclusive)!r})"
            ),
            (
                f"Decoder table: {len(tables.decoder)} entries "
                f"({invalid_ascii} invalid, represented by {INVALID})"
            ),
            "",
        )
    )

    for encoder in codec.encoders:
        encoded = tuple(map(ord, encoder.alphabet))
        lines.extend((format_rust_array(encoder.constant, encoded, width), ""))

    lines.extend(
        (
            format_rust_array(codec.decoder_constant, tables.decoder, width),
            "",
            f"const {codec.min_ascii_constant}: usize = {tables.min_ascii};",
            (
                f"const {codec.max_ascii_constant}: usize = {max_inclusive} + 1; "
                "// Exclusive; one past the end."
            ),
        )
    )
    return "\n".join(lines)


def output_width(value: str) -> int:
    width = int(value)
    if width < 40:
        raise argparse.ArgumentTypeError("width must be at least 40 columns")
    return width


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    codec_names = ", ".join(codec.key for codec in CODECS)
    parser = argparse.ArgumentParser(
        description="Display Rust-ready encoder and decoder lookup tables."
    )
    parser.add_argument(
        "codecs",
        nargs="*",
        metavar="CODEC",
        help=f"codec(s) to display; defaults to all ({codec_names})",
    )
    parser.add_argument(
        "--width",
        default=DEFAULT_WIDTH,
        type=output_width,
        help=f"maximum array line width (default: {DEFAULT_WIDTH})",
    )

    args = parser.parse_args(argv)
    known_codecs = {codec.key: codec for codec in CODECS}
    unknown = [name for name in args.codecs if name not in known_codecs]
    if unknown:
        parser.error(
            f"unknown codec(s): {', '.join(unknown)}; choose from {codec_names}"
        )

    args.codecs = [known_codecs[name] for name in args.codecs] or list(CODECS)
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    reports = (
        format_tables(build_tables(codec), args.width) for codec in args.codecs
    )
    print("\n\n".join(reports))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

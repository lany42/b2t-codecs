# b2t-codecs

Dependency-free binary-to-text codecs for Base16, Base32, Base64, ASCII85,
Adobe85, and Z85.

## Quick Start

```rust
use b2t_codecs::{encode_base64_string, try_decode_base64_string};

let encoded = encode_base64_string(b"Rust is great!");
assert_eq!(encoded, "UnVzdCBpcyBncmVhdCE=");
assert_eq!(
    try_decode_base64_string(&encoded).as_deref(),
    Some(b"Rust is great!".as_slice()),
);
```

## Codec Matrix

| Codec | Size cost for full quanta | Use-case keywords |
|---|---:|---|
| Base16 | 2.00× (100% larger) | human-readable bytes, debugging, checksums, identifiers |
| Base32 | 1.60× (60% larger) | human transcription, case-insensitive systems, URI-friendly tokens, uncommon protocols |
| Base32Hex | 1.60× (60% larger) | sortable encodings, numeric-looking identifiers, DNS-style data |
| Base64 | 1.33× (33% larger) | web APIs, JSON payloads, MIME, general binary transport |
| Base64URL | 1.33× (33% larger) | URLs, filenames, cookies, web tokens |
| ASCII85 | 1.25× (25% larger) | compact printable data, ASCII85 interoperability, controlled text formats |
| Adobe85 | about 1.25× (25% larger) | PostScript-style data, partial tails, zero-heavy data |
| Z85 | 1.25× (25% larger) | ZeroMQ, source-code literals, JSON and configuration strings |

The ratios compare encoded ASCII bytes with input bytes for complete encoding
quanta. Padding and partial tails can increase the ratio for short inputs.
Adobe85 can be smaller for zero-heavy input because one `z` represents a full
four-byte zero quantum.

Base32 and Base64URL use URI-friendly alphabets, but this crate's encoders emit
RFC padding where required. The `=` padding byte may still require escaping in
some URI components. [`trim_base64_end_padding`] removes Base64 or Base64URL end
padding when the surrounding protocol permits unpadded data.

Strict ASCII85 and Z85 require input lengths divisible by four and encoded
lengths divisible by five. Adobe85 accepts partial final quanta. Unlike
ASCII85, Z85 avoids quote and backslash characters, making it convenient inside
source-code and JSON strings.

[`trim_base64_end_padding`]: https://docs.rs/b2t-codecs/latest/b2t_codecs/fn.trim_base64_end_padding.html

## License

Licensed under the GNU Affero General Public License, version 3 only
(`AGPL-3.0-only`).

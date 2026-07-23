# b2t-codecs

Freestanding binary-to-text codecs for Base16, Base32, Base64, and Base85.

## Quick Start

```rust
use b2t_codecs::{encode_base64_string, try_decode_base64_string};

let encoded = encode_base64_string(b"Rust is great!");
assert_eq!(encoded, "UnVzdCBpcyBncmVhdCE=");

let decoded = &*try_decode_base64_string(&encoded).unwrap();
assert_eq!(decoded, b"Rust is great!");
```

## Codecs

### Which do I Choose?

Choose based on where the encoded string will live:

- For easy inspection or transcription, use Base16 or Base32.
- For broadly interoperable binary text, use Base64.
- For URL tokens and filenames, use Base64URL.
- For denser JSON, YAML, or TOML strings, use Z85.

| Codec | Size | URL | JSON | XML | YAML | TOML | HTML |
|---|---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Base16 | 2.00× | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Base32 | 1.60× | ✅* | ✅ | ✅ | ✅ | ✅ | ✅ |
| Base32Hex | 1.60× | ✅* | ✅ | ✅ | ✅ | ✅ | ✅ |
| Base64 | 1.33× | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Base64URL | 1.33× | ✅* | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ascii85 | 1.25× | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Adobe85 | ~1.25× | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Z85 | 1.25× | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ |

- ✅ Every character in the codec alphabet can be embedded without escaping.
- ❌ At least one character in the codec alphabet must be escaped.

JSON, YAML, and TOML assume double-quoted strings. XML and HTML cover text
content and quoted attribute values. Sizes compare complete encoding quanta.

Adobe85 APIs use raw payloads. Encoders omit the traditional `<~` and `~>`
delimiters, while decoders ignore ASCII whitespace within payloads.

\* Canonical Base32, Base32Hex, and Base64URL output includes reserved `=`
padding. Remove it to make the output URL-safe as-is, or percent-encode it with
the rest of the URL component.

## License

Licensed under the GNU Affero General Public License, version 3 only
(`AGPL-3.0-only`).

# b2t-codecs

Freestanding binary-to-text codecs for Base16, Base32, Base64, and Base85.

The `alloc` feature is enabled by default. To use only allocation-free APIs,
disable default features in your `Cargo.toml`:

```yaml
[dependencies]
b2t-codecs = { version = "2", default-features = false }
```

## Quick Start

```rust
use b2t_codecs::{encode_base64_string, try_decode_base64_string};

let encoded = encode_base64_string(b"Rust is great!");
assert_eq!(encoded, "UnVzdCBpcyBncmVhdCE=");

let decoded = &*try_decode_base64_string(&encoded).unwrap();
assert_eq!(decoded, b"Rust is great!");
```

## Todo

- [x] No-alloc API for Base16, v2.0
- [x] No-alloc API for Base32, v2.1
- [ ] No-alloc API for Base64, v2.2
- [ ] No-alloc API for Base85, v2.3

## Codecs

### Which do I Choose?

Choose based on where the encoded string will live:

- For easy inspection or transcription, use Base16 or Base32.
- For broadly interoperable binary text, use Base64.
- For URL tokens and filenames, use Base64URL.
- For denser JSON, YAML, or TOML strings, use Z85.

| Codec | Size | Padding | URL | JSON | XML | YAML | TOML | HTML |
|---|---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Base16 | 2.00× | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Base32 | 1.60× | ✅ | ✅* | ✅ | ✅ | ✅ | ✅ | ✅ |
| Base32Hex | 1.60× | ✅ | ✅* | ✅ | ✅ | ✅ | ✅ | ✅ |
| Base64 | 1.33× | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Base64URL | 1.33× | ✅ | ✅* | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ascii85 | 1.25× | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Adobe85 | ~1.25× | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Z85 | 1.25× | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ |

- Padding: ✅ accepts arbitrary byte lengths; ❌ requires aligned input.
- URL through HTML: ✅ every alphabet character can be embedded without
  escaping; ❌ at least one alphabet character must be escaped.

JSON, YAML, and TOML assume double-quoted strings. XML and HTML cover text
content and quoted attribute values. Sizes compare complete encoding quanta.
Padding indicates whether arbitrary byte lengths are accepted: Base16 needs no
padding symbols, Base32 and Base64 pad partial tails, Adobe85 uses implicit tail
padding, and strict Ascii85 and Z85 require four-byte input alignment.

Adobe85 APIs use raw payloads. Encoders omit the traditional `<~` and `~>`
delimiters, while decoders ignore ASCII whitespace within payloads.

\* Canonical Base32, Base32Hex, and Base64URL output includes reserved `=`
padding. Remove it to make the output URL-safe as-is, or percent-encode it with
the rest of the URL component.

## License

Licensed under the GNU Affero General Public License, version 3 only
(`AGPL-3.0-only`).

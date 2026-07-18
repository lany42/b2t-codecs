ASCII85 = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu"

Z85 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"

BASE16 = "0123456789ABCDEF"

BASE16_LOWER = "0123456789abcdef"

# NOTE: In base16 decoding table, "abcdef" map to "ABCDEF"
BASE16_ALIASES = "abcdef"

BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

BASE64_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


assert len(ASCII85) == 85
assert len(Z85) == 85
assert len(BASE16) == 16
assert len(BASE16_LOWER) == 16
assert len(BASE64) == 64
assert len(BASE64_URL) == 64


for alphabet in [ASCII85, Z85, BASE64, BASE64_URL]:
    as_ascii = [ord(c) for c in alphabet]
    min_ascii = min(as_ascii)

    decoder = [0xFF for _ in range(min_ascii, max(as_ascii) + 1)]

    for d, c in enumerate(as_ascii):
        i = c - min_ascii
        decoder[i] = d

    print(alphabet)
    print("MIN_ASCII:", min_ascii)
    print("MAX_ASCII:", max(as_ascii))
    print(len(as_ascii))
    print(as_ascii)
    print(len(decoder))
    print(decoder)


# BASE16 decoder table
# The encoder alphabet can either be upper or lowercase base on user preference
# but the decoding table can combine both, canonicalizing the lowercase as aliases
# for the uppercase table
as_ascii = [ord(c) for c in BASE16 + BASE16_ALIASES]
min_ascii = min(as_ascii)

decoder = [0xFF for _ in range(min_ascii, max(as_ascii) + 1)]

lower = {}
for d, c in enumerate([ord(c) for c in BASE16]):
    i = c - min_ascii
    decoder[i] = d
    char = chr(c)
    if char in "ABCDEF":
        char = char.lower()
        lower[char] = d

for c in BASE16_ALIASES:
    i = ord(c) - min_ascii
    d = lower[c]
    decoder[i] = d

print(BASE16)
print("MIN_ASCII:", min_ascii)
print("MAX_ASCII:", max(as_ascii))
print(len(BASE16))
print([ord(c) for c in BASE16])
print(len(BASE16_LOWER))
print([ord(c) for c in BASE16_LOWER])
print(len(decoder))
print(decoder)

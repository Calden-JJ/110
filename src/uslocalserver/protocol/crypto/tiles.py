"""`AlgoId -> cipher`: the 14-tile table both directions of the game link use.

The server picks the cipher for a body from the *opcode*, not from any header
field: `AlgoId = sub % 14`.  That was proven on the C->S `plain=` oracle
(every logged plaintext is reproduced byte-for-byte) and then independently on
S->C, where a wrong tile decrypts to uniform noise while the right one leaves
runs of zeros, repeated words and length prefixes (59 of the capture's 60
S->C frames; the 60th is `(0,1)` CHANNELINFO, still open).

The key is `data/crypto/channelinfo_key_blob.bin`, 334 bytes with no slack:
the 14 entries are concatenated in AlgoId order, so each tile's key is a
slice.  `AlgoId 6` is special -- the server ships both RFC MISTY1 and the DFO
variant, and the variant is the one the wire uses (the stock one fails every
gold pair); only the variant appears here.
"""
from __future__ import annotations

from . import (
    KEY_BLOB,
    ecb_decrypt,
    ecb_encrypt,
    xor32_encrypt,
    aes128_encrypt,
    aes128_decrypt,
    blowfish_dfo_encrypt,
    blowfish_dfo_decrypt,
    cast128_encrypt,
    cast128_decrypt,
    dfo9_encrypt,
    dfo9_decrypt,
    dfo11_encrypt,
    dfo11_decrypt,
    dfo13_encrypt,
    dfo13_decrypt,
    dfo16_encrypt,
    dfo16_decrypt,
    misty1_dfo_encrypt,
    misty1_dfo_decrypt,
    rc6_dfo_encrypt,
    rc6_dfo_decrypt,
    skipjack_encrypt,
    skipjack_decrypt,
    twofish_encrypt,
    twofish_decrypt,
    xtea_be_encrypt,
    xtea_be_decrypt,
    xtea_le_encrypt,
    xtea_le_decrypt,
)

#: `(name, key slice, block size, share, unshare)`.  `xor32` ignores the block
#: size because it xor-fold the key's last u32 and passes a 1..3-byte tail
#: through itself; it is listed as 4 so `decrypt_body` takes the same path.
TILES = (
    ("XTEA-BE", (0, 16), 8, xtea_be_encrypt, xtea_be_decrypt),
    ("CAST-128", (16, 32), 8, cast128_encrypt, cast128_decrypt),
    ("RC6-480-DFO", (32, 92), 16, rc6_dfo_encrypt, rc6_dfo_decrypt),
    ("Twofish256", (92, 124), 16, twofish_encrypt, twofish_decrypt),
    ("AES-128", (124, 140), 16, aes128_encrypt, aes128_decrypt),
    ("Skipjack", (140, 150), 8, skipjack_encrypt, skipjack_decrypt),
    ("MISTY1-DFO", (150, 166), 8, misty1_dfo_encrypt, misty1_dfo_decrypt),
    ("Blowfish-DFO", (166, 222), 8, blowfish_dfo_encrypt, blowfish_dfo_decrypt),
    ("XTEA-LE", (222, 238), 8, xtea_le_encrypt, xtea_le_decrypt),
    ("DFO-Rijndael12", (238, 254), 16, dfo9_encrypt, dfo9_decrypt),
    ("XOR-32", (254, 262), 4, xor32_encrypt, xor32_encrypt),
    ("Khazad-like", (262, 278), 8, dfo11_encrypt, dfo11_decrypt),
    ("DFO-16B", (278, 294), 16, dfo16_encrypt, dfo16_decrypt),
    ("Custom 8B", (294, 334), 8, dfo13_encrypt, dfo13_decrypt),
)

ALGO_COUNT = len(TILES)


def algo_id(opcode_sub: int) -> int:
    """The tile an opcode selects.  `sub` is the raw header field, not `sub % 14`."""
    return opcode_sub % ALGO_COUNT


def _key(algo: int) -> bytes:
    start, stop = TILES[algo][1]
    return KEY_BLOB.read_bytes()[start:stop]


def decrypt_body(algo: int, data: bytes) -> bytes:
    """Decrypt a whole body with tile `algo`; a trailing partial block passes through."""
    _, _, bs, _, unshare = TILES[algo]
    if not data:
        return b""
    if bs == 4:
        return unshare(data, _key(algo))
    return ecb_decrypt(unshare, data, _key(algo), bs)


def encrypt_body(algo: int, data: bytes) -> bytes:
    _, _, bs, share, _ = TILES[algo]
    if not data:
        return b""
    if bs == 4:
        return share(data, _key(algo))
    return ecb_encrypt(share, data, _key(algo), bs)

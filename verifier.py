"""Programme A: the deliberately broken PKCS#1 v1.5 verifier (plus a strict one).

The flaw: instead of rebuilding the unique expected block and comparing it
byte-for-byte, broken_verify only checks that the START and the END look right
and never checks that the FF padding runs all the way to the DigestInfo. The
bytes in between are unchecked — exactly the gap the forge exploits.
"""

import re

from pkcs1 import MIN_FF_PADDING, digest_info_suffix, i2osp

# Start landmark: 00 01, >= 8 bytes of FF, then a 00 separator. Anchored at
# offset 0, but does NOT require the padding to reach the DigestInfo.
_START_RE = re.compile(rb"\x00\x01\xff{%d,}\x00" % MIN_FF_PADDING)


def broken_verify(message: bytes, signature: int, n: int, e: int) -> bool:
    k = (n.bit_length() + 7) // 8
    block = i2osp(pow(signature, e, n), k)

    if not _START_RE.match(block):
        return False
    # END check only; the middle between separator and suffix is never inspected.
    return block.endswith(digest_info_suffix(message))


def strict_verify(message: bytes, signature: int, n: int, e: int) -> bool:
    """Correct verifier: rebuild the one valid block and compare exactly."""
    k = (n.bit_length() + 7) // 8
    block = i2osp(pow(signature, e, n), k)

    suffix = digest_info_suffix(message)
    ff_len = k - 3 - len(suffix)
    if ff_len < MIN_FF_PADDING:
        return False
    expected = b"\x00\x01" + (b"\xff" * ff_len) + b"\x00" + suffix
    return block == expected


if __name__ == "__main__":
    from rsa_keygen import load_key

    key = load_key()
    print("random signature, broken_verify:", broken_verify(b"hello", 42, key["n"], key["e"]))
    print("random signature, strict_verify:", strict_verify(b"hello", 42, key["n"], key["e"]))

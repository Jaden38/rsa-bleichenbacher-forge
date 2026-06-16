"""Shared PKCS#1 v1.5 constants and integer maths (public-key only, no secrets).

All arithmetic uses Python big ints, never floats: a double's ~53-bit mantissa
would be off by hundreds of bits on a 2048-bit cube root.
"""

import hashlib

# ASN.1 DER DigestInfo header for SHA-256; must be byte-exact or verification
# (real or forged) fails silently. Published constant, looked up not guessed.
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")

# PKCS#1 mandates at least 8 bytes of 0xFF padding; the broken verifier enforces
# only this lower bound (and nothing about where the padding ends).
MIN_FF_PADDING = 8


def sha256(message: bytes) -> bytes:
    return hashlib.sha256(message).digest()


def digest_info_suffix(message: bytes) -> bytes:
    """DigestInfo || SHA-256(message): the trailing bytes of a valid block."""
    return SHA256_DIGEST_INFO + sha256(message)


def i2osp(x: int, length: int) -> bytes:
    """Integer to fixed-width big-endian octets (keeps the leading 0x00 byte)."""
    return x.to_bytes(length, "big")


def os2ip(octets: bytes) -> int:
    return int.from_bytes(octets, "big")


def icbrt(n: int) -> int:
    """floor(n ** (1/3)), exact, via binary search (invariant lo**3 <= n)."""
    if n < 0:
        raise ValueError("icbrt is defined for non-negative integers only")
    if n < 2:
        return n
    lo, hi = 0, 1
    while hi ** 3 <= n:
        hi <<= 1
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if mid ** 3 <= n:
            lo = mid
        else:
            hi = mid
    return lo


def icbrt_ceil(n: int) -> int:
    r = icbrt(n)
    return r if r ** 3 == n else r + 1


def cube_root_mod_2k(target: int, k: int) -> int:
    """Return s in [0, 2**k) with s**3 ≡ target (mod 2**k); target must be odd.

    Built bit by bit (Hensel lift): for odd s, setting bit i of s flips exactly
    bit i of s**3 and leaves the lower bits untouched (the cross term 3*s**2*2^i
    is odd*2^i). So we walk up, fixing each disagreeing bit. This is what lets
    the forge pin the block's low bytes (suffix) independently of its high bytes.
    """
    if target & 1 == 0:
        raise ValueError("cube_root_mod_2k requires an odd target")
    s = 1
    for i in range(1, k):
        if ((s * s * s) ^ target) & (1 << i):
            s |= (1 << i)
    return s

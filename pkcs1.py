"""
pkcs1.py — Shared PKCS#1 v1.5 constants and integer maths for the PoC.

This module is imported by both the verifier (Programme A) and the forger
(Programme B). It deliberately contains *no* RSA private-key material: the whole
point of Bleichenbacher's attack is that the forger only needs the **public**
key (n, e). Everything here is either public PKCS#1 structure or pure integer
arithmetic on Python big integers.

Why big integers (and never floats)? RSA on a 2048-bit modulus manipulates
~2048-bit numbers. IEEE-754 doubles carry only ~53 bits of mantissa, so any
float-based "cube root" would be off by hundreds of bits and silently break the
forgery. Python's `int` is arbitrary precision, so we stay exact throughout.
"""

import hashlib

# ---------------------------------------------------------------------------
# PKCS#1 v1.5 DigestInfo
# ---------------------------------------------------------------------------
# A correct RSA-PKCS#1 v1.5 signature, once "decrypted" with the public key
# (i.e. s^e mod n), decodes to this byte block, filling the full modulus width:
#
#     00 01 FF FF ... FF 00 <DigestInfo> <HASH>
#     ^^^^^ ^^^^^^^^^^^^ ^^ ^^^^^^^^^^^^ ^^^^^^
#     fixed  PS padding   |   ASN.1 DER   message hash
#     prefix (>= 8 x FF)  separator
#
# The DigestInfo is a fixed ASN.1 DER header that names the hash algorithm and
# wraps the digest. For SHA-256 the exact bytes are below. These bytes must be
# byte-for-byte correct: a single wrong byte makes a real verifier reject, and
# (more relevant here) makes our forged "end" fail the lenient check too. They
# are a published constant — looked up, never guessed.
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")

# Number of leading "guaranteed" 0xFF padding bytes a *correct* block must have.
# PKCS#1 mandates the padding string PS be at least 8 bytes of 0xFF. Our broken
# verifier (Programme A) will reuse this lower bound — that is the only part of
# the padding length it bothers to enforce, which is precisely the flaw.
MIN_FF_PADDING = 8


def sha256(message: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of *message*."""
    return hashlib.sha256(message).digest()


def digest_info_suffix(message: bytes) -> bytes:
    """
    Build the trailing part of a valid signature block for *message*:
    DigestInfo || SHA-256(message). This is the chunk that, in a correct
    signature, sits at the very END of the block. The lenient verifier checks
    that the block ends with exactly these bytes, so the forger must reproduce
    them exactly at the low end of its constructed cube.
    """
    return SHA256_DIGEST_INFO + sha256(message)


# ---------------------------------------------------------------------------
# Integer <-> octet-string conversions (PKCS#1's I2OSP / OS2IP)
# ---------------------------------------------------------------------------
def i2osp(x: int, length: int) -> bytes:
    """Integer-to-Octet-String: big-endian, zero-padded to *length* bytes.

    The leading zero padding matters: a 2048-bit modulus block is always 256
    bytes, and a valid block starts with a 0x00 byte, so the top byte is
    frequently zero. `int.to_bytes` reproduces that fixed width."""
    return x.to_bytes(length, "big")


def os2ip(octets: bytes) -> int:
    """Octet-String-to-Integer: interpret bytes as a big-endian integer."""
    return int.from_bytes(octets, "big")


# ---------------------------------------------------------------------------
# Exact integer cube root (floor), no floats
# ---------------------------------------------------------------------------
def icbrt(n: int) -> int:
    """
    Return floor(n ** (1/3)) for n >= 0, computed exactly with binary search.

    Used by the forger to turn a *desired* top-of-block value into a base `s`
    whose cube `s**3` lands in the wanted range. Newton's method would also
    work, but binary search is trivially correct and easy to audit: we keep an
    invariant lo**3 <= n and converge on the largest such integer.
    """
    if n < 0:
        raise ValueError("icbrt is defined for non-negative integers only")
    if n < 2:
        return n
    # Establish an upper bound hi with hi**3 > n by doubling.
    lo, hi = 0, 1
    while hi ** 3 <= n:
        hi <<= 1
    # Binary search for the floor cube root in [lo, hi).
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if mid ** 3 <= n:
            lo = mid
        else:
            hi = mid
    return lo


def icbrt_ceil(n: int) -> int:
    """Smallest integer r with r**3 >= n (ceiling cube root)."""
    r = icbrt(n)
    return r if r ** 3 == n else r + 1


# ---------------------------------------------------------------------------
# Cube root modulo a power of two (the heart of the "suffix" construction)
# ---------------------------------------------------------------------------
def cube_root_mod_2k(target: int, k: int) -> int:
    """
    Return s in [0, 2**k) such that s**3 ≡ target (mod 2**k).

    Requires *target* to be odd; for odd targets the cube map is a bijection on
    the units mod 2**k, so the root exists and is unique. We build s one bit at
    a time (a Hensel-style lift):

      * s = 1 satisfies s**3 ≡ target (mod 2) because target is odd.
      * Suppose s**3 ≡ target (mod 2**i). Look at bit i. Setting bit i of s adds
        2**i, and (s + 2**i)**3 = s**3 + 3*s**2*2**i + ...  Since s is odd,
        3*s**2 is odd, so that cross term flips exactly bit i of the cube (and
        only touches bits >= i). So if bit i of s**3 disagrees with target, we
        set bit i of s to fix it, without disturbing the lower i bits.

    Why this is the crucial primitive: flipping a *high* bit of s never changes
    the *low* bits of s**3. That lets us nail the block's trailing bytes (the
    DigestInfo+hash "end") using only the low bits of s, leaving the high bits
    free to shape the block's leading bytes (the "00 01 FF..." start). The
    uncontrolled bits in between become the garbage middle the broken verifier
    fails to police.
    """
    if target & 1 == 0:
        raise ValueError("cube_root_mod_2k requires an odd target")
    s = 1
    for i in range(1, k):
        # If bit i of the current cube differs from the target, set bit i of s.
        if ((s * s * s) ^ target) & (1 << i):
            s |= (1 << i)
    return s

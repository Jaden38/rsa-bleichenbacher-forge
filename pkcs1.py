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

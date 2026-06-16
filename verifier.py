"""
verifier.py — Programme A: the deliberately broken PKCS#1 v1.5 verifier.

This is the vulnerable target. A *correct* verifier rebuilds the entire expected
block (00 01 FF...FF 00 DigestInfo HASH, filling the full modulus width) and
compares it byte-for-byte against s**e mod n. This one does NOT. Following the
TP spec for Sujet 3, it only checks that:

  * the START is well-formed  : 00 01, then >= 8 bytes of FF padding, then a
    00 separator  (regex  ^\\x00\\x01\\xff{8,}\\x00 ), and
  * the END is well-formed    : the block ends with DigestInfo || SHA-256(msg).

Everything *between* the separator and the trailing DigestInfo is never
inspected. That uncontrolled middle region is the entire vulnerability: the
verifier parses landmarks instead of reconstructing-and-comparing, and it never
checks that the FF padding runs all the way down to the DigestInfo (i.e. that
the hash sits at its *correct* offset, not merely somewhere at the end).

The contrast with the strict verifier (also provided, for the report) makes the
flaw concrete and testable.
"""

import re

from pkcs1 import (
    MIN_FF_PADDING,
    digest_info_suffix,
    i2osp,
    os2ip,
)

# Anchored regex for the "start is correct" landmark check.
#   \x00\x01      fixed PKCS#1 v1.5 block-type prefix (00 = leading, 01 = type 1)
#   \xff{8,}      padding string PS: AT LEAST 8 bytes of 0xFF (the only length
#                 constraint this broken verifier enforces)
#   \x00          the single 0x00 separator that ends the padding
# re.match anchors at offset 0, so this asserts the block *begins* this way.
# Crucially it does NOT assert the FF run continues up to the DigestInfo, nor
# that DigestInfo immediately follows the separator.
_START_RE = re.compile(rb"\x00\x01\xff{%d,}\x00" % MIN_FF_PADDING)


def broken_verify(message: bytes, signature: int, n: int, e: int) -> bool:
    """Return True if *signature* passes the LENIENT (vulnerable) check for
    *message* under public key (n, e).

    Steps mirror a real verifier up to the padding inspection, then cut corners:
    """
    k = (n.bit_length() + 7) // 8  # modulus width in bytes (256 for 2048-bit)

    # 1. "RSA decrypt" the signature with the PUBLIC key: m = s**e mod n.
    m = pow(signature, e, n)

    # 2. Encode the recovered integer back into a fixed-width byte block. A
    #    valid block has a leading 0x00, so the full width (with zero padding)
    #    is what the structural checks below expect.
    block = i2osp(m, k)

    # 3. START check (regex landmark): 00 01 FF{8,} 00 at the very beginning.
    if not _START_RE.match(block):
        return False

    # 4. END check (landmark): the block must finish with DigestInfo||HASH.
    #    This is where "the end is correct" is enforced -- and nothing about the
    #    bytes between step 3's separator and this suffix is ever looked at.
    suffix = digest_info_suffix(message)
    if not block.endswith(suffix):
        return False

    # 5. (Broken!) A correct verifier would now confirm the FF padding extends
    #    right up to the suffix -- i.e. that block == 00 01 FF...FF 00 suffix
    #    with NO gap. This verifier skips that, accepting any garbage middle.
    return True

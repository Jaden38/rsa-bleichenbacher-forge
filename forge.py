r"""
forge.py — Programme B: Bleichenbacher's RSA signature forgery (e = 3).

Goal: produce an integer `s` (the forged signature) such that the broken
verifier in verifier.py accepts it for an attacker-chosen message -- WITHOUT the
private key. We only use the public modulus n (and e = 3).

The verifier accepts any block of the shape

    00 01 FF FF ... FF 00 [ uncontrolled garbage ] 00 DigestInfo HASH
    \________ START it checks ________/             \___ END it checks ___/

so we must build a perfect cube  s**3  whose 256-byte big-endian encoding has
those exact START bytes and those exact END bytes, with anything in between.

Two independent anchors, glued by one structural fact about cubing:

  *  LOW bits of s**3 depend ONLY on the low bits of s.
     (s**3 mod 2^t is a function of s mod 2^t.)

So we split the work:

  1. SUFFIX (the END): choose the low bits of s so that s**3 ends in exactly
     `DigestInfo || HASH`. This is a cube root modulo a power of two
     (pkcs1.cube_root_mod_2k) -- the bit-by-bit Hensel lift. It pins the bottom
     ~408 bits of s.

  2. PREFIX (the START): the high bits of s control the top of s**3. We want
     s**3 to fall in the interval whose top bytes are `00 01 FF*8 00`. Take the
     integer cube root of the bottom of that interval to find where s must live;
     the interval is astronomically wide compared to the suffix-pinned bits, so
     we can satisfy BOTH constraints at once: pick the value congruent to the
     suffix root (mod 2^408) that lands inside the prefix interval.

  3. MIDDLE: whatever bits of s we did not constrain produce arbitrary middle
     bytes in s**3 -- exactly the "octets non controles" the verifier ignores.

Because s**3 stays well below n (a 2048-bit block starting 00 01... is ~2^2033,
the modulus is ~2^2047), s**3 mod n == s**3, so no modular wrap-around interferes.
"""

from pkcs1 import (
    MIN_FF_PADDING,
    cube_root_mod_2k,
    digest_info_suffix,
    i2osp,
    icbrt_ceil,
    os2ip,
)


def _ensure_odd_hash_message(base_message: bytes):
    """Return (message, suffix_bytes) where SHA-256(message) ends in an odd byte.

    The suffix cube root (cube_root_mod_2k) requires an ODD target, and the
    target's lowest byte is the hash's last byte. About half of all messages
    already hash to an odd last byte; for the rest we append an incrementing
    counter. The attacker is free to choose the message anyway (the TP says
    "message arbitraire choisi par l'attaquant"), so this tweak is legitimate
    and we surface the exact bytes that were signed."""
    counter = 0
    while True:
        message = base_message if counter == 0 else base_message + b":" + str(counter).encode()
        suffix = digest_info_suffix(message)
        if suffix[-1] & 1:  # odd last byte -> suffix integer is odd
            return message, suffix
        counter += 1


def forge_signature(base_message: bytes, n: int, e: int = 3, *, verbose: bool = False):
    """Forge a signature for *base_message* under public key (n, e=3).

    Returns (message, signature) where `message` is the exact bytes that were
    forged for (possibly base_message with a counter appended to get an odd
    hash) and `signature` is the integer forgery. Raises if e != 3 (this PoC
    targets the classic low-exponent case)."""
    if e != 3:
        raise ValueError("this forgery targets the e = 3 case only")

    k = (n.bit_length() + 7) // 8  # block width in bytes (256 for 2048-bit)

    # --- choose the message so the suffix integer is odd (cube-root-able) -----
    message, suffix = _ensure_odd_hash_message(base_message)
    suffix_int = os2ip(suffix)
    suffix_bits = len(suffix) * 8  # bits we will pin at the low end of s**3

    # --- ANCHOR 1: suffix root (pins the END of the block) -------------------
    # s_low has s_low**3 ≡ suffix_int (mod 2**suffix_bits), so the low
    # len(suffix) bytes of s_low**3 are exactly DigestInfo||HASH.
    s_low = cube_root_mod_2k(suffix_int, suffix_bits)
    if verbose:
        print(f"[forge] suffix is {len(suffix)} bytes ({suffix_bits} bits), root computed")

    # --- ANCHOR 2: prefix interval (pins the START of the block) -------------
    # We want s**3 to begin with these exact top bytes. Including the 00
    # separator in the prefix means the verifier's  ^00 01 FF+ 00  regex matches
    # on our fixed bytes regardless of the garbage that follows.
    prefix = b"\x00\x01" + (b"\xff" * MIN_FF_PADDING) + b"\x00"
    prefix_int = os2ip(prefix)

    # The block is k bytes; the prefix occupies the top len(prefix) bytes, so
    # any s**3 in [lo_block, hi_block) has exactly those leading bytes.
    shift_bits = (k - len(prefix)) * 8
    lo_block = prefix_int << shift_bits          # smallest block with this prefix
    hi_block = (prefix_int + 1) << shift_bits     # first block past it

    # s must satisfy  lo_block <= s**3 < hi_block, i.e. s in [icbrt_ceil(lo), icbrt(hi-1)].
    s_min = icbrt_ceil(lo_block)

    # --- GLUE: pick s ≡ s_low (mod 2**suffix_bits) with s >= s_min ------------
    # Adding any multiple of 2**suffix_bits keeps the suffix-pinned low bits
    # intact (anchor 1 preserved) while moving s up into the prefix interval
    # (anchor 2). The interval is ~2^600 wide vs a 2^408 step, so a valid s is
    # guaranteed and found almost immediately.
    modulus = 1 << suffix_bits
    s = s_min + ((s_low - s_min) % modulus)  # smallest s >= s_min with right low bits
    while s ** 3 < lo_block:
        s += modulus  # nudge up if rounding left us just below the interval

    if s ** 3 >= hi_block:
        # Would mean the prefix interval is narrower than one suffix step --
        # impossible for these sizes, but we assert rather than emit a bad forge.
        raise RuntimeError("prefix interval too narrow for suffix step (unexpected sizing)")

    if verbose:
        block = i2osp(s ** 3, k)
        print(f"[forge] forged block head: {block[:12].hex()}")
        print(f"[forge] forged block tail: {block[-len(suffix):].hex()}")

    return message, s


if __name__ == "__main__":
    # Stand-alone demo of the forge against the broken verifier.
    from rsa_keygen import load_key
    from verifier import broken_verify, strict_verify

    key = load_key()
    msg = b"attacker-chosen message: pay 1000000 to mallory"
    forged_msg, sig = forge_signature(msg, key["n"], key["e"], verbose=True)
    print("forged message:", forged_msg)
    print("broken_verify accepts forgery:", broken_verify(forged_msg, sig, key["n"], key["e"]))
    print("strict_verify accepts forgery:", strict_verify(forged_msg, sig, key["n"], key["e"]))

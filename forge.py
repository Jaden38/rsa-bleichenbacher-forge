"""Programme B: Bleichenbacher's e = 3 signature forgery (public key only).

We build a perfect cube s**3 whose 256-byte encoding is

    00 01 FF..FF 00 [ garbage ] 00 DigestInfo HASH

i.e. a valid-looking START and END with anything in between. Two independent
anchors, exploiting that the low bits of s**3 depend only on the low bits of s:

  * suffix (END): low bits of s, via cube_root_mod_2k, pin DigestInfo||HASH.
  * prefix (START): high bits of s, via icbrt, place 00 01 FF..FF 00 at the top.

The prefix interval (~2^600 wide) dwarfs the suffix step (2^408), so a single s
satisfies both. s**3 stays well below n, so s**3 mod n == s**3.
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
    """Pick a message whose hash ends in an odd byte (cube_root_mod_2k needs an
    odd target). The attacker chooses the message, so we append a counter."""
    counter = 0
    while True:
        message = base_message if counter == 0 else base_message + b":" + str(counter).encode()
        suffix = digest_info_suffix(message)
        if suffix[-1] & 1:
            return message, suffix
        counter += 1


def forge_signature(base_message: bytes, n: int, e: int = 3, *, verbose: bool = False):
    """Forge a signature accepted by broken_verify. Returns (message, signature),
    where message may carry an appended counter (see _ensure_odd_hash_message)."""
    if e != 3:
        raise ValueError("this forgery targets the e = 3 case only")

    k = (n.bit_length() + 7) // 8
    message, suffix = _ensure_odd_hash_message(base_message)
    suffix_bits = len(suffix) * 8

    # Anchor 1 — pin the END: low bits of s give s**3 ending in DigestInfo||HASH.
    s_low = cube_root_mod_2k(os2ip(suffix), suffix_bits)

    # Anchor 2 — pin the START: s**3 in [lo_block, hi_block) has these top bytes.
    # The 00 separator is baked in so broken_verify's regex matches any middle.
    prefix = b"\x00\x01" + (b"\xff" * MIN_FF_PADDING) + b"\x00"
    shift_bits = (k - len(prefix)) * 8
    lo_block = os2ip(prefix) << shift_bits
    hi_block = (os2ip(prefix) + 1) << shift_bits

    # Smallest s >= icbrt_ceil(lo_block) that keeps the suffix bits (≡ s_low).
    # Adding multiples of 2**suffix_bits preserves anchor 1 while reaching the
    # prefix interval; the interval is far wider than the step, so this lands.
    modulus = 1 << suffix_bits
    s_min = icbrt_ceil(lo_block)
    s = s_min + ((s_low - s_min) % modulus)
    while s ** 3 < lo_block:
        s += modulus
    if s ** 3 >= hi_block:
        raise RuntimeError("prefix interval too narrow for suffix step (unexpected sizing)")

    if verbose:
        block = i2osp(s ** 3, k)
        print(f"[forge] suffix {len(suffix)} bytes; block head {block[:12].hex()}")
        print(f"[forge] block tail {block[-len(suffix):].hex()}")

    return message, s


if __name__ == "__main__":
    from rsa_keygen import load_key
    from verifier import broken_verify, strict_verify

    key = load_key()
    msg = b"attacker-chosen message: pay 1000000 to mallory"
    forged_msg, sig = forge_signature(msg, key["n"], key["e"], verbose=True)
    print("forged message:", forged_msg)
    print("broken_verify accepts forgery:", broken_verify(forged_msg, sig, key["n"], key["e"]))
    print("strict_verify accepts forgery:", strict_verify(forged_msg, sig, key["n"], key["e"]))

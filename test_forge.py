"""Tests de bon fonctionnement autonomes (sans pytest). Lancer : python3 test_forge.py"""

import os

from forge import forge_signature
from pkcs1 import cube_root_mod_2k, digest_info_suffix, icbrt, icbrt_ceil, os2ip
from rsa_keygen import KEY_PATH, generate_key, load_key, save_key, sign
from verifier import broken_verify, strict_verify


def test_icbrt():
    for x in [0, 1, 7, 8, 9, 26, 27, 28, 10**30]:
        r = icbrt(x)
        assert r ** 3 <= x < (r + 1) ** 3, x
    assert icbrt(27) == 3 and icbrt(26) == 2
    assert icbrt_ceil(27) == 3 and icbrt_ceil(28) == 4


def test_cube_root_mod_2k():
    for t in [1, 3, 0x12345, (1 << 200) | 1]:
        k = max(8, t.bit_length() + 1)
        s = cube_root_mod_2k(t, k)
        assert (s ** 3) % (1 << k) == t % (1 << k), t
    try:
        cube_root_mod_2k(4, 16)  # une cible paire doit lever une exception
    except ValueError:
        pass
    else:
        raise AssertionError("even target should raise")


def _key():
    if os.path.exists(KEY_PATH):
        return load_key()
    k = generate_key()
    save_key(k)
    return k


def test_forge_end_to_end():
    key = _key()
    n, e = key["n"], key["e"]
    fmsg, sig = forge_signature(b"forge me please", n, e)
    assert broken_verify(fmsg, sig, n, e), "broken verifier must accept the forgery"
    assert not strict_verify(fmsg, sig, n, e), "strict verifier must reject the forgery"
    assert sig ** 3 < n, "s**3 must stay below the modulus for e=3 forgery"
    block = (sig ** 3).to_bytes((n.bit_length() + 7) // 8, "big")
    assert block.endswith(digest_info_suffix(fmsg))


def test_honest_signature_passes_both():
    key = _key()
    n, e = key["n"], key["e"]
    msg = b"legit"
    k = (n.bit_length() + 7) // 8
    suffix = digest_info_suffix(msg)
    block = b"\x00\x01" + b"\xff" * (k - 3 - len(suffix)) + b"\x00" + suffix
    sig = sign(os2ip(block), key)
    assert broken_verify(msg, sig, n, e)
    assert strict_verify(msg, sig, n, e)


def test_garbage_rejected():
    key = _key()
    n, e = key["n"], key["e"]
    for bad in [0, 1, 2, 42, n - 1]:
        assert not broken_verify(b"x", bad, n, e)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"ok  {t.__name__}")
    print(f"\nAll {len(tests)} tests passed.")

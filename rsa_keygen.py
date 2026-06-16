"""Generate a 2048-bit RSA key with e = 3, standard library only.

This is the only place a private key exists; the forge never touches it.
Run directly to (re)generate key.json.
"""

import json
import os
import sys

# Small primes for cheap trial division before Miller-Rabin.
_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
]


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin; 40 rounds gives a false-positive rate below 4**-40."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(rounds):
        a = 2 + int.from_bytes(os.urandom((n.bit_length() + 7) // 8), "big") % (n - 3)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits: int) -> int:
    while True:
        candidate = int.from_bytes(os.urandom((bits + 7) // 8), "big")
        candidate |= (1 << (bits - 1)) | 1  # force full length and oddness
        # Reject p ≡ 1 (mod 3): it would make gcd(3, p-1) = 3 and break e = 3.
        if candidate % 3 == 1:
            continue
        if _is_probable_prime(candidate):
            return candidate


def generate_key(bits: int = 2048, e: int = 3) -> dict:
    half = bits // 2
    while True:
        p = _random_prime(half)
        q = _random_prime(half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        d = pow(e, -1, (p - 1) * (q - 1))
        return {"n": n, "e": e, "d": d, "p": p, "q": q, "bits": bits}


def sign(message_hash_block: int, key: dict) -> int:
    """Honest signing primitive (demo sanity check only, not the attack)."""
    return pow(message_hash_block, key["d"], key["n"])


KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "key.json")


def save_key(key: dict, path: str = KEY_PATH) -> None:
    # JSON has no big-int type, so store the integers as decimal strings.
    with open(path, "w") as fh:
        json.dump({k: str(v) for k, v in key.items()}, fh, indent=2)


def load_key(path: str = KEY_PATH) -> dict:
    with open(path) as fh:
        raw = json.load(fh)
    return {k: int(v) for k, v in raw.items()}


if __name__ == "__main__":
    print("Generating a 2048-bit RSA key with e = 3 (this can take a few seconds)...")
    key = generate_key()
    save_key(key)
    print(f"Wrote {KEY_PATH}")
    print(f"  modulus bit length : {key['n'].bit_length()}")
    print(f"  public exponent e  : {key['e']}")
    token = 0x1234567890ABCDEF
    assert pow(pow(token, key["d"], key["n"]), key["e"], key["n"]) == token
    print("  round-trip self-check: OK", file=sys.stderr)

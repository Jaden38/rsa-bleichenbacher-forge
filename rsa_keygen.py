"""
rsa_keygen.py — Generate a 2048-bit RSA key with public exponent e = 3.

The TP requires a 2048-bit key "generated for the exercise" with e = 3. We hand
-roll the key generation with nothing but the standard library (Miller-Rabin
primality testing + os.urandom for entropy) so the project has no third-party
dependencies and every step is auditable. This is the ONE place a private key
exists; the attack (forge.py) never touches it.

Why e = 3 specifically? Bleichenbacher's forgery exploits that with a tiny
public exponent the "RSA decryption" of a signature is just s**e, and for e = 3
that is a plain cube. Cube roots are cheap to approximate with integers, which
is what makes the forgery tractable. e = 3 must be coprime to (p-1) and (q-1),
so we reject any prime p with p % 3 == 1.

Run directly to (re)generate key.json:
    python3 rsa_keygen.py
"""

import json
import os
import sys

# A handful of small primes for cheap trial division before the (more
# expensive) Miller-Rabin rounds. This rejects the ~80% of random odd numbers
# that have a small factor, massively speeding up prime search.
_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
]


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin probabilistic primality test.

    `rounds` random witnesses give a false-positive probability below 4**-rounds
    (~10**-24 at 40 rounds), which is comfortably negligible for a school PoC.
    """
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    # Write n-1 as d * 2**r with d odd.
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(rounds):
        # Random witness a in [2, n-2].
        a = 2 + int.from_bytes(os.urandom((n.bit_length() + 7) // 8), "big") % (n - 3)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # composite: no witness escaped to n-1
    return True


def _random_prime(bits: int) -> int:
    """Generate a random `bits`-bit prime p with p % 3 != 1 (so 3 stays
    coprime to p-1, a requirement for e = 3 to be a valid exponent)."""
    while True:
        candidate = int.from_bytes(os.urandom((bits + 7) // 8), "big")
        # Force the top bit (guarantee full bit length) and the bottom bit (odd).
        candidate |= (1 << (bits - 1)) | 1
        if candidate % 3 == 1:
            continue  # would make gcd(3, p-1) == 3, breaking e = 3
        if _is_probable_prime(candidate):
            return candidate


def generate_key(bits: int = 2048, e: int = 3) -> dict:
    """Generate an RSA key dict with fields n, e, d, p, q.

    We split the modulus bit length across two primes of `bits // 2` each. We
    loop until p != q and the private exponent d exists (it always does once
    both primes satisfy p % 3 != 1)."""
    half = bits // 2
    while True:
        p = _random_prime(half)
        q = _random_prime(half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue  # occasionally the product is 1 bit short; retry
        phi = (p - 1) * (q - 1)
        # d is the modular inverse of e modulo phi; pow(e, -1, phi) raises if it
        # does not exist, which our p % 3 != 1 guard already prevents.
        d = pow(e, -1, phi)
        return {"n": n, "e": e, "d": d, "p": p, "q": q, "bits": bits}


def sign(message_hash_block: int, key: dict) -> int:
    """Honest RSA signing primitive: s = block**d mod n.

    Only used by demo.py to show that a *legitimately* produced signature also
    passes the verifier — a sanity check, NOT part of the attack. Takes an
    already-encoded integer block so the encoding logic lives in one place."""
    return pow(message_hash_block, key["d"], key["n"])


KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "key.json")


def save_key(key: dict, path: str = KEY_PATH) -> None:
    """Persist the key as JSON (ints stored as decimal strings, since JSON has
    no big-integer type)."""
    with open(path, "w") as fh:
        json.dump({k: str(v) for k, v in key.items()}, fh, indent=2)


def load_key(path: str = KEY_PATH) -> dict:
    """Load a key previously written by save_key."""
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
    # Self-check: e*d ≡ 1 mod phi, so signing then verifying a token round-trips.
    token = 0x1234567890ABCDEF
    assert pow(pow(token, key["d"], key["n"]), key["e"], key["n"]) == token
    print("  round-trip self-check: OK", file=sys.stderr)

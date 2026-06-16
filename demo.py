"""PoC de bout en bout : une signature honnête passe les deux vérificateurs ; une
forgée (à partir de la seule clé publique) passe le défectueux mais échoue au strict.
"""

import os

from forge import forge_signature
from pkcs1 import digest_info_suffix, os2ip
from rsa_keygen import KEY_PATH, generate_key, load_key, save_key, sign
from verifier import broken_verify, strict_verify


def _honest_signature(message: bytes, key: dict) -> int:
    """Signature PKCS#1 v1.5 légitime (seul usage de la clé privée)."""
    k = (key["n"].bit_length() + 7) // 8
    suffix = digest_info_suffix(message)
    block = b"\x00\x01" + (b"\xff" * (k - 3 - len(suffix))) + b"\x00" + suffix
    return sign(os2ip(block), key)


def _row(label: str, value: bool) -> str:
    return f"  {label:<34} {'ACCEPT' if value else 'REJECT'}"


def main() -> None:
    if os.path.exists(KEY_PATH):
        key = load_key()
        print(f"Loaded existing key from {KEY_PATH}")
    else:
        print("No key found; generating a fresh 2048-bit e=3 key...")
        key = generate_key()
        save_key(key)
    n, e = key["n"], key["e"]
    print(f"  modulus bits = {n.bit_length()}, e = {e}\n")

    honest_msg = b"This message was signed by the legitimate key holder."
    honest_sig = _honest_signature(honest_msg, key)
    print("Honest signature (made WITH the private key):")
    print(_row("broken verifier", broken_verify(honest_msg, honest_sig, n, e)))
    print(_row("strict verifier", strict_verify(honest_msg, honest_sig, n, e)))
    print()

    target = b"TRANSFER 1000000 EUR TO mallory@evil.example"
    print(f"Forging a signature for attacker message:\n  {target!r}")
    print("  (using ONLY the public key n, e -- no private key)\n")
    forged_msg, forged_sig = forge_signature(target, n, e, verbose=True)
    if forged_msg != target:
        print(f"  note: appended counter for an odd hash -> signed bytes:\n  {forged_msg!r}")
    print()

    broken_ok = broken_verify(forged_msg, forged_sig, n, e)
    strict_ok = strict_verify(forged_msg, forged_sig, n, e)
    print("Forged signature:")
    print(_row("broken verifier (vulnerable)", broken_ok))
    print(_row("strict verifier (fixed)", strict_ok))
    print()

    if broken_ok and not strict_ok:
        print("RESULT: forgery ACCEPTED by the broken verifier and REJECTED by the")
        print("        strict one -- Bleichenbacher's attack reproduced successfully.")
    else:
        raise SystemExit("UNEXPECTED: the PoC did not behave as designed.")


if __name__ == "__main__":
    main()

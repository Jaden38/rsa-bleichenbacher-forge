"""Programme A : le vérificateur PKCS#1 v1.5 volontairement défectueux (+ un strict).

La faille : au lieu de reconstruire l'unique bloc attendu et de le comparer
octet par octet, broken_verify vérifie seulement que le DÉBUT et la FIN ont l'air
corrects, sans jamais contrôler que le bourrage FF descend jusqu'au DigestInfo.
Les octets entre les deux ne sont pas contrôlés — exactement la brèche exploitée.
"""

import re

from pkcs1 import MIN_FF_PADDING, digest_info_suffix, i2osp

# Balise de début : 00 01, >= 8 octets FF, puis un séparateur 00. Ancrée à
# l'offset 0, mais n'exige PAS que le bourrage atteigne le DigestInfo.
_START_RE = re.compile(rb"\x00\x01\xff{%d,}\x00" % MIN_FF_PADDING)


def broken_verify(message: bytes, signature: int, n: int, e: int) -> bool:
    k = (n.bit_length() + 7) // 8
    block = i2osp(pow(signature, e, n), k)

    if not _START_RE.match(block):
        return False
    # Contrôle de FIN seulement ; le milieu entre séparateur et suffixe est ignoré.
    return block.endswith(digest_info_suffix(message))


def strict_verify(message: bytes, signature: int, n: int, e: int) -> bool:
    """Vérificateur correct : reconstruit l'unique bloc valide et compare exactement."""
    k = (n.bit_length() + 7) // 8
    block = i2osp(pow(signature, e, n), k)

    suffix = digest_info_suffix(message)
    ff_len = k - 3 - len(suffix)
    if ff_len < MIN_FF_PADDING:
        return False
    expected = b"\x00\x01" + (b"\xff" * ff_len) + b"\x00" + suffix
    return block == expected


if __name__ == "__main__":
    from rsa_keygen import load_key

    key = load_key()
    print("random signature, broken_verify:", broken_verify(b"hello", 42, key["n"], key["e"]))
    print("random signature, strict_verify:", strict_verify(b"hello", 42, key["n"], key["e"]))

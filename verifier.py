r"""Programme A : le vérificateur PKCS#1 v1.5 volontairement défectueux (+ un strict).

Une signature valide, « déchiffrée » avec la clé publique (s**e mod n), redonne
un bloc de la largeur du module :

    00 01 FF FF ... FF 00 <DigestInfo> <HASH>
    \__/ \__________/ \/ \__________________/
    préfixe  bourrage  séparateur   suffixe à vérifier
             (>= 8 FF)              (DigestInfo + empreinte)

La faille : au lieu de RECONSTRUIRE cet unique bloc attendu et de le comparer
octet par octet (ce que fait strict_verify), broken_verify se contente de
RECONNAÎTRE des balises — un DÉBUT correct et une FIN correcte — sans jamais
contrôler que le bourrage FF descend bien jusqu'au DigestInfo. Autrement dit, il
ne vérifie pas que l'empreinte est à sa BONNE position, seulement qu'elle est
quelque part à la fin. Les octets entre le séparateur et le suffixe ne sont donc
pas contrôlés : c'est exactement la brèche que la forge exploite.
"""

import re

from pkcs1 import MIN_FF_PADDING, digest_info_suffix, i2osp

# Balise de début : 00 01, puis >= 8 octets FF, puis un séparateur 00. re.match
# ancre à l'offset 0, donc on impose bien que le bloc COMMENCE ainsi — mais on
# n'exige PAS que la suite de FF se prolonge jusqu'au DigestInfo. C'est ce « non
# dit » de la regex qui laisse un trou exploitable.
_START_RE = re.compile(rb"\x00\x01\xff{%d,}\x00" % MIN_FF_PADDING)


def broken_verify(message: bytes, signature: int, n: int, e: int) -> bool:
    k = (n.bit_length() + 7) // 8
    block = i2osp(pow(signature, e, n), k)   # « déchiffrement » RSA public : s**e mod n

    # Contrôle 1 (DÉBUT) : la regex de balise. Échoue si le préfixe/bourrage manque.
    if not _START_RE.match(block):
        return False
    # Contrôle 2 (FIN) : le bloc se termine par DigestInfo||HASH. C'est tout — rien
    # n'est vérifié entre le séparateur (contrôle 1) et ce suffixe, d'où la faille.
    return block.endswith(digest_info_suffix(message))


def strict_verify(message: bytes, signature: int, n: int, e: int) -> bool:
    """Vérificateur correct : reconstruit l'unique bloc valide et compare exactement."""
    k = (n.bit_length() + 7) // 8
    block = i2osp(pow(signature, e, n), k)

    suffix = digest_info_suffix(message)
    # Le bourrage doit remplir TOUT l'espace entre 00 01 / séparateur 00 et le suffixe :
    # il y a donc une seule longueur de FF possible, et un seul bloc valide. On le
    # reconstruit puis on compare octet par octet — aucune place pour du « garbage ».
    ff_len = k - 3 - len(suffix)
    if ff_len < MIN_FF_PADDING:
        return False   # empreinte trop grande pour le module (n'arrive pas ici)
    expected = b"\x00\x01" + (b"\xff" * ff_len) + b"\x00" + suffix
    return block == expected


if __name__ == "__main__":
    from rsa_keygen import load_key

    key = load_key()
    print("random signature, broken_verify:", broken_verify(b"hello", 42, key["n"], key["e"]))
    print("random signature, strict_verify:", strict_verify(b"hello", 42, key["n"], key["e"]))

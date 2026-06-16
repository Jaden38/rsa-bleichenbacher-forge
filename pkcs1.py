"""Constantes PKCS#1 v1.5 et arithmétique entière partagées (clé publique seule).

Tous les calculs utilisent les grands entiers Python, jamais des flottants : la
mantisse ~53 bits d'un double se tromperait de centaines de bits sur une racine
cubique de 2048 bits.
"""

import hashlib

# En-tête DigestInfo ASN.1 DER pour SHA-256 ; doit être exact à l'octet près,
# sinon la vérification (réelle ou forgée) échoue silencieusement. Constante
# publiée, recopiée et non devinée.
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")

# PKCS#1 impose au moins 8 octets de bourrage 0xFF ; le vérificateur défectueux
# ne contrôle que cette borne basse (et rien sur l'endroit où le bourrage finit).
MIN_FF_PADDING = 8


def sha256(message: bytes) -> bytes:
    return hashlib.sha256(message).digest()


def digest_info_suffix(message: bytes) -> bytes:
    """DigestInfo || SHA-256(message) : les octets de fin d'un bloc valide."""
    return SHA256_DIGEST_INFO + sha256(message)


def i2osp(x: int, length: int) -> bytes:
    """Entier vers octets big-endian de largeur fixe (conserve l'octet 0x00 de tête)."""
    return x.to_bytes(length, "big")


def os2ip(octets: bytes) -> int:
    return int.from_bytes(octets, "big")


def icbrt(n: int) -> int:
    """floor(n ** (1/3)), exact, par recherche dichotomique (invariant lo**3 <= n)."""
    if n < 0:
        raise ValueError("icbrt is defined for non-negative integers only")
    if n < 2:
        return n
    lo, hi = 0, 1
    while hi ** 3 <= n:
        hi <<= 1
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if mid ** 3 <= n:
            lo = mid
        else:
            hi = mid
    return lo


def icbrt_ceil(n: int) -> int:
    r = icbrt(n)
    return r if r ** 3 == n else r + 1


def cube_root_mod_2k(target: int, k: int) -> int:
    """Renvoie s dans [0, 2**k) tel que s**3 ≡ target (mod 2**k) ; target impair.

    Construit bit par bit (remontée de Hensel) : pour s impair, poser le bit i de
    s bascule exactement le bit i de s**3 et laisse les bits inférieurs intacts
    (le terme croisé 3*s**2*2^i est impair*2^i). On remonte donc en corrigeant
    chaque bit en désaccord. C'est ce qui permet à la forge de figer les octets
    bas du bloc (suffixe) indépendamment de ses octets hauts.
    """
    if target & 1 == 0:
        raise ValueError("cube_root_mod_2k requires an odd target")
    s = 1
    for i in range(1, k):
        if ((s * s * s) ^ target) & (1 << i):
            s |= (1 << i)
    return s

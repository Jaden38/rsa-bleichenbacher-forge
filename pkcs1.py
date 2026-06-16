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
    """floor(n ** (1/3)), exact, par recherche dichotomique (invariant lo**3 <= n).

    On reste en entiers : `round(n ** (1/3))` passerait par un float, dont la
    mantisse ~53 bits est très insuffisante face à un n de ~2000 bits et donnerait
    une racine fausse de centaines de bits. La dichotomie ci-dessous est exacte.
    """
    if n < 0:
        raise ValueError("icbrt is defined for non-negative integers only")
    if n < 2:
        return n
    lo, hi = 0, 1
    while hi ** 3 <= n:          # double hi jusqu'à dépasser n (borne haute sûre)
        hi <<= 1
    while hi - lo > 1:           # invariant : lo**3 <= n < hi**3
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

    Pourquoi target doit être impair : sur les unités de Z/2**k (les impairs),
    x ↦ x**3 est une bijection (3 est premier avec l'ordre 2**(k-1) du groupe),
    donc tout impair a une racine cubique unique mod 2**k. Pour un target pair il
    n'y en a en général pas — d'où le ValueError (la forge contourne en choisissant
    un message dont l'empreinte finit impaire).

    Méthode : remontée bit par bit (lemme de Hensel). Invariant après l'étape i :
    s**3 ≡ target (mod 2**(i+1)).
      * s = 1 démarre l'invariant mod 2 (target impair).
      * Pour s impair, (s + 2**i)**3 = s**3 + 3*s**2*2**i + ... : le terme 3*s**2*2**i
        est impair*2**i, donc poser le bit i de s bascule EXACTEMENT le bit i de s**3
        sans toucher aux bits < i. On corrige donc le bit i ssi il est en désaccord.
    C'est ce verrouillage des bits bas qui permet à la forge de figer le suffixe du
    bloc indépendamment de son préfixe.
    """
    if target & 1 == 0:
        raise ValueError("cube_root_mod_2k requires an odd target")
    s = 1
    for i in range(1, k):
        # bit i du cube courant en désaccord avec la cible ? -> on pose le bit i de s
        if ((s * s * s) ^ target) & (1 << i):
            s |= (1 << i)
    return s

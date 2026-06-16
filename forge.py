"""Programme B : la forge de signature de Bleichenbacher pour e = 3 (clé publique seule).

On construit un cube parfait s**3 dont l'encodage sur 256 octets vaut

    00 01 FF..FF 00 [ garbage ] 00 DigestInfo HASH

c'est-à-dire un DÉBUT et une FIN d'apparence valide, avec n'importe quoi entre
les deux. Deux ancrages indépendants, exploitant que les bits bas de s**3 ne
dépendent que des bits bas de s :

  * suffixe (FIN) : les bits bas de s, via cube_root_mod_2k, fixent DigestInfo||HASH.
  * préfixe (DÉBUT) : les bits hauts de s, via icbrt, placent 00 01 FF..FF 00 en tête.

L'intervalle du préfixe (~2^600 de large) écrase le pas du suffixe (2^408), donc
un seul s satisfait les deux. s**3 reste bien sous n, donc s**3 mod n == s**3.
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
    """Choisit un message dont l'empreinte finit par un octet impair (cube_root_mod_2k
    exige une cible impaire). L'attaquant choisit le message : on ajoute un compteur."""
    counter = 0
    while True:
        message = base_message if counter == 0 else base_message + b":" + str(counter).encode()
        suffix = digest_info_suffix(message)
        if suffix[-1] & 1:
            return message, suffix
        counter += 1


def forge_signature(base_message: bytes, n: int, e: int = 3, *, verbose: bool = False):
    """Forge une signature acceptée par broken_verify. Renvoie (message, signature),
    où message peut porter un compteur ajouté (cf. _ensure_odd_hash_message)."""
    if e != 3:
        raise ValueError("this forgery targets the e = 3 case only")

    k = (n.bit_length() + 7) // 8
    message, suffix = _ensure_odd_hash_message(base_message)
    suffix_bits = len(suffix) * 8

    # Ancrage 1 — fixer la FIN : les bits bas de s donnent s**3 finissant par DigestInfo||HASH.
    s_low = cube_root_mod_2k(os2ip(suffix), suffix_bits)

    # Ancrage 2 — fixer le DÉBUT : s**3 dans [lo_block, hi_block) a ces octets de tête.
    # Le séparateur 00 est inclus pour que la regex de broken_verify matche tout milieu.
    prefix = b"\x00\x01" + (b"\xff" * MIN_FF_PADDING) + b"\x00"
    shift_bits = (k - len(prefix)) * 8
    lo_block = os2ip(prefix) << shift_bits
    hi_block = (os2ip(prefix) + 1) << shift_bits

    # Plus petit s >= icbrt_ceil(lo_block) qui conserve les bits du suffixe (≡ s_low).
    # Ajouter des multiples de 2**suffix_bits préserve l'ancrage 1 tout en atteignant
    # l'intervalle du préfixe ; l'intervalle est bien plus large que le pas, donc ça tombe.
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

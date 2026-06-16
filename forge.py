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

    k = (n.bit_length() + 7) // 8          # largeur du bloc en octets (256 pour 2048 bits)
    message, suffix = _ensure_odd_hash_message(base_message)
    suffix_bits = len(suffix) * 8          # nombre de bits bas de s**3 que l'on impose

    # --- Ancrage 1 : fixer la FIN du bloc (le suffixe DigestInfo||HASH) ----------------
    # On veut que les octets de poids faible de s**3 soient exactement DigestInfo||HASH,
    # c.-à-d. s**3 ≡ suffixe (mod 2**suffix_bits). cube_root_mod_2k résout cette congruence
    # et renvoie s_low. Conséquence clé : s**3 mod 2**suffix_bits ne dépend QUE de
    # s mod 2**suffix_bits, donc tant que les bits bas de s valent s_low, la FIN est correcte —
    # quels que soient les bits hauts. On garde ainsi toute liberté sur le DÉBUT (ancrage 2).
    s_low = cube_root_mod_2k(os2ip(suffix), suffix_bits)

    # --- Ancrage 2 : fixer le DÉBUT du bloc (le préfixe 00 01 FF..FF 00) ---------------
    # On choisit les octets de tête imposés et on les place en haut d'un bloc de k octets.
    # Tout entier dans [lo_block, hi_block) a EXACTEMENT ces octets de tête : lo_block est
    # ce préfixe suivi de zéros, hi_block le préfixe incrémenté de 1 (donc on couvre toutes
    # les valeurs des octets bas en gardant le préfixe figé). On inclut le séparateur 00
    # dans le préfixe pour que la regex ^00 01 FF+ 00 de broken_verify matche, peu importe
    # le « garbage » qui suit.
    prefix = b"\x00\x01" + (b"\xff" * MIN_FF_PADDING) + b"\x00"
    shift_bits = (k - len(prefix)) * 8
    lo_block = os2ip(prefix) << shift_bits
    hi_block = (os2ip(prefix) + 1) << shift_bits

    # --- Recollage des deux ancrages (style restes chinois sur les puissances de 2) ----
    # Il faut un s tel que s**3 ∈ [lo_block, hi_block) (DÉBUT) ET s ≡ s_low (mod 2**suffix_bits)
    # (FIN). On part du plus petit s dont le cube atteint l'intervalle, icbrt_ceil(lo_block),
    # puis on le « recale » sur la bonne classe de congruence modulo 2**suffix_bits. Ajouter
    # des multiples de ce module ne change jamais les bits bas (FIN préservée) et fait monter
    # s pour entrer dans l'intervalle du préfixe. Comme cet intervalle (~2**600 en s) est très
    # large devant le pas (2**408), un s valide existe toujours et est trouvé en quelques pas.
    modulus = 1 << suffix_bits
    s_min = icbrt_ceil(lo_block)
    s = s_min + ((s_low - s_min) % modulus)   # plus petit s >= s_min avec s ≡ s_low (mod modulus)
    while s ** 3 < lo_block:                   # le recalage a pu nous laisser juste sous l'intervalle
        s += modulus
    if s ** 3 >= hi_block:
        # Impossible avec ce dimensionnement (intervalle ≫ pas) ; on échoue franchement
        # plutôt que de renvoyer une forge invalide.
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

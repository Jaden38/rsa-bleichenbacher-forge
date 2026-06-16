# rsa-bleichenbacher-forge

**TP PoC Crypto — Sujet 3 : Forge de signature RSA par faute (attaque de Bleichenbacher, 2006)**

> Preuve de concept de l'attaque de Bleichenbacher contre un vérificateur de
> signatures RSA-PKCS#1 v1.5 **laxiste** (vérification du padding « façon regex »)
> avec exposant public faible **e = 3** et module **2048 bits**. On forge une
> signature valide pour un message arbitraire **sans jamais utiliser la clé
> privée**.

## Auteur

- Damien Nithard - M2 AL

## Rappel du sujet (Sujet 3)

- **Programme A — Vérificateur vulnérable** : implémenter un vérificateur
  RSA-PKCS#1 v1.5 qui vérifie le padding **incorrectement** : au lieu de
  reconstruire le bloc attendu et de le comparer octet par octet, il contrôle
  seulement que **le début et la fin** sont corrects (style regex), laissant des
  octets **non contrôlés** au milieu. Clé RSA 2048 bits, e = 3.
- **Programme B — Forge** : implémenter l'attaque de Bleichenbacher, c'est-à-dire
  construire mathématiquement une valeur dont le cube (cas e = 3) donne un bloc
  qui passe la vérification défectueuse, pour un message choisi par l'attaquant.

## Contenu du dépôt

| Fichier | Rôle |
|---|---|
| `pkcs1.py` | Constantes PKCS#1 (DigestInfo SHA-256) + arithmétique entière : racine cubique entière, **racine cubique modulo 2^k** (cœur de la forge). |
| `rsa_keygen.py` | Génération maison d'une clé RSA 2048 bits avec e = 3 (Miller-Rabin, bibliothèque standard uniquement). **Seul endroit où une clé privée existe.** |
| `verifier.py` | **Programme A** : `broken_verify` (vulnérable) + `strict_verify` (correct, = le correctif). |
| `forge.py` | **Programme B** : `forge_signature`, la construction « garbage-in-the-middle ». N'utilise que la clé publique. |
| `demo.py` | Démonstration de bout en bout : clé → signature honnête → forge → vérifications. |
| `test_forge.py` | Tests sans dépendance (primitives mathématiques + attaque complète). |

## Installation & utilisation

Aucune dépendance externe : **Python 3.8+** et la bibliothèque standard suffisent
(`hashlib`, `os`, `re`, `json`).

```bash
# 1. (optionnel) générer une nouvelle clé 2048 bits e=3 -> key.json
python3 rsa_keygen.py

# 2. démonstration complète de l'attaque
python3 demo.py

# 3. lancer les tests
python3 test_forge.py
```

`demo.py` génère automatiquement `key.json` s'il est absent. Sortie attendue :
la signature honnête est acceptée par les deux vérificateurs ; la **signature
forgée** est **acceptée par le vérificateur laxiste** et **rejetée par le
vérificateur strict**.

---

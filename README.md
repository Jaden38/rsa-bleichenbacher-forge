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

# Rapport

## 1. Structure du padding PKCS#1 v1.5 et faille exploitée

### Le bloc de signature correct

Une signature RSA-PKCS#1 v1.5 d'un message *m* est `s = (EM)^d mod n`, où le
**message encodé** `EM` remplit *toute* la largeur du module (256 octets pour
2048 bits) selon la structure suivante :

```
00 01 FF FF ... FF 00 │ DigestInfo │ HASH
└┬┘ └┬┘ └────┬────┘ └┬┘ └────┬─────┘ └─┬─┘
 │   │       │       │       │         └─ empreinte du message (SHA-256 = 32 o)
 │   │       │       │       └─ en-tête ASN.1 DER identifiant l'algo de hachage
 │   │       │       └─ séparateur 0x00 unique
 │   │       └─ chaîne de bourrage PS : des 0xFF, AU MOINS 8, qui remplissent
 │   │          tout l'espace restant
 │   └─ type de bloc (01 = signature)
 └─ octet de tête nul (garantit EM < n)
```

Pour SHA-256, le `DigestInfo` vaut exactement (19 octets) :
`30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20`.

La vérification consiste à calculer `EM' = s^e mod n` puis à confirmer que `EM'`
**est** ce bloc. Le point essentiel : pour un message et une clé donnés, **il
n'existe qu'un seul `EM` valide**. La bonne façon de vérifier est donc de
**reconstruire** `EM` et de le **comparer octet par octet**.

### La faille (et pourquoi e = 3 l'aggrave)

Le vérificateur vulnérable **analyse** le bloc au lieu de le reconstruire. Il
repère des « balises » :

- au **début** : `00 01`, une suite de `FF` (au moins 8), puis un `00` —
  en regex : `^\x00\x01\xff{8,}\x00` ;
- à la **fin** : le bloc se termine par `DigestInfo || HASH`.

…mais il **ne vérifie pas** que le bourrage `FF` descend bien jusqu'au
`DigestInfo`, autrement dit que le hash est à sa **position correcte**. Tout ce
qui se trouve entre le séparateur et le `DigestInfo` final est **ignoré**
(cf. `verifier.py`, `broken_verify`, étape 5). Voilà les « octets non
contrôlés » du sujet.

L'exposant `e = 3` transforme cette négligence en attaque pratique : « déchiffrer »
la signature revient à calculer un simple **cube** `s^3`. Comme un bloc valide
commence par `00 01…`, il vaut environ `2^2033`, très en deçà du module
(`≈ 2^2047`) ; donc `s^3 mod n = s^3` (pas de réduction modulaire). Forger une
signature se ramène alors à **fabriquer un cube parfait** dont les octets de
début et de fin sont imposés — un problème de racine cubique, abordable avec de
l'arithmétique entière. (Avec un grand exposant, p. ex. 65537, il faudrait
extraire une racine e-ième exacte sous contrainte, ce qui n'a pas de solution
simple : c'est pourquoi l'attaque vise les petits exposants.)

## 2. Construction mathématique de la forge

On veut un entier `s` tel que les 256 octets de `s^3` aient la forme :

```
00 01 FF…FF 00 │  …  garbage  …  │ 00 DigestInfo HASH
└─ DÉBUT vérifié ┘                 └─── FIN vérifiée ───┘
```

La construction repose sur **un fait structurel du cube** :

> Les bits **de poids faible** de `s^3` ne dépendent que des bits de poids
> faible de `s` (formellement, `s^3 mod 2^t` ne dépend que de `s mod 2^t`).

On découpe donc le travail en deux ancrages **indépendants**, recollés à la fin.

### Ancrage 1 — la FIN (suffixe) : racine cubique modulo 2^k

On veut que `s^3` se termine **exactement** par `DigestInfo || HASH`
(51 octets = 408 bits). Cela revient à résoudre

```
s_low^3 ≡ (DigestInfo || HASH)   (mod 2^408)
```

Pour une cible **impaire**, l'élévation au cube est une bijection sur les unités
modulo `2^k` : la racine existe et est unique. On la calcule **bit par bit**
(remontée de Hensel, `pkcs1.cube_root_mod_2k`) :

- `s = 1` convient modulo 2 (la cible est impaire) ;
- en supposant `s^3 ≡ cible (mod 2^i)`, poser le bit *i* de `s` ajoute `2^i` ;
  le terme croisé `3·s²·2^i` (avec `s` impair, donc `3·s²` impair) **bascule
  exactement le bit *i* de `s^3`** sans toucher aux bits inférieurs. On corrige
  donc le bit *i* si nécessaire et on monte.

> La cible doit être impaire, c.-à-d. le dernier octet du hash impair. Comme
> l'attaquant **choisit le message**, `forge.py` ajoute au besoin un compteur au
> message jusqu'à obtenir une empreinte impaire (`_ensure_odd_hash_message`).
> Le message exactement signé est affiché.

Cet ancrage **fige les ~408 bits de poids faible** de `s`.

### Ancrage 2 — le DÉBUT (préfixe) : racine cubique entière

On veut que les **octets de tête** de `s^3` soient `00 01 FF…FF 00`. Soit
`P` l'entier formé par ces octets de préfixe placés en haut d'un bloc de `k`
octets. Tout cube tombant dans l'intervalle

```
[ P · 2^s , (P+1) · 2^s )      avec  s = 8·(k − longueur_préfixe)
```

possède exactement ces octets de tête. Il suffit donc que
`s ∈ [⌈(P·2^s)^{1/3}⌉, …)`. On calcule cette borne via une **racine cubique
entière exacte** (`pkcs1.icbrt`, recherche dichotomique, sans flottants — un
double n'a que ~53 bits de mantisse et fausserait tout).

### Recollage (et le MILIEU non contrôlé)

L'intervalle du préfixe est **gigantesque** comparé au pas de l'ancrage 1 :
sa largeur en `s` est de l'ordre de `2^600`, contre un pas de `2^408`. On choisit
donc le `s` qui est :

- **≡ s_low (mod 2^408)** → la FIN reste correcte (ajouter un multiple de
  `2^408` ne change jamais les bits faibles de `s^3`), et
- **dans l'intervalle du préfixe** → le DÉBUT est correct.

Comme `2^600 ≫ 2^408`, un tel `s` existe toujours et se trouve immédiatement
(`forge.py`). Les bits de `s` laissés libres produisent des octets **arbitraires
au milieu** de `s^3` : précisément les octets que le vérificateur laxiste ne
regarde pas. On inclut le séparateur `00` dans le préfixe figé, ce qui garantit
que la regex `^\x00\x01\xff+\x00` matche quel que soit le contenu du milieu.

Le résultat `s` est la **signature forgée** ; aucune clé privée n'intervient.

### Schéma de la construction

Comment les bits de `s` (la signature forgée, ~683 bits) gouvernent les octets de
`s^3` (le bloc déchiffré de 256 octets que le vérificateur inspecte) :

```
                           s   (la signature forgée, ~683 bits)
   ┌──────────────────────────┬───────────────────────────┬───────────────────────┐
   │  bits HAUTS              │       bits du MILIEU        │     bits BAS (408)    │
   │  réglés via icbrt(...)   │        (laissés libres)     │  s_low = racine       │
   │  → ancrage du PRÉFIXE    │                             │  cubique mod 2^408    │
   │                          │                             │  → ancrage du SUFFIXE │
   └────────────┬─────────────┴──────────────┬──────────────┴───────────┬───────────┘
                │ pilotent le HAUT de s^3     │ octets quelconques        │ pilotent le
                │  (intervalle [P·2^s,(P+1)·2^s))                          │  BAS de s^3
                ▼                             ▼                           ▼
                                    élévation au cube  (e = 3)
                ▼                             ▼                           ▼
   s^3  =  bloc de 256 octets  (s^3 < n  ⇒  s^3 mod n = s^3, pas de réduction) :
   ┌──────────────────────────┬───────────────────────────┬───────────────────────┐
   │  00 01 FF…FF 00          │   …  GARBAGE  (non vérifié) │  00 DigestInfo HASH   │
   │  ◄── DÉBUT vérifié ──►   │                             │  ◄── FIN vérifiée ──► │
   │  ^\x00\x01\xff{8,}\x00   │     « octets non contrôlés »│  block.endswith(...)  │
   └──────────────────────────┴───────────────────────────┴───────────────────────┘
        ▲                                                             ▲
        │ Fait clé : les bits BAS de s^3 ne dépendent QUE des bits    │
        │ bas de s. On fige donc la FIN sans perturber le DÉBUT, et   │
        └─ inversement — le MILIEU absorbe tout le reste. ────────────┘
```

Flux de l'attaque (qui ne touche jamais la clé privée) :

```
  message attaquant ─► SHA-256 (rendu impair) ─► DigestInfo‖HASH = SUFFIXE
                                                        │
        PRÉFIXE 00 01 FF…FF 00 ──┐                      ▼
                                 ├─► racine cubique mod 2^408  ─► s_low
        n (clé PUBLIQUE) ──► icbrt(P·2^s) ─► borne ────┐        │
                                                        ▼        ▼
                              recollage : s ≡ s_low (mod 2^408) ∩ intervalle préfixe
                                                        │
                                                        ▼
                                       s  =  SIGNATURE FORGÉE
                                                        │
                              broken_verify(message, s, n, e=3)  ─► ACCEPT ✓
                              strict_verify(message, s, n, e=3)  ─► REJECT ✗
```

## 3. Implémentations réelles touchées

L'attaque, présentée par Daniel Bleichenbacher au rump session de CRYPTO 2006,
a frappé de nombreuses bibliothèques à exposant faible (souvent e = 3) au fil des
années — la même faute de « parsing au lieu de reconstruction » réapparaissant
régulièrement :

- **OpenSSL** — **CVE-2006-4339** : acceptait du contenu après le hash
  (octets de fin non contrôlés), forge par racine cubique.
- **Mozilla NSS** (Firefox, Thunderbird) — **CVE-2006-4340**, même vague de 2006.
- **GnuTLS** — **CVE-2006-4790**, variante de la même négligence de padding.
- **python-rsa** — **CVE-2016-1494** : variante « octets de fin » remise en
  lumière par Filippo Valsorda dix ans plus tard.
- **Bouncy Castle**, **Apache XML Security**, et d'autres ont connu des
  variantes ; la conférence Black Hat USA 2019 *« A Decade After Bleichenbacher
  '06 »* a montré que la forge fonctionnait **encore** sur plusieurs
  implémentations en 2019 (notamment certaines vérifications « début ET fin »
  laissant le milieu libre — exactement le cas de ce TP).

Point commun : un vérificateur qui **cherche des motifs** dans le bloc déchiffré
au lieu de **régénérer l'unique bloc valide et de comparer**.

## 4. Correction

1. **Vérification stricte du padding (reconstruction + comparaison).** Ne jamais
   « parser » le bloc déchiffré. Reconstruire l'unique `EM` attendu
   (`00 01 FF…FF 00 DigestInfo HASH`, bourrage complet) et comparer **octet par
   octet**, de préférence en **temps constant**. C'est ce que fait
   `strict_verify` dans ce dépôt — il **rejette** notre forge (voir `demo.py`).
2. **Migrer vers RSASSA-PSS.** PSS introduit un sel aléatoire et une structure
   probabiliste avec preuve de sécurité ; il n'y a pas de « bloc à motifs » à
   contourner, ce qui élimine cette classe d'attaques par malléabilité.
3. **Défenses complémentaires.** Éviter les exposants publics faibles (utiliser
   e = 65537) réduit drastiquement la marge dont dispose l'attaquant ; et
   imposer la longueur exacte attendue du bloc.

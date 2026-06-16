# rsa-bleichenbacher-forge

**TP PoC Crypto — Sujet 3 : Forge de signature RSA par faute (attaque de Bleichenbacher, 2006)**

> Preuve de concept de l'attaque de Bleichenbacher contre un vérificateur de
> signatures RSA-PKCS#1 v1.5 **laxiste** (vérification du padding « façon regex »)
> avec exposant public faible **e = 3** et module **2048 bits**. On forge une
> signature valide pour un message arbitraire **sans jamais utiliser la clé
> privée**.

## Auteur

- Damien Nithard - M2 AL

# ICES, IntrepidCore Engineering Standard

ICES est un standard de scellement cryptographique pour les notes de calcul d'ingénierie. Il rend une décision d'ingénierie **attribuable, datée et non répudiable** : un financeur, un bureau de contrôle ou un assureur peut vérifier, seul et hors ligne, qu'un calcul n'a pas été modifié depuis sa signature et qu'il vient bien de la clé qui l'a signé.

ICES **ne rend pas la fraude physique impossible**. Un sceau atteste l'intégrité et l'origine d'un document ; la validité physique du modèle reste soumise à l'examen de l'ingénieur.

ICES est **gratuit à produire et à vérifier**.

## État du dépôt

Pré-publication, spécification **v0.1**, livre blanc **v4.0** (en relecture). Ce dépôt est privé jusqu'à la publication prévue le 2 novembre 2026.

- Le **vérificateur de référence** est un script Python en ligne de commande. Il applique la spécification et le livre blanc : arrondi par champ, canonicalisation JCS (RFC 8785), condensat SHA3-256, signature Ed25519, liste locale de clés de confiance avec dates de validité et de révocation, refus par défaut sans liste.
- Le **vérificateur de production** (binaire Rust hors ligne, `ices-core`) est en développement : voir `verifier/rust/`.
- Ne sont pas implémentés (Phases 2 et 3 de la feuille de route) : journal de transparence, horodatage en deux paliers, attestation agrafée, Manifeste de Projet. Le tableau d'avancement du livre blanc (section 10) donne le niveau d'affirmation de chaque mécanisme.

## Contenu

| Dossier | Contenu | Licence |
|---|---|---|
| `spec/` | Spécification ICES v0.1 (source LaTeX et PDF), schéma JSON du MissionBundle | CC BY 4.0 |
| `whitepaper/` | Livre blanc ICES v4.0 (source LaTeX, PDF, bibliographie, figures) | CC BY 4.0 |
| `test-vectors/` | Six sceaux d'exemple et la liste de clés de confiance de démonstration | Apache-2.0 |
| `verifier/python/` | Vérificateur de référence hors ligne | Apache-2.0 |
| `verifier/rust/` | Vérificateur de production (à venir) | Apache-2.0 |
| `tests/` | Tests du vérificateur (RFC 8785, did:key, condensat, vecteurs) | Apache-2.0 |
| `tools/` | Générateur des vecteurs de test | Apache-2.0 |
| `assets/` | Logos IntrepidCore et IntrepidLab | **non couverts** (voir plus bas) |

## Vérifier un sceau

Il faut Python 3 et la bibliothèque `pynacl`.

```bash
pip install pynacl
python verifier/python/ices_verify.py test-vectors/example-bundle.json --trusted-keys test-vectors/trusted-keys.json
python verifier/python/ices_verify.py test-vectors/tampered-bundle.json --trusted-keys test-vectors/trusted-keys.json
```

Codes de sortie : `0` sceau conforme, `1` sceau rejeté, `2` vérification impossible (fichier malformé, option manquante). Les six résultats attendus sont dans `test-vectors/README.md`.

Le vérificateur recalcule le condensat SHA3-256 sur les blocs canonicalisés, vérifie la signature Ed25519 avec la clé publique du sceau, puis contrôle que cette clé figure dans la liste de clés de confiance et qu'elle n'était pas révoquée à la date de signature. Sans `--trusted-keys`, il refuse (fail-closed) ; l'option `--integrity-only` limite explicitement la vérification à l'intégrité et le dit dans le verdict. Aucun secret partagé n'est nécessaire. Sous Windows, lancez la commande avec `PYTHONUTF8=1` si la console affiche une erreur d'encodage.

Lancer les tests :

```bash
python -m unittest discover -s tests
```

## Licences

- **Code, vecteurs de test, outils et tests** : Apache License 2.0, voir [`LICENSE`](LICENSE).
- **Spécification et livre blanc** : Creative Commons Attribution 4.0 International, voir [`LICENSE-CC-BY-4.0.txt`](LICENSE-CC-BY-4.0.txt). Vous pouvez copier, redistribuer et adapter ces textes, y compris à des fins commerciales, à condition de citer l'auteur.
- **Noms, logos et motifs graphiques** : les logos (`assets/`, `spec/logo.png`), les noms « IntrepidCore », « IntrepidLab » et « ICES » et les motifs de l'Atlas graphique (`whitepaper/ic-motifs.tex`, `whitepaper/ic-editorial.tex`) ne sont pas concédés par ces licences. Pour tout usage de la marque, écrivez à l'adresse ci-dessous.

Chaque fichier source porte, quand le format le permet, un identifiant SPDX.

## Citer ICES

Voir [`CITATION.cff`](CITATION.cff).

## Contribuer et signaler un problème

Voir [`CONTRIBUTING.md`](CONTRIBUTING.md). Pour une faille de sécurité, voir [`SECURITY.md`](SECURITY.md).

## Contact

contact@intrepidcore.io

Copyright 2026 Serge TABE DJATO.

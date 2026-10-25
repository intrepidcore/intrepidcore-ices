# ICES, IntrepidCore Engineering Standard

ICES est un standard de scellement cryptographique pour les notes de calcul d'ingénierie. Il rend une décision d'ingénierie **attribuable, datée et non répudiable** : un financeur, un bureau de contrôle ou un assureur peut vérifier, seul et hors ligne, qu'un calcul n'a pas été modifié depuis sa signature et qu'il vient bien de la clé qui l'a signé.

ICES **ne rend pas la fraude physique impossible**. Un sceau atteste l'intégrité et l'origine d'un document ; la validité physique du modèle reste soumise à l'examen de l'ingénieur.

ICES est **gratuit à produire et à vérifier**.

## État du dépôt

Pré-publication. Version de la spécification : **0.1**. Le vérificateur de référence actuel est un squelette Python ; la version de production (binaire Rust, `ices-core`) est en développement et n'est pas encore dans ce dépôt (voir `verifier/rust/`).

## Contenu

| Dossier | Contenu | Licence |
|---|---|---|
| `spec/` | Spécification ICES v0.1 (source LaTeX et PDF), schéma JSON du MissionBundle | CC BY 4.0 |
| `whitepaper/` | Livre blanc ICES v3 (source LaTeX, PDF, bibliographie, figures) | CC BY 4.0 |
| `test-vectors/` | Sceaux d'exemple (deux valides, un falsifié) | Apache-2.0 |
| `verifier/python/` | Vérificateur de référence hors ligne (squelette) | Apache-2.0 |
| `verifier/rust/` | Vérificateur de production (à venir) | Apache-2.0 |
| `tools/` | Générateur des sceaux d'exemple | Apache-2.0 |
| `assets/` | Logo IntrepidCore | **non couvert** (voir plus bas) |

## Vérifier un sceau

Il faut Python 3 et la bibliothèque `pynacl`.

```bash
pip install pynacl
python verifier/python/ices_verify.py test-vectors/example-bundle.json
python verifier/python/ices_verify.py test-vectors/tampered-bundle.json
```

Résultat attendu :

- `example-bundle.json` : **VALIDE** (intégrité OK, signature Ed25519 OK) ;
- `tampered-bundle.json` : **INVALIDE** (échec de l'intégrité : un résultat a été modifié après la signature).

Sous Windows, si la console affiche une erreur d'encodage, lancez la commande avec `PYTHONUTF8=1`.

Le vérificateur recalcule le condensat SHA3-256 sur les blocs canonicalisés du document (entrées, scénario, résultats, contrôles), puis vérifie la signature Ed25519 avec la clé **publique**. Aucun secret partagé n'est nécessaire.

## Licences

- **Code, vecteurs de test et outils** : Apache License 2.0, voir [`LICENSE`](LICENSE).
- **Spécification et livre blanc** : Creative Commons Attribution 4.0 International, voir [`LICENSE-CC-BY-4.0.txt`](LICENSE-CC-BY-4.0.txt). Vous pouvez copier, redistribuer et adapter ces textes, y compris à des fins commerciales, à condition de citer l'auteur.
- **Noms et logo** : le logo (`assets/logo.png`, `spec/logo.png`) et les noms « IntrepidCore » et « ICES » ne sont pas concédés par ces licences. Pour tout usage de la marque, écrivez à l'adresse ci-dessous.

Chaque fichier source porte, quand le format le permet, un identifiant SPDX.

## Citer ICES

Voir [`CITATION.cff`](CITATION.cff).

## Contribuer et signaler un problème

Voir [`CONTRIBUTING.md`](CONTRIBUTING.md). Pour une faille de sécurité, voir [`SECURITY.md`](SECURITY.md).

## Contact

contact@intrepidcore.io

Copyright 2026 Serge TABE DJATO.

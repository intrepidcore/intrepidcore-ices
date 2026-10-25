# Vecteurs de test

Trois MissionBundles pour essayer un vérificateur. Les données sont des exemples de démonstration.

| Fichier | Contenu | Résultat attendu |
|---|---|---|
| `example-bundle.json` | sceau valide, domaine `aep` | VALIDE |
| `example-bundle-atlas.json` | sceau valide, domaine `atlas` | VALIDE |
| `tampered-bundle.json` | `example-bundle.json` avec `outputs.distribution.n_troncons` modifié après la signature | INVALIDE (échec de l'intégrité) |

Toute implémentation de vérificateur doit produire ces trois résultats.

Génération : `tools/make_example_bundle.py` (nécessite `pynacl`). Le sceau falsifié se produit en modifiant une valeur de `outputs` sans resigner.

Licence : Apache-2.0 (`../LICENSE`).

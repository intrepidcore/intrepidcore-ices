# Vecteurs de test

Six MissionBundles et une liste de clés de confiance de démonstration. Les données sont des exemples ; les clés sont des clés de démonstration à ne jamais réutiliser.

| Fichier | Contenu | Verdict attendu | Code |
|---|---|---|---|
| `example-bundle.json` | sceau valide, domaine `aep`, clé enrôlée | CONFORME | 0 |
| `example-bundle-atlas.json` | sceau valide, domaine `atlas`, clé enrôlée | CONFORME | 0 |
| `tampered-bundle.json` | `example-bundle.json` dont le CAPEX est modifié après la signature | REJETÉ : intégrité en échec | 1 |
| `unenrolled-bundle.json` | signature valide, clé absente de la liste de confiance | REJETÉ : clé non enrôlée | 1 |
| `revoked-bundle.json` | signature valide, clé révoquée avant la date de signature | REJETÉ : clé révoquée | 1 |
| `malformed-bundle.json` | champ obligatoire `header.engine_version` supprimé | NON VÉRIFIABLE | 2 |
| `trusted-keys.json` | clés `demo-aep-01`, `demo-atlas-01` et `demo-revoquee-01` (révoquée) | (liste fournie avec `--trusted-keys`) | |

Toute implémentation de vérificateur doit produire ces résultats avec la liste `trusted-keys.json`. Un vérificateur qui accepte `unenrolled-bundle.json` ou `revoked-bundle.json` ne respecte pas le livre blanc.

Le condensat de `example-bundle.json` est `2028f4be7a414290a3f69884489f734bc95ec787d67cd9ab25e9c324f3e40331`. Il est cité dans l'annexe A du livre blanc : ne régénérez pas ces fichiers sans mettre à jour l'annexe.

Génération : `tools/make_example_bundle.py` (nécessite `pynacl`). Chaque exécution tire de nouvelles clés et produit de nouveaux condensats.

Licence : Apache-2.0 (`../LICENSE`).

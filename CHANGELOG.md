# Journal des changements

## [Non publié]

- Structure initiale du dépôt : spécification v0.1, livre blanc v3, vecteurs de test, vérificateur de référence Python.
- Vecteur falsifié `tampered-bundle.json` régénéré à partir de `example-bundle.json` (un résultat modifié après la signature) : le vérificateur le rejette sur l'intégrité. L'ancien vecteur n'avait pas le champ `engine_version` et faisait échouer le vérificateur avec une exception au lieu d'un rejet propre.
- Licences : Apache-2.0 (code, vecteurs, outils), CC BY 4.0 (spécification, livre blanc).

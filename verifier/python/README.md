# Vérificateur de référence (Python)

Implémentation de référence et banc de test de la spécification ICES v0.1 et du livre blanc v4.0.

```bash
pip install pynacl
python ices_verify.py ../../test-vectors/example-bundle.json --trusted-keys ../../test-vectors/trusted-keys.json
python ices_verify.py --json ../../test-vectors/example-bundle.json --trusted-keys ../../test-vectors/trusted-keys.json
python ices_verify.py ../../test-vectors/unenrolled-bundle.json --integrity-only
```

## Ce que fait le script

1. Arrondit chaque nombre flottant à la précision de son champ (table de l'annexe A du livre blanc, `PRECISION_PAR_CHAMP`).
2. Sérialise selon JCS (RFC 8785) : clés triées par unités UTF-16, nombres au format ECMAScript.
3. Calcule le condensat SHA3-256 de `canon(inputs) || canon(scenario) || engine_version || canon(outputs) || canon(gates)`, sans séparateur ; `scenario` est omis s'il est absent.
4. Vérifie la signature Ed25519 du condensat avec la clé publique du sceau (base64 ou `did:key`).
5. Contrôle l'ancrage de confiance : clé présente dans `--trusted-keys`, valide et non révoquée à la date de signature. Sans liste, refus par défaut.

Codes de sortie : 0 conforme, 1 rejeté, 2 vérification impossible. Le script ne lève plus d'exception sur un fichier malformé.

## Limites

- Horodatage de palier 1 seulement : la date de signature est celle que déclare l'émetteur.
- Aucun contrôle du Manifeste de Projet ni du journal de transparence (Phases 2 et 3).
- Concaténation du condensat sans séparateur entre blocs, comme écrit dans la spécification. L'ajout d'une séparation de domaine entre blocs est une décision à prendre pour la version suivante de la spécification, et non un changement du code seul.

Lancer les tests depuis la racine du dépôt : `python -m unittest discover -s tests`.

Licence : Apache-2.0 (`../../LICENSE`).

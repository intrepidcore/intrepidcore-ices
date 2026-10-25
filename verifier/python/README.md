# Vérificateur de référence (Python)

Squelette de référence et banc de test du contrat ICES v0.1.

```bash
pip install pynacl
python ices_verify.py ../../test-vectors/example-bundle.json
python ices_verify.py --json ../../test-vectors/example-bundle.json
```

Sous Windows, lancez avec `PYTHONUTF8=1` si la console affiche une erreur d'encodage.

**Limite connue.** Sur un MissionBundle malformé (champ manquant), le squelette s'arrête sur une exception au lieu de répondre INVALIDE. La version de production doit rejeter proprement tout sceau malformé.

Licence : Apache-2.0 (`../../LICENSE`).

# Vérificateur ICES

Le vérificateur recalcule le condensat SHA3-256 sur la forme canonique des blocs signés, puis vérifie la signature Ed25519 avec la clé publique du sceau. Il fonctionne hors ligne et n'utilise aucun secret.

- `python/` : vérificateur de référence (squelette Python).
- `rust/` : vérificateur de production (binaire statique, `ices-core`), à venir.

Licence : Apache-2.0 (`../LICENSE`).

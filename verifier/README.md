# Vérificateur ICES

Le vérificateur recalcule le condensat SHA3-256 sur la forme canonique (arrondi par champ puis JCS) des blocs signés, vérifie la signature Ed25519 avec la clé publique du sceau, puis contrôle que cette clé figure dans une liste de clés de confiance. Il fonctionne hors ligne et n'utilise aucun secret partagé.

- `python/` : vérificateur de référence, en ligne de commande, sans interface graphique.
- `rust/` : vérificateur de production (binaire statique, `ices-core`), à venir.

Licence : Apache-2.0 (`../LICENSE`).

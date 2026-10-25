# Vérificateur de production (Rust)

À venir. Cible : crate `ices-core` (SHA3-256, Ed25519, canonicalisation JCS, RFC 8785) et binaire statique distribuable hors ligne, sans dépendance réseau.

Critères d'acceptation :

1. Le binaire reproduit les résultats du squelette Python sur tous les vecteurs de `../../test-vectors/`.
2. Un sceau malformé est rejeté avec un message clair, sans arrêt sur exception.
3. Aucune dépendance réseau ; aucun secret partagé.

Licence : Apache-2.0 (`../../LICENSE`).

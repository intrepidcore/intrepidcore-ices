# Vérificateur de production (Rust)

À venir. Cible : crate `ices-core` (SHA3-256, Ed25519, JCS RFC 8785, arrondi par champ) et binaire statique `ices`, distribuable hors ligne, sans dépendance réseau.

Le comportement de référence est celui du livre blanc et du vérificateur Python (`../python/`). Critères d'acceptation :

1. Le binaire donne les six verdicts et les six codes de sortie de `../../test-vectors/README.md`, avec la liste `trusted-keys.json`.
2. Il reproduit les condensats de tous les vecteurs, y compris l'exemple de la RFC 8785 et la table de précision de l'annexe A du livre blanc.
3. Il applique l'ancrage de confiance : refus par défaut sans liste de clés, clé non enrôlée ou révoquée à la date de signature rejetée, clés en base64 et en `did:key` acceptées.
4. Un fichier malformé est signalé avec un message clair et le code 2, sans arrêt sur exception.
5. Aucune dépendance réseau et aucun secret partagé ; exécutable pour Windows et Linux.
6. Les dépendances cryptographiques sont sous licence permissive compatible avec Apache-2.0.

Interface graphique : hors périmètre de cette version ; c'est un chantier distinct, à cadrer après la publication.

Licence : Apache-2.0 (`../../LICENSE`).

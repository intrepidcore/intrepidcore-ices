# Contribuer

Les contributions sont les bienvenues : corrections de la spécification, vecteurs de test supplémentaires, implémentations de vérificateurs dans d'autres langages.

1. Ouvrez une *issue* pour décrire le changement avant un travail important.
2. Faites une branche et une *pull request*.
3. Toute implémentation de vérificateur doit passer les vecteurs de `test-vectors/` : sceaux valides acceptés, sceau falsifié, clé non enrôlée et clé révoquée rejetés, fichier malformé signalé sans arrêt sur exception. Lancez `python -m unittest discover -s tests` pour le vérificateur de référence.

**Licence des contributions.** En proposant une contribution, vous acceptez qu'elle soit publiée sous la licence du dossier concerné : Apache-2.0 pour le code, les vecteurs de test, les outils et les tests, CC BY 4.0 pour la spécification et le livre blanc.

**Hiérarchie des textes.** Le livre blanc fait foi. Si le schéma, la spécification ou le code divergent du livre blanc, c'est le schéma, la spécification ou le code qui se corrige, jamais le livre blanc pour s'aligner sur un code qui ne fait pas ce que le texte demande.

**Ce qui ne change pas sans discussion :** l'ordre des blocs du condensat, l'algorithme de condensat (SHA3-256), l'algorithme de signature (Ed25519), la table de précision par champ et la canonicalisation JCS. Un écart sur ces points fait dériver le condensat et casse l'interopérabilité entre implémentations.

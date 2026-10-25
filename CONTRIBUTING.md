# Contribuer

Les contributions sont les bienvenues : corrections de la spécification, vecteurs de test supplémentaires, implémentations de vérificateurs dans d'autres langages.

1. Ouvrez une *issue* pour décrire le changement avant un travail important.
2. Faites une branche et une *pull request*.
3. Toute implémentation de vérificateur doit passer les vecteurs de `test-vectors/` : sceaux valides acceptés, sceau falsifié rejeté.

**Licence des contributions.** En proposant une contribution, vous acceptez qu'elle soit publiée sous la licence du dossier concerné : Apache-2.0 pour le code, les vecteurs de test et les outils, CC BY 4.0 pour la spécification et le livre blanc.

**Ce qui ne change pas sans discussion :** l'ordre canonique des champs signés, l'algorithme de condensat (SHA3-256) et l'algorithme de signature (Ed25519). Un écart sur ces points fait dériver le condensat et casse l'interopérabilité entre implémentations.

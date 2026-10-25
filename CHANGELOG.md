# Journal des changements

## [Non publié]

### Livre blanc v4.0 (remplace la v3.0 de juillet 2026)

- Mise aux normes du guide de rédaction v7.0 : couverture double marque, page de titre avec métadonnées, résumé exécutif de 130 mots, pagination romaine puis « page / total », listes des figures et des tableaux, annexes en lettres, statut et signatures.
- Style éditorial, ambiance Marque : cinq ouvertures de partie et une ouverture d'annexes, avec les motifs C05, B01, A02, D06, D05 et A05 de l'Atlas.
- Annexe A alignée sur la spécification v0.1 : enveloppe `ices_envelope`, table de précision par champ, vecteurs de test et sorties réelles du vérificateur. Les mécanismes des phases 2 et 3 passent en « extensions prévues ».
- Tableau d'avancement : chaque mécanisme porte son niveau d'affirmation (vérifié, exploratoire).
- Retraits : la section « Modèle économique » (grille de deux paliers et prix), les figures de tarification et de revenus, la phrase sur les éditeurs sans licence. Un paragraphe qualitatif, au conditionnel, sans montant, les remplace.
- Affirmations affaiblies ou marquées `À CONFIRMER` : qualification du cachet en UEMOA, exclusion de garantie CIMA, assurabilité du BCT, prime réduite. Sources vérifiées : article 48 de la directive 04/2005/CM/UEMOA, audit sénégalais 2023, RFC et FIPS avec DOI ou URL. Source du Togo (2015) retirée faute d'avoir pu être retrouvée.
- Figures régénérées en vectoriel, sans titre dans l'image, sans chiffre inventé, avec texte alternatif.
- Erreur corrigée : l'exemple « avant et après » montrait `6.200000`, alors que la forme JCS de 6,2 est `6.2`.

### Vérificateur de référence (Python)

- Condensat calculé dans l'ordre de la spécification (`engine_version` entre `scenario` et `outputs`) ; l'ancien code l'ajoutait à la fin.
- Arrondi par champ et sérialisation JCS (RFC 8785) à la place d'un arrondi uniforme à 6 décimales et d'un tri de clés simple.
- Liste de clés de confiance (`--trusted-keys`) avec dates de validité et de révocation ; refus par défaut sans liste ; `--integrity-only` explicite.
- Décodage des clés `did:key`.
- Plus d'exception sur un fichier malformé : code de sortie 2.
- 20 tests, dont l'exemple de la RFC 8785 et un vecteur `did:key` du W3C.

### Vecteurs de test

- Six vecteurs et une liste de clés de démonstration, régénérés : le condensat de l'exemple devient `2028f4be…0331`.
- Ajout des cas « clé non enrôlée », « clé révoquée » et « fichier malformé ». L'ancien vecteur falsifié n'avait pas `engine_version` et faisait échouer l'ancien vérificateur avec une exception.

### Licences et structure

- Apache-2.0 (code, vecteurs, outils, tests) et CC BY 4.0 (spécification, livre blanc). Auteur : Serge TABE DJATO.
- Structure initiale du dépôt.

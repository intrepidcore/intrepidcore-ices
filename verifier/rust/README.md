# Vérificateur de production (Rust)

Crate `ices-core` et binaire `ices` : vérifient hors ligne le sceau d'un MissionBundle ICES, selon la spécification v0.1 et le livre blanc v4.0. Aucune dépendance réseau, aucun secret partagé.

```bash
cargo build --release --locked
./target/release/ices verify ../../test-vectors/example-bundle.json --trusted-keys ../../test-vectors/trusted-keys.json
./target/release/ices verify bundle.json --trusted-keys cles.json --json
./target/release/ices verify bundle.json --integrity-only      # intégrité et signature, sans ancrage
./target/release/ices canon bundle.json                         # formes canoniques de chaque bloc (audit)
```

Codes de sortie : 0 conforme, 1 rejeté, 2 non vérifiable (fichier malformé, option manquante, lecture impossible). Sans `--trusted-keys` ni `--integrity-only`, la vérification est refusée.

## Ce que fait le vérificateur

Étapes de la section « Étapes de la vérification » du livre blanc :

1. arrondi par champ (table de précision de l'annexe A) puis sérialisation JCS (RFC 8785), sans calcul flottant intermédiaire : l'arrondi opère sur les chiffres de l'écriture décimale la plus courte, avec égalité vers le pair ;
2. condensat SHA3-256 de `C(inputs) ‖ C(scenario) ‖ engine_version ‖ C(outputs) ‖ C(gates)`, sans séparateur ; `scenario` est omis s'il est absent ;
3. extraction de la signature et de la clé publique, en base64 ou en `did:key` ;
4. signature Ed25519 (vérification stricte : clés d'ordre faible et signatures non canoniques refusées) et égalité du condensat annoncé et du condensat recalculé ;
5. ancrage dans la liste de clés de confiance : clé enrôlée, valide et non révoquée à la date de signature, comparée en UTC ;
7. verdict motivé : condensat divergent, signature invalide, clé non enrôlée, clé révoquée à la date de signature (champ `reasons` en JSON).

## Bornes de cette version

Ce que la version 0.1 du vérificateur ne fait pas, et que les sorties disent :

- **Étape 6 (clé autorisée pour la phase du document, d'après le Manifeste de Projet)** : non vérifiée, déclarée `NON_VERIFIE`. Elle relève de la Phase 3 de la feuille de route.
- **Journal de transparence, horodatage en deux paliers, attestation agrafée** : absents (Phase 2). La date de signature est celle que déclare l'émetteur.
- **Séparation de domaine entre blocs** : la spécification v0.1 concatène sans séparateur ; le code suit le texte. Changer cela est une décision de spécification (version 0.2), pas un réglage du code.
- **Interface graphique** : hors périmètre, chantier distinct.
- **Pas d'audit cryptographique indépendant.** Le code s'appuie sur `ed25519-dalek` et `sha3` (RustCrypto), non sur une implémentation maison.
- **Plateformes.** Construit et testé sous Windows x86_64 avec la chaîne `x86_64-pc-windows-gnu` (MSVC n'est pas installé sur la machine de développement). Linux : le workflow `.github/workflows/verifier-rust.yml` construit et teste sous Ubuntu et Windows (33 tests Rust, parité avec le script Python, six vecteurs publics) et produit un binaire statique musl ; exécution réussie le 5 novembre 2026 (commit `a4c9c9a`). Pas de test sous macOS ni sur architecture ARM.

## Écarts connus avec le vérificateur Python

Les condensats sont identiques sur les six vecteurs publics et sur des milliers de bundles aléatoires (`tests/test_rust_parity.py`). Écarts voulus, sur des entrées hors du domaine normal :

- un nombre dont l'arrondi dépasse 28 chiffres significatifs est refusé (code 2), là où le script Python s'arrête sur une exception décimale ;
- les horodatages doivent être au format RFC 3339 (avec fuseau) ; le script Python accepte aussi des formes ISO 8601 plus larges ;
- un BOM UTF-8 en tête de fichier est toléré.

## Deux pièges trouvés par le test de parité

- `serde_json` lit les flottants avec une méthode rapide mais pas toujours exacte : `333333333.33333329` donnait `333333333.33333325`. La fonctionnalité `float_roundtrip` est donc obligatoire (activée dans `Cargo.toml`).
- Pour la plus courte écriture d'un nombre, la bibliothèque standard de Rust départage mal deux candidats équidistants : `80559923956500.625` s'écrit `…63` alors qu'ECMAScript, JCS et Python écrivent `…62` (chiffre pair). `canon.rs` recalcule donc les chiffres par un arrondi exact à la longueur minimale.

## Tests

```bash
cargo test --release --locked                      # RFC 8785, arrondi, six vecteurs, ancrage, cas limites (33 tests)
ICES_BIN=target/release/ices python ../../tests/test_rust_parity.py   # parité avec le script Python, fuzz de bundles et d'octets
```

## Dépendances

Toutes sous licence permissive compatible avec Apache-2.0 : `serde_json`, `sha3`, `ed25519-dalek` (BSD-3-Clause), `bs58`, `base64`, `chrono` (MIT ou Apache-2.0).

Licence : Apache-2.0 (`../../LICENSE`).

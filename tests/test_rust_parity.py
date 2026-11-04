#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Serge TABE DJATO
"""Parité entre le vérificateur Python de référence et le binaire Rust.

Les deux implémentations doivent produire le même condensat SHA3-256 pour tout
bundle : le livre blanc exige que « deux implémentations conformes appliquent
strictement » la table de précision. Ce test tire des bundles aléatoires
(nombres de toute grandeur, champs de la table de précision, valeurs en
égalité d'arrondi, chaînes Unicode) et compare les condensats.

Utilisation :  ICES_BIN=chemin/vers/ices[.exe] python tests/test_rust_parity.py
Sans ICES_BIN, le test est ignoré (le binaire doit avoir été construit).
"""
from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE / "verifier" / "python"))
import ices_verify as ref  # noqa: E402

BIN = os.environ.get("ICES_BIN")
CHAMPS = list(ref.PRECISION_PAR_CHAMP) + ["autre", "valeur", "x"]
CHAINES = ["", "a", "é", "€", "𝄞", "tab\t", "retour\n", "guillemet\"", "barre\\", "\u0001", "\u007f", "ﬁ"]


def nombre(rng: random.Random):
    genre = rng.random()
    if genre < 0.15:
        return rng.randint(-10**6, 10**6)
    if genre < 0.30:  # égalités d'arrondi : x,5 à diverses précisions
        return round(rng.randint(-5000, 5000) / 10 ** rng.randint(0, 7) + 5 * 10 ** -rng.randint(1, 9), 12)
    if genre < 0.50:
        return rng.uniform(-1000, 1000)
    if genre < 0.65:
        return rng.uniform(-1, 1) * 10 ** rng.randint(-12, 14)
    if genre < 0.75:
        return float(rng.randint(0, 10**9)) + rng.choice([0.0, 0.5, 0.25, 0.125, 0.9999996, 0.0000004])
    return rng.uniform(0, 1) * rng.choice([1, 1e-3, 1e3, 1e8])


def valeur(rng: random.Random, profondeur: int = 0):
    r = rng.random()
    if profondeur > 3 or r < 0.55:
        c = rng.random()
        if c < 0.75:
            return nombre(rng)
        if c < 0.85:
            return rng.choice([True, False, None])
        return rng.choice(CHAINES) + str(rng.randint(0, 99))
    if r < 0.8:
        return [valeur(rng, profondeur + 1) for _ in range(rng.randint(0, 4))]
    return {rng.choice(CHAMPS + CHAINES) + str(rng.randint(0, 3)): valeur(rng, profondeur + 1) for _ in range(rng.randint(0, 5))} | {
        rng.choice(CHAMPS): valeur(rng, profondeur + 1)
    }


def bundle(rng: random.Random) -> dict:
    b = {
        "header": {"schema_version": 2, "domain": "aep", "engine_version": rng.choice(["a1b2c3d", "é-ver", "v1.0.0"])},
        "inputs": valeur(rng),
        "outputs": valeur(rng),
        "gates": [{"id": "G1", "status": "PASS", "evidence": nombre(rng)}],
        "ices_envelope": {
            "alg": "Ed25519", "digest_alg": "SHA3-256", "digest": "00" * 32,
            "sig": "AAAA", "pubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "key_id": "fuzz", "signed_at": "2026-07-01T00:00:00Z",
        },
    }
    if rng.random() < 0.7:
        b["scenario"] = valeur(rng)
    return b


@unittest.skipUnless(BIN and Path(BIN).exists(), "ICES_BIN absent : construire le binaire Rust")
class ParitePythonRust(unittest.TestCase):
    def condensat_rust(self, b: dict) -> str:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(b, f, ensure_ascii=False)
            chemin = f.name
        try:
            p = subprocess.run([BIN, "verify", chemin, "--integrity-only", "--json"],
                               capture_output=True, text=True, encoding="utf-8")
        finally:
            os.unlink(chemin)
        self.assertIn(p.returncode, (0, 1), p.stderr)
        return json.loads(p.stdout)["recomputed_digest"]

    def test_condensats_identiques_sur_bundles_aleatoires(self):
        rng = random.Random(20261104)
        comparés = 0
        total = int(os.environ.get("ICES_FUZZ", "600"))
        for _ in range(total):
            b = bundle(rng)
            try:
                attendu = ref.compute_digest(b)
            except (ref.MalformedBundle, ArithmeticError):
                continue
            self.assertEqual(self.condensat_rust(b), attendu, json.dumps(b, ensure_ascii=False)[:400])
            comparés += 1
        self.assertGreater(comparés, total * 2 // 3)

    def test_vecteurs_publics(self):
        for nom in ["example-bundle", "example-bundle-atlas", "tampered-bundle", "unenrolled-bundle", "revoked-bundle"]:
            b = json.loads((RACINE / "test-vectors" / f"{nom}.json").read_text(encoding="utf-8"))
            self.assertEqual(self.condensat_rust(b), ref.compute_digest(b), nom)

    def test_fichiers_alteres_jamais_de_panique(self):
        """Un fichier abîmé donne 0, 1 ou 2 (jamais un arrêt brutal du processus)."""
        rng = random.Random(7)
        cles = str(RACINE / "test-vectors" / "trusted-keys.json")
        sources = [(RACINE / "test-vectors" / n).read_bytes() for n in
                   ["example-bundle.json", "example-bundle-atlas.json", "tampered-bundle.json"]]
        for i in range(int(os.environ.get("ICES_FUZZ_OCTETS", "300"))):
            octets = bytearray(rng.choice(sources))
            for _ in range(rng.randint(1, 4)):
                mode = rng.random()
                pos = rng.randrange(len(octets))
                if mode < 0.4:
                    octets[pos] = rng.randrange(256)
                elif mode < 0.7:
                    del octets[pos:pos + rng.randint(1, 30)]
                else:
                    octets[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
            if rng.random() < 0.2:
                octets = octets[:rng.randrange(len(octets))]
            with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as f:
                f.write(octets)
                chemin = f.name
            try:
                p = subprocess.run([BIN, "verify", chemin, "--trusted-keys", cles], capture_output=True, timeout=30)
            finally:
                os.unlink(chemin)
            self.assertIn(p.returncode, (0, 1, 2), f"essai {i} : code {p.returncode}")

    def test_exemple_du_livre_blanc(self):
        b = json.loads((RACINE / "test-vectors" / "example-bundle.json").read_text(encoding="utf-8"))
        self.assertEqual(self.condensat_rust(b), "2028f4be7a414290a3f69884489f734bc95ec787d67cd9ab25e9c324f3e40331")


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Serge TABE DJATO
"""Tests du vérificateur de référence : `python -m unittest discover -s tests` depuis la racine."""
import base64
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE / "verifier" / "python"))
import ices_verify as iv  # noqa: E402

VECTEURS = RACINE / "test-vectors"


def charger(nom):
    return json.loads((VECTEURS / nom).read_text(encoding="utf-8"))


CLES = charger("trusted-keys.json")


class TestJcs(unittest.TestCase):
    def test_exemple_rfc8785(self):
        """Exemple de la section 3.2.4 de la RFC 8785."""
        v = {"numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001],
             "string": "€$\u000f\nA'B\"\\\\\"/", "literals": [None, True, False]}
        attendu = ('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
                   '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}')
        self.assertEqual(iv.jcs(v), attendu)

    def test_nombres_es6(self):
        cas = [(110.0, "110"), (6.2, "6.2"), (0.5, "0.5"), (-0.0, "0"), (1e21, "1e+21"), (1e-7, "1e-7"),
               (1e-6, "0.000001"), (123456789012345680000.0, "123456789012345680000"), (-4.35, "-4.35")]
        for x, s in cas:
            self.assertEqual(iv.nombre_es6(x), s, x)

    def test_tri_des_cles_par_unites_utf16(self):
        # U+10000 (paire de substituts D800 DC00) se range avant U+FF5E en UTF-16, après en points de code
        self.assertEqual(iv.jcs({"～": 1, "\U00010000": 2}), '{"\U00010000":2,"～":1}')


class TestPrecision(unittest.TestCase):
    def test_precision_par_champ(self):
        v = {"pression_bar": 6.20000049, "diameters_mm": [110.4, 160.6], "debit_m3h": 12.345678, "autre": 1.23456789}
        p = iv.appliquer_precision(v)
        self.assertEqual(p, {"pression_bar": 6.2, "diameters_mm": [110.0, 161.0], "debit_m3h": 12.3457, "autre": 1.234568})

    def test_egalite_vers_le_pair(self):
        self.assertEqual(iv.arrondir(0.5, 0), 0.0)
        self.assertEqual(iv.arrondir(1.5, 0), 2.0)
        self.assertEqual(iv.arrondir(2.5, 0), 2.0)

    def test_entiers_inchanges(self):
        self.assertEqual(iv.appliquer_precision({"n": 327, "ok": True}), {"n": 327, "ok": True})


class TestCondensat(unittest.TestCase):
    def test_ordre_de_la_specification(self):
        b = charger("example-bundle.json")
        h = hashlib.sha3_256()
        h.update(iv.jcs(iv.appliquer_precision(b["inputs"])).encode())
        h.update(iv.jcs(iv.appliquer_precision(b["scenario"])).encode())
        h.update(b["header"]["engine_version"].encode())
        h.update(iv.jcs(iv.appliquer_precision(b["outputs"])).encode())
        h.update(iv.jcs(iv.appliquer_precision(b["gates"])).encode())
        self.assertEqual(iv.compute_digest(b), h.hexdigest())

    def test_sans_scenario(self):
        b = charger("example-bundle-atlas.json")
        self.assertNotIn("scenario", b)
        self.assertEqual(len(iv.compute_digest(b)), 64)


class TestDidKey(unittest.TestCase):
    def test_aller_retour(self):
        pub = base64.b64decode(CLES[0]["pubkey"])
        d = iv.did_key(pub)
        self.assertTrue(d.startswith("did:key:z6Mk"))
        self.assertEqual(iv.cle_publique(d), pub)

    def test_vecteur_w3c(self):
        # Exemple de la méthode did:key (clé Ed25519 publique de test)
        d = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        self.assertEqual(len(iv.cle_publique(d)), 32)
        self.assertEqual(iv.did_key(iv.cle_publique(d)), d)


class TestVerification(unittest.TestCase):
    def verdict(self, nom, **kw):
        return iv.verify_bundle(charger(nom), CLES, **kw)

    def test_valides(self):
        for nom in ("example-bundle.json", "example-bundle-atlas.json"):
            v = self.verdict(nom)
            self.assertTrue(v["valid"], nom)
            self.assertEqual(v["anchoring"], "ENROLEE")

    def test_falsifie(self):
        v = self.verdict("tampered-bundle.json")
        self.assertFalse(v["valid"])
        self.assertFalse(v["integrity"])
        self.assertTrue(v["signature"])

    def test_cle_non_enrolee(self):
        v = self.verdict("unenrolled-bundle.json")
        self.assertTrue(v["integrity"] and v["signature"])
        self.assertEqual(v["anchoring"], "NON_ENROLEE")
        self.assertFalse(v["valid"])

    def test_cle_revoquee(self):
        v = self.verdict("revoked-bundle.json")
        self.assertEqual(v["anchoring"], "REVOQUEE")
        self.assertFalse(v["valid"])

    def test_integrite_seule(self):
        v = self.verdict("unenrolled-bundle.json", integrite_seule=True)
        self.assertTrue(v["valid"])
        self.assertEqual(v["anchoring"], "NON_VERIFIE")

    def test_signature_alteree(self):
        b = charger("example-bundle.json")
        sig = bytearray(base64.b64decode(b["ices_envelope"]["sig"]))
        sig[0] ^= 1
        b["ices_envelope"]["sig"] = base64.b64encode(bytes(sig)).decode()
        v = iv.verify_bundle(b, CLES)
        self.assertFalse(v["signature"])
        self.assertFalse(v["valid"])

    def test_malforme(self):
        with self.assertRaises(iv.MalformedBundle):
            iv.verify_bundle(charger("malformed-bundle.json"), CLES)

    def test_non_scelle(self):
        b = charger("example-bundle.json")
        del b["ices_envelope"]
        with self.assertRaises(iv.MalformedBundle):
            iv.verify_bundle(b, CLES)

    def test_codes_de_sortie(self):
        cle = str(VECTEURS / "trusted-keys.json")
        attendu = {"example-bundle.json": 0, "example-bundle-atlas.json": 0, "tampered-bundle.json": 1,
                   "unenrolled-bundle.json": 1, "revoked-bundle.json": 1, "malformed-bundle.json": 2}
        for nom, code in attendu.items():
            self.assertEqual(iv.main([str(VECTEURS / nom), "--trusted-keys", cle]), code, nom)
        # refus par défaut sans liste de clés
        self.assertEqual(iv.main([str(VECTEURS / "example-bundle.json")]), 2)


class TestSchema(unittest.TestCase):
    def test_vecteurs_conformes_au_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema non installé")
        schema = json.loads((RACINE / "spec" / "mission-bundle.schema.json").read_text(encoding="utf-8"))
        for nom in ("example-bundle.json", "example-bundle-atlas.json"):
            jsonschema.validate(charger(nom), schema)


if __name__ == "__main__":
    unittest.main()

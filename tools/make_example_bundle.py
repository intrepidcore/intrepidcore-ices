#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Serge TABE DJATO
"""Génère les vecteurs de test ICES (dossier test-vectors/).

Chaque exécution tire de nouvelles clés de démonstration : les vecteurs publiés
dans le dépôt sont ceux d'une exécution précise, et la liste des clés de
confiance (trusted-keys.json) en est issue. Ne jamais réutiliser ces clés.

Vecteurs produits :
  example-bundle.json         domaine aep, sceau valide, clé enrôlée          -> CONFORME
  example-bundle-atlas.json   domaine atlas, sceau valide, clé enrôlée        -> CONFORME
  tampered-bundle.json        un résultat modifié après la signature          -> REJETÉ (intégrité)
  unenrolled-bundle.json      sceau valide, clé absente de la liste           -> REJETÉ (clé non enrôlée)
  revoked-bundle.json         sceau valide, clé révoquée avant la signature   -> REJETÉ (clé révoquée)
  malformed-bundle.json       champ obligatoire supprimé                      -> NON VÉRIFIABLE (code 2)
  trusted-keys.json           liste des clés de confiance de démonstration
"""
import base64
import copy
import json
import sys
from pathlib import Path

from nacl.signing import SigningKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "verifier" / "python"))
from ices_verify import compute_digest, did_key  # noqa: E402

SORTIE = Path(__file__).resolve().parents[1] / "test-vectors"
SIGNE_LE = "2026-06-30T10:00:01Z"


def sceller(bundle: dict, sk: SigningKey, key_id: str) -> dict:
    """finalize() : condensat canonique puis signature Ed25519."""
    b = copy.deepcopy(bundle)
    b.pop("ices_envelope", None)
    digest = compute_digest(b)
    b["ices_envelope"] = {
        "alg": "Ed25519",
        "digest_alg": "SHA3-256",
        "digest": digest,
        "sig": base64.b64encode(sk.sign(bytes.fromhex(digest)).signature).decode(),
        "pubkey": base64.b64encode(bytes(sk.verify_key)).decode(),
        "signed_at": SIGNE_LE,
        "key_id": key_id,
    }
    return b


def ecrire(nom: str, contenu) -> None:
    (SORTIE / nom).write_text(json.dumps(contenu, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{nom} écrit.")


# ── Domaine aep (hydraulique) ───────────────────────────────────────────
bundle_aep = {
    "header": {
        "schema_version": 2,
        "project_key": "DEMO-AEP",
        "domain": "aep",
        "engine_version": "a1b2c3d",
        "created_utc": "2026-06-30T10:00:00Z",
        "phase_range": {"from": "phase0", "to": "report"},
    },
    "inputs": {
        "config_canonical": {"cpj": 1.2, "taux_pct": 3.5},
        "fallback_registry": {"rugosite_defaut": 130},
        "network_canonical": {"n_nodes": 306, "n_links": 327},
        "demand": {"p_base": 35848, "taux_pct": 3.5, "horizons": [2025, 2030, 2035], "cpj": 1.2},
        "geo_refs": {
            "dem_raster_sha": "deadbeef",
            "atlas_realization_ids": ["sgs:TG-GOLFE:r001", "sgs:TG-GOLFE:r002"],
            "atlas_pipeline_version": "L1-L5@9f8e7d",
            "thiessen_method": "voronoi_exact",
        },
    },
    "scenario": {
        "ensemble_seed": 42,
        "n_realizations": 200,
        "axes": {"demand_growth": "gompertz", "iws_schedule": "6h-peak",
                 "power_outage": "poisson", "roughness": "lognormal", "soil": "atlas_sgs"},
    },
    "outputs": {
        "distribution": {"n_troncons": 327, "longueur_m": 153271.11, "solveurs": ["lcpi", "ensemble"]},
        "robustness": {"p_service_ge_target": 0.96, "equity_index": 0.82, "resilience_outage": 0.71},
        "costs": {"capex_fcfa": 275931289.0, "tarif_eie": 412.5},
    },
    "gates": [
        {"id": "P0_PREFLIGHT_HASH", "status": "PASS", "evidence": "c5997530"},
        {"id": "DI07_OPTIM_FEASIBLE", "status": "PASS", "evidence": "p_service=0.96"},
        {"id": "C01_CAPEX_POSITIF", "status": "PASS"},
    ],
}

# ── Domaine atlas (pipeline géostatistique), preuve de généralisation ───
bundle_atlas = {
    "header": {
        "schema_version": 2,
        "project_key": "DEMO-ATLAS-GOLFE",
        "domain": "atlas",
        "engine_version": "L1-L5@9f8e7d",
        "created_utc": "2026-06-30T11:00:00Z",
        "phase_range": {"from": "L1", "to": "L5"},
    },
    "inputs": {
        "config_canonical": {"cellsize_m": 100, "min_points": 8},
        "fallback_registry": {"variogram_nugget_defaut": 0.1},
        "geostatistics": {
            "variogram_model": "spherical",
            "kriging_method": "SGS",
            "sondage_ids": ["BH-2019-014", "BH-2020-233", "BH-2021-087"],
            "maille_resolution_km": 2.0,
        },
    },
    "outputs": {
        "realizations": {
            "realization_ids": ["sgs:TG-GOLFE:r001", "sgs:TG-GOLFE:r002"],
            "p10_p90_range": {"cbr_pct": [12.4, 28.9]},
            "kriging_variance_ref": "var-map-golfe-2026Q2",
        }
    },
    "gates": [
        {"id": "LOO_RMSE_THRESHOLD", "status": "PASS", "evidence": "rmse=13.27%"},
        {"id": "BLOCK_VALIDATION_PASS", "status": "PASS"},
    ],
}

# ── Clés de démonstration ───────────────────────────────────────────────
sk_aep, sk_atlas = SigningKey.generate(), SigningKey.generate()
sk_inconnue, sk_revoquee = SigningKey.generate(), SigningKey.generate()


def entree(key_id: str, sk: SigningKey, revoquee_le=None) -> dict:
    return {
        "key_id": key_id,
        "pubkey": base64.b64encode(bytes(sk.verify_key)).decode(),
        "did": did_key(bytes(sk.verify_key)),
        "valid_from": "2026-01-01T00:00:00Z",
        "revoked_at": revoquee_le,
    }


ecrire("trusted-keys.json", [
    entree("demo-aep-01", sk_aep),
    entree("demo-atlas-01", sk_atlas),
    entree("demo-revoquee-01", sk_revoquee, revoquee_le="2026-06-30T10:00:00Z"),
])

aep = sceller(bundle_aep, sk_aep, "demo-aep-01")
ecrire("example-bundle.json", aep)
ecrire("example-bundle-atlas.json", sceller(bundle_atlas, sk_atlas, "demo-atlas-01"))

# Falsification : un résultat change après la signature, sans resigner.
falsifie = copy.deepcopy(aep)
falsifie["outputs"]["costs"]["capex_fcfa"] = 137965644.5
ecrire("tampered-bundle.json", falsifie)

ecrire("unenrolled-bundle.json", sceller(bundle_aep, sk_inconnue, "demo-inconnue-01"))
ecrire("revoked-bundle.json", sceller(bundle_aep, sk_revoquee, "demo-revoquee-01"))

malforme = copy.deepcopy(aep)
del malforme["header"]["engine_version"]
ecrire("malformed-bundle.json", malforme)

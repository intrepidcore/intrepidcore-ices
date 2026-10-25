#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Serge TABE DJATO
"""Signataires de référence ICES (squelette du finalize() côté noyau).

Génère une paire de clés Ed25519, construit deux MissionBundle d'exemple
(domaine aep et domaine atlas — preuve que le schéma généralisé v2 couvre
plusieurs produits), calcule le condensat canonique et appose le sceau.
Sert de fixture de test pour le vérificateur et de référence
d'implémentation pour toute implémentation native du sceau.
"""
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "verifier" / "python"))
from ices_verify import compute_digest  # noqa: E402

from nacl.signing import SigningKey  # noqa: E402

HERE = Path(__file__).resolve().parents[1] / "test-vectors"


def sign_and_write(bundle: dict, filename: str) -> None:
    """finalize() : condensat canonique puis signature Ed25519."""
    sk = SigningKey.generate()
    digest_hex = compute_digest(bundle)
    sig = sk.sign(bytes.fromhex(digest_hex)).signature
    bundle["ices_envelope"] = {
        "alg": "Ed25519",
        "digest_alg": "SHA3-256",
        "digest": digest_hex,
        "sig": base64.b64encode(sig).decode(),
        "pubkey": base64.b64encode(bytes(sk.verify_key)).decode(),
        "signed_at": "2026-06-30T10:00:01Z",
        "key_id": "fde-demo-01",
    }
    (HERE / filename).write_text(
        json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{filename} signé et écrit.")


# ── Domaine aep (LCPI hydraulique) ──────────────────────────────────────
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

# ── Domaine atlas (pipeline géostatistique) — preuve de généralisation ──
bundle_atlas = {
    "header": {
        "schema_version": 2,
        "project_key": "DEMO-ATLAS-GOLFE",
        "domain": "atlas",
        "engine_version": "L1-L5@9f8e7d",  # version du pipeline geostat, PAS un sha LCPI
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

sign_and_write(bundle_aep, "example-bundle.json")
sign_and_write(bundle_atlas, "example-bundle-atlas.json")

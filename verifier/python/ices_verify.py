#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Serge TABE DJATO
# Développeur: IntrepidCore — ICES reference verifier (squelette v0.1)
# Contact: contact@intrepidcore.io
#
# ICES verify — vérificateur de référence HORS-LIGNE du MissionBundle.
#
# Ce que ce squelette démontre (le contrat ICES) :
#   1. Canonicalisation déterministe des sous-objets signés.
#   2. Recalcul du condensat SHA3-256 sur la séquence canonique.
#   3. Vérification de la signature Ed25519 avec la clé PUBLIQUE.
#      => aucun secret partagé. Un bailleur exécute ceci seul.
#
# Cible de production : crate Rust `ices-core` (ed25519-dalek + sha3),
# binaire statique distribuable offline (zones CEDEAO sans connectivité).
# Ce script Python est le squelette de référence / banc de test.
#
# Dépendances : pip install pynacl   (Ed25519 via libsodium)

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
except ImportError:  # pragma: no cover
    VerifyKey = None  # type: ignore
    BadSignatureError = Exception  # type: ignore

# Ordre canonique des champs entrant dans le condensat (NON négociable :
# tout écart fait dériver le hash). Doit être identique côté signataire.
SIGNED_FIELDS = ("inputs", "scenario", "outputs", "gates")

FLOAT_PRECISION = 6  # arrondi des flottants à précision fixe


# ─────────────────────────────────────────────────────────────────────────
# 1. Canonicalisation déterministe
# ─────────────────────────────────────────────────────────────────────────
def canonicalize(obj: Any) -> Any:
    """Forme canonique : clés triées, flottants arrondis, listes préservées.

    Règle d'or : même entrée logique -> même octets, sur toute machine.
    Les chemins absolus doivent déjà avoir été remplacés par des empreintes
    en amont (au finalize()), jamais ici.
    """
    if isinstance(obj, dict):
        return {k: canonicalize(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [canonicalize(v) for v in obj]
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float):
        return round(obj, FLOAT_PRECISION)
    return obj


def canonical_bytes(value: Any) -> bytes:
    """Sérialisation canonique stable (UTF-8, séparateurs compacts, clés triées)."""
    return json.dumps(
        canonicalize(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


# ─────────────────────────────────────────────────────────────────────────
# 2. Condensat SHA3-256 sur la séquence canonique
# ─────────────────────────────────────────────────────────────────────────
def compute_digest(bundle: dict) -> str:
    h = hashlib.sha3_256()
    for field in SIGNED_FIELDS:
        if field == "scenario" and field not in bundle:
            continue  # legacy déterministe : pas de scénario
        h.update(canonical_bytes(bundle.get(field, {})))
        h.update(b"\x1e")  # séparateur de champ (record separator)
    h.update(bundle["header"]["engine_version"].encode("utf-8"))
    return h.hexdigest()


# ─────────────────────────────────────────────────────────────────────────
# 3. Vérification du sceau
# ─────────────────────────────────────────────────────────────────────────
class VerdictError(Exception):
    pass


def verify_bundle(bundle: dict) -> dict:
    """Retourne un verdict structuré. Lève VerdictError si non vérifiable."""
    env = bundle.get("ices_envelope")
    if env is None:
        raise VerdictError("Bundle non scellé (ices_envelope absent) — état legacy.")

    if env.get("alg") != "Ed25519" or env.get("digest_alg") != "SHA3-256":
        raise VerdictError(f"Algorithmes non conformes ICES v0.1 : {env.get('alg')}/{env.get('digest_alg')}")

    # 3a. Intégrité : recalcul du condensat
    recomputed = compute_digest(bundle)
    digest_ok = (recomputed == env["digest"])

    # 3b. Authenticité : signature Ed25519 sur le condensat, clé publique
    sig_ok = False
    if VerifyKey is None:
        raise VerdictError("PyNaCl non installé (pip install pynacl) — vérification impossible.")
    try:
        vk = VerifyKey(base64.b64decode(env["pubkey"]))
        vk.verify(bytes.fromhex(env["digest"]), base64.b64decode(env["sig"]))
        sig_ok = True
    except (BadSignatureError, ValueError):
        sig_ok = False

    gates = bundle.get("gates", [])
    failed = [g["id"] for g in gates if g.get("status") == "FAIL"]

    return {
        "valid": digest_ok and sig_ok,
        "digest_match": digest_ok,
        "signature_valid": sig_ok,
        "recomputed_digest": recomputed,
        "claimed_digest": env["digest"],
        "domain": bundle["header"]["domain"],
        "engine_version": bundle["header"]["engine_version"],
        "atlas_realization_ids": bundle.get("inputs", {}).get("geo_refs", {}).get("atlas_realization_ids", []),
        "gates_failed": failed,
        "key_id": env.get("key_id"),
    }


# ─────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ices verify",
                                description="Vérifie hors-ligne un MissionBundle ICES (Ed25519).")
    p.add_argument("bundle", type=Path, help="chemin du MissionBundle JSON")
    p.add_argument("--json", action="store_true", help="sortie JSON brute")
    args = p.parse_args(argv)

    try:
        bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
        verdict = verify_bundle(bundle)
    except (VerdictError, OSError, json.JSONDecodeError) as e:
        print(f"✗ ICES : {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(verdict, ensure_ascii=False, indent=2))
    else:
        ok = verdict["valid"]
        mark = "✓" if ok else "✗"
        print(f"{mark} ICES verify — {'VALIDE' if ok else 'INVALIDE'}")
        print(f"    intégrité (digest)  : {'OK' if verdict['digest_match'] else 'ÉCHEC'}")
        print(f"    signature Ed25519   : {'OK' if verdict['signature_valid'] else 'ÉCHEC'}")
        print(f"    domaine             : {verdict['domain']}")
        print(f"    moteur (engine)     : {verdict['engine_version']}")
        print(f"    réalisations Atlas  : {len(verdict['atlas_realization_ids'])}")
        if verdict["gates_failed"]:
            print(f"    ⚠ gates en échec    : {', '.join(verdict['gates_failed'])}")
    return 0 if verdict["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

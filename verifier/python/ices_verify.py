#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Serge TABE DJATO
"""ICES verify : vérificateur de référence hors ligne du MissionBundle (Python).

Il applique la spécification ICES v0.1 et le livre blanc ICES v4.0 :

1. Canonicalisation : arrondi à précision fixée par champ (annexe A du livre
   blanc), puis sérialisation JSON Canonicalization Scheme (JCS, RFC 8785).
2. Condensat SHA3-256 de
   canon(inputs) || canon(scenario) || engine_version || canon(outputs) || canon(gates),
   dans cet ordre (spécification, section 3). Un bundle sans `scenario` omet ce terme.
3. Signature Ed25519 vérifiée avec la clé publique du sceau.
4. Ancrage de confiance : la clé du sceau doit figurer dans la liste de clés de
   confiance fournie (`--trusted-keys`) et ne pas avoir été révoquée à la date de
   signature. Sans liste, le vérificateur refuse (fail-closed) ; `--integrity-only`
   limite explicitement la vérification à l'intégrité.

Non couvert par cette version (Phases 2 et 3 de la feuille de route) : horodatage
en deux paliers, attestation agrafée, Manifeste de Projet, journal de transparence.

Codes de sortie : 0 conforme, 1 rejeté, 2 non vérifiable (fichier malformé, option
manquante).

Dépendance : pip install pynacl
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from decimal import ROUND_HALF_EVEN, Decimal
from pathlib import Path
from typing import Any

try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey
except ImportError:  # pragma: no cover
    VerifyKey = None  # type: ignore
    BadSignatureError = Exception  # type: ignore

# ─────────────────────────────────────────────────────────────────────────
# 1. Table de précision par champ (livre blanc, annexe A)
# ─────────────────────────────────────────────────────────────────────────
PRECISION_DEFAUT = 6
PRECISION_PAR_CHAMP: dict[str, int] = {
    "diametre_mm": 0, "diameters_mm": 0,
    "pression_bar": 3, "pressure_bar": 3,
    "debit_m3h": 4, "flow_m3h": 4,
    "cote_m": 3, "elevation_m": 3,
    "rugosite_hw": 2, "roughness_hw": 2,
    "resilience_outage": 6, "equity_index": 6, "p_service_ge_target": 6,
    "resilience_index": 6, "cot": 6, "eens": 6, "lowlp": 6,
    "latitude": 7, "longitude": 7,
}


class MalformedBundle(Exception):
    """Le fichier ne peut pas être vérifié : structure absente ou invalide."""


def arrondir(x: float, decimales: int) -> float:
    """Arrondi au plus proche, égalité vers le pair, sur la représentation
    décimale la plus courte de x (résultat identique sur toute plateforme)."""
    q = Decimal(1).scaleb(-decimales)
    return float(Decimal(repr(x)).quantize(q, rounding=ROUND_HALF_EVEN))


def appliquer_precision(obj: Any, decimales: int | None = None) -> Any:
    """Parcourt le document ; un champ nommé dans la table impose sa précision
    à tous les nombres flottants qu'il contient, sinon PRECISION_DEFAUT."""
    if isinstance(obj, dict):
        return {k: appliquer_precision(v, PRECISION_PAR_CHAMP.get(k, decimales)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [appliquer_precision(v, decimales) for v in obj]
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float):
        return arrondir(obj, PRECISION_DEFAUT if decimales is None else decimales)
    return obj


# ─────────────────────────────────────────────────────────────────────────
# 2. Sérialisation JCS (RFC 8785)
# ─────────────────────────────────────────────────────────────────────────
def nombre_es6(x: float) -> str:
    """Représentation d'un nombre selon ECMAScript (Number.prototype.toString)."""
    if x != x or x in (float("inf"), float("-inf")):
        raise MalformedBundle("nombre non fini : interdit en JCS")
    if x == 0:
        return "0"
    signe = "-" if x < 0 else ""
    d = Decimal(repr(abs(x)))
    chiffres = "".join(str(c) for c in d.as_tuple().digits).rstrip("0") or "0"
    k = len(chiffres)
    n = len(d.as_tuple().digits) + d.as_tuple().exponent  # position de la virgule
    if k <= n <= 21:
        s = chiffres + "0" * (n - k)
    elif 0 < n <= 21:
        s = chiffres[:n] + "." + chiffres[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + chiffres
    else:
        e = n - 1
        mant = chiffres[0] if k == 1 else chiffres[0] + "." + chiffres[1:]
        s = f"{mant}e{'+' if e >= 0 else '-'}{abs(e)}"
    return signe + s


def jcs(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        if abs(value) > 2 ** 53:
            raise MalformedBundle("entier hors de la plage exacte d'un double IEEE 754")
        return str(value)
    if isinstance(value, float):
        return nombre_es6(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        cles = sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))  # unités UTF-16
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(value[k]) for k in cles) + "}"
    raise MalformedBundle(f"type non sérialisable : {type(value).__name__}")


def forme_canonique(value: Any) -> bytes:
    return jcs(appliquer_precision(value)).encode("utf-8")


# ─────────────────────────────────────────────────────────────────────────
# 3. Condensat SHA3-256 (spécification, section 3)
# ─────────────────────────────────────────────────────────────────────────
def compute_digest(bundle: dict) -> str:
    try:
        engine = bundle["header"]["engine_version"]
        inputs, outputs, gates = bundle["inputs"], bundle["outputs"], bundle["gates"]
    except (KeyError, TypeError) as e:
        raise MalformedBundle(f"champ obligatoire absent : {e}") from e
    h = hashlib.sha3_256()
    h.update(forme_canonique(inputs))
    if "scenario" in bundle:  # état « legacy » déterministe : pas de scénario
        h.update(forme_canonique(bundle["scenario"]))
    h.update(engine.encode("utf-8"))
    h.update(forme_canonique(outputs))
    h.update(forme_canonique(gates))
    return h.hexdigest()


# ─────────────────────────────────────────────────────────────────────────
# 4. Clés : base64 brut ou did:key (Ed25519, multicodec 0xed01)
# ─────────────────────────────────────────────────────────────────────────
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    brut = n.to_bytes((n.bit_length() + 7) // 8, "big")
    zeros = len(s) - len(s.lstrip("1"))
    return b"\x00" * zeros + brut


def base58_encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = _B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + s


def cle_publique(valeur: str) -> bytes:
    """Octets bruts d'une clé publique Ed25519 : did:key:z6Mk… ou base64."""
    try:
        if valeur.startswith("did:key:z"):
            b = base58_decode(valeur[len("did:key:z"):])
            if b[:2] != b"\xed\x01" or len(b) != 34:
                raise ValueError("did:key non Ed25519")
            return b[2:]
        b = base64.b64decode(valeur, validate=True)
    except (ValueError, KeyError) as e:
        raise MalformedBundle(f"clé publique illisible : {e}") from e
    if len(b) != 32:
        raise MalformedBundle("une clé publique Ed25519 compte 32 octets")
    return b


def did_key(pub: bytes) -> str:
    return "did:key:z" + base58_encode(b"\xed\x01" + pub)


def _horodatage(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def statut_ancrage(pub: bytes, signed_at: str | None, cles_confiance: list[dict]) -> str:
    """ENROLEE, NON_ENROLEE ou REVOQUEE à la date de signature."""
    date = _horodatage(signed_at)
    for k in cles_confiance:
        if cle_publique(k["pubkey"]) != pub:
            continue
        debut, fin = _horodatage(k.get("valid_from")), _horodatage(k.get("revoked_at"))
        if date is None:
            return "REVOQUEE" if fin else "ENROLEE"
        if (debut and date < debut) or (fin and date >= fin):
            return "REVOQUEE"
        return "ENROLEE"
    return "NON_ENROLEE"


# ─────────────────────────────────────────────────────────────────────────
# 5. Vérification du sceau
# ─────────────────────────────────────────────────────────────────────────
def verify_bundle(bundle: dict, cles_confiance: list[dict] | None, integrite_seule: bool = False) -> dict:
    env = bundle.get("ices_envelope")
    if env is None:
        raise MalformedBundle("bundle non scellé (ices_envelope absent)")
    try:
        if env["alg"] != "Ed25519" or env["digest_alg"] != "SHA3-256":
            raise MalformedBundle(f"algorithmes non conformes à ICES v0.1 : {env['alg']}, {env['digest_alg']}")
        claimed, sig_b64, pub_s = env["digest"], env["sig"], env["pubkey"]
    except (KeyError, TypeError) as e:
        raise MalformedBundle(f"enveloppe incomplète : {e}") from e

    recomputed = compute_digest(bundle)
    integrite = recomputed == claimed
    pub = cle_publique(pub_s)

    signature = False
    if VerifyKey is None:
        raise MalformedBundle("PyNaCl non installé (pip install pynacl)")
    try:
        VerifyKey(pub).verify(bytes.fromhex(claimed), base64.b64decode(sig_b64))
        signature = True
    except (BadSignatureError, ValueError):
        signature = False

    if integrite_seule:
        ancrage = "NON_VERIFIE"
    else:
        ancrage = statut_ancrage(pub, env.get("signed_at"), cles_confiance or [])

    ok = integrite and signature and (integrite_seule or ancrage == "ENROLEE")
    return {
        "valid": ok,
        "integrity": integrite,
        "signature": signature,
        "anchoring": ancrage,
        "recomputed_digest": recomputed,
        "claimed_digest": claimed,
        "signer": env.get("key_id"),
        "signer_did": did_key(pub),
        "signed_at": env.get("signed_at"),
        "domain": bundle["header"].get("domain"),
        "engine_version": bundle["header"]["engine_version"],
        "gates_failed": [g.get("id") for g in bundle.get("gates", []) if g.get("status") == "FAIL"],
        "manifest": "NON_VERIFIE",
    }


# ─────────────────────────────────────────────────────────────────────────
# 6. Ligne de commande
# ─────────────────────────────────────────────────────────────────────────
_ANCRAGE = {
    "ENROLEE": "clé enrôlée",
    "NON_ENROLEE": "CLÉ NON ENRÔLÉE",
    "REVOQUEE": "CLÉ RÉVOQUÉE à la date de signature",
    "NON_VERIFIE": "non vérifié (--integrity-only)",
}


def _ligne(libelle: str, valeur: str) -> str:
    return f"{libelle} {'.' * max(2, 38 - len(libelle))} {valeur}"


def afficher(v: dict) -> None:
    print(_ligne("Sceau ICES", "CONFORME" if v["valid"] else "REJETÉ"))
    print(_ligne("Condensat SHA3-256", v["recomputed_digest"]))
    print(_ligne("Intégrité (recalcul)", "OK" if v["integrity"] else "ÉCHEC : le contenu a changé après la signature"))
    print(_ligne("Signature Ed25519", "VALIDE" if v["signature"] else "INVALIDE"))
    print(_ligne("Signataire", f"{v['signer']} ({_ANCRAGE[v['anchoring']]})"))
    print(_ligne("Identifiant de clé", v["signer_did"]))
    print(_ligne("Horodatage", f"{v['signed_at']} (palier 1 : date déclarée par l'émetteur)"))
    print(_ligne("Manifeste de Projet", "non vérifié (Phase 3 de la feuille de route)"))
    print(_ligne("Domaine, moteur", f"{v['domain']}, {v['engine_version']}"))
    if v["gates_failed"]:
        print(_ligne("Contrôles en échec", ", ".join(v["gates_failed"])))


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(prog="ices verify", description="Vérifie hors ligne un MissionBundle ICES.")
    p.add_argument("bundle", type=Path, help="chemin du MissionBundle JSON")
    p.add_argument("--trusted-keys", type=Path, help="liste JSON des clés de confiance (key_id, pubkey, valid_from, revoked_at)")
    p.add_argument("--integrity-only", action="store_true", help="vérifie l'intégrité et la signature sans ancrage de confiance")
    p.add_argument("--json", action="store_true", help="sortie JSON")
    a = p.parse_args(argv)

    try:
        if not a.trusted_keys and not a.integrity_only:
            raise MalformedBundle("aucune liste de clés de confiance (--trusted-keys) : refus par défaut ; "
                                  "--integrity-only limite la vérification à l'intégrité")
        bundle = json.loads(a.bundle.read_text(encoding="utf-8"))
        cles = json.loads(a.trusted_keys.read_text(encoding="utf-8")) if a.trusted_keys else None
        verdict = verify_bundle(bundle, cles, a.integrity_only)
    except (MalformedBundle, OSError, json.JSONDecodeError, ValueError, KeyError, TypeError) as e:
        print(f"ICES : vérification impossible : {e}", file=sys.stderr)
        return 2

    if a.json:
        print(json.dumps(verdict, ensure_ascii=False, indent=2))
    else:
        afficher(verdict)
    return 0 if verdict["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

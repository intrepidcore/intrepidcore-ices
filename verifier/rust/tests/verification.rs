// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Serge TABE DJATO
//! Verdicts : six vecteurs publics, ancrage de confiance et cas limites.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use ices_core::keys::{cle_publique, did_key};
use ices_core::{compute_digest, verify_bundle, Ancrage};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

fn vecteurs() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors")
}

fn lire(nom: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(vecteurs().join(nom)).unwrap()).unwrap()
}

fn cles() -> Vec<Value> {
    lire("trusted-keys.json").as_array().unwrap().clone()
}

fn lancer(args: &[&str]) -> (i32, String, String) {
    let sortie = Command::new(env!("CARGO_BIN_EXE_ices")).args(args).output().unwrap();
    (
        sortie.status.code().unwrap(),
        String::from_utf8_lossy(&sortie.stdout).into_owned(),
        String::from_utf8_lossy(&sortie.stderr).into_owned(),
    )
}

fn cli(fichier: &str) -> (i32, String, String) {
    let b = vecteurs().join(fichier);
    let k = vecteurs().join("trusted-keys.json");
    lancer(&["verify", b.to_str().unwrap(), "--trusted-keys", k.to_str().unwrap()])
}

#[test]
fn vecteur_exemple_conforme_code_0() {
    let (code, out, _) = cli("example-bundle.json");
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("CONFORME"));
    assert!(out.contains("2028f4be7a414290a3f69884489f734bc95ec787d67cd9ab25e9c324f3e40331"));
}

#[test]
fn vecteur_atlas_conforme_code_0() {
    let (code, out, _) = cli("example-bundle-atlas.json");
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("clé enrôlée"));
}

#[test]
fn vecteur_altere_rejete_integrite_code_1() {
    let (code, out, _) = cli("tampered-bundle.json");
    assert_eq!(code, 1);
    assert!(out.contains("ÉCHEC"));
    assert!(out.contains("condensat divergent"));
}

#[test]
fn vecteur_non_enrole_rejete_code_1() {
    let (code, out, _) = cli("unenrolled-bundle.json");
    assert_eq!(code, 1);
    assert!(out.contains("CLÉ NON ENRÔLÉE"));
}

#[test]
fn vecteur_revoque_rejete_code_1() {
    let (code, out, _) = cli("revoked-bundle.json");
    assert_eq!(code, 1);
    assert!(out.contains("RÉVOQUÉE"));
}

#[test]
fn vecteur_malforme_non_verifiable_code_2() {
    let (code, _, err) = cli("malformed-bundle.json");
    assert_eq!(code, 2);
    assert!(err.contains("header.engine_version"), "{err}");
}

#[test]
fn refus_par_defaut_sans_liste_de_cles() {
    let b = vecteurs().join("example-bundle.json");
    let (code, _, err) = lancer(&["verify", b.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(err.contains("refus par défaut"));
}

#[test]
fn integrity_only_accepte_une_cle_non_enrolee_et_le_dit() {
    let b = vecteurs().join("unenrolled-bundle.json");
    let (code, out, _) = lancer(&["verify", b.to_str().unwrap(), "--integrity-only"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("non vérifié (--integrity-only)"));
}

#[test]
fn sortie_json_et_champs_du_verdict() {
    let b = vecteurs().join("revoked-bundle.json");
    let k = vecteurs().join("trusted-keys.json");
    let (code, out, _) = lancer(&["verify", b.to_str().unwrap(), "--trusted-keys", k.to_str().unwrap(), "--json"]);
    assert_eq!(code, 1);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["valid"], json!(false));
    assert_eq!(v["integrity"], json!(true));
    assert_eq!(v["signature"], json!(true));
    assert_eq!(v["anchoring"], json!("REVOQUEE"));
    assert_eq!(v["manifest"], json!("NON_VERIFIE"));
    assert_eq!(v["phase_authorization"], json!("NON_VERIFIE"));
    assert_eq!(v["reasons"], json!(["clé révoquée à la date de signature"]));
}

#[test]
fn fichier_absent_ou_json_invalide_code_2() {
    let k = vecteurs().join("trusted-keys.json");
    let (code, _, err) = lancer(&["verify", "n-existe-pas.json", "--trusted-keys", k.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(err.contains("impossible"));
    let (code, _, _) = lancer(&["verify", k.to_str().unwrap(), "--trusted-keys", k.to_str().unwrap()]);
    assert_eq!(code, 2); // une liste de clés n'est pas un bundle
}

#[test]
fn option_inconnue_et_aide() {
    assert_eq!(lancer(&["--zzz"]).0, 2);
    let (code, out, _) = lancer(&["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("Usage"));
    let (code, out, _) = lancer(&["--version"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("ices "));
}

// ── Bundles construits dans le test, avec une clé déterministe ──────────────

fn cle() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn bundle_signe(signed_at: &str, sans_scenario: bool) -> Value {
    let mut b = json!({
        "header": { "schema_version": 2, "domain": "aep", "engine_version": "test-1" },
        "inputs": { "cote_m": 12.34567, "demande": 35848 },
        "scenario": { "graine": 42 },
        "outputs": { "cout": 275931289.0 },
        "gates": [ { "id": "G1", "status": "PASS" }, { "id": "G2", "status": "FAIL" } ]
    });
    if sans_scenario {
        b.as_object_mut().unwrap().remove("scenario");
    }
    let digest = compute_digest(&b).unwrap();
    let sig = cle().sign(&hex_vers_octets(&digest));
    let pubkey = cle().verifying_key().to_bytes();
    b["ices_envelope"] = json!({
        "alg": "Ed25519", "digest_alg": "SHA3-256", "digest": digest,
        "sig": STANDARD.encode(sig.to_bytes()),
        "pubkey": STANDARD.encode(pubkey),
        "key_id": "test-cle", "signed_at": signed_at
    });
    b
}

fn hex_vers_octets(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn liste(valid_from: Option<&str>, revoked_at: Option<&str>) -> Vec<Value> {
    vec![json!({
        "key_id": "test-cle",
        "pubkey": STANDARD.encode(cle().verifying_key().to_bytes()),
        "valid_from": valid_from,
        "revoked_at": revoked_at
    })]
}

#[test]
fn bundle_signe_conforme_et_controles_en_echec_remontes() {
    let b = bundle_signe("2026-07-01T00:00:00Z", false);
    let v = verify_bundle(&b, Some(&liste(Some("2026-01-01T00:00:00Z"), None)), false).unwrap();
    assert!(v.valid && v.integrity && v.signature);
    assert_eq!(v.anchoring, Ancrage::Enrolee);
    assert_eq!(v.gates_failed, vec![json!("G2")]);
    assert!(v.reasons.is_empty());
}

#[test]
fn bundle_sans_scenario_omet_ce_terme() {
    let avec = bundle_signe("2026-07-01T00:00:00Z", false);
    let sans = bundle_signe("2026-07-01T00:00:00Z", true);
    assert_ne!(compute_digest(&avec).unwrap(), compute_digest(&sans).unwrap());
    let v = verify_bundle(&sans, Some(&liste(None, None)), false).unwrap();
    assert!(v.valid);
}

#[test]
fn revocation_a_la_date_de_signature() {
    let l = liste(Some("2026-01-01T00:00:00Z"), Some("2026-07-01T00:00:00Z"));
    // signé avant la révocation : accepté ; à la date exacte ou après : révoqué
    assert!(verify_bundle(&bundle_signe("2026-06-30T23:59:59Z", false), Some(&l), false).unwrap().valid);
    let v = verify_bundle(&bundle_signe("2026-07-01T00:00:00Z", false), Some(&l), false).unwrap();
    assert!(!v.valid);
    assert_eq!(v.anchoring, Ancrage::Revoquee);
}

#[test]
fn signature_avant_valid_from_est_rejetee() {
    let l = liste(Some("2026-07-01T00:00:00Z"), None);
    let v = verify_bundle(&bundle_signe("2026-06-01T00:00:00Z", false), Some(&l), false).unwrap();
    assert_eq!(v.anchoring, Ancrage::Revoquee);
    assert!(!v.valid);
}

#[test]
fn fuseaux_horaires_compares_en_utc() {
    // 2026-07-01T01:00:00+02:00 = 2026-06-30T23:00:00Z, avant la révocation à minuit UTC.
    let l = liste(None, Some("2026-07-01T00:00:00Z"));
    assert!(verify_bundle(&bundle_signe("2026-07-01T01:00:00+02:00", false), Some(&l), false).unwrap().valid);
}

#[test]
fn cle_en_did_key_equivalente_a_la_cle_en_base64() {
    let pubkey = cle().verifying_key().to_bytes();
    let did = did_key(&pubkey);
    assert!(did.starts_with("did:key:z6Mk"));
    assert_eq!(cle_publique(&did).unwrap(), pubkey);
    assert_eq!(cle_publique(&STANDARD.encode(pubkey)).unwrap(), pubkey);
    let mut b = bundle_signe("2026-07-01T00:00:00Z", false);
    b["ices_envelope"]["pubkey"] = json!(did);
    assert!(verify_bundle(&b, Some(&liste(None, None)), false).unwrap().valid);
}

#[test]
fn cles_illisibles_sont_malformees() {
    assert!(cle_publique("pas-une-cle!").is_err());
    assert!(cle_publique("AAAA").is_err()); // base64 valide mais 3 octets
    assert!(cle_publique("did:key:z6Mk").is_err());
    assert!(cle_publique("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme").is_err()); // secp256k1
}

#[test]
fn signature_alteree_ou_illisible_donne_signature_invalide() {
    let l = liste(None, None);
    let mut b = bundle_signe("2026-07-01T00:00:00Z", false);
    let mut octets = STANDARD.decode(b["ices_envelope"]["sig"].as_str().unwrap()).unwrap();
    octets[0] ^= 1;
    b["ices_envelope"]["sig"] = json!(STANDARD.encode(octets));
    let v = verify_bundle(&b, Some(&l), false).unwrap();
    assert!(v.integrity && !v.signature && !v.valid);
    assert_eq!(v.reasons, vec!["signature invalide"]);

    b["ices_envelope"]["sig"] = json!("!!pas du base64!!");
    assert!(!verify_bundle(&b, Some(&l), false).unwrap().signature);
    b["ices_envelope"]["sig"] = json!("AAAA");
    assert!(!verify_bundle(&b, Some(&l), false).unwrap().signature);
}

#[test]
fn signature_d_une_autre_cle_est_invalide() {
    let mut b = bundle_signe("2026-07-01T00:00:00Z", false);
    let autre = SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();
    b["ices_envelope"]["pubkey"] = json!(STANDARD.encode(autre));
    let v = verify_bundle(&b, None, true).unwrap();
    assert!(!v.signature && !v.valid);
}

#[test]
fn algorithmes_non_conformes_et_enveloppe_incomplete() {
    let mut b = bundle_signe("2026-07-01T00:00:00Z", false);
    b["ices_envelope"]["alg"] = json!("HS256");
    assert!(verify_bundle(&b, None, true).is_err());
    let mut b = bundle_signe("2026-07-01T00:00:00Z", false);
    b["ices_envelope"]["digest_alg"] = json!("SHA-256");
    assert!(verify_bundle(&b, None, true).is_err());
    let mut b = bundle_signe("2026-07-01T00:00:00Z", false);
    b["ices_envelope"].as_object_mut().unwrap().remove("sig");
    assert!(verify_bundle(&b, None, true).is_err());
    let mut b = bundle_signe("2026-07-01T00:00:00Z", false);
    b.as_object_mut().unwrap().remove("ices_envelope");
    assert!(verify_bundle(&b, None, true).is_err());
}

#[test]
fn modifier_un_champ_du_contenu_change_le_condensat() {
    let b = bundle_signe("2026-07-01T00:00:00Z", false);
    for (bloc, champ, valeur) in [
        ("inputs", "demande", json!(35849)),
        ("outputs", "cout", json!(275931290.0)),
        ("scenario", "graine", json!(43)),
    ] {
        let mut t = b.clone();
        t[bloc][champ] = valeur;
        let v = verify_bundle(&t, Some(&liste(None, None)), false).unwrap();
        assert!(!v.integrity && !v.valid, "{bloc}.{champ}");
    }
    let mut t = b.clone();
    t["header"]["engine_version"] = json!("test-2");
    assert!(!verify_bundle(&t, Some(&liste(None, None)), false).unwrap().integrity);
    let mut t = b.clone();
    t["gates"][0]["status"] = json!("FAIL");
    assert!(!verify_bundle(&t, Some(&liste(None, None)), false).unwrap().integrity);
}

#[test]
fn un_ecart_sous_la_precision_n_altere_pas_le_condensat() {
    // cote_m est arrondi à 3 décimales avant le hachage.
    let b = bundle_signe("2026-07-01T00:00:00Z", false);
    let mut t = b.clone();
    t["inputs"]["cote_m"] = json!(12.3456701);
    assert!(verify_bundle(&t, Some(&liste(None, None)), false).unwrap().integrity);
    let mut t = b.clone();
    t["inputs"]["cote_m"] = json!(12.3466);
    assert!(!verify_bundle(&t, Some(&liste(None, None)), false).unwrap().integrity);
}

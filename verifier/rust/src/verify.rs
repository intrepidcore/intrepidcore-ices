// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Serge TABE DJATO
//! Vérification du sceau d'un MissionBundle (spécification ICES v0.1, livre
//! blanc v4.0, section « Étapes de la vérification »).
//!
//! Étapes couvertes : 1 (arrondi et JCS), 2 (condensat SHA3-256), 3 (extraction
//! de la signature et de la clé), 4 (signature Ed25519 et égalité des
//! condensats), 5 (liste de confiance et révocation), 7 (verdict motivé).
//! L'étape 6 (autorisation de la clé pour la phase du document, d'après le
//! Manifeste de Projet) relève de la Phase 3 de la feuille de route : le
//! verdict la déclare « NON_VERIFIE ».

use crate::canon::forme_canonique;
use crate::error::{Malformed, Result};
use crate::keys::{cle_publique, did_key, statut_ancrage, Ancrage};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};

/// Verdict complet d'une vérification.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub valid: bool,
    pub integrity: bool,
    pub signature: bool,
    pub anchoring: Ancrage,
    pub recomputed_digest: String,
    pub claimed_digest: String,
    pub signer: Option<String>,
    pub signer_did: String,
    pub signed_at: Option<String>,
    pub domain: Option<String>,
    pub engine_version: String,
    pub gates_failed: Vec<Value>,
    /// Motifs précis du rejet, vide si le sceau est conforme.
    pub reasons: Vec<&'static str>,
}

impl Verdict {
    /// Forme JSON : champs du vérificateur de référence, plus `reasons` et
    /// `phase_authorization`.
    pub fn to_json(&self) -> Value {
        json!({
            "valid": self.valid,
            "integrity": self.integrity,
            "signature": self.signature,
            "anchoring": self.anchoring.code(),
            "recomputed_digest": self.recomputed_digest,
            "claimed_digest": self.claimed_digest,
            "signer": self.signer,
            "signer_did": self.signer_did,
            "signed_at": self.signed_at,
            "domain": self.domain,
            "engine_version": self.engine_version,
            "gates_failed": self.gates_failed,
            "manifest": "NON_VERIFIE",
            "phase_authorization": "NON_VERIFIE",
            "reasons": self.reasons,
        })
    }
}

fn texte(v: Option<&Value>, nom: &str) -> Result<String> {
    v.and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Malformed::new(format!("champ obligatoire absent ou non textuel : {nom}")))
}

fn requis<'a>(v: &'a Value, nom: &str) -> Result<&'a Value> {
    v.get(nom)
        .ok_or_else(|| Malformed::new(format!("champ obligatoire absent : {nom}")))
}

/// Condensat SHA3-256, en hexadécimal minuscule, de
/// `C(inputs) ‖ C(scenario) ‖ engine_version ‖ C(outputs) ‖ C(gates)`.
/// Un bundle sans `scenario` omet ce terme.
pub fn compute_digest(bundle: &Value) -> Result<String> {
    let header = requis(bundle, "header")?;
    let engine = texte(header.get("engine_version"), "header.engine_version")?;
    let inputs = requis(bundle, "inputs")?;
    let outputs = requis(bundle, "outputs")?;
    let gates = requis(bundle, "gates")?;
    let mut h = Sha3_256::new();
    h.update(forme_canonique(inputs)?);
    if let Some(s) = bundle.get("scenario") {
        h.update(forme_canonique(s)?);
    }
    h.update(engine.as_bytes());
    h.update(forme_canonique(outputs)?);
    h.update(forme_canonique(gates)?);
    Ok(hex(&h.finalize()))
}

/// Formes canoniques des blocs signés, dans l'ordre du condensat : outil
/// d'audit pour comparer deux implémentations octet par octet.
pub fn blocs_canoniques(bundle: &Value) -> Result<Vec<(&'static str, String)>> {
    let header = requis(bundle, "header")?;
    let engine = texte(header.get("engine_version"), "header.engine_version")?;
    let canon = |v: &Value| -> Result<String> {
        String::from_utf8(forme_canonique(v)?).map_err(|_| Malformed::new("UTF-8 invalide"))
    };
    let mut blocs = vec![("inputs", canon(requis(bundle, "inputs")?)?)];
    if let Some(s) = bundle.get("scenario") {
        blocs.push(("scenario", canon(s)?));
    }
    blocs.push(("engine_version", engine));
    blocs.push(("outputs", canon(requis(bundle, "outputs")?)?));
    blocs.push(("gates", canon(requis(bundle, "gates")?)?));
    Ok(blocs)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_vers_octets(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Signature Ed25519 sur les octets du condensat. Toute entrée illisible
/// (hexadécimal, base64, longueur) donne une signature invalide, pas une erreur.
fn signature_valide(pubkey: &[u8; 32], digest_hex: &str, sig_b64: &str) -> bool {
    let (Some(msg), Ok(sig), Ok(vk)) = (
        hex_vers_octets(digest_hex),
        STANDARD.decode(sig_b64),
        VerifyingKey::from_bytes(pubkey),
    ) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig) else {
        return false;
    };
    vk.verify_strict(&msg, &sig).is_ok()
}

/// Vérifie le sceau d'un bundle. Sans liste de clés (`cles_confiance` absente)
/// et hors `integrite_seule`, la clé est « non enrôlée » : refus par défaut.
pub fn verify_bundle(
    bundle: &Value,
    cles_confiance: Option<&[Value]>,
    integrite_seule: bool,
) -> Result<Verdict> {
    let env = bundle
        .get("ices_envelope")
        .ok_or_else(|| Malformed::new("bundle non scellé (ices_envelope absent)"))?;
    let alg = texte(env.get("alg"), "ices_envelope.alg")?;
    let digest_alg = texte(env.get("digest_alg"), "ices_envelope.digest_alg")?;
    if alg != "Ed25519" || digest_alg != "SHA3-256" {
        return Err(Malformed::new(format!(
            "algorithmes non conformes à ICES v0.1 : {alg}, {digest_alg}"
        )));
    }
    let claimed = texte(env.get("digest"), "ices_envelope.digest")?;
    let sig_b64 = texte(env.get("sig"), "ices_envelope.sig")?;
    let pub_s = texte(env.get("pubkey"), "ices_envelope.pubkey")?;

    let recomputed = compute_digest(bundle)?;
    let integrite = recomputed == claimed;
    let pubkey = cle_publique(&pub_s)?;
    let signature = signature_valide(&pubkey, &claimed, &sig_b64);

    let ancrage = if integrite_seule {
        Ancrage::NonVerifie
    } else {
        statut_ancrage(&pubkey, env.get("signed_at"), cles_confiance.unwrap_or(&[]))?
    };
    let ok = integrite && signature && (integrite_seule || ancrage == Ancrage::Enrolee);

    let mut reasons = Vec::new();
    if !integrite {
        reasons.push("condensat divergent : le contenu a changé après la signature");
    }
    if !signature {
        reasons.push("signature invalide");
    }
    match ancrage {
        Ancrage::NonEnrolee => reasons.push("clé non enrôlée dans la liste de confiance"),
        Ancrage::Revoquee => reasons.push("clé révoquée à la date de signature"),
        _ => {}
    }

    let header = requis(bundle, "header")?;
    let gates_failed = bundle
        .get("gates")
        .and_then(Value::as_array)
        .map(|g| {
            g.iter()
                .filter(|x| x.get("status").and_then(Value::as_str) == Some("FAIL"))
                .map(|x| x.get("id").cloned().unwrap_or(Value::Null))
                .collect()
        })
        .unwrap_or_default();

    Ok(Verdict {
        valid: ok,
        integrity: integrite,
        signature,
        anchoring: ancrage,
        recomputed_digest: recomputed,
        claimed_digest: claimed,
        signer: env.get("key_id").and_then(Value::as_str).map(str::to_owned),
        signer_did: did_key(&pubkey),
        signed_at: env.get("signed_at").and_then(Value::as_str).map(str::to_owned),
        domain: header.get("domain").and_then(Value::as_str).map(str::to_owned),
        engine_version: texte(header.get("engine_version"), "header.engine_version")?,
        gates_failed,
        reasons,
    })
}

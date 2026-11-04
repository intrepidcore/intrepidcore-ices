// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Serge TABE DJATO
//! Clés publiques Ed25519 (base64 brut ou `did:key`) et ancrage de confiance.

use crate::error::{Malformed, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde_json::Value;

/// Préfixe multicodec d'une clé publique Ed25519 dans un `did:key` (0xed01).
const MULTICODEC_ED25519: [u8; 2] = [0xed, 0x01];
const PREFIXE_DID: &str = "did:key:z";

/// Octets bruts d'une clé publique Ed25519 : `did:key:z6Mk…` ou base64.
pub fn cle_publique(valeur: &str) -> Result<[u8; 32]> {
    let octets: Vec<u8> = if let Some(b58) = valeur.strip_prefix(PREFIXE_DID) {
        let b = bs58::decode(b58)
            .into_vec()
            .map_err(|e| Malformed::new(format!("clé publique illisible : {e}")))?;
        if b.len() != 34 || b[..2] != MULTICODEC_ED25519 {
            return Err(Malformed::new("clé publique illisible : did:key non Ed25519"));
        }
        b[2..].to_vec()
    } else {
        STANDARD
            .decode(valeur)
            .map_err(|e| Malformed::new(format!("clé publique illisible : {e}")))?
    };
    octets
        .try_into()
        .map_err(|_| Malformed::new("une clé publique Ed25519 compte 32 octets"))
}

/// Identifiant `did:key` d'une clé publique Ed25519.
pub fn did_key(pubkey: &[u8; 32]) -> String {
    let mut b = MULTICODEC_ED25519.to_vec();
    b.extend_from_slice(pubkey);
    format!("{PREFIXE_DID}{}", bs58::encode(b).into_string())
}

/// Résultat de l'ancrage de la clé du sceau dans la liste de confiance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ancrage {
    Enrolee,
    NonEnrolee,
    Revoquee,
    NonVerifie,
}

impl Ancrage {
    pub fn code(self) -> &'static str {
        match self {
            Ancrage::Enrolee => "ENROLEE",
            Ancrage::NonEnrolee => "NON_ENROLEE",
            Ancrage::Revoquee => "REVOQUEE",
            Ancrage::NonVerifie => "NON_VERIFIE",
        }
    }
}

fn horodatage(v: Option<&Value>) -> Result<Option<DateTime<Utc>>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => DateTime::parse_from_rfc3339(s)
            .map(|d| Some(d.with_timezone(&Utc)))
            .map_err(|e| Malformed::new(format!("horodatage illisible « {s} » : {e}"))),
        Some(_) => Err(Malformed::new("horodatage : une chaîne RFC 3339 est attendue")),
    }
}

/// Statut de la clé à la date de signature : enrôlée, non enrôlée ou révoquée.
/// Sans date de signature, une clé qui porte une date de révocation est
/// considérée comme révoquée (refus par prudence).
pub fn statut_ancrage(
    pubkey: &[u8; 32],
    signed_at: Option<&Value>,
    cles_confiance: &[Value],
) -> Result<Ancrage> {
    let date = horodatage(signed_at)?;
    for k in cles_confiance {
        let valeur = k
            .get("pubkey")
            .and_then(Value::as_str)
            .ok_or_else(|| Malformed::new("liste de confiance : champ pubkey absent"))?;
        if &cle_publique(valeur)? != pubkey {
            continue;
        }
        let debut = horodatage(k.get("valid_from"))?;
        let fin = horodatage(k.get("revoked_at"))?;
        return Ok(match date {
            None if fin.is_some() => Ancrage::Revoquee,
            None => Ancrage::Enrolee,
            Some(d) if debut.is_some_and(|b| d < b) || fin.is_some_and(|f| d >= f) => {
                Ancrage::Revoquee
            }
            Some(_) => Ancrage::Enrolee,
        });
    }
    Ok(Ancrage::NonEnrolee)
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Serge TABE DJATO
//! `ices verify` : vérifie hors ligne un MissionBundle ICES.
//!
//! Codes de sortie : 0 conforme, 1 rejeté, 2 non vérifiable (fichier malformé,
//! option manquante, erreur de lecture).

use ices_core::{blocs_canoniques, verify_bundle, Ancrage, Malformed, Verdict};
use serde_json::Value;
use std::path::PathBuf;
use std::process::ExitCode;

const AIDE: &str = "\
Usage : ices [verify] <bundle.json> [--trusted-keys <cles.json>] [--integrity-only] [--json]
        ices canon <bundle.json>      affiche la forme canonique de chaque bloc signé (audit)

  --trusted-keys <f>   liste JSON des clés de confiance (key_id, pubkey, valid_from, revoked_at)
  --integrity-only     vérifie l'intégrité et la signature, sans ancrage de confiance
  --json               sortie JSON
  --version            affiche la version

Sans liste de clés et sans --integrity-only, la vérification est refusée (refus par défaut).
Codes de sortie : 0 conforme, 1 rejeté, 2 non vérifiable.";

struct Options {
    bundle: PathBuf,
    trusted_keys: Option<PathBuf>,
    integrity_only: bool,
    json: bool,
    canon: bool,
}

enum Commande {
    Verifier(Options),
    Aide,
    Version,
}

fn lire_arguments(args: &[String]) -> Result<Commande, Malformed> {
    let mut bundle = None;
    let mut trusted_keys = None;
    let mut integrity_only = false;
    let mut json = false;
    let mut canon = false;
    let mut it = args.iter().peekable();
    match it.peek().map(|s| s.as_str()) {
        Some("verify") => {
            it.next();
        }
        Some("canon") => {
            it.next();
            canon = true;
        }
        _ => {}
    }
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => return Ok(Commande::Aide),
            "--version" | "-V" => return Ok(Commande::Version),
            "--integrity-only" => integrity_only = true,
            "--json" => json = true,
            "--trusted-keys" => {
                let v = it
                    .next()
                    .ok_or_else(|| Malformed::new("--trusted-keys attend un chemin"))?;
                trusted_keys = Some(PathBuf::from(v));
            }
            autre if autre.starts_with("--trusted-keys=") => {
                trusted_keys = Some(PathBuf::from(&autre["--trusted-keys=".len()..]));
            }
            autre if autre.starts_with('-') => {
                return Err(Malformed::new(format!("option inconnue : {autre}")))
            }
            chemin => {
                if bundle.replace(PathBuf::from(chemin)).is_some() {
                    return Err(Malformed::new("un seul fichier de bundle est attendu"));
                }
            }
        }
    }
    let bundle = bundle.ok_or_else(|| Malformed::new("chemin du MissionBundle absent"))?;
    Ok(Commande::Verifier(Options { bundle, trusted_keys, integrity_only, json, canon }))
}

fn lire_json(chemin: &PathBuf) -> Result<Value, Malformed> {
    let brut = std::fs::read(chemin)
        .map_err(|e| Malformed::new(format!("lecture de {} impossible : {e}", chemin.display())))?;
    let brut = brut.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&brut);
    serde_json::from_slice(brut)
        .map_err(|e| Malformed::new(format!("JSON invalide dans {} : {e}", chemin.display())))
}

fn ligne(libelle: &str, valeur: &str) -> String {
    let points = 38usize.saturating_sub(libelle.chars().count()).max(2);
    format!("{libelle} {} {valeur}", ".".repeat(points))
}

fn libelle_ancrage(a: Ancrage) -> &'static str {
    match a {
        Ancrage::Enrolee => "clé enrôlée",
        Ancrage::NonEnrolee => "CLÉ NON ENRÔLÉE",
        Ancrage::Revoquee => "CLÉ RÉVOQUÉE à la date de signature",
        Ancrage::NonVerifie => "non vérifié (--integrity-only)",
    }
}

fn afficher(v: &Verdict) {
    let signataire = v.signer.clone().unwrap_or_else(|| "null".into());
    let signed_at = v.signed_at.clone().unwrap_or_else(|| "null".into());
    let domaine = v.domain.clone().unwrap_or_else(|| "null".into());
    println!("{}", ligne("Sceau ICES", if v.valid { "CONFORME" } else { "REJETÉ" }));
    println!("{}", ligne("Condensat SHA3-256", &v.recomputed_digest));
    println!(
        "{}",
        ligne(
            "Intégrité (recalcul)",
            if v.integrity { "OK" } else { "ÉCHEC : le contenu a changé après la signature" }
        )
    );
    println!("{}", ligne("Signature Ed25519", if v.signature { "VALIDE" } else { "INVALIDE" }));
    println!("{}", ligne("Signataire", &format!("{signataire} ({})", libelle_ancrage(v.anchoring))));
    println!("{}", ligne("Identifiant de clé", &v.signer_did));
    println!(
        "{}",
        ligne("Horodatage", &format!("{signed_at} (palier 1 : date déclarée par l'émetteur)"))
    );
    println!("{}", ligne("Manifeste de Projet", "non vérifié (Phase 3 de la feuille de route)"));
    println!("{}", ligne("Domaine, moteur", &format!("{domaine}, {}", v.engine_version)));
    if !v.gates_failed.is_empty() {
        let ids: Vec<String> = v
            .gates_failed
            .iter()
            .map(|g| g.as_str().map(str::to_owned).unwrap_or_else(|| "null".into()))
            .collect();
        println!("{}", ligne("Contrôles en échec", &ids.join(", ")));
    }
    if !v.reasons.is_empty() {
        println!("{}", ligne("Motifs du rejet", &v.reasons.join(" ; ")));
    }
}

fn executer(args: &[String]) -> Result<Option<Verdict>, Malformed> {
    let opts = match lire_arguments(args)? {
        Commande::Aide => {
            println!("{AIDE}");
            return Ok(None);
        }
        Commande::Version => {
            println!("ices {}", env!("CARGO_PKG_VERSION"));
            return Ok(None);
        }
        Commande::Verifier(o) => o,
    };
    if opts.canon {
        let bundle = lire_json(&opts.bundle)?;
        for (nom, forme) in blocs_canoniques(&bundle)? {
            println!("{nom}	{forme}");
        }
        return Ok(None);
    }
    if opts.trusted_keys.is_none() && !opts.integrity_only {
        return Err(Malformed::new(
            "aucune liste de clés de confiance (--trusted-keys) : refus par défaut ; \
             --integrity-only limite la vérification à l'intégrité",
        ));
    }
    let bundle = lire_json(&opts.bundle)?;
    let cles = match &opts.trusted_keys {
        Some(p) => match lire_json(p)? {
            Value::Array(a) => Some(a),
            _ => return Err(Malformed::new("la liste de clés de confiance doit être un tableau JSON")),
        },
        None => None,
    };
    let verdict = verify_bundle(&bundle, cles.as_deref(), opts.integrity_only)?;
    if opts.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&verdict.to_json()).expect("sérialisation JSON")
        );
    } else {
        afficher(&verdict);
    }
    Ok(Some(verdict))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match executer(&args) {
        Ok(Some(v)) if v.valid => ExitCode::from(0),
        Ok(Some(_)) => ExitCode::from(1),
        Ok(None) => ExitCode::from(0),
        Err(e) => {
            eprintln!("ICES : vérification impossible : {e}");
            ExitCode::from(2)
        }
    }
}

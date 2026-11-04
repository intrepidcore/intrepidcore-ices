// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Serge TABE DJATO
//! Canonicalisation : arrondi par champ (annexe A du livre blanc), puis
//! sérialisation JSON Canonicalization Scheme (JCS, RFC 8785).
//!
//! L'arrondi travaille sur la représentation décimale la plus courte du
//! nombre, par manipulation de chiffres : aucun calcul flottant intermédiaire,
//! donc un résultat identique sur toute plateforme.

use crate::error::{Malformed, Result};
use serde_json::{Number, Value};

/// Nombre de décimales de tout nombre flottant hors du tableau.
pub const PRECISION_DEFAUT: i32 = 6;

/// Plus grand entier exactement représentable par un double IEEE 754.
const ENTIER_MAX: u64 = 1 << 53;

/// Chiffres significatifs au plus dans un résultat d'arrondi (contexte décimal
/// de 28 chiffres du vérificateur de référence).
const CHIFFRES_MAX: i32 = 28;

/// Précision imposée par un nom de champ (livre blanc, tableau « précision »).
pub fn precision_champ(nom: &str) -> Option<i32> {
    Some(match nom {
        "diametre_mm" | "diameters_mm" => 0,
        "pression_bar" | "pressure_bar" => 3,
        "debit_m3h" | "flow_m3h" => 4,
        "cote_m" | "elevation_m" => 3,
        "rugosite_hw" | "roughness_hw" => 2,
        "resilience_outage" | "equity_index" | "p_service_ge_target" | "resilience_index"
        | "cot" | "eens" | "lowlp" => 6,
        "latitude" | "longitude" => 7,
        _ => return None,
    })
}

/// Chiffres significatifs les plus courts qui redonnent `x` (hors signe) :
/// `(chiffres, n)` avec x = 0,chiffres × 10^n. `x` est fini et non nul.
///
/// La bibliothèque standard de Rust produit la longueur minimale, mais départage
/// mal deux candidats équidistants de la valeur exacte (elle prend le plus
/// grand, par exemple …63 pour 80559923956500,625). ECMAScript (et donc JCS)
/// exige le plus proche et, à égalité, le chiffre pair. On recalcule donc les
/// chiffres à cette longueur par un arrondi exact (égalité vers le pair), et on
/// ne garde ce résultat que s'il redonne bien `x`.
fn chiffres_courts(x: f64) -> (String, i32) {
    let ax = x.abs();
    let (mut chiffres, mut exp) = decouper(&format!("{:e}", ax));
    let exact = format!("{:.*e}", chiffres.len().saturating_sub(1), ax);
    if exact.parse::<f64>().is_ok_and(|r| r == ax) {
        let (c, e) = decouper(&exact);
        chiffres = c;
        exp = e;
    }
    (chiffres, exp + 1)
}

/// Sépare une écriture scientifique en chiffres (sans zéros finaux) et exposant.
fn decouper(s: &str) -> (String, i32) {
    let (mant, exp) = s.split_once('e').expect("format scientifique");
    let exp: i32 = exp.parse().expect("exposant entier");
    let mut chiffres: String = mant.chars().filter(|c| *c != '.').collect();
    while chiffres.len() > 1 && chiffres.ends_with('0') {
        chiffres.pop();
    }
    (chiffres, exp)
}

/// Arrondi au plus proche, égalité vers le pair, à `dec` décimales.
pub fn arrondir(x: f64, dec: i32) -> Result<f64> {
    if !x.is_finite() {
        return Err(Malformed::new("nombre non fini : interdit en JCS"));
    }
    if x == 0.0 {
        return Ok(0.0);
    }
    let (d, n) = chiffres_courts(x);
    let d = d.as_bytes();
    let garde = n + dec; // nombre de chiffres conservés
    let (res, nres): (Vec<u8>, i32) = if garde >= d.len() as i32 {
        (d.to_vec(), n)
    } else if garde < 0 {
        (Vec::new(), 0)
    } else if garde == 0 {
        let reste_non_nul = d[1..].iter().any(|c| *c != b'0');
        if d[0] > b'5' || (d[0] == b'5' && reste_non_nul) {
            (vec![b'1'], n + 1)
        } else {
            (Vec::new(), 0)
        }
    } else {
        let g = garde as usize;
        let mut gardes = d[..g].to_vec();
        let c = d[g];
        let reste_non_nul = d[g + 1..].iter().any(|c| *c != b'0');
        let dernier_impair = (gardes[g - 1] - b'0') % 2 == 1;
        let monter = c > b'5' || (c == b'5' && (reste_non_nul || dernier_impair));
        let mut npos = n;
        if monter {
            let mut i = g;
            loop {
                if i == 0 {
                    gardes.insert(0, b'1');
                    npos += 1;
                    break;
                }
                i -= 1;
                if gardes[i] == b'9' {
                    gardes[i] = b'0';
                } else {
                    gardes[i] += 1;
                    break;
                }
            }
        }
        while gardes.len() > 1 && gardes.last() == Some(&b'0') {
            gardes.pop();
        }
        (gardes, npos)
    };
    if res.is_empty() {
        return Ok(0.0);
    }
    if nres > 0 && nres + dec > CHIFFRES_MAX {
        return Err(Malformed::new(
            "nombre trop grand pour l'arrondi décimal à 28 chiffres significatifs",
        ));
    }
    let texte = format!("0.{}e{}", String::from_utf8_lossy(&res), nres);
    let v: f64 = texte.parse().map_err(|_| Malformed::new("arrondi illisible"))?;
    Ok(if x < 0.0 { -v } else { v })
}

/// Parcourt le document : un champ nommé dans la table impose sa précision à
/// tous les nombres flottants qu'il contient, sinon la précision par défaut.
pub fn appliquer_precision(v: &Value, dec: Option<i32>) -> Result<Value> {
    Ok(match v {
        Value::Object(m) => {
            let mut out = serde_json::Map::new();
            for (k, x) in m {
                out.insert(k.clone(), appliquer_precision(x, precision_champ(k).or(dec))?);
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(
            a.iter()
                .map(|x| appliquer_precision(x, dec))
                .collect::<Result<Vec<_>>>()?,
        ),
        Value::Number(n) if n.is_f64() => {
            let f = n.as_f64().ok_or_else(|| Malformed::new("nombre illisible"))?;
            let r = arrondir(f, dec.unwrap_or(PRECISION_DEFAUT))?;
            Value::Number(
                Number::from_f64(r).ok_or_else(|| Malformed::new("nombre non fini : interdit en JCS"))?,
            )
        }
        autre => autre.clone(),
    })
}

/// Représentation d'un nombre selon ECMAScript (`Number.prototype.toString`).
pub fn nombre_es6(x: f64) -> Result<String> {
    if !x.is_finite() {
        return Err(Malformed::new("nombre non fini : interdit en JCS"));
    }
    if x == 0.0 {
        return Ok("0".to_string());
    }
    let signe = if x < 0.0 { "-" } else { "" };
    let (chiffres, n) = chiffres_courts(x);
    let k = chiffres.len() as i32;
    let corps = if k <= n && n <= 21 {
        format!("{}{}", chiffres, "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &chiffres[..n as usize], &chiffres[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{}", "0".repeat((-n) as usize), chiffres)
    } else {
        let e = n - 1;
        let mant = if k == 1 {
            chiffres.clone()
        } else {
            format!("{}.{}", &chiffres[..1], &chiffres[1..])
        };
        format!("{}e{}{}", mant, if e >= 0 { "+" } else { "-" }, e.abs())
    };
    Ok(format!("{signe}{corps}"))
}

fn echapper(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Sérialisation JCS (RFC 8785). Les clés sont triées par unités UTF-16.
pub fn jcs(v: &Value) -> Result<String> {
    let mut out = String::new();
    jcs_into(v, &mut out)?;
    Ok(out)
}

fn jcs_into(v: &Value, out: &mut String) -> Result<()> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::String(s) => echapper(s, out),
        Value::Number(n) => {
            if n.is_f64() {
                out.push_str(&nombre_es6(
                    n.as_f64().ok_or_else(|| Malformed::new("nombre illisible"))?,
                )?);
            } else {
                let magnitude = if let Some(i) = n.as_i64() {
                    i.unsigned_abs()
                } else {
                    n.as_u64().ok_or_else(|| Malformed::new("entier illisible"))?
                };
                if magnitude > ENTIER_MAX {
                    return Err(Malformed::new(
                        "entier hors de la plage exacte d'un double IEEE 754",
                    ));
                }
                out.push_str(&n.to_string());
            }
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_into(x, out)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut cles: Vec<&String> = m.keys().collect();
            cles.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in cles.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                echapper(k, out);
                out.push(':');
                jcs_into(&m[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Forme canonique d'un bloc signé : arrondi par champ puis JCS, en UTF-8.
pub fn forme_canonique(v: &Value) -> Result<Vec<u8>> {
    Ok(jcs(&appliquer_precision(v, None)?)?.into_bytes())
}

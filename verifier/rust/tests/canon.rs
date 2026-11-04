// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Serge TABE DJATO
//! Canonicalisation : exemples de la RFC 8785 et règles d'arrondi du livre blanc.

use ices_core::canon::{appliquer_precision, arrondir, forme_canonique, jcs, nombre_es6};
use serde_json::{json, Value};

fn es6(x: f64) -> String {
    nombre_es6(x).unwrap()
}

/// RFC 8785, annexe B : représentation ECMAScript des nombres.
#[test]
fn nombres_es6_de_la_rfc_8785() {
    assert_eq!(es6(0.0), "0");
    assert_eq!(es6(-0.0), "0");
    assert_eq!(es6(5e-324), "5e-324");
    assert_eq!(es6(f64::MAX), "1.7976931348623157e+308");
    assert_eq!(es6(9007199254740992.0), "9007199254740992");
    assert_eq!(es6(295147905179352830000.0), "295147905179352830000");
    assert_eq!(es6(9.999999999999997e22), "9.999999999999997e+22");
    assert_eq!(es6(1e21), "1e+21");
    assert_eq!(es6(1e22), "1e+22");
    assert_eq!(es6(0.000001), "0.000001");
    assert_eq!(es6(1e-7), "1e-7");
    assert_eq!(es6(4.5), "4.5");
    assert_eq!(es6(333333333.33333329), "333333333.3333333");
    assert_eq!(es6(-1.5), "-1.5");
    assert_eq!(es6(100.0), "100");
}

/// Deux écritures de même longueur également proches : ECMAScript prend le chiffre pair.
/// 80559923956500,625 est exactement représentable ; la bibliothèque standard
/// de Rust écrit …63, ECMAScript et Python écrivent …62. Trouvé par le test de parité.
#[test]
fn egalite_exacte_entre_deux_ecritures_courtes_chiffre_pair() {
    assert_eq!(es6(80559923956500.625), "80559923956500.62");
    assert_eq!(es6(0.5), "0.5");
    assert_eq!(es6(2.5), "2.5");
    assert_eq!(es6(1.0000000000000002), "1.0000000000000002");
    assert_eq!(arrondir(80559923956500.625, 6).unwrap(), 80559923956500.625);
}

/// RFC 8785, section 3.2.4 : exemple de référence, sans arrondi.
#[test]
fn exemple_de_la_rfc_8785() {
    let entree = r#"{
      "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
      "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
      "literals": [null, true, false]
    }"#;
    let v: Value = serde_json::from_str(entree).unwrap();
    let attendu = "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}";
    assert_eq!(jcs(&v).unwrap(), attendu);
}

/// RFC 8785, section 3.2.3 : tri des clés par unités UTF-16.
#[test]
fn tri_des_cles_par_unites_utf16() {
    let v = json!({
        "\u{20ac}": "Euro Sign",
        "\r": "Carriage Return",
        "\u{fb33}": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\u{1f600}": "Emoji: Grinning Face",
        "\u{0080}": "Control",
        "\u{00f6}": "Latin Small Letter O With Diaeresis"
    });
    let canon = jcs(&v).unwrap();
    let positions: Vec<usize> = ["\"\\r\"", "\"1\"", "\"\u{0080}\"", "\"\u{00f6}\"", "\"\u{20ac}\"", "\"\u{1f600}\"", "\"\u{fb33}\""]
        .iter()
        .map(|k| canon.find(k).expect("clé présente"))
        .collect();
    assert!(positions.windows(2).all(|p| p[0] < p[1]), "ordre UTF-16 : {canon}");
}

#[test]
fn arrondi_egalite_vers_le_pair() {
    assert_eq!(arrondir(0.125, 2).unwrap(), 0.12);
    assert_eq!(arrondir(0.135, 2).unwrap(), 0.14);
    assert_eq!(arrondir(2.5, 0).unwrap(), 2.0);
    assert_eq!(arrondir(3.5, 0).unwrap(), 4.0);
    assert_eq!(arrondir(1.5, 0).unwrap(), 2.0);
    assert_eq!(arrondir(0.5, 0).unwrap(), 0.0);
    assert_eq!(arrondir(0.0000005, 6).unwrap(), 0.0);
    assert_eq!(arrondir(0.0000015, 6).unwrap(), 0.000002);
    assert_eq!(arrondir(0.0000004, 6).unwrap(), 0.0);
    assert_eq!(arrondir(999.9996, 3).unwrap(), 1000.0);
    assert_eq!(arrondir(-2.5, 0).unwrap(), -2.0);
    assert_eq!(arrondir(0.6, 0).unwrap(), 1.0);
}

#[test]
fn arrondi_sur_la_representation_decimale_la_plus_courte() {
    // 2.675 est stocké 2.67499999… mais s'écrit « 2.675 » : égalité, chiffre précédent 7 impair.
    assert_eq!(arrondir(2.675, 2).unwrap(), 2.68);
    assert_eq!(arrondir(1.005, 2).unwrap(), 1.0);
}

#[test]
fn nombres_non_finis_refuses() {
    assert!(arrondir(f64::NAN, 6).is_err());
    assert!(arrondir(f64::INFINITY, 6).is_err());
    assert!(nombre_es6(f64::NEG_INFINITY).is_err());
}

#[test]
fn precision_par_champ_et_heritage() {
    let v = json!({
        "latitude": 6.1319444444,
        "cote_m": 12.34567,
        "diametre_mm": 110.4,
        "debit_m3h": 1.23456789,
        "autre": 1.23456789,
        "pression_bar": { "valeurs": [4.12345, 4.9996] },
        "entier": 42,
        "booleen": true
    });
    let r = appliquer_precision(&v, None).unwrap();
    assert_eq!(r["latitude"], json!(6.1319444));
    assert_eq!(r["cote_m"], json!(12.346));
    assert_eq!(r["diametre_mm"], json!(110.0));
    assert_eq!(r["debit_m3h"], json!(1.2346));
    assert_eq!(r["autre"], json!(1.234568));
    assert_eq!(r["pression_bar"]["valeurs"], json!([4.123, 5.0]));
    assert_eq!(r["entier"], json!(42));
    assert_eq!(r["booleen"], json!(true));
}

#[test]
fn entier_hors_plage_exacte_refuse() {
    let v: Value = serde_json::from_str("9007199254740993").unwrap();
    assert!(jcs(&v).is_err());
    let ok: Value = serde_json::from_str("9007199254740992").unwrap();
    assert_eq!(jcs(&ok).unwrap(), "9007199254740992");
}

#[test]
fn forme_canonique_est_deterministe_selon_l_ordre_des_cles() {
    let a: Value = serde_json::from_str(r#"{"b":1.0000004,"a":[1,2.5]}"#).unwrap();
    let b: Value = serde_json::from_str(r#"{"a":[1,2.5],"b":1.0000004}"#).unwrap();
    assert_eq!(forme_canonique(&a).unwrap(), forme_canonique(&b).unwrap());
    assert_eq!(String::from_utf8(forme_canonique(&a).unwrap()).unwrap(), r#"{"a":[1,2.5],"b":1}"#);
}

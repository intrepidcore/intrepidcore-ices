// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Serge TABE DJATO
//! `ices-core` : vérificateur hors ligne de sceaux ICES.
//!
//! Aucune dépendance réseau, aucun secret partagé : le vérificateur recalcule
//! le condensat SHA3-256 sur la forme canonique (arrondi par champ puis JCS),
//! vérifie la signature Ed25519 et contrôle la clé contre une liste de clés de
//! confiance fournie à l'exécution.

pub mod canon;
pub mod error;
pub mod keys;
pub mod verify;

pub use error::{Malformed, Result};
pub use keys::Ancrage;
pub use verify::{blocs_canoniques, compute_digest, verify_bundle, Verdict};

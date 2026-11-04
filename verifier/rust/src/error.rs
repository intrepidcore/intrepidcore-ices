// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Serge TABE DJATO
//! Erreur unique du vérificateur : le fichier ne peut pas être vérifié.

use std::fmt;

/// Le fichier ne peut pas être vérifié : structure absente, invalide ou hors
/// des limites de la spécification. Se traduit par le code de sortie 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Malformed(pub String);

impl Malformed {
    pub fn new(msg: impl Into<String>) -> Self {
        Malformed(msg.into())
    }
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Malformed {}

pub type Result<T> = std::result::Result<T, Malformed>;

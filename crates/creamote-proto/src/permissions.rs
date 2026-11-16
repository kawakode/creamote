//! Permissions de session et de gestion, partagées par le serveur (RBAC,
//! émission des tickets) et le host (application des tickets).

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Ensemble de permissions (masque de bits stocké en base).
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Permissions(u64);

impl Permissions {
    /// Voir l'écran.
    pub const VIEW: Self = Self(1 << 0);
    /// Prendre le contrôle clavier/souris.
    pub const CONTROL: Self = Self(1 << 1);
    /// Presse-papier partagé.
    pub const CLIPBOARD: Self = Self(1 << 2);
    /// Transfert de fichiers.
    pub const FILE_TRANSFER: Self = Self(1 << 3);
    /// Se connecter sans consentement de l'utilisateur présent.
    pub const UNATTENDED: Self = Self(1 << 4);
    /// Gérer les machines et les parcs.
    pub const MANAGE_DEVICES: Self = Self(1 << 5);
    /// Gérer les membres, groupes, rôles et attributions.
    pub const MANAGE_ACCESS: Self = Self(1 << 6);
    /// Consulter le journal d'audit.
    pub const VIEW_AUDIT: Self = Self(1 << 7);

    pub const NONE: Self = Self(0);
    pub const ALL: Self = Self((1 << 8) - 1);

    const NAMES: [(&'static str, Self); 8] = [
        ("view_screen", Self::VIEW),
        ("control", Self::CONTROL),
        ("clipboard", Self::CLIPBOARD),
        ("file_transfer", Self::FILE_TRANSFER),
        ("unattended", Self::UNATTENDED),
        ("manage_devices", Self::MANAGE_DEVICES),
        ("manage_access", Self::MANAGE_ACCESS),
        ("view_audit", Self::VIEW_AUDIT),
    ];

    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Ignore les bits inconnus (valeur venant de la base).
    pub const fn from_bits_truncate(bits: u64) -> Self {
        Self(bits & Self::ALL.0)
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn names(self) -> Vec<&'static str> {
        Self::NAMES
            .iter()
            .filter(|(_, p)| self.contains(*p))
            .map(|(n, _)| *n)
            .collect()
    }

    pub fn from_names<S: AsRef<str>>(names: &[S]) -> Result<Self, String> {
        names.iter().try_fold(Self::NONE, |acc, n| {
            Self::NAMES
                .iter()
                .find(|(name, _)| *name == n.as_ref())
                .map(|(_, p)| acc.union(*p))
                .ok_or_else(|| format!("permission inconnue : {}", n.as_ref()))
        })
    }
}

impl std::ops::BitOr for Permissions {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl std::fmt::Debug for Permissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.names()).finish()
    }
}

impl Serialize for Permissions {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.names().serialize(s)
    }
}

impl<'de> Deserialize<'de> for Permissions {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let names = Vec::<String>::deserialize(d)?;
        Self::from_names(&names).map_err(serde::de::Error::custom)
    }
}

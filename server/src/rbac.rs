//! Contrôle d'accès : permissions, rôles intégrés et évaluation.
//!
//! Règle unique : un **rôle** (ensemble de permissions) est attribué à un
//! **sujet** (utilisateur ou groupe de sécurité) sur une **portée** (entité,
//! parc ou machine). Une attribution sur un parc vaut pour ses sous-parcs et
//! leurs machines. Les permissions effectives sont l'union des attributions
//! qui s'appliquent.

use std::collections::HashMap;

pub use creamote_proto::permissions::Permissions;

/// Rôles intégrés, disponibles dans toutes les entités.
pub struct BuiltinRole {
    pub id: &'static str,
    pub name: &'static str,
    pub permissions: Permissions,
}

pub const BUILTIN_ROLES: [BuiltinRole; 4] = [
    BuiltinRole {
        id: "owner",
        name: "Propriétaire d'entité",
        permissions: Permissions::ALL,
    },
    BuiltinRole {
        id: "fleet-admin",
        name: "Admin de parc",
        permissions: Permissions::VIEW
            .union(Permissions::CONTROL)
            .union(Permissions::CLIPBOARD)
            .union(Permissions::FILE_TRANSFER)
            .union(Permissions::UNATTENDED)
            .union(Permissions::MANAGE_DEVICES),
    },
    BuiltinRole {
        id: "technician",
        name: "Technicien",
        permissions: Permissions::VIEW
            .union(Permissions::CONTROL)
            .union(Permissions::CLIPBOARD)
            .union(Permissions::FILE_TRANSFER),
    },
    BuiltinRole {
        id: "observer",
        name: "Observateur",
        permissions: Permissions::VIEW,
    },
];

pub fn builtin_role(id: &str) -> Option<&'static BuiltinRole> {
    BUILTIN_ROLES.iter().find(|r| r.id == id)
}

/// Portée d'une attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    Entity,
    Fleet(String),
    Device(String),
}

impl Scope {
    pub fn kind(&self) -> &'static str {
        match self {
            Scope::Entity => "entity",
            Scope::Fleet(_) => "fleet",
            Scope::Device(_) => "device",
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Scope::Entity => "",
            Scope::Fleet(id) | Scope::Device(id) => id,
        }
    }

    pub fn from_parts(kind: &str, id: &str) -> Option<Self> {
        match kind {
            "entity" => Some(Scope::Entity),
            "fleet" => Some(Scope::Fleet(id.to_owned())),
            "device" => Some(Scope::Device(id.to_owned())),
            _ => None,
        }
    }
}

/// Attribution déjà filtrée pour un utilisateur donné.
#[derive(Debug, Clone)]
pub struct Grant {
    pub permissions: Permissions,
    pub scope: Scope,
}

/// Arborescence des parcs d'une entité.
#[derive(Debug, Default)]
pub struct FleetTree {
    parent: HashMap<String, Option<String>>,
}

impl FleetTree {
    pub fn new(edges: impl IntoIterator<Item = (String, Option<String>)>) -> Self {
        Self {
            parent: edges.into_iter().collect(),
        }
    }

    pub fn contains(&self, fleet: &str) -> bool {
        self.parent.contains_key(fleet)
    }

    /// `ancestor` est-il `fleet` ou l'un de ses parents ?
    pub fn is_ancestor_or_self(&self, ancestor: &str, fleet: &str) -> bool {
        let mut current = Some(fleet);
        // La profondeur est bornée par le nombre de parcs : protège d'un cycle.
        for _ in 0..=self.parent.len() {
            match current {
                Some(f) if f == ancestor => return true,
                Some(f) => current = self.parent.get(f).and_then(|p| p.as_deref()),
                None => return false,
            }
        }
        false
    }
}

/// Ce sur quoi on évalue les permissions.
#[derive(Debug, Clone, Copy)]
pub enum Target<'a> {
    Entity,
    Fleet(&'a str),
    Device { id: &'a str, fleet: Option<&'a str> },
}

pub fn effective(grants: &[Grant], tree: &FleetTree, target: Target<'_>) -> Permissions {
    grants
        .iter()
        .filter(|g| match (&g.scope, target) {
            (Scope::Entity, _) => true,
            (Scope::Fleet(f), Target::Fleet(t)) => tree.is_ancestor_or_self(f, t),
            (
                Scope::Fleet(f),
                Target::Device {
                    fleet: Some(df), ..
                },
            ) => tree.is_ancestor_or_self(f, df),
            (Scope::Device(d), Target::Device { id, .. }) => d == id,
            _ => false,
        })
        .fold(Permissions::NONE, |acc, g| acc | g.permissions)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> FleetTree {
        // siege > compta > postes ; atelier à part
        FleetTree::new([
            ("siege".into(), None),
            ("compta".into(), Some("siege".into())),
            ("postes".into(), Some("compta".into())),
            ("atelier".into(), None),
        ])
    }

    fn grant(p: Permissions, scope: Scope) -> Grant {
        Grant {
            permissions: p,
            scope,
        }
    }

    #[test]
    fn names_roundtrip() {
        let p = Permissions::VIEW | Permissions::UNATTENDED;
        assert_eq!(p.names(), vec!["view_screen", "unattended"]);
        assert_eq!(Permissions::from_names(&p.names()).unwrap(), p);
        assert!(Permissions::from_names(&["voler"]).is_err());
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<Permissions>(&json).unwrap(), p);
    }

    #[test]
    fn fleet_grant_inherits_down_not_up() {
        let t = tree();
        let g = [grant(Permissions::CONTROL, Scope::Fleet("compta".into()))];
        let on = |fleet| {
            effective(
                &g,
                &t,
                Target::Device {
                    id: "pc",
                    fleet: Some(fleet),
                },
            )
        };
        assert!(on("postes").contains(Permissions::CONTROL));
        assert!(on("compta").contains(Permissions::CONTROL));
        assert_eq!(on("siege"), Permissions::NONE);
        assert_eq!(on("atelier"), Permissions::NONE);
        assert_eq!(effective(&g, &t, Target::Entity), Permissions::NONE);
    }

    #[test]
    fn grants_union_and_device_scope() {
        let t = tree();
        let g = [
            grant(Permissions::VIEW, Scope::Entity),
            grant(Permissions::FILE_TRANSFER, Scope::Device("pc-1".into())),
        ];
        let pc1 = effective(
            &g,
            &t,
            Target::Device {
                id: "pc-1",
                fleet: Some("atelier"),
            },
        );
        assert_eq!(pc1, Permissions::VIEW | Permissions::FILE_TRANSFER);
        let pc2 = effective(
            &g,
            &t,
            Target::Device {
                id: "pc-2",
                fleet: Some("atelier"),
            },
        );
        assert_eq!(pc2, Permissions::VIEW);
    }

    #[test]
    fn cycle_does_not_loop_forever() {
        let t = FleetTree::new([
            ("a".into(), Some("b".into())),
            ("b".into(), Some("a".into())),
        ]);
        assert!(!t.is_ancestor_or_self("z", "a"));
    }

    #[test]
    fn builtin_roles_are_ordered_by_power() {
        let p = |id| builtin_role(id).unwrap().permissions;
        assert!(p("owner").contains(p("fleet-admin")));
        assert!(p("fleet-admin").contains(p("technician")));
        assert!(p("technician").contains(p("observer")));
        assert!(!p("technician").contains(Permissions::UNATTENDED));
    }
}

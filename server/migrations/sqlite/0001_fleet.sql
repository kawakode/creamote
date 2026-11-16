-- Gestion de parc : comptes, entités, parcs, groupes, rôles, attributions, audit.
-- Entiers en INTEGER (64 bits), booléens en 0/1, horodatages en secondes Unix.

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_superadmin INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE api_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE entities (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE memberships (
    entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (entity_id, user_id)
);

CREATE TABLE fleets (
    id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    parent_id TEXT REFERENCES fleets(id),
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX fleets_entity ON fleets(entity_id);

CREATE TABLE security_groups (
    id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE group_members (
    group_id TEXT NOT NULL REFERENCES security_groups(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    permissions INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE role_bindings (
    id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX role_bindings_entity ON role_bindings(entity_id);

CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    at INTEGER NOT NULL,
    entity_id TEXT,
    actor_user_id TEXT,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE INDEX audit_log_entity_at ON audit_log(entity_id, at);

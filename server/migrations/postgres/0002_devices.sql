-- Machines enrôlées et jetons d'enrôlement.

CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    fleet_id TEXT NOT NULL REFERENCES fleets(id),
    -- ID court (9 chiffres) dérivé de la clé, affiché aux utilisateurs.
    device_id TEXT NOT NULL,
    -- Clé publique Ed25519 en hexadécimal : identité de la machine.
    signing_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    platform TEXT NOT NULL,
    enrolled_at BIGINT NOT NULL,
    last_seen BIGINT
);
CREATE INDEX devices_entity ON devices(entity_id);
CREATE INDEX devices_device_id ON devices(device_id);

CREATE TABLE enrollment_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    fleet_id TEXT NOT NULL REFERENCES fleets(id) ON DELETE CASCADE,
    created_by TEXT,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    uses_left BIGINT NOT NULL
);
CREATE INDEX enrollment_tokens_entity ON enrollment_tokens(entity_id);

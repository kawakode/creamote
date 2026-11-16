-- Double authentification TOTP et carnet d'adresses personnel.

ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
-- Dernier pas de temps accepté : un code ne sert qu'une fois.
ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;

CREATE TABLE recovery_codes (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at INTEGER,
    PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE address_book (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    -- ID court (9 chiffres) de la machine.
    device_id TEXT NOT NULL,
    notes TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX address_book_user ON address_book(user_id);

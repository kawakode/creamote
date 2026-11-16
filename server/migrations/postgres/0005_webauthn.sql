-- Clés de sécurité WebAuthn (second facteur).
CREATE TABLE webauthn_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Identifiant de la clé chez l'authentificateur (base64url).
    credential_id TEXT NOT NULL UNIQUE,
    -- Clé publique COSE (base64url).
    public_key TEXT NOT NULL,
    alg BIGINT NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    name TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials(user_id);

-- Lien entre un compte et son identité chez le fournisseur OIDC (`émetteur|sub`).
ALTER TABLE users ADD COLUMN oidc_subject TEXT;
CREATE UNIQUE INDEX users_oidc_subject ON users(oidc_subject);

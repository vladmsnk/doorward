-- The box's own signing keys, and the secrets the gateway presents to
-- upstreams. Private material is sealed with the operator's master key
-- before it reaches the database; the database never holds it in clear.

CREATE TABLE signing_keys (
    kid         text        PRIMARY KEY,               -- JWK thumbprint (RFC 7638)
    alg         text        NOT NULL,                  -- ES256
    public_jwk  jsonb       NOT NULL,                  -- published in the JWKS
    private_enc bytea       NOT NULL,                  -- sealed PKCS#8 private key
    created_at  timestamptz NOT NULL DEFAULT now(),
    retired_at  timestamptz                            -- set: no longer signs or is published
);

CREATE TABLE secrets (
    name       text        PRIMARY KEY,                -- what a manifest's secret_ref names
    value_enc  bytea       NOT NULL,                   -- sealed value
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text        NOT NULL
);

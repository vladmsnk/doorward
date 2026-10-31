-- The box's one database: configuration and records side by side.
--
-- Configuration (manifests, agents, mandates) is versioned: a write adds a
-- row and nothing is overwritten, so a consent can name the mandate version
-- the user saw and a decision the policy it was made under. Records are
-- append-only; the only updates are the state transitions the contract
-- allows (a consent ends, an approval closes).

CREATE TABLE documents (
    kind        text        NOT NULL,                 -- Manifest, Agent, Mandate
    name        text        NOT NULL,
    version     integer     NOT NULL,                 -- 1, 2, 3 … per (kind, name)
    digest      text        NOT NULL,                 -- sha-256:… of doc, byte for byte
    doc         text        NOT NULL,                 -- the document as validated, compact JSON, kept verbatim so the digest holds
    disabled    boolean     NOT NULL DEFAULT false,   -- a disabled version is the current one and refuses use
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text        NOT NULL,                 -- administrator, or 'system' for registration and the like
    PRIMARY KEY (kind, name, version)
);

-- The current version of every document, for the hot path.
CREATE VIEW current_documents AS
    SELECT DISTINCT ON (kind, name) *
    FROM documents
    ORDER BY kind, name, version DESC;

-- Operations a manifest declares, unnested for lookups by audience and name.
CREATE INDEX documents_manifest_audience
    ON documents ((doc::jsonb -> 'spec' ->> 'audience'))
    WHERE kind = 'Manifest';

CREATE TABLE consents (
    id              text        PRIMARY KEY,
    user_iss        text        NOT NULL,
    user_sub        text        NOT NULL,
    agent           text        NOT NULL,
    mandate         text        NOT NULL,
    mandate_version text        NOT NULL,             -- digest, as the record carries it
    status          text        NOT NULL,             -- active, expired, revoked
    granted_at      timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    revoked_by      text,
    doc             jsonb       NOT NULL              -- the full Consent record
);

CREATE INDEX consents_by_user ON consents (user_iss, user_sub, status);
CREATE INDEX consents_by_agent ON consents (agent, status);

CREATE TABLE grants (
    jti         text        PRIMARY KEY,
    subject     text        NOT NULL,
    client_id   text        NOT NULL,
    agent       text        NOT NULL,
    mandate     text        NOT NULL,
    consent     text        REFERENCES consents (id),
    issued_at   timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    single_use  boolean     NOT NULL DEFAULT false,
    action_hash text,                                 -- for a single-use grant: the one call it allows
    used_at     timestamptz,                          -- when a single-use grant was spent
    doc         jsonb       NOT NULL                  -- the claims as issued
);

CREATE INDEX grants_by_consent ON grants (consent) WHERE consent IS NOT NULL;
CREATE INDEX grants_by_agent ON grants (agent, expires_at);

-- Decisions form a hash chain: seq is dense from 0 and each record's hash
-- covers the previous one. Appending takes the chain lock, so two writers
-- cannot both claim the same seq.
CREATE TABLE decisions (
    seq         bigint      PRIMARY KEY,
    id          text        NOT NULL UNIQUE,
    at          timestamptz NOT NULL,
    agent       text,
    "user"      text,
    owner       text,
    grant_id    text,
    mandate     text,
    consent     text,
    outcome     text        NOT NULL,
    prev        text,
    hash        text        NOT NULL,
    doc         jsonb       NOT NULL
);

CREATE INDEX decisions_by_grant ON decisions (grant_id, seq);
CREATE INDEX decisions_by_agent ON decisions (agent, at);

CREATE TABLE approvals (
    id               text        PRIMARY KEY,
    status           text        NOT NULL,            -- pending, approved, rejected, expired
    created_at       timestamptz NOT NULL,
    closed_at        timestamptz,
    mandate          text        NOT NULL,
    consent          text,
    grant_id         text        NOT NULL,
    agent            text        NOT NULL,
    action_hash      text        NOT NULL,
    single_use_grant text,
    doc              jsonb       NOT NULL
);

CREATE INDEX approvals_pending ON approvals (status, created_at) WHERE status = 'pending';

-- Budgets. A key names what the budget belongs to: grant:<jti>:<limit>,
-- or consent:<id>:<limit>:<period>. Consumption is an atomic conditional
-- update, so parallel calls cannot overdraw.
CREATE TABLE counters (
    key      text    PRIMARY KEY,
    consumed numeric NOT NULL DEFAULT 0
);

CREATE TABLE schema_migrations (
    version    integer     PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

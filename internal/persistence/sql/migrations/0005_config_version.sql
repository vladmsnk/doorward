-- One counter that every configuration write bumps: documents, their
-- disabled flag, secrets. A decision point reads it on every decision and
-- reloads its snapshot of the configuration only when it changed, so a
-- change takes effect on the next call without every call reading every
-- document.
CREATE TABLE config_version (
    id         int         PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    version    bigint      NOT NULL DEFAULT 0,
    changed_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO config_version (id) VALUES (1);

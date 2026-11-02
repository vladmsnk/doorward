-- One open approval request per exact call: the same agent, mandate,
-- consent and action hash. Two first attempts of one held call arriving
-- together could each open a request; now the second insert fails and the
-- decision point reuses the first. A service agent's requests have no
-- consent, hence the coalesce.
CREATE UNIQUE INDEX approvals_one_pending_per_call
    ON approvals (agent, mandate, coalesce(consent, ''), action_hash)
    WHERE status = 'pending';

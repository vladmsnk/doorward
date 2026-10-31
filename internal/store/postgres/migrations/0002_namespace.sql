-- A namespace on every document and record, unused by the first version.
-- When several teams or tenants share one box, documents and records get
-- scoped by it; adding the column now means no data migration then.
ALTER TABLE documents ADD COLUMN namespace text;
ALTER TABLE consents  ADD COLUMN namespace text;
ALTER TABLE grants    ADD COLUMN namespace text;
ALTER TABLE decisions ADD COLUMN namespace text;
ALTER TABLE approvals ADD COLUMN namespace text;

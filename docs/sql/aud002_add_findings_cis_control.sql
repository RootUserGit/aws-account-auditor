-- AUD-002: persist CIS control id on each finding (optional).
-- Run once against existing Postgres (create_all does not ALTER existing tables).

ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS cis_control VARCHAR(32);

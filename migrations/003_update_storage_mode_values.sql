BEGIN;

-- Rename storage_mode values to new semantics
-- both -> full
-- filesystem -> archive
UPDATE protection_jobs SET storage_mode = 'full' WHERE storage_mode = 'both';
UPDATE protection_jobs SET storage_mode = 'archive' WHERE storage_mode = 'filesystem';

-- Update default and CHECK constraint to reflect new allowed values
ALTER TABLE protection_jobs ALTER COLUMN storage_mode SET DEFAULT 'full';
-- Drop old auto-named check constraint if present, then add the new one
ALTER TABLE protection_jobs DROP CONSTRAINT IF EXISTS protection_jobs_storage_mode_check;
ALTER TABLE protection_jobs
    ADD CONSTRAINT protection_jobs_storage_mode_check
    CHECK (storage_mode IN ('archive', 'ipfs', 'full'));

COMMIT;

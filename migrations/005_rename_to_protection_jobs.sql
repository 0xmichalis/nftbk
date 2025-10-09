BEGIN;

-- Rename backup_metadata to protection_jobs
ALTER TABLE backup_metadata RENAME TO protection_jobs;

-- Add storage_mode column
-- Default to 'both' for backwards compatibility with existing rows that have pin_on_ipfs
ALTER TABLE protection_jobs
ADD COLUMN storage_mode VARCHAR(20) NOT NULL DEFAULT 'both'
CHECK (storage_mode IN ('filesystem', 'ipfs', 'both'));

-- Update storage_mode based on existing pin_on_ipfs flag
UPDATE protection_jobs
SET storage_mode = CASE
    WHEN pin_on_ipfs = true THEN 'both'
    ELSE 'filesystem'
END;

-- Drop the now-redundant pin_on_ipfs column
ALTER TABLE protection_jobs DROP COLUMN pin_on_ipfs;

COMMIT;


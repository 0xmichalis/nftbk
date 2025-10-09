-- Add pin_on_ipfs boolean to backup_metadata with a safe default
ALTER TABLE backup_metadata
ADD COLUMN IF NOT EXISTS pin_on_ipfs BOOLEAN NOT NULL DEFAULT FALSE;

-- Backfill is unnecessary due to DEFAULT FALSE; ensure existing rows are set
UPDATE backup_metadata SET pin_on_ipfs = FALSE WHERE pin_on_ipfs IS NULL;


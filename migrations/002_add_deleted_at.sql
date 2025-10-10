-- Add deleted_at field to protection_jobs table
-- This field tracks when a deletion job was started for a backup

BEGIN;

-- Add deleted_at column to protection_jobs table
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'protection_jobs' 
        AND column_name = 'deleted_at'
    ) THEN
        ALTER TABLE protection_jobs ADD COLUMN deleted_at TIMESTAMPTZ;
    END IF;
END $$;

-- Create index for deleted_at queries
CREATE INDEX IF NOT EXISTS idx_protection_jobs_deleted_at ON protection_jobs (deleted_at);

COMMIT;

BEGIN;

-- Create backup_requests table for filesystem-specific metadata
CREATE TABLE IF NOT EXISTS backup_requests (
    task_id VARCHAR(255) PRIMARY KEY REFERENCES protection_jobs(task_id) ON DELETE CASCADE,
    archive_format VARCHAR(8) NOT NULL CHECK (archive_format IN ('zip', 'tar.gz')),
    expires_at TIMESTAMPTZ
);

-- Migrate existing data from protection_jobs
-- Only migrate rows that have filesystem storage (storage_mode = 'filesystem' or 'both')
INSERT INTO backup_requests (task_id, archive_format, expires_at)
SELECT task_id, archive_format, expires_at
FROM protection_jobs
WHERE storage_mode IN ('filesystem', 'both');

-- Drop the migrated columns from protection_jobs
ALTER TABLE protection_jobs DROP COLUMN archive_format;
ALTER TABLE protection_jobs DROP COLUMN expires_at;

-- Create index on expires_at for efficient expiration queries
CREATE INDEX IF NOT EXISTS idx_backup_requests_expires_at ON backup_requests (expires_at);

COMMIT;


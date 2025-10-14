-- Move status and fatal_error from backup_tasks to archive_requests and add task-level
-- status/fatal columns to pin_requests (excluding 'expired' for IPFS)

BEGIN;

-- Add new columns to archive_requests
ALTER TABLE archive_requests ADD COLUMN IF NOT EXISTS status VARCHAR(12) CHECK (status IN ('in_progress', 'done', 'error', 'expired'));
ALTER TABLE archive_requests ADD COLUMN IF NOT EXISTS fatal_error TEXT;

-- Backfill from backup_tasks to archive_requests where applicable
UPDATE archive_requests ar
SET status = bt.status,
    fatal_error = bt.fatal_error
FROM backup_tasks bt
WHERE ar.task_id = bt.task_id;

-- Add task-level status/fatal for IPFS pins (no 'expired' for this subresource)
ALTER TABLE pin_requests ADD COLUMN IF NOT EXISTS task_status VARCHAR(12) CHECK (task_status IN ('in_progress', 'done', 'error'));
ALTER TABLE pin_requests ADD COLUMN IF NOT EXISTS fatal_error TEXT;

-- Drop columns from backup_tasks
ALTER TABLE backup_tasks DROP COLUMN IF EXISTS status;
ALTER TABLE backup_tasks DROP COLUMN IF EXISTS fatal_error;

COMMIT;



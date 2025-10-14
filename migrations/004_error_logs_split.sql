-- Move non-fatal error logs to subresource tables and support IPFS pin errors
-- - Drop error_log from backup_tasks
-- - Add error_log to archive_requests
-- - Add error_log to pin_requests
-- - Migrate existing backup_tasks.error_log into archive_requests.error_log

BEGIN;

-- Add error_log to archive_requests if missing
ALTER TABLE archive_requests ADD COLUMN IF NOT EXISTS error_log TEXT;

-- Add error_log to pin_requests if missing
ALTER TABLE pin_requests ADD COLUMN IF NOT EXISTS error_log TEXT;

-- Migrate existing error_log values from backup_tasks to archive_requests.error_log
-- Only copy when archive_requests row exists; otherwise value would be unused.
UPDATE archive_requests ar
SET error_log = bt.error_log
FROM backup_tasks bt
WHERE ar.task_id = bt.task_id AND bt.error_log IS NOT NULL;

-- Drop error_log from backup_tasks
ALTER TABLE backup_tasks DROP COLUMN IF EXISTS error_log;

COMMIT;



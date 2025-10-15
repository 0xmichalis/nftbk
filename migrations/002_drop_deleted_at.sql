-- Drop deleted_at column from backup_tasks; this column is no longer used
BEGIN;
ALTER TABLE backup_tasks DROP COLUMN IF EXISTS deleted_at;
COMMIT;

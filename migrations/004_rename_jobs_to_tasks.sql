-- Rename tables and related indexes from job terminology to task terminology
-- protection_jobs -> backup_tasks
-- backup_requests -> archive_requests

BEGIN;

-- Rename core table only if source exists and destination does not
DO $$
BEGIN
    IF to_regclass('public.protection_jobs') IS NOT NULL
       AND to_regclass('public.backup_tasks') IS NULL THEN
        EXECUTE 'ALTER TABLE protection_jobs RENAME TO backup_tasks';
    END IF;
END $$;

-- Rename indices on protection_jobs
DO $$
BEGIN
    IF to_regclass('public.idx_protection_jobs_requestor') IS NOT NULL THEN
        EXECUTE 'ALTER INDEX idx_protection_jobs_requestor RENAME TO idx_backup_tasks_requestor';
    END IF;
    IF to_regclass('public.idx_protection_jobs_tokens_gin') IS NOT NULL THEN
        EXECUTE 'ALTER INDEX idx_protection_jobs_tokens_gin RENAME TO idx_backup_tasks_tokens_gin';
    END IF;
    IF to_regclass('public.idx_protection_jobs_status') IS NOT NULL THEN
        EXECUTE 'ALTER INDEX idx_protection_jobs_status RENAME TO idx_backup_tasks_status';
    END IF;
    IF to_regclass('public.idx_protection_jobs_deleted_at') IS NOT NULL THEN
        EXECUTE 'ALTER INDEX idx_protection_jobs_deleted_at RENAME TO idx_backup_tasks_deleted_at';
    END IF;
END $$;

-- Rename the storage mode constraint if present
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'protection_jobs_storage_mode_check'
    ) THEN
        IF to_regclass('public.backup_tasks') IS NOT NULL THEN
            EXECUTE 'ALTER TABLE backup_tasks RENAME CONSTRAINT protection_jobs_storage_mode_check TO backup_tasks_storage_mode_check';
        END IF;
    END IF;
END $$;

-- Rename dependent table for archive requests
DO $$
BEGIN
    IF to_regclass('public.backup_requests') IS NOT NULL
       AND to_regclass('public.archive_requests') IS NULL THEN
        EXECUTE 'ALTER TABLE backup_requests RENAME TO archive_requests';
    END IF;
END $$;

-- Rename index on backup_requests
DO $$
BEGIN
    IF to_regclass('public.idx_backup_requests_expires_at') IS NOT NULL THEN
        EXECUTE 'ALTER INDEX idx_backup_requests_expires_at RENAME TO idx_archive_requests_expires_at';
    END IF;
END $$;

-- Ensure foreign keys in pin_requests still reference the renamed table
-- Note: PostgreSQL automatically updates FK references on table rename.
-- This block is defensive in case environments differ; no-op if already correct.
DO $$
DECLARE
    fk_name text;
BEGIN
    IF to_regclass('public.protection_jobs') IS NOT NULL THEN
        FOR fk_name IN
            SELECT conname
            FROM pg_constraint
            WHERE conrelid = to_regclass('public.pin_requests')
              AND confrelid = to_regclass('public.protection_jobs')
        LOOP
            EXECUTE format('ALTER TABLE pin_requests DROP CONSTRAINT %I', fk_name);
            EXECUTE 'ALTER TABLE pin_requests ADD CONSTRAINT pin_requests_task_fk FOREIGN KEY (task_id) REFERENCES backup_tasks(task_id) ON DELETE CASCADE';
        END LOOP;
    END IF;
END $$;

COMMIT;



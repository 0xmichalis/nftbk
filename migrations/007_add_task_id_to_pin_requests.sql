-- Add task_id foreign key to pin_requests table
-- This migration adds the missing relationship between pin_requests and protection_jobs

BEGIN;

-- Step 1: Add task_id column to pin_requests
ALTER TABLE pin_requests ADD COLUMN task_id VARCHAR(255);

-- Step 2: Populate task_id by matching requestor to protection_jobs
-- This links existing pin requests to their corresponding protection jobs
UPDATE pin_requests 
SET task_id = (
    SELECT pj.task_id 
    FROM protection_jobs pj 
    WHERE pj.requestor = pin_requests.requestor 
    ORDER BY pj.created_at DESC 
    LIMIT 1
)
WHERE task_id IS NULL;

-- Step 3: Handle any orphaned pin requests (no matching protection job)
-- Set them to a placeholder task_id to maintain referential integrity
UPDATE pin_requests 
SET task_id = 'legacy-' || id::text 
WHERE task_id IS NULL;

-- Step 4: Make task_id NOT NULL
ALTER TABLE pin_requests ALTER COLUMN task_id SET NOT NULL;

-- Step 5: Add foreign key constraint
ALTER TABLE pin_requests 
ADD CONSTRAINT fk_pin_requests_task_id 
FOREIGN KEY (task_id) REFERENCES protection_jobs(task_id) ON DELETE CASCADE;

-- Step 6: Add index for efficient queries
CREATE INDEX IF NOT EXISTS idx_pin_requests_task_id ON pin_requests (task_id);

COMMIT;

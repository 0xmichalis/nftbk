-- Add 'unpaid' status to archive_requests and pin_requests tables
-- This allows marking backups as unpaid when x402 settlement fails

-- Update archive_requests table to include 'unpaid' status
ALTER TABLE archive_requests 
DROP CONSTRAINT IF EXISTS archive_requests_status_check;

ALTER TABLE archive_requests 
ADD CONSTRAINT archive_requests_status_check 
CHECK (status IN ('in_progress', 'done', 'error', 'expired', 'unpaid'));

-- Update pin_requests table to include 'unpaid' status
ALTER TABLE pin_requests 
DROP CONSTRAINT IF EXISTS pin_requests_status_check;

ALTER TABLE pin_requests 
ADD CONSTRAINT pin_requests_status_check 
CHECK (status IN ('in_progress', 'done', 'error', 'unpaid'));

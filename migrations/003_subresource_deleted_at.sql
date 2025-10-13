-- Add deleted_at fields to subresource tables for granular deletion tracking
-- This allows us to track deletion of specific subresources (archive, IPFS pins)
-- without affecting the main backup task status

BEGIN;

-- Add deleted_at to archive_requests table
ALTER TABLE archive_requests ADD COLUMN deleted_at TIMESTAMPTZ;

-- Add deleted_at to pin_requests table  
ALTER TABLE pin_requests ADD COLUMN deleted_at TIMESTAMPTZ;

-- Add indexes for the new deleted_at fields
CREATE INDEX IF NOT EXISTS idx_archive_requests_deleted_at ON archive_requests (deleted_at);
CREATE INDEX IF NOT EXISTS idx_pin_requests_deleted_at ON pin_requests (deleted_at);

COMMIT;

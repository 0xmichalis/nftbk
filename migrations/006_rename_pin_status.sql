-- Rename pin_requests.status to pin_status for clarity

BEGIN;

ALTER TABLE pin_requests RENAME COLUMN status TO pin_status;

COMMIT;



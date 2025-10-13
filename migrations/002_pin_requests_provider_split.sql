-- Rename provider to provider_type and add provider_url to pin_requests
BEGIN;

ALTER TABLE pin_requests
    RENAME COLUMN provider TO provider_type;

ALTER TABLE pin_requests
    ADD COLUMN IF NOT EXISTS provider_url TEXT;

COMMIT;

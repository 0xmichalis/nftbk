-- Restructure IPFS tables to match archive pattern
-- - Create new pin_requests table as task-level subresource (like archive_requests)
-- - Create pins table for individual pin records
-- - Update pinned_tokens to reference pins instead of pin_requests

BEGIN;

-- Create new pin_requests table as task-level subresource
CREATE TABLE pin_requests_new (
    task_id VARCHAR(255) PRIMARY KEY REFERENCES backup_tasks(task_id) ON DELETE CASCADE,
    status VARCHAR(12) NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'done', 'error')),
    fatal_error TEXT,
    error_log TEXT,
    deleted_at TIMESTAMPTZ
);

-- Migrate task-level data to new pin_requests table
INSERT INTO pin_requests_new (task_id, status, fatal_error, error_log)
SELECT DISTINCT 
    pr.task_id,
    COALESCE(pr.task_status, 'in_progress') as status,
    pr.fatal_error,
    pr.error_log
FROM pin_requests pr
ON CONFLICT (task_id) DO NOTHING;

-- Create pins table for individual pin records
CREATE TABLE pins (
    id BIGSERIAL PRIMARY KEY,
    task_id VARCHAR(255) NOT NULL,
    provider_type VARCHAR(64) NOT NULL,
    provider_url TEXT,
    cid VARCHAR(255) NOT NULL,
    request_id VARCHAR(255) NOT NULL,
    pin_status VARCHAR(12) NOT NULL CHECK (pin_status IN ('queued', 'pinning', 'pinned', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Migrate individual pin records to pins table
INSERT INTO pins (task_id, provider_type, provider_url, cid, request_id, pin_status, created_at)
SELECT 
    pr.task_id,
    pr.provider_type,
    pr.provider_url,
    pr.cid,
    pr.request_id,
    pr.pin_status,
    NOW() as created_at
FROM pin_requests pr;

-- Create new pinned_tokens table that references pins
CREATE TABLE pinned_tokens_new (
    pin_id BIGINT PRIMARY KEY,
    chain TEXT NOT NULL,
    contract_address TEXT NOT NULL,
    token_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Migrate pinned_tokens data to new structure
INSERT INTO pinned_tokens_new (pin_id, chain, contract_address, token_id, created_at)
SELECT 
    p.id as pin_id,
    pt.chain,
    pt.contract_address,
    pt.token_id,
    pt.created_at
FROM pinned_tokens pt
JOIN pin_requests pr ON pt.pin_request_id = pr.id
JOIN pins p ON p.task_id = pr.task_id AND p.cid = pr.cid AND p.request_id = pr.request_id;

-- Drop old tables
DROP TABLE pinned_tokens;
DROP TABLE pin_requests;

-- Rename new tables to final names
ALTER TABLE pin_requests_new RENAME TO pin_requests;
ALTER TABLE pinned_tokens_new RENAME TO pinned_tokens;

-- Add foreign key constraints
ALTER TABLE pins ADD CONSTRAINT fk_pins_task_id 
    FOREIGN KEY (task_id) REFERENCES pin_requests(task_id) ON DELETE CASCADE;
ALTER TABLE pinned_tokens ADD CONSTRAINT fk_pinned_tokens_pin_id 
    FOREIGN KEY (pin_id) REFERENCES pins(id) ON DELETE CASCADE;

-- Create indexes for new tables
CREATE INDEX IF NOT EXISTS idx_pin_requests_status ON pin_requests (status);
CREATE INDEX IF NOT EXISTS idx_pin_requests_deleted_at ON pin_requests (deleted_at);

CREATE INDEX IF NOT EXISTS idx_pins_task_id ON pins (task_id);
CREATE INDEX IF NOT EXISTS idx_pins_provider_type ON pins (provider_type);
CREATE INDEX IF NOT EXISTS idx_pins_cid ON pins (cid);
CREATE INDEX IF NOT EXISTS idx_pins_pin_status ON pins (pin_status);
CREATE INDEX IF NOT EXISTS idx_pins_request_id ON pins (request_id);

CREATE INDEX IF NOT EXISTS pinned_tokens_token_idx ON pinned_tokens(chain, contract_address, token_id);

COMMIT;

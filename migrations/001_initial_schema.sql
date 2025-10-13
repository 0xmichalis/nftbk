-- NFT Protection Service - Initial Schema
-- This migration creates the complete schema for the NFT protection service
-- reflecting the latest table names and constraints

BEGIN;

-- Core backup tasks table
CREATE TABLE IF NOT EXISTS backup_tasks (
    task_id VARCHAR(255) PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    requestor VARCHAR(255) NOT NULL,
    nft_count INTEGER NOT NULL,
    tokens JSONB NOT NULL,
    status VARCHAR(12) NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'done', 'error', 'expired')),
    error_log TEXT,
    fatal_error TEXT,
    storage_mode VARCHAR(20) NOT NULL DEFAULT 'full' CHECK (storage_mode IN ('archive', 'ipfs', 'full')),
    deleted_at TIMESTAMPTZ
);

-- Archive requests table
CREATE TABLE IF NOT EXISTS archive_requests (
    task_id VARCHAR(255) PRIMARY KEY REFERENCES backup_tasks(task_id) ON DELETE CASCADE,
    archive_format VARCHAR(8) NOT NULL CHECK (archive_format IN ('zip', 'tar.gz')),
    expires_at TIMESTAMPTZ
);

-- IPFS pin requests table
CREATE TABLE IF NOT EXISTS pin_requests (
    id BIGSERIAL PRIMARY KEY,
    task_id VARCHAR(255) NOT NULL REFERENCES backup_tasks(task_id) ON DELETE CASCADE,
    provider VARCHAR(64) NOT NULL,
    cid VARCHAR(255) NOT NULL,
    request_id VARCHAR(255) NOT NULL,
    status VARCHAR(12) NOT NULL CHECK (status IN ('queued', 'pinning', 'pinned', 'failed')),
    requestor VARCHAR(255) NOT NULL
);

-- Pinned tokens table (links tokens to pin requests)
CREATE TABLE IF NOT EXISTS pinned_tokens (
    pin_request_id BIGINT PRIMARY KEY REFERENCES pin_requests(id) ON DELETE CASCADE,
    chain TEXT NOT NULL,
    contract_address TEXT NOT NULL,
    token_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for backup_tasks
CREATE INDEX IF NOT EXISTS idx_backup_tasks_requestor ON backup_tasks (requestor);
CREATE INDEX IF NOT EXISTS idx_backup_tasks_tokens_gin ON backup_tasks USING GIN (tokens);
CREATE INDEX IF NOT EXISTS idx_backup_tasks_status ON backup_tasks (status);
CREATE INDEX IF NOT EXISTS idx_backup_tasks_deleted_at ON backup_tasks (deleted_at);

-- Indexes for archive_requests
CREATE INDEX IF NOT EXISTS idx_archive_requests_expires_at ON archive_requests (expires_at);

-- Indexes for pin_requests
CREATE INDEX IF NOT EXISTS idx_pin_requests_task_id ON pin_requests (task_id);
CREATE INDEX IF NOT EXISTS idx_pin_requests_requestor ON pin_requests (requestor);
CREATE INDEX IF NOT EXISTS idx_pin_requests_cid ON pin_requests (cid);
CREATE INDEX IF NOT EXISTS idx_pin_requests_status ON pin_requests (status);

-- Indexes for pinned_tokens
CREATE INDEX IF NOT EXISTS pinned_tokens_token_idx ON pinned_tokens(chain, contract_address, token_id);

COMMIT;

-- NFT Protection Service - Initial Schema
-- This migration creates the complete schema for the NFT protection service
-- reflecting the latest table names and constraints

-- Core backup tasks table
CREATE TABLE IF NOT EXISTS backup_tasks (
    task_id VARCHAR(255) PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    requestor VARCHAR(255) NOT NULL,
    nft_count INTEGER NOT NULL,
    storage_mode VARCHAR(20) NOT NULL DEFAULT 'full' CHECK (storage_mode IN ('archive', 'ipfs', 'full'))
);

-- Archive requests table
CREATE TABLE IF NOT EXISTS archive_requests (
    task_id VARCHAR(255) PRIMARY KEY REFERENCES backup_tasks(task_id) ON DELETE CASCADE,
    archive_format VARCHAR(8) NOT NULL CHECK (archive_format IN ('zip', 'tar.gz')),
    expires_at TIMESTAMPTZ,
    status VARCHAR(12) NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'done', 'error', 'expired')),
    fatal_error TEXT,
    error_log TEXT,
    deleted_at TIMESTAMPTZ
);

-- IPFS pin requests table
CREATE TABLE IF NOT EXISTS pin_requests (
    task_id VARCHAR(255) PRIMARY KEY REFERENCES backup_tasks(task_id) ON DELETE CASCADE,
    status VARCHAR(12) NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'done', 'error')),
    fatal_error TEXT,
    error_log TEXT,
    deleted_at TIMESTAMPTZ
);

-- Pins related to pin requests
CREATE TABLE IF NOT EXISTS pins (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    token_id BIGINT REFERENCES tokens(id) ON DELETE CASCADE,
    task_id VARCHAR(255) NOT NULL REFERENCES pin_requests(task_id) ON DELETE CASCADE,
    provider_type VARCHAR(64) NOT NULL,
    provider_url TEXT,
    cid VARCHAR(255) NOT NULL,
    request_id VARCHAR(255) NOT NULL,
    pin_status VARCHAR(12) NOT NULL CHECK (pin_status IN ('queued', 'pinning', 'pinned', 'failed'))
);

-- Tokens related to backup tasks
CREATE TABLE IF NOT EXISTS tokens (
    id BIGSERIAL PRIMARY KEY,
    task_id VARCHAR(255) NOT NULL REFERENCES backup_tasks(task_id) ON DELETE CASCADE,
    chain TEXT NOT NULL,
    contract_address TEXT NOT NULL,
    token_id TEXT NOT NULL,
    UNIQUE (task_id, chain, contract_address, token_id)
);

-- Indexes for backup_tasks
CREATE INDEX IF NOT EXISTS idx_backup_tasks_requestor ON backup_tasks (requestor);

-- Indexes for archive_requests
CREATE INDEX IF NOT EXISTS idx_archive_requests_expires_at ON archive_requests (expires_at);
CREATE INDEX IF NOT EXISTS idx_archive_requests_status ON archive_requests (status);

-- Indexes for pin_requests
CREATE INDEX IF NOT EXISTS idx_pin_requests_status ON pin_requests (status);

-- Indexes for pins
CREATE INDEX IF NOT EXISTS idx_pins_task_id ON pins (task_id);
CREATE INDEX IF NOT EXISTS idx_pins_provider_type ON pins (provider_type);
CREATE INDEX IF NOT EXISTS idx_pins_cid ON pins (cid);
CREATE INDEX IF NOT EXISTS idx_pins_pin_status ON pins (pin_status);
CREATE INDEX IF NOT EXISTS idx_pins_request_id ON pins (request_id);

-- Indexes for tokens
CREATE INDEX IF NOT EXISTS idx_tokens_task_id ON tokens(task_id);
CREATE INDEX IF NOT EXISTS idx_tokens_tuple ON tokens(chain, contract_address, token_id);

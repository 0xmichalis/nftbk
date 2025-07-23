CREATE TABLE IF NOT EXISTS backup_metadata (
    task_id VARCHAR(255) PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    requestor VARCHAR(255) NOT NULL,
    archive_format VARCHAR(8) NOT NULL CHECK (archive_format IN ('zip', 'tar.gz')),
    nft_count INTEGER NOT NULL,
    tokens JSONB NOT NULL,
    status VARCHAR(12) NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'done', 'error', 'expired')),
    expires_at TIMESTAMPTZ,
    error_log TEXT,
    fatal_error TEXT
);

CREATE INDEX IF NOT EXISTS idx_requestor ON backup_metadata (requestor);
CREATE INDEX IF NOT EXISTS idx_expires_at ON backup_metadata (expires_at);
CREATE INDEX IF NOT EXISTS idx_tokens_gin ON backup_metadata USING GIN (tokens);
CREATE INDEX IF NOT EXISTS idx_status ON backup_metadata (status);

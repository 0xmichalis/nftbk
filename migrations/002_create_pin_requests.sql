CREATE TABLE IF NOT EXISTS pin_requests (
    id BIGSERIAL PRIMARY KEY,
    provider VARCHAR(64) NOT NULL,
    cid VARCHAR(255) NOT NULL,
    request_id VARCHAR(255) NOT NULL,
    status VARCHAR(12) NOT NULL CHECK (status IN ('queued', 'pinning', 'pinned', 'failed')),
    requestor VARCHAR(255) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pin_requests_requestor ON pin_requests (requestor);
CREATE INDEX IF NOT EXISTS idx_pin_requests_cid ON pin_requests (cid);
CREATE INDEX IF NOT EXISTS idx_pin_requests_status ON pin_requests (status);

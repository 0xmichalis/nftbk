CREATE TABLE IF NOT EXISTS pinned_tokens (
  pin_request_id BIGINT PRIMARY KEY REFERENCES pin_requests(id) ON DELETE CASCADE,
  chain TEXT NOT NULL,
  contract_address TEXT NOT NULL,
  token_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for querying by token (chain, contract, token_id)
CREATE INDEX IF NOT EXISTS pinned_tokens_token_idx
  ON pinned_tokens(chain, contract_address, token_id);

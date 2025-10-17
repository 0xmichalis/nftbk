-- Normalize tokens out of backup_tasks.tokens JSONB
-- - Create tokens table owned by backup_tasks
-- - Backfill from existing JSONB
-- - Add pins.token_id (1 token : many pins) and backfill
-- - Drop pinned_tokens (superseded by pins.token_id)

BEGIN;

-- 1) Tokens table
CREATE TABLE IF NOT EXISTS tokens (
    id BIGSERIAL PRIMARY KEY,
    task_id VARCHAR(255) NOT NULL REFERENCES backup_tasks(task_id) ON DELETE CASCADE,
    chain TEXT NOT NULL,
    contract_address TEXT NOT NULL,
    token_id TEXT NOT NULL,
    UNIQUE (task_id, chain, contract_address, token_id)
);

-- Helpful indexes
CREATE INDEX IF NOT EXISTS idx_tokens_task_id ON tokens(task_id);
CREATE INDEX IF NOT EXISTS idx_tokens_tuple ON tokens(chain, contract_address, token_id);

-- 2) Backfill tokens from backup_tasks.tokens JSONB
-- tokens JSON shape: [{ chain: string, tokens: ["<contract>:<token>", ...] }, ...]
INSERT INTO tokens (task_id, chain, contract_address, token_id)
SELECT
    bt.task_id,
    elem->>'chain' AS chain,
    split_part(tok, ':', 1) AS contract_address,
    split_part(tok, ':', 2) AS token_id
FROM backup_tasks bt
     CROSS JOIN LATERAL jsonb_array_elements(bt.tokens) AS elem
     CROSS JOIN LATERAL jsonb_array_elements_text(elem->'tokens') AS tok
ON CONFLICT (task_id, chain, contract_address, token_id) DO NOTHING;

-- 3) Add pins.token_id and backfill from pinned_tokens
ALTER TABLE pins ADD COLUMN IF NOT EXISTS token_id BIGINT;

-- Backfill pins.token_id by matching pinned_tokens rows to tokens within same task
UPDATE pins AS p
SET token_id = t.id
FROM pinned_tokens pt, tokens t
WHERE pt.pin_id = p.id
  AND t.task_id = p.task_id
  AND t.chain = pt.chain
  AND t.contract_address = pt.contract_address
  AND t.token_id = pt.token_id
  AND p.token_id IS DISTINCT FROM t.id;

-- Enforce FK and NOT NULL after backfill
ALTER TABLE pins
    ADD CONSTRAINT pins_token_id_fkey FOREIGN KEY (token_id) REFERENCES tokens(id) ON DELETE CASCADE;

ALTER TABLE pins
    ALTER COLUMN token_id SET NOT NULL;

-- 4) Drop legacy pinned_tokens table
DROP TABLE IF EXISTS pinned_tokens;

-- 5) Drop legacy tokens JSONB and its index from backup_tasks
DROP INDEX IF EXISTS idx_backup_tasks_tokens_gin;
ALTER TABLE backup_tasks DROP COLUMN IF EXISTS tokens;

COMMIT;



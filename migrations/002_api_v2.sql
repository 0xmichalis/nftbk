-- Version 2 separates captured NFT observations, archives, pin sets and work.
-- The 1.x tables remain intact so that migration preserves the original data.
CREATE TABLE principals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    UNIQUE (issuer, subject)
);
CREATE TABLE backups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES principals(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    state TEXT NOT NULL CHECK (state IN ('awaiting_payment','queued','running','ready','partial','failed','deleting','deleted')),
    specification JSONB NOT NULL,
    specification_hash TEXT NOT NULL,
    manifest_sha256 TEXT,
    provenance TEXT NOT NULL DEFAULT 'captured',
    legacy_task_id TEXT UNIQUE,
    deletion_requested_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);
CREATE TABLE blobs (
    sha256 TEXT PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    storage_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    state TEXT NOT NULL DEFAULT 'ready' CHECK (state IN ('ready','deleting','deleted'))
);
CREATE TABLE backup_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_id UUID NOT NULL REFERENCES backups(id),
    chain_id TEXT NOT NULL CHECK (chain_id ~ '^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$'),
    contract_address TEXT NOT NULL,
    token_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','ready','partial','failed','unsupported')),
    metadata_uri TEXT,
    metadata_sha256 TEXT REFERENCES blobs(sha256),
    observed_at TIMESTAMPTZ,
    block_reference TEXT,
    error JSONB,
    UNIQUE (backup_id, chain_id, contract_address, token_id),
    UNIQUE (id, backup_id)
);
CREATE TABLE item_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    item_id UUID NOT NULL REFERENCES backup_items(id),
    role TEXT NOT NULL,
    source_uri TEXT,
    filename TEXT,
    fallback_filename TEXT,
    observed_at TIMESTAMPTZ,
    path TEXT NOT NULL,
    sha256 TEXT REFERENCES blobs(sha256),
    cid TEXT,
    size_bytes BIGINT CHECK (size_bytes >= 0),
    state TEXT NOT NULL CHECK (state IN ('queued','running','ready','partial','failed','unsupported')),
    error JSONB,
    UNIQUE (item_id, path),
    UNIQUE (id, item_id)
);
CREATE TABLE archives (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_id UUID NOT NULL REFERENCES backups(id),
    owner_id UUID NOT NULL REFERENCES principals(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    state TEXT NOT NULL CHECK (state IN ('awaiting_payment','queued','running','ready','partial','failed','deleting','deleted','expired')),
    format TEXT NOT NULL CHECK (format IN ('zip','tar.gz')),
    retention_days INTEGER NOT NULL CHECK (retention_days BETWEEN 1 AND 365),
    expires_at TIMESTAMPTZ,
    sha256 TEXT REFERENCES blobs(sha256),
    storage_key TEXT,
    size_bytes BIGINT CHECK (size_bytes >= 0),
    error JSONB,
    deletion_requested_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    UNIQUE (id, backup_id)
);
CREATE TABLE provider_instances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_key TEXT NOT NULL UNIQUE,
    provider_type TEXT NOT NULL,
    provider_url TEXT NOT NULL,
    credential_reference TEXT
);
CREATE TABLE pin_sets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_id UUID NOT NULL REFERENCES backups(id),
    owner_id UUID NOT NULL REFERENCES principals(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    state TEXT NOT NULL CHECK (state IN ('awaiting_payment','queued','running','ready','partial','failed','deleting','deleted')),
    provider_ids UUID[] NOT NULL,
    error JSONB,
    deletion_requested_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    UNIQUE (id, backup_id)
);
CREATE TABLE provider_pins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES provider_instances(id),
    cid TEXT NOT NULL,
    request_id TEXT,
    submitted_at TIMESTAMPTZ,
    state TEXT NOT NULL CHECK (state IN ('queued','pinning','pinned','failed','deleting','deleted','reconciliation_required')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    error JSONB,
    UNIQUE (provider_id, request_id)
);
CREATE UNIQUE INDEX provider_pins_pending ON provider_pins(provider_id, cid) WHERE request_id IS NULL AND state = 'queued';
CREATE TABLE pin_memberships (
    pin_set_id UUID NOT NULL,
    backup_id UUID NOT NULL,
    item_id UUID NOT NULL,
    asset_id UUID NOT NULL,
    pin_id UUID NOT NULL REFERENCES provider_pins(id),
    PRIMARY KEY (pin_set_id, asset_id, pin_id),
    FOREIGN KEY (pin_set_id, backup_id) REFERENCES pin_sets(id, backup_id),
    FOREIGN KEY (item_id, backup_id) REFERENCES backup_items(id, backup_id),
    FOREIGN KEY (asset_id, item_id) REFERENCES item_assets(id, item_id)
);
CREATE TABLE quotes (
    source_backup_id UUID REFERENCES backups(id),
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES principals(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    specification JSONB NOT NULL,
    specification_hash TEXT NOT NULL,
    pricing_version TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('calculating','ready','failed','expired')),
    amount_atomic NUMERIC(78,0) CHECK (amount_atomic >= 0),
    asset_symbol TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    asset_address TEXT NOT NULL,
    asset_decimals SMALLINT NOT NULL CHECK (asset_decimals BETWEEN 0 AND 255),
    estimated_size_bytes BIGINT CHECK (estimated_size_bytes >= 0),
    plan JSONB NOT NULL DEFAULT '[]',
    expires_at TIMESTAMPTZ NOT NULL,
    error JSONB
);
CREATE TABLE operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES principals(id),
    kind TEXT NOT NULL CHECK (kind IN ('capture','archive','pin','delete_backup','delete_archive','delete_pin_set','quote')),
    backup_id UUID REFERENCES backups(id),
    archive_id UUID REFERENCES archives(id),
    pin_set_id UUID REFERENCES pin_sets(id),
    quote_id UUID REFERENCES quotes(id),
    state TEXT NOT NULL CHECK (state IN ('awaiting_payment','queued','running','succeeded','failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_token UUID,
    lease_until TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    error JSONB,
    CHECK ((kind IN ('capture','delete_backup') AND backup_id IS NOT NULL AND archive_id IS NULL AND pin_set_id IS NULL AND quote_id IS NULL)
        OR (kind IN ('archive','delete_archive') AND archive_id IS NOT NULL AND backup_id IS NULL AND pin_set_id IS NULL AND quote_id IS NULL)
        OR (kind IN ('pin','delete_pin_set') AND pin_set_id IS NOT NULL AND backup_id IS NULL AND archive_id IS NULL AND quote_id IS NULL)
        OR (kind = 'quote' AND quote_id IS NOT NULL AND backup_id IS NULL AND archive_id IS NULL AND pin_set_id IS NULL))
);
CREATE UNIQUE INDEX operations_active_backup ON operations(backup_id, kind) WHERE state IN ('awaiting_payment','queued','running');
CREATE UNIQUE INDEX operations_active_archive ON operations(archive_id, kind) WHERE state IN ('awaiting_payment','queued','running');
CREATE UNIQUE INDEX operations_active_pin_set ON operations(pin_set_id, kind) WHERE state IN ('awaiting_payment','queued','running');
ALTER TABLE provider_pins ADD COLUMN operation_id UUID REFERENCES operations(id);
CREATE TABLE service_keys (name TEXT PRIMARY KEY, key BYTEA NOT NULL CHECK(octet_length(key)=32));
CREATE TABLE blob_leases (sha256 TEXT NOT NULL REFERENCES blobs(sha256), operation_id UUID NOT NULL REFERENCES operations(id), PRIMARY KEY(sha256,operation_id));
CREATE TABLE pin_deletions (operation_id UUID NOT NULL REFERENCES operations(id),pin_id UUID NOT NULL REFERENCES provider_pins(id),PRIMARY KEY(operation_id,pin_id));
CREATE TABLE operation_attempts (
    operation_id UUID NOT NULL REFERENCES operations(id),
    number INTEGER NOT NULL,
    lease_token UUID,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error JSONB,
    PRIMARY KEY (operation_id, number)
);
CREATE TABLE operation_events (
    id BIGSERIAL PRIMARY KEY,
    operation_id UUID NOT NULL REFERENCES operations(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    event JSONB NOT NULL
);
CREATE TABLE payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_id UUID UNIQUE REFERENCES backups(id),
    archive_id UUID UNIQUE REFERENCES archives(id),
    pin_set_id UUID UNIQUE REFERENCES pin_sets(id),
    CHECK(num_nonnulls(backup_id,archive_id,pin_set_id)=1),
    quote_id UUID NOT NULL REFERENCES quotes(id),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','settling','paid','failed','reconciliation_required')),
    proof_hash TEXT UNIQUE,
    settle_request JSONB,
    settlement JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE idempotency_keys (
    owner_id UUID NOT NULL REFERENCES principals(id),
    endpoint TEXT NOT NULL,
    key TEXT NOT NULL CHECK (length(key) BETWEEN 1 AND 200),
    payload_hash TEXT NOT NULL,
    resource_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (owner_id, endpoint, key)
);
CREATE INDEX backups_owner_created ON backups(owner_id, created_at DESC, id DESC);
CREATE INDEX archives_owner_created ON archives(owner_id, created_at DESC, id DESC);
CREATE INDEX pin_sets_owner_created ON pin_sets(owner_id, created_at DESC, id DESC);
CREATE INDEX archives_expiration ON archives(expires_at) WHERE state IN ('ready','partial');
CREATE INDEX operations_runnable ON operations(available_at, created_at, id) WHERE state = 'queued';
CREATE INDEX operations_expired_leases ON operations(lease_until) WHERE state = 'running';
CREATE INDEX pin_memberships_pin ON pin_memberships(pin_id);
CREATE INDEX provider_pins_monitor ON provider_pins(updated_at) WHERE state IN ('queued','pinning','deleting','reconciliation_required');

ALTER TABLE backups ADD UNIQUE(id,owner_id);
ALTER TABLE archives ADD UNIQUE(id,owner_id);
ALTER TABLE pin_sets ADD UNIQUE(id,owner_id);
ALTER TABLE quotes ADD UNIQUE(id,owner_id);
ALTER TABLE archives ADD FOREIGN KEY(backup_id,owner_id) REFERENCES backups(id,owner_id);
ALTER TABLE pin_sets ADD FOREIGN KEY(backup_id,owner_id) REFERENCES backups(id,owner_id);
ALTER TABLE quotes ADD FOREIGN KEY(source_backup_id,owner_id) REFERENCES backups(id,owner_id);
ALTER TABLE operations ADD FOREIGN KEY(backup_id,owner_id) REFERENCES backups(id,owner_id);
ALTER TABLE operations ADD FOREIGN KEY(archive_id,owner_id) REFERENCES archives(id,owner_id);
ALTER TABLE operations ADD FOREIGN KEY(pin_set_id,owner_id) REFERENCES pin_sets(id,owner_id);
ALTER TABLE operations ADD FOREIGN KEY(quote_id,owner_id) REFERENCES quotes(id,owner_id);

-- Resolve legacy names without changing legacy task IDs or filesystem paths.
CREATE FUNCTION nftbk_caip2(value TEXT) RETURNS TEXT LANGUAGE SQL IMMUTABLE STRICT AS $$
 SELECT CASE value WHEN 'ethereum' THEN 'eip155:1' WHEN 'polygon' THEN 'eip155:137'
 WHEN 'base' THEN 'eip155:8453' WHEN 'base-sepolia' THEN 'eip155:84532'
 WHEN 'arbitrum' THEN 'eip155:42161' WHEN 'optimism' THEN 'eip155:10'
 WHEN 'shape' THEN 'eip155:360' WHEN 'zora' THEN 'eip155:7777777'
 WHEN 'tezos' THEN 'tezos:NetXdQprcVkpaWU' WHEN 'ghostnet' THEN 'tezos:NetXnHfVqm9iesp'
 ELSE value END
$$;
INSERT INTO principals(issuer, subject)
SELECT DISTINCT CASE WHEN requestor = 'admin' THEN 'nftbk:local' ELSE 'legacy' END, requestor FROM backup_tasks;
INSERT INTO backups(owner_id, created_at, updated_at, state, specification, specification_hash, provenance, legacy_task_id)
SELECT p.id, b.created_at, b.updated_at, 'ready',
 jsonb_build_object('nfts', COALESCE((SELECT jsonb_agg(jsonb_build_object('chain_id',nftbk_caip2(t.chain),'contract_address',t.contract_address,'token_id',t.token_id)) FROM tokens t WHERE t.task_id=b.task_id),'[]'::jsonb), 'outputs','[]'::jsonb),
 b.task_id, 'legacy', b.task_id
FROM backup_tasks b JOIN principals p ON p.subject=b.requestor AND p.issuer=CASE WHEN b.requestor='admin' THEN 'nftbk:local' ELSE 'legacy' END;
INSERT INTO backup_items(backup_id, chain_id, contract_address, token_id, state)
SELECT b.id, nftbk_caip2(t.chain), CASE WHEN nftbk_caip2(t.chain) LIKE 'eip155:%' THEN lower(t.contract_address) ELSE t.contract_address END, t.token_id, 'unsupported'
FROM tokens t JOIN backups b ON b.legacy_task_id=t.task_id
ON CONFLICT (backup_id,chain_id,contract_address,token_id) DO NOTHING;
INSERT INTO archives(backup_id, owner_id, created_at, state, format, retention_days, expires_at, storage_key, error, deletion_requested_at)
SELECT b.id,b.owner_id,b.created_at,
 CASE WHEN a.deleted_at IS NOT NULL THEN 'deleting' WHEN a.status='done' THEN 'ready' WHEN a.status='in_progress' THEN 'queued' WHEN a.status='expired' THEN 'expired' ELSE 'failed' END,
 a.archive_format,3,a.expires_at,'nftbk-'||a.task_id||'.'||a.archive_format,
 CASE WHEN a.fatal_error IS NOT NULL OR a.error_log IS NOT NULL THEN jsonb_build_object('code','legacy_error','message',concat_ws(E'\n',a.fatal_error,a.error_log),'retryable',true) END,a.deleted_at
FROM archive_requests a JOIN backups b ON b.legacy_task_id=a.task_id;
INSERT INTO provider_instances(instance_key,provider_type,provider_url)
SELECT DISTINCT 'legacy:'||provider_type||':'||COALESCE(provider_url,''),provider_type,COALESCE(provider_url,'') FROM pins;
INSERT INTO pin_sets(backup_id,owner_id,created_at,state,provider_ids,error,deletion_requested_at)
SELECT b.id,b.owner_id,b.created_at,
 CASE WHEN pr.deleted_at IS NOT NULL THEN 'deleting' WHEN pr.status='error' THEN 'failed' ELSE 'running' END,
 ARRAY(SELECT DISTINCT pi.id FROM pins p JOIN provider_instances pi ON pi.instance_key='legacy:'||p.provider_type||':'||COALESCE(p.provider_url,'') WHERE p.task_id=pr.task_id),
 CASE WHEN pr.fatal_error IS NOT NULL OR pr.error_log IS NOT NULL THEN jsonb_build_object('code','legacy_error','message',concat_ws(E'\n',pr.fatal_error,pr.error_log),'retryable',true) END,pr.deleted_at
FROM pin_requests pr JOIN backups b ON b.legacy_task_id=pr.task_id;
INSERT INTO provider_pins(provider_id,cid,request_id,state,created_at)
SELECT pi.id,p.cid,p.request_id,p.pin_status,min(p.created_at)
FROM pins p JOIN provider_instances pi ON pi.instance_key='legacy:'||p.provider_type||':'||COALESCE(p.provider_url,'')
GROUP BY pi.id,p.cid,p.request_id,p.pin_status ON CONFLICT (provider_id,request_id) DO NOTHING;
INSERT INTO item_assets(item_id,role,path,cid,state)
SELECT DISTINCT i.id,'legacy_ipfs','legacy-ipfs/'||p.cid,p.cid,'ready'
FROM pins p JOIN tokens t ON t.id=p.token_id JOIN backups b ON b.legacy_task_id=t.task_id
JOIN backup_items i ON i.backup_id=b.id AND i.chain_id=nftbk_caip2(t.chain) AND i.contract_address=CASE WHEN nftbk_caip2(t.chain) LIKE 'eip155:%' THEN lower(t.contract_address) ELSE t.contract_address END AND i.token_id=t.token_id
ON CONFLICT (item_id,path) DO NOTHING;
INSERT INTO pin_memberships(pin_set_id,backup_id,item_id,asset_id,pin_id)
SELECT DISTINCT ps.id,b.id,i.id,a.id,pp.id
FROM pins p JOIN tokens t ON t.id=p.token_id JOIN backups b ON b.legacy_task_id=p.task_id
JOIN backup_items i ON i.backup_id=b.id AND i.chain_id=nftbk_caip2(t.chain) AND i.contract_address=CASE WHEN nftbk_caip2(t.chain) LIKE 'eip155:%' THEN lower(t.contract_address) ELSE t.contract_address END AND i.token_id=t.token_id
JOIN item_assets a ON a.item_id=i.id AND a.cid=p.cid JOIN pin_sets ps ON ps.backup_id=b.id
JOIN provider_instances pi ON pi.instance_key='legacy:'||p.provider_type||':'||COALESCE(p.provider_url,'')
JOIN provider_pins pp ON pp.provider_id=pi.id AND pp.request_id=p.request_id
ON CONFLICT DO NOTHING;
INSERT INTO operations(owner_id,kind,archive_id,state)
SELECT owner_id, CASE WHEN state='deleting' THEN 'delete_archive' ELSE 'archive' END,id,'queued' FROM archives WHERE state IN ('queued','deleting');
INSERT INTO operations(owner_id,kind,pin_set_id,state)
SELECT owner_id, CASE WHEN state='deleting' THEN 'delete_pin_set' ELSE 'pin' END,id,'queued' FROM pin_sets WHERE state IN ('running','deleting');

CREATE VIEW api_archives AS SELECT a.id,a.owner_id,a.created_at,
 jsonb_build_object('id',a.id,'backup_id',a.backup_id,'created_at',a.created_at,'state',a.state,'format',a.format,'expires_at',a.expires_at,'sha256',a.sha256,'size_bytes',a.size_bytes,'error',a.error,'deletion_requested_at',a.deletion_requested_at,'deleted_at',a.deleted_at,
 'operation_id',(SELECT o.id FROM operations o WHERE o.archive_id=a.id ORDER BY o.created_at DESC,o.id DESC LIMIT 1)) AS document FROM archives a;
CREATE VIEW api_pin_sets AS SELECT ps.id,ps.owner_id,ps.created_at,
 jsonb_build_object('id',ps.id,'backup_id',ps.backup_id,'created_at',ps.created_at,'state',ps.state,'error',ps.error,'deletion_requested_at',ps.deletion_requested_at,'deleted_at',ps.deleted_at,
 'requested_nft_count',(SELECT count(*) FROM backup_items i WHERE i.backup_id=ps.backup_id),
 'eligible_nft_count',(SELECT count(DISTINCT i.id) FROM backup_items i JOIN item_assets a ON a.item_id=i.id WHERE i.backup_id=ps.backup_id AND a.cid IS NOT NULL),
 'skipped_nft_count',(SELECT count(*) FROM backup_items i WHERE i.backup_id=ps.backup_id AND NOT EXISTS(SELECT 1 FROM item_assets a WHERE a.item_id=i.id AND a.cid IS NOT NULL)),
 'protected_nft_count',(SELECT count(*) FROM backup_items i WHERE i.backup_id=ps.backup_id AND cardinality(ps.provider_ids)>0 AND EXISTS(SELECT 1 FROM item_assets a WHERE a.item_id=i.id AND a.cid IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM item_assets a CROSS JOIN unnest(ps.provider_ids) AS providers(provider_id) WHERE a.item_id=i.id AND a.cid IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pin_memberships m JOIN provider_pins pp ON pp.id=m.pin_id WHERE m.pin_set_id=ps.id AND m.asset_id=a.id AND pp.provider_id=providers.provider_id AND pp.state='pinned'))),
 'operation_id',(SELECT o.id FROM operations o WHERE o.pin_set_id=ps.id ORDER BY o.created_at DESC,o.id DESC LIMIT 1)) AS document FROM pin_sets ps;
CREATE VIEW api_backups AS SELECT b.id,b.owner_id,b.created_at,
 jsonb_build_object('id',b.id,'created_at',b.created_at,'updated_at',b.updated_at,'state',b.state,'provenance',b.provenance,'manifest_sha256',b.manifest_sha256,
 'nft_count',(SELECT count(*) FROM backup_items i WHERE i.backup_id=b.id),
 'captured_count',(SELECT count(*) FROM backup_items i WHERE i.backup_id=b.id AND i.state='ready'),
 'failed_count',(SELECT count(*) FROM backup_items i WHERE i.backup_id=b.id AND i.state IN ('failed','partial')),
 'archives',COALESCE((SELECT jsonb_agg(a.document ORDER BY a.created_at,a.id) FROM api_archives a JOIN archives r ON r.id=a.id WHERE r.backup_id=b.id),'[]'::jsonb),
 'pin_sets',COALESCE((SELECT jsonb_agg(p.document ORDER BY p.created_at,p.id) FROM api_pin_sets p JOIN pin_sets r ON r.id=p.id WHERE r.backup_id=b.id),'[]'::jsonb),
 'operation_id',(SELECT o.id FROM operations o WHERE o.backup_id=b.id ORDER BY o.created_at DESC,o.id DESC LIMIT 1)) AS document FROM backups b;
CREATE VIEW api_items AS SELECT i.id,b.owner_id,b.created_at,i.backup_id,
 (to_jsonb(i)-'backup_id')||jsonb_build_object('backup_id',i.backup_id,'assets',COALESCE((SELECT jsonb_agg(to_jsonb(a) ORDER BY a.path) FROM item_assets a WHERE a.item_id=i.id),'[]'::jsonb)) AS document
 FROM backup_items i JOIN backups b ON b.id=i.backup_id;
CREATE VIEW api_operations AS SELECT o.id,o.owner_id,o.created_at,
 jsonb_build_object('id',o.id,'kind',o.kind,'target_id',COALESCE(o.backup_id,o.archive_id,o.pin_set_id,o.quote_id),'state',o.state,'attempts',o.attempts,'created_at',o.created_at,'updated_at',o.updated_at,'error',o.error) AS document FROM operations o;
CREATE VIEW api_quotes AS SELECT q.id,q.owner_id,q.created_at,
 jsonb_build_object('id',q.id,'state',CASE WHEN q.expires_at<=now() THEN 'expired' ELSE q.state END,'amount_atomic',q.amount_atomic::text,'asset_symbol',q.asset_symbol,'chain_id',q.chain_id,'asset_address',q.asset_address,'asset_decimals',q.asset_decimals,'estimated_size_bytes',q.estimated_size_bytes,'expires_at',q.expires_at,'pricing_version',q.pricing_version,'error',q.error,
 'operation_id',(SELECT o.id FROM operations o WHERE o.quote_id=q.id ORDER BY o.created_at DESC,o.id DESC LIMIT 1)) AS document FROM quotes q;

CREATE VIEW api_pins AS SELECT DISTINCT pp.id,ps.owner_id,pp.created_at,
 jsonb_build_object('id',pp.id,'provider_id',pp.provider_id,'cid',pp.cid,'state',pp.state,'created_at',pp.created_at,'updated_at',pp.updated_at,'error',pp.error,
 'nfts',(SELECT jsonb_agg(DISTINCT jsonb_build_object('chain_id',i.chain_id,'contract_address',i.contract_address,'token_id',i.token_id)) FROM pin_memberships pm JOIN backup_items i ON i.id=pm.item_id JOIN pin_sets owned ON owned.id=pm.pin_set_id WHERE pm.pin_id=pp.id AND owned.owner_id=ps.owner_id)) AS document
 FROM provider_pins pp JOIN pin_memberships m ON m.pin_id=pp.id JOIN pin_sets ps ON ps.id=m.pin_set_id;

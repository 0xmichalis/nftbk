-- Legacy quotes have no approved recipient and must be quoted again before payment.
ALTER TABLE quotes ADD COLUMN pay_to TEXT NOT NULL DEFAULT '';
CREATE OR REPLACE VIEW api_quotes AS SELECT q.id,q.owner_id,q.created_at,
 jsonb_build_object('id',q.id,'state',CASE WHEN q.expires_at<=now() THEN 'expired' ELSE q.state END,'amount_atomic',q.amount_atomic::text,'asset_symbol',q.asset_symbol,'chain_id',q.chain_id,'asset_address',q.asset_address,'pay_to',q.pay_to,'asset_decimals',q.asset_decimals,'estimated_size_bytes',q.estimated_size_bytes,'expires_at',q.expires_at,'pricing_version',q.pricing_version,'error',q.error,
 'operation_id',(SELECT o.id FROM operations o WHERE o.quote_id=q.id ORDER BY o.created_at DESC,o.id DESC LIMIT 1)) AS document FROM quotes q;


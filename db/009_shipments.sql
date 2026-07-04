-- =============================================================================
-- 009 — Mercado Envíos (P2): frescura de estados de envío + etiquetas.
--
-- (a) order_snapshots.shipment_id: id del envío de ML denormalizado — permite
--     resolver "webhook de topic shipments → qué orden actualizar" sin escanear
--     JSON, y buscar el envío para la etiqueta. Se puebla en el upsert del
--     snapshot y acá se backfillea desde el JSON ya guardado (shipping.id).
--
-- Idempotente: IF NOT EXISTS + UPDATE re-ejecutable (solo filas NULL).
-- =============================================================================

ALTER TABLE order_snapshots ADD COLUMN IF NOT EXISTS shipment_id BIGINT;

CREATE INDEX IF NOT EXISTS order_snapshots_shipment_idx
    ON order_snapshots (account_id, shipment_id);

UPDATE order_snapshots
   SET shipment_id = (order_json->'shipping'->>'id')::BIGINT
 WHERE shipment_id IS NULL
   AND (order_json->'shipping'->>'id') ~ '^[0-9]+$';

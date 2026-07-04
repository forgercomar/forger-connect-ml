-- =============================================================================
-- 008 — Ventas ML (F0): snapshots completos de órdenes + job de backfill.
--
-- Hasta acá el pipeline de órdenes reducía cada orden ML a 4 campos por item
-- (sku/quantity/ml_item_id/variation_id) para el ledger de stock. Ventas ML
-- necesita la orden ENTERA (comprador, pagos/fees, envío, totales, fechas)
-- para poblar el espejo wf_orders del plugin, facturar por ARCA y alimentar
-- Finanzas.
--
-- order_snapshots guarda UNA fila por (cuenta, orden) con:
--   - order_json:    la orden ML completa (GET /orders/{id} u orders/search).
--   - billing_json:  GET /orders/{id}/billing_info (x-version: 2) — datos
--                    fiscales del comprador (DNI/CUIT, razón social).
--   - shipment_json: GET /shipments/{id} — estado del envío.
--
-- La puebla el pipeline en vivo (procesador de órdenes del scheduler) y el
-- backfill histórico (job 'orders_backfill', también del scheduler). Los
-- snapshots NO se purgan: son la fuente del historial de Ventas ML
-- (GET /v1/orders/history). order_events sigue siendo la cola de entrega
-- (esa sí se purga cuando las filas ya fueron entregadas — ver retención).
--
-- Idempotente: CREATE IF NOT EXISTS + DO $$...$$ re-ejecutables.
-- =============================================================================

CREATE TABLE IF NOT EXISTS order_snapshots (
    id              BIGSERIAL PRIMARY KEY,
    account_id      BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    ml_order_id     VARCHAR(32) NOT NULL,
    -- Orden ML completa, cruda, tal como la devolvió la API.
    order_json      JSONB NOT NULL,
    -- Datos fiscales del comprador (puede no existir → NULL).
    billing_json    JSONB,
    -- Estado del envío (solo si la orden tiene shipping.id → puede ser NULL).
    shipment_json   JSONB,
    -- date_created de la orden en ML — ordena el paginado del historial.
    ml_date_created TIMESTAMPTZ,
    fetched_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, ml_order_id)
);

-- Paginado de GET /v1/orders/history: por cuenta, de la más nueva a la más vieja.
CREATE INDEX IF NOT EXISTS order_snapshots_account_date_idx
    ON order_snapshots (account_id, ml_date_created DESC NULLS LAST, id DESC);

-- Nuevo tipo de job 'orders_backfill' (lo procesa el scheduler en su propio
-- loop — NO compite con el worker de sync/push). El CHECK original de 001 es
-- inmutable (migraciones aplicadas no se editan), así que se reemplaza acá.
-- Se busca el constraint por su definición y no por nombre, por si Postgres
-- lo auto-nombró distinto; re-ejecutar el bloque es inofensivo.
DO $$
DECLARE
    c RECORD;
BEGIN
    FOR c IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'jobs'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%auto_link_sku%'
    LOOP
        EXECUTE format('ALTER TABLE jobs DROP CONSTRAINT %I', c.conname);
    END LOOP;
    ALTER TABLE jobs ADD CONSTRAINT jobs_type_check
        CHECK (type IN ('sync_incremental','sync_full','auto_link_sku','push','orders_backfill'));
END $$;

-- =============================================================================
-- 004_order_events.sql — Cola de órdenes de MercadoLibre.
--
-- ML manda un webhook `orders_v2` cada vez que cambia el estado de una venta.
-- El webhook NO trae los datos de la orden, solo el id. El central lo encola
-- acá; el procesador del scheduler baja la orden de ML (GET /orders/{id}),
-- extrae los SKUs vendidos + cantidades + estado, y deja el resultado listo
-- para que el plugin lo baje y lo aplique a su ledger de stock.
--
-- Modelo pull, igual que webhook_events. El central hace el trabajo pesado
-- (llamar a la API de ML con el token custodiado); el plugin solo aplica.
-- =============================================================================

CREATE TABLE IF NOT EXISTS order_events (
    id            BIGSERIAL PRIMARY KEY,
    account_id    BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    -- Orden ML afectada (extraída del `resource` del webhook).
    ml_order_id   VARCHAR(32) NOT NULL,
    received_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Procesamiento: el worker baja la orden de ML y completa estos campos.
    processed_at  TIMESTAMPTZ,
    order_status  TEXT,                 -- 'paid', 'cancelled', 'confirmed', ...
    -- Items vendidos: [{ sku, quantity, ml_item_id, variation_id }]
    items_json    JSONB,
    error         TEXT,                 -- si falló bajar la orden de ML
    -- Entrega al plugin.
    delivered_at  TIMESTAMPTZ
);

-- El procesador escanea lo no procesado.
CREATE INDEX IF NOT EXISTS order_events_unprocessed_idx
    ON order_events (account_id, id) WHERE processed_at IS NULL;
-- El plugin baja lo procesado y no entregado.
CREATE INDEX IF NOT EXISTS order_events_undelivered_idx
    ON order_events (account_id, id) WHERE processed_at IS NOT NULL AND delivered_at IS NULL;
-- Cleanup de entregados viejos.
CREATE INDEX IF NOT EXISTS order_events_delivered_idx
    ON order_events (delivered_at) WHERE delivered_at IS NOT NULL;

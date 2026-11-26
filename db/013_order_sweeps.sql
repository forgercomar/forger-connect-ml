-- =============================================================================
-- 013_order_sweeps.sql — Barrido periódico de órdenes (red de avisos perdidos).
--
-- Si el aviso orders_v2 de una venta no llega (el conector caído más de una
-- hora: ML reintenta durante una hora y después lo descarta), la venta no
-- entraba nunca por la central. El barrido (order-sweep.js) le pide a ML cada
-- WFML_ORDER_SWEEP_INTERVAL las órdenes ACTUALIZADAS desde su último paso
-- (/orders/search con order.date_last_updated.from/to) y encola en order_events
-- la que falta o la que cambió, por el mismo camino que el aviso.
--
-- order_sweeps guarda, por cuenta, hasta dónde está barrido (cursor_at) y lo
-- que trajo: el dato que muestra que el barrido funciona es «recovered», las
-- órdenes que el aviso no había traído.
--
-- order_events.source distingue el origen de cada fila: NULL = el aviso de ML
-- (como hasta ahora) y 'sweep' = el barrido.
--
-- Idempotente: CREATE IF NOT EXISTS / ADD COLUMN IF NOT EXISTS.
-- =============================================================================

CREATE TABLE IF NOT EXISTS order_sweeps (
    account_id        BIGINT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    -- Todo lo actualizado en ML hasta este momento ya se comparó con la cola.
    cursor_at         TIMESTAMPTZ NOT NULL,
    last_run_at       TIMESTAMPTZ,
    last_ok_at        TIMESTAMPTZ,
    last_error        TEXT,
    -- Última pasada: órdenes que devolvió ML, encoladas, y de esas las que el
    -- aviso no había traído (nuevas = sin ningún rastro; cambios = una versión
    -- más nueva que la que ya tenía la cola).
    last_seen         INT NOT NULL DEFAULT 0,
    last_enqueued     INT NOT NULL DEFAULT 0,
    last_recovered_new     INT NOT NULL DEFAULT 0,
    last_recovered_changes INT NOT NULL DEFAULT 0,
    -- Acumulados desde que existe el barrido para la cuenta.
    total_recovered_new     BIGINT NOT NULL DEFAULT 0,
    total_recovered_changes BIGINT NOT NULL DEFAULT 0,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE order_events ADD COLUMN IF NOT EXISTS source TEXT;

-- El barrido busca los rastros de cada orden por (cuenta, orden); el ack también.
CREATE INDEX IF NOT EXISTS order_events_account_order_idx
    ON order_events (account_id, ml_order_id);

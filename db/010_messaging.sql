-- =============================================================================
-- 010_messaging.sql — Colas de Mensajería (post-venta) y Preguntas (pre-venta).
--
-- ML manda webhooks `messages` (resource /messages/{id}) y `questions`
-- (resource /questions/{id}). Como con las órdenes, el webhook solo trae el id:
-- el central lo encola acá, el tick del scheduler baja el contenido de ML con
-- el token custodiado y deja el payload CRUDO listo para que el plugin lo baje
-- (GET /v1/messages|questions/pending) y lo aplique con ack.
--
-- PRINCIPIO (decisión del dueño 2026-07-05): el central es SOLO cola de
-- tránsito — las conversaciones de los clientes NO se acumulan en infra
-- Forger. Las filas entregadas se purgan por retención (purgeDeliveredRows);
-- el historial vivo queda en el WordPress del cliente. NO hay tabla snapshot.
-- =============================================================================

CREATE TABLE IF NOT EXISTS message_events (
    id            BIGSERIAL PRIMARY KEY,
    account_id    BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    -- Id del mensaje ML (extraído del `resource` del webhook).
    ml_message_id VARCHAR(64) NOT NULL,
    resource      TEXT NOT NULL DEFAULT '',
    received_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Procesamiento: el tick baja el mensaje de ML y completa estos campos.
    processed_at  TIMESTAMPTZ,
    payload_json  JSONB,               -- mensaje ML crudo (from/to/text/pack)
    error         TEXT,
    -- Entrega al plugin.
    delivered_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS message_events_unprocessed_idx
    ON message_events (account_id, id) WHERE processed_at IS NULL;
CREATE INDEX IF NOT EXISTS message_events_undelivered_idx
    ON message_events (account_id, id) WHERE processed_at IS NOT NULL AND delivered_at IS NULL;
CREATE INDEX IF NOT EXISTS message_events_delivered_idx
    ON message_events (delivered_at) WHERE delivered_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS question_events (
    id             BIGSERIAL PRIMARY KEY,
    account_id     BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    ml_question_id VARCHAR(32) NOT NULL,
    received_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at   TIMESTAMPTZ,
    payload_json   JSONB,              -- pregunta ML cruda (text/item_id/status/answer)
    error          TEXT,
    delivered_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS question_events_unprocessed_idx
    ON question_events (account_id, id) WHERE processed_at IS NULL;
CREATE INDEX IF NOT EXISTS question_events_undelivered_idx
    ON question_events (account_id, id) WHERE processed_at IS NOT NULL AND delivered_at IS NULL;
CREATE INDEX IF NOT EXISTS question_events_delivered_idx
    ON question_events (delivered_at) WHERE delivered_at IS NOT NULL;

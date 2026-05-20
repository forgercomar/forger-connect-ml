-- =============================================================================
-- 002_sync_staging.sql — Staging de items sincronizados + cache de access_token.
--
-- Modelo B-pull: el worker del central trae items de ML y los deja acá. El
-- plugin después los baja vía GET /v1/jobs/:id/results y los aplica a su
-- wf_ml_items local. Una vez bajados se marcan delivered_at y un cron los
-- limpia pasados unos días.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- accounts: columnas para cachear el access_token de ML.
-- -----------------------------------------------------------------------------
-- El worker necesita un access_token válido para llamar a la API de ML. En vez
-- de refrescar en cada request (gasta el refresh_token y es lento), cacheamos
-- el access_token encriptado + su expiración. Si todavía es válido, se reusa.
ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS access_token_enc  TEXT,
    ADD COLUMN IF NOT EXISTS access_token_iv   TEXT,
    ADD COLUMN IF NOT EXISTS access_expires_at TIMESTAMPTZ;

-- -----------------------------------------------------------------------------
-- synced_items: items traídos de ML, esperando que el plugin los baje.
-- -----------------------------------------------------------------------------
-- item_data es un JSONB con el row COMPLETO listo para upsert en wf_ml_items
-- del plugin. El worker lo arma en Node; el plugin lo aplica tal cual sin
-- tener que re-mapear campo por campo. Flexible ante cambios de schema.
CREATE TABLE IF NOT EXISTS synced_items (
    id            BIGSERIAL PRIMARY KEY,
    account_id    BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    job_id        BIGINT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    -- Identidad del item ML (para dedup + orden estable al paginar resultados).
    ml_item_id    VARCHAR(32) NOT NULL,
    variation_id  BIGINT,                       -- NULL = padre / item simple
    -- Row completo para wf_ml_items, serializado.
    item_data     JSONB NOT NULL,
    -- Timeline.
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at  TIMESTAMPTZ                   -- NULL = pendiente de bajar
);

-- -----------------------------------------------------------------------------
-- Índices de synced_items
-- -----------------------------------------------------------------------------
-- Bajar resultados de un job, ordenados y paginables.
CREATE INDEX IF NOT EXISTS synced_items_job_idx
    ON synced_items (job_id, id);
-- Buscar lo no entregado de una cuenta (cuando el plugin pregunta "¿hay algo
-- nuevo para mí?" sin un job_id específico).
CREATE INDEX IF NOT EXISTS synced_items_pending_idx
    ON synced_items (account_id, delivered_at) WHERE delivered_at IS NULL;
-- Cleanup de entregados viejos.
CREATE INDEX IF NOT EXISTS synced_items_delivered_idx
    ON synced_items (delivered_at) WHERE delivered_at IS NOT NULL;

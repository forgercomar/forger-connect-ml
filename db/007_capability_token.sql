-- =============================================================================
-- 007_capability_token.sql — Enforcement del capability-token de licencia (Fase 6).
--
-- El license-api (api.goforger.com) emite tokens WFCAP1.<payload>.<sig> firmados
-- Ed25519 que el satélite manda en el header X-Wfml-License-Token. El central los
-- verifica (license-token.js) para decidir si una cuenta tiene licencia VIGENTE
-- antes de servir sync/push/handshake. Esta migración agrega el estado persistente
-- que el enforcement necesita:
--
--   1) license_denylist: revocaciones EXPLÍCITAS (revoke desde el portal vía
--      POST /internal/license-revoked). La denylist GANA siempre — incluso sobre
--      la gracia. El server la carga en un Set en memoria y la refresca cada 60s.
--
--   2) accounts.last_valid_license_token_at: timestamp del último token VÁLIDO que
--      la cuenta presentó. Es el ancla de la GRACIA: si el token falta/expiró pero
--      este sello está dentro de GRACE_PERIOD_SEC (default 72h), las operaciones de
--      jobs (sync/push) se permiten igual — no rompemos por una caída de infra del
--      license-api. El handshake NO usa gracia (es entrada nueva).
--
--   3) accounts.license_id / accounts.license_exp: copia del claim del último token
--      válido. license_exp lo usa el worker para saltear jobs de cuentas con
--      licencia vencida + fuera de gracia (sin perder eventos).
--
-- Idempotente: CREATE TABLE IF NOT EXISTS + ADD COLUMN IF NOT EXISTS, seguro de
-- re-correr (mismo patrón que las migraciones previas).
-- =============================================================================

CREATE TABLE IF NOT EXISTS license_denylist (
    license_id  TEXT PRIMARY KEY,
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason      TEXT
);

ALTER TABLE accounts ADD COLUMN IF NOT EXISTS last_valid_license_token_at TIMESTAMPTZ;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS license_id TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS license_exp TIMESTAMPTZ;

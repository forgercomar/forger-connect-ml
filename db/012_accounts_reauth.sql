-- =============================================================================
-- 012_accounts_reauth.sql — Cuenta que Mercado Libre dejó de autorizar.
--
-- Cuando ML rechaza la renovación del token con invalid_grant (el vendedor le
-- quitó el permiso a la aplicación, o el refresh_token ya no vale), el conector
-- no marcaba nada: las órdenes, preguntas y push de esa cuenta fallaban en
-- silencio en cada vuelta y el sistema no se enteraba (ensayo-ml, escenario 7c).
-- Ahora la renovación rechazada deja reauth_required_at; una renovación buena o
-- un saludo nuevo (reconectar) la limpian, y GET /v1/sync/pending se lo dice al
-- sistema para que muestre el aviso de reconectar.
-- =============================================================================

ALTER TABLE accounts ADD COLUMN IF NOT EXISTS reauth_required_at TIMESTAMPTZ;

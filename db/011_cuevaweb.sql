-- 011_cuevaweb.sql — EL MODO CUEVAWEB (conectar.cuevaweb.com.ar, CUEVAWEB_MODO=1). 12/11/2026.
--
-- Sólo AGREGA tablas nuevas (Forger no las usa ni las ve): las tiendas de CuevaWeb que registra su panel, sus
-- conexiones con Mercado Libre y Mercado Pago (los tokens, cifrados con WFML_TOKEN_KEY), los «state» del OAuth y los
-- avisos que se les reenvían. Ver cuevaweb.js. Idempotente (IF NOT EXISTS), como las demás.

-- Las tiendas: las da de alta el panel de CuevaWeb (admin.cuevaweb.com.ar) con su dirección y su clave (la
-- CUEVAWEB_CLAVE de cada tienda). La tienda se presenta con la huella de su clave (clave_id) y firma con la clave.
CREATE TABLE IF NOT EXISTS cuevaweb_tiendas (
    id          BIGSERIAL PRIMARY KEY,
    panel_id    TEXT NOT NULL UNIQUE,          -- el id de la tienda en el panel de CuevaWeb
    clave_id    TEXT NOT NULL UNIQUE,          -- la huella de su clave (con esto se presenta)
    clave       TEXT NOT NULL,                 -- su clave, cifrada (enc1: auth.js sealSecret)
    url         TEXT NOT NULL,                 -- https://su-dominio (adonde se reenvían los avisos y vuelve el dueño)
    nombre      TEXT NOT NULL DEFAULT '',
    creada      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actualizada TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    baja        TIMESTAMPTZ
);

-- Las conexiones: una activa y, mientras el dueño vuelve a su tienda, una pendiente por tienda y servicio. La pendiente
-- se activa sólo cuando la tienda la confirma con el nonce del navegador que empezó (y no hay otra tienda con esa cuenta).
CREATE TABLE IF NOT EXISTS cuevaweb_conexiones (
    id            BIGSERIAL PRIMARY KEY,
    tienda_id     BIGINT NOT NULL REFERENCES cuevaweb_tiendas(id) ON DELETE CASCADE,
    servicio      TEXT NOT NULL CHECK (servicio IN ('ml', 'mp')),
    estado        TEXT NOT NULL DEFAULT 'pendiente' CHECK (estado IN ('pendiente', 'activa')),
    usuario_id    TEXT NOT NULL,               -- el user_id de Mercado Libre o de Mercado Pago
    nombre        TEXT NOT NULL DEFAULT '',    -- el apodo (nickname) o el nombre de la cuenta
    sitio         TEXT NOT NULL DEFAULT '',    -- Mercado Libre: el site_id (MLA…)
    clave_publica TEXT NOT NULL DEFAULT '',    -- Mercado Pago: la public_key
    produccion    BOOLEAN NOT NULL DEFAULT TRUE, -- Mercado Pago: live_mode
    access_enc    TEXT,
    access_iv     TEXT,
    refresh_enc   TEXT,
    refresh_iv    TEXT,
    vence         TIMESTAMPTZ,                 -- cuándo vence el access_token
    nonce         TEXT NOT NULL DEFAULT '',    -- el del navegador que la empezó (hasta que la tienda la confirma)
    conectada     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confirmada    TIMESTAMPTZ,
    renovada      TIMESTAMPTZ,
    error         TEXT,
    error_en      TIMESTAMPTZ,
    UNIQUE (tienda_id, servicio, estado)
);
CREATE INDEX IF NOT EXISTS cuevaweb_conexiones_usuario ON cuevaweb_conexiones (servicio, usuario_id) WHERE estado = 'activa';

-- Los «state» del OAuth (uno por vez que el dueño toca «Conectar…»): de un solo uso y por 15 minutos.
CREATE TABLE IF NOT EXISTS cuevaweb_estados (
    estado     TEXT PRIMARY KEY,
    tienda_id  BIGINT NOT NULL REFERENCES cuevaweb_tiendas(id) ON DELETE CASCADE,
    servicio   TEXT NOT NULL,
    vuelta     TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    creado     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    usado      TIMESTAMPTZ
);

-- Los avisos para cada tienda (las notificaciones de Mercado Libre y de Mercado Pago, y los de acá: «hay un token
-- nuevo»). Se reenvían solos; los que no llegan, la tienda los trae (GET /cuevaweb/v1/avisos) y los confirma (ack).
CREATE TABLE IF NOT EXISTS cuevaweb_avisos (
    id         BIGSERIAL PRIMARY KEY,
    tienda_id  BIGINT NOT NULL REFERENCES cuevaweb_tiendas(id) ON DELETE CASCADE,
    origen     TEXT NOT NULL,                  -- ml | mp | cuevaweb
    tema       TEXT NOT NULL,                  -- el topic (orders_v2, questions…; payment; mp_token)
    recurso    TEXT NOT NULL DEFAULT '',
    cuerpo     JSONB NOT NULL,
    recibido   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    entregado  TIMESTAMPTZ,
    intentos   INT NOT NULL DEFAULT 0,
    proximo    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    error      TEXT
);
CREATE INDEX IF NOT EXISTS cuevaweb_avisos_pendientes ON cuevaweb_avisos (tienda_id, id) WHERE entregado IS NULL;
CREATE INDEX IF NOT EXISTS cuevaweb_avisos_proximos ON cuevaweb_avisos (proximo) WHERE entregado IS NULL;

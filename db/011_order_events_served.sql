-- =============================================================================
-- 011_order_events_served.sql — Qué avisos de órdenes ya vio el plugin.
--
-- POST /v1/orders/ack confirma por ml_order_id. Sin esta marca, el ack
-- también daba por entregados los avisos de esa orden que llegaron DESPUÉS de
-- que el plugin pidió /v1/orders/pending (incluso los todavía sin procesar):
-- una cancelación o un «entregado» que caía en ese rato no le llegaba nunca al
-- sistema (ensayo-ml, escenario 3d). Ahora pending marca served_at en los
-- avisos que devuelve y el ack sólo confirma esos.
-- =============================================================================

ALTER TABLE order_events ADD COLUMN IF NOT EXISTS served_at TIMESTAMPTZ;

-- 012_cuevaweb_avisos.sql — EL MODO CUEVAWEB: los avisos que la tienda viene a buscar (12/11/2026, la revisión).
--
-- Sólo AGREGA columnas a cuevaweb_avisos (011), idempotente. Cuando el reenvío no llega, la tienda trae sus avisos
-- (GET /cuevaweb/v1/avisos) y confirma los que pudo hacer (ack). Para que uno que la tienda no puede hacer nunca (un pago
-- de otra cuenta, Mercado Pago ya desconectado) no tape a los nuevos ni se repita para siempre:
--   traido / traidas   cuándo se lo llevó la tienda por última vez y cuántas veces (sin confirmarlo): vuelve recién
--                      después de una espera cada vez más larga, y los que nunca se llevó van primero;
--   descartado         pasadas 12 veces (o a los 7 días de haber llegado) se descarta: ya no se manda ni se trae, y el
--                      panel de CuevaWeb lo cuenta.
ALTER TABLE cuevaweb_avisos ADD COLUMN IF NOT EXISTS traido TIMESTAMPTZ;
ALTER TABLE cuevaweb_avisos ADD COLUMN IF NOT EXISTS traidas INT NOT NULL DEFAULT 0;
ALTER TABLE cuevaweb_avisos ADD COLUMN IF NOT EXISTS descartado TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS cuevaweb_avisos_por_traer ON cuevaweb_avisos (tienda_id, traidas, id) WHERE entregado IS NULL AND descartado IS NULL;

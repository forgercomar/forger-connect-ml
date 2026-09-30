/**
 * sql-preguntas.js — las consultas de la cola de preguntas que tienen que
 * poder probarse contra un Postgres de verdad (test/backfill-preguntas.test.mjs).
 *
 * Sembrar una pregunta ABIERTA en la cola, una sola vez mientras tenga un
 * evento sin entregar (POST /v1/questions/backfill).
 *
 * Los tipos van EXPLÍCITOS a propósito (v2.10.1). Sin ellos Postgres deducía
 * dos tipos distintos para $2: `character varying` por la columna de destino y
 * `text` por la comparación `ml_question_id = $2` del WHERE, y rechazaba la
 * consulta con «inconsistent types deduced for parameter $2» (42P08). Como el
 * plugin reintenta el backfill hasta que sale bien, cada drain volvía a pedir
 * hasta 10 páginas a Mercado Libre y volvía a fallar: ninguna pregunta abierta
 * se sembraba nunca.
 */
export const SQL_SEMBRAR_PREGUNTA_ABIERTA = `INSERT INTO question_events (account_id, ml_question_id, processed_at, payload_json)
 SELECT $1::bigint, $2::text, NOW(), $3::jsonb
 WHERE NOT EXISTS (
     SELECT 1 FROM question_events
     WHERE account_id = $1::bigint AND ml_question_id = $2::text AND delivered_at IS NULL
 )`;

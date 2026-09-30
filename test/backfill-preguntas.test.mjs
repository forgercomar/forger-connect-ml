/**
 * backfill-preguntas.test.mjs — v2.10.1: la consulta que siembra las preguntas
 * abiertas (POST /v1/questions/backfill) contra un Postgres DE VERDAD.
 *
 * El bug (30-09-2026, visto en el log de producción al implementar 2.10.0, pero
 * presente desde 2.9.0): Postgres deducía dos tipos para $2 y rechazaba la
 * consulta (42P08 «inconsistent types deduced for parameter $2»). Ningún mock
 * lo ve: hace falta el planner de Postgres. Por eso esta prueba necesita una
 * base descartable:
 *
 *   DATABASE_URL_TEST=postgres://usuario:clave@localhost:5433/cml_test \
 *     node --test test/backfill-preguntas.test.mjs
 *
 * Sin DATABASE_URL_TEST la prueba se SALTEA y lo dice (no da verde en silencio).
 * Trabaja en un schema propio (cml_prueba_backfill) que crea y borra.
 *
 * Cubre:
 *   T1 CONTROL: la forma vieja de la consulta (sin tipos) falla en Postgres con
 *      42P08 — si esto deja de fallar, la prueba ya no mide lo que dice.
 *   T2 la consulta del código siembra la pregunta (1 fila) y es idempotente
 *      mientras el evento esté sin entregar (la segunda vez 0 filas).
 *   T3 entregado el evento, la misma pregunta se puede volver a sembrar.
 *   T4 lo guardado: account_id, ml_question_id como texto y payload_json JSONB.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { SQL_SEMBRAR_PREGUNTA_ABIERTA } from '../sql-preguntas.js';

const URL = process.env.DATABASE_URL_TEST || '';
const SCHEMA = 'cml_prueba_backfill';

const SQL_VIEJA = `INSERT INTO question_events (account_id, ml_question_id, processed_at, payload_json)
 SELECT $1, $2, NOW(), $3
 WHERE NOT EXISTS (
     SELECT 1 FROM question_events
     WHERE account_id = $1 AND ml_question_id = $2 AND delivered_at IS NULL
 )`;

const DDL = `
CREATE SCHEMA ${SCHEMA};
SET search_path TO ${SCHEMA};
CREATE TABLE accounts (id BIGSERIAL PRIMARY KEY);
CREATE TABLE question_events (
    id             BIGSERIAL PRIMARY KEY,
    account_id     BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    ml_question_id VARCHAR(32) NOT NULL,
    received_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at   TIMESTAMPTZ,
    payload_json   JSONB,
    error          TEXT,
    delivered_at   TIMESTAMPTZ
);
INSERT INTO accounts (id) VALUES (7);`;

test('backfill de preguntas abiertas contra Postgres', { skip: URL ? false : 'falta DATABASE_URL_TEST (una base descartable): la prueba necesita el planner de Postgres' }, async (t) => {
    const cliente = new pg.Client({ connectionString: URL });
    await cliente.connect();
    await cliente.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
    await cliente.query(DDL);
    const q = { id: 123456789, text: '¿Tienen stock?', status: 'UNANSWERED', item_id: 'MLA1' };
    const params = [7, String(q.id), JSON.stringify(q)];
    try {
        await t.test('T1 control: la consulta sin tipos falla con 42P08 (el bug de producción)', async () => {
            await cliente.query(`SET search_path TO ${SCHEMA}`);
            await assert.rejects(cliente.query(SQL_VIEJA, params), (e) => e.code === '42P08' && /parameter \$2/.test(e.message));
        });
        await t.test('T2 la consulta del código siembra una vez y no repite mientras esté sin entregar', async () => {
            const r1 = await cliente.query(SQL_SEMBRAR_PREGUNTA_ABIERTA, params);
            const r2 = await cliente.query(SQL_SEMBRAR_PREGUNTA_ABIERTA, params);
            assert.equal(r1.rowCount, 1);
            assert.equal(r2.rowCount, 0);
            const n = await cliente.query('SELECT count(*)::int AS n FROM question_events');
            assert.equal(n.rows[0].n, 1);
        });
        await t.test('T3 entregado el evento, la misma pregunta se vuelve a sembrar', async () => {
            await cliente.query('UPDATE question_events SET delivered_at = NOW()');
            const r3 = await cliente.query(SQL_SEMBRAR_PREGUNTA_ABIERTA, params);
            assert.equal(r3.rowCount, 1);
            const n = await cliente.query('SELECT count(*)::int AS n FROM question_events');
            assert.equal(n.rows[0].n, 2);
        });
        await t.test('T4 lo guardado: la cuenta, el id como texto y el payload como JSONB', async () => {
            const f = await cliente.query(`SELECT account_id::text AS cuenta, ml_question_id AS pregunta, payload_json->>'text' AS texto,
                                                  pg_typeof(payload_json)::text AS tipo, processed_at IS NOT NULL AS procesada
                                           FROM question_events ORDER BY id DESC LIMIT 1`);
            assert.deepEqual(f.rows[0], { cuenta: '7', pregunta: '123456789', texto: '¿Tienen stock?', tipo: 'jsonb', procesada: true });
        });
    } finally {
        await cliente.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
        await cliente.end();
    }
});

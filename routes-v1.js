/**
 * routes-v1.js — API REST del Central Orchestrator (v1).
 *
 * Todos los endpoints viven bajo /v1/* y se autentican con HMAC shared-secret
 * por cuenta (ver auth.js). La única excepción es /v1/handshake que se
 * autentica con el HUB_SECRET global (mismo que el OAuth bridge), porque es
 * por definición el primer contacto antes de tener un secret de cuenta.
 *
 * Endpoints:
 *
 *   POST /v1/handshake          → registra cuenta (o rota su secret). Auth: HUB.
 *   POST /v1/jobs               → crea un job + sus steps. Auth: cuenta.
 *   GET  /v1/jobs/:job_id       → status + progress. Auth: cuenta.
 *   POST /v1/jobs/:job_id/next-batch → siguiente step (o "done"). Auth: cuenta.
 *   POST /v1/jobs/:job_id/report     → resultado de un step. Auth: cuenta.
 *   POST /v1/jobs/:job_id/cancel     → aborta el job. Auth: cuenta.
 *
 * Convenciones:
 *   - Toda fecha sale como ISO8601 UTC.
 *   - Errores: { ok: false, error: '<code>', message: '<human>' } + status code.
 *   - Éxitos:  { ok: true,  ...data }.
 */

import crypto from 'node:crypto';
import { query, tx } from './db.js';
import {
    verifyRequest,
    generateSecret,
    generatePublicId,
    encryptToken,
} from './auth.js';

// =============================================================================
// Constantes del job runtime
// =============================================================================

// Lease default cuando un plugin "toma" un step (next-batch). Si no reporta
// dentro de este tiempo, el step queda disponible para que otro plugin/worker
// lo tome. 90s es suficiente para batches de 50 items.
const STEP_LEASE_SEC = 90;

// Cantidad máxima de steps por job (anti-explosion: si el cliente pide 1M
// de items, rechazamos en vez de matar Postgres).
const MAX_STEPS_PER_JOB = 5000;

// Job types válidos. Cualquier otro string se rechaza al crear job.
const VALID_JOB_TYPES = new Set([
    'sync_incremental',
    'sync_full',
    'auto_link_sku',
    'push',
]);

// =============================================================================
// Helpers internos
// =============================================================================

function nowIso() { return new Date().toISOString(); }

/**
 * Acceso al body crudo (string). Lo necesitamos para verificar el HMAC, que
 * incluye el sha256 del body original. Express ya lo parseó a req.body, pero
 * el express.json() option `verify` nos permite stashearlo crudo en req.rawBody.
 *
 * (Esa configuración se hace en server.js — acá solo lo leemos.)
 */
function getRawBody(req) {
    return req.rawBody || '';
}

/**
 * Middleware que verifica el HMAC + carga la cuenta en req.account.
 * Usar en las rutas que requieren auth de cuenta.
 */
async function authAccount(req, res, next) {
    const publicId = req.get('X-Wfml-Account') || '';
    const ts       = req.get('X-Wfml-Ts')      || '';
    const sig      = req.get('X-Wfml-Sig')     || '';
    if (!publicId || !ts || !sig) {
        return res.status(401).json({ ok: false, error: 'unauthorized', message: 'Faltan headers de auth.' });
    }
    let acc;
    try {
        const r = await query(
            `SELECT id, public_id, ml_user_id, ml_nickname, ml_site_id, site_url, shared_secret, revoked_at
             FROM accounts WHERE public_id = $1`,
            [publicId]
        );
        acc = r.rows[0];
    } catch (err) {
        return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
    }
    if (!acc || acc.revoked_at) {
        return res.status(401).json({ ok: false, error: 'unknown_account' });
    }
    const verdict = verifyRequest({
        secret: acc.shared_secret,
        method: req.method,
        path: req.originalUrl.split('?')[0], // sin query string
        ts,
        body: getRawBody(req),
        sigGiven: sig,
    });
    if (!verdict.ok) {
        return res.status(401).json({ ok: false, error: 'bad_signature', message: verdict.reason });
    }
    req.account = acc;
    // Bump last_seen para detección de actividad. Fire-and-forget.
    query('SELECT bump_account_last_seen($1)', [acc.id]).catch((e) =>
        console.warn('[v1] bump_account_last_seen failed:', e.message)
    );
    next();
}

/**
 * Construye el array de steps a insertar según el tipo de job + input.
 *
 * Cada step describe un chunk concreto que el plugin sabe ejecutar.
 *
 * Devuelve `{ steps, totalCount }` donde steps es array de { seq, input }.
 */
function buildStepsForJob(type, params) {
    const chunkSize = Math.max(1, Math.min(500, Number(params.chunk_size) || 50));
    if (type === 'sync_full' || type === 'sync_incremental') {
        // Plugin nos dice cuántos items espera total. Creamos N steps con
        // offset/limit. El plugin va a usar esos params para llamar a ML.
        const total = Number(params.total) || 0;
        if (total <= 0) {
            return { steps: [{ seq: 0, input: { offset: 0, limit: chunkSize, since_ts: params.since_ts || null } }], totalCount: 1 };
        }
        const steps = [];
        let seq = 0;
        for (let offset = 0; offset < total; offset += chunkSize) {
            steps.push({
                seq,
                input: {
                    offset,
                    limit: Math.min(chunkSize, total - offset),
                    since_ts: params.since_ts || null,
                },
            });
            seq++;
        }
        return { steps, totalCount: steps.length };
    }
    if (type === 'auto_link_sku') {
        // Plugin nos manda la lista de candidatos (ml_item_id + sku) y los
        // partimos en chunks para procesar.
        const candidates = Array.isArray(params.candidates) ? params.candidates : [];
        const steps = [];
        for (let i = 0, seq = 0; i < candidates.length; i += chunkSize, seq++) {
            steps.push({
                seq,
                input: { candidates: candidates.slice(i, i + chunkSize) },
            });
        }
        return { steps, totalCount: steps.length };
    }
    if (type === 'push') {
        const items = Array.isArray(params.items) ? params.items : [];
        const steps = [];
        for (let i = 0, seq = 0; i < items.length; i += chunkSize, seq++) {
            steps.push({
                seq,
                input: { items: items.slice(i, i + chunkSize) },
            });
        }
        return { steps, totalCount: steps.length };
    }
    throw new Error(`Tipo de job desconocido: ${type}`);
}

// =============================================================================
// Mount
// =============================================================================

export function mountV1(app, opts = {}) {
    const HUB_SECRET = opts.hubSecret;
    if (!HUB_SECRET) {
        throw new Error('mountV1: hubSecret requerido');
    }
    // Registramos cada ruta con DOS paths: el "limpio" /v1/* y el prefijado
    // /connect-ml/v1/*. Esto es por el reverse proxy de EasyPanel: el dominio
    // wooforger.dev sirve a comingsoon en la raíz, y solo enruta /connect-ml/*
    // hacia este container. Con ambas formas registradas, no importa si el
    // proxy strippea o conserva el prefijo: la ruta siempre matchea.
    const p = (path) => [path, '/connect-ml' + path];

    // -------------------------------------------------------------------------
    // POST /v1/handshake
    // Body:
    //   {
    //     ml_user_id: number,
    //     ml_nickname: string,
    //     ml_site_id: string ("MLA"...),
    //     site_url: string,
    //     refresh_token: string (de ML; lo encriptamos al guardar),
    //     handshake_sig: base64 HMAC(HUB_SECRET, json sin handshake_sig)
    //   }
    // Respuesta:
    //   { ok: true, account_id: "acc_...", shared_secret: "base64" }
    //
    // Idempotente sobre ml_user_id: si la cuenta ya existe, rota el secret y
    // actualiza site_url + refresh_token.
    // -------------------------------------------------------------------------
    app.post(p('/v1/handshake'), async (req, res) => {
        const body = req.body || {};
        const sigGiven = String(body.handshake_sig || '');
        if (!sigGiven) {
            return res.status(400).json({ ok: false, error: 'missing_sig' });
        }
        const payloadObj = { ...body };
        delete payloadObj.handshake_sig;
        const payloadStr = JSON.stringify(payloadObj);
        const expectedSig = crypto.createHmac('sha256', HUB_SECRET)
            .update(payloadStr, 'utf8')
            .digest('base64');
        try {
            const a = Buffer.from(expectedSig);
            const b = Buffer.from(sigGiven);
            if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
                return res.status(403).json({ ok: false, error: 'bad_sig' });
            }
        } catch (_) {
            return res.status(403).json({ ok: false, error: 'bad_sig' });
        }

        const mlUserId = Number(body.ml_user_id);
        const siteUrl  = String(body.site_url || '').trim();
        const nick     = String(body.ml_nickname || '').trim();
        const siteId   = String(body.ml_site_id  || '').trim();
        const refreshT = String(body.refresh_token || '').trim();
        if (!mlUserId || !siteUrl) {
            return res.status(400).json({ ok: false, error: 'missing_fields', message: 'ml_user_id y site_url son obligatorios.' });
        }

        const newSecret = generateSecret();
        let enc = { ciphertext: '', iv: '' };
        if (refreshT) {
            try {
                enc = encryptToken(refreshT);
            } catch (err) {
                return res.status(500).json({ ok: false, error: 'crypto_failed', message: err.message });
            }
        }

        try {
            // Upsert sobre ml_user_id (la unique partial index excluye revocadas).
            const existing = await query(
                `SELECT id, public_id FROM accounts WHERE ml_user_id = $1 AND revoked_at IS NULL`,
                [mlUserId]
            );
            let accId, accPublic;
            if (existing.rowCount > 0) {
                accId = existing.rows[0].id;
                accPublic = existing.rows[0].public_id;
                await query(
                    `UPDATE accounts
                     SET ml_nickname = $2,
                         ml_site_id  = $3,
                         site_url    = $4,
                         shared_secret = $5,
                         refresh_token_enc = COALESCE(NULLIF($6, ''), refresh_token_enc),
                         refresh_token_iv  = COALESCE(NULLIF($7, ''), refresh_token_iv),
                         last_token_refresh_at = CASE WHEN $6 <> '' THEN NOW() ELSE last_token_refresh_at END
                     WHERE id = $1`,
                    [accId, nick, siteId, siteUrl, newSecret, enc.ciphertext, enc.iv]
                );
            } else {
                accPublic = generatePublicId('acc');
                const ins = await query(
                    `INSERT INTO accounts
                        (public_id, ml_user_id, ml_nickname, ml_site_id, site_url,
                         shared_secret, refresh_token_enc, refresh_token_iv, last_token_refresh_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                             CASE WHEN $7 <> '' THEN NOW() ELSE NULL END)
                     RETURNING id`,
                    [accPublic, mlUserId, nick, siteId, siteUrl, newSecret, enc.ciphertext, enc.iv]
                );
                accId = ins.rows[0].id;
            }

            return res.json({
                ok: true,
                account_id: accPublic,
                shared_secret: newSecret,
                rotated: existing.rowCount > 0,
            });
        } catch (err) {
            console.error('[handshake] db error:', err);
            return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
        }
    });

    // -------------------------------------------------------------------------
    // POST /v1/jobs
    // Body:
    //   {
    //     type: 'sync_full' | 'sync_incremental' | 'auto_link_sku' | 'push',
    //     params: {...}    // depende del tipo (ver buildStepsForJob)
    //   }
    // Respuesta:
    //   { ok: true, job_id: "job_...", steps_total: N, status: "pending" }
    // -------------------------------------------------------------------------
    app.post(p('/v1/jobs'), authAccount, async (req, res) => {
        const body = req.body || {};
        const type = String(body.type || '');
        if (!VALID_JOB_TYPES.has(type)) {
            return res.status(400).json({ ok: false, error: 'bad_type', message: `type debe ser uno de: ${[...VALID_JOB_TYPES].join(', ')}` });
        }
        const params = body.params && typeof body.params === 'object' ? body.params : {};
        const jobPublic = generatePublicId('job');

        // Los jobs sync_* NO pre-crean steps: el worker del central los procesa
        // descubriendo el total contra ML y paginando solo. Los jobs push /
        // auto_link_sku sí pre-crean steps (modelo A: el plugin los ejecuta).
        const isSyncJob = (type === 'sync_full' || type === 'sync_incremental');

        if (isSyncJob) {
            try {
                await query(
                    `INSERT INTO jobs (public_id, account_id, type, status, input, steps_total)
                     VALUES ($1, $2, $3, 'pending', $4, 0)`,
                    [jobPublic, req.account.id, type, JSON.stringify(params)]
                );
            } catch (err) {
                console.error('[v1/jobs] create sync error:', err);
                return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
            }
            return res.json({
                ok: true,
                job_id: jobPublic,
                type,
                status: 'pending',
                steps_total: 0, // el worker lo va a setear al descubrir el total
            });
        }

        // Jobs con steps pre-calculados (push / auto_link_sku).
        let plan;
        try {
            plan = buildStepsForJob(type, params);
        } catch (err) {
            return res.status(400).json({ ok: false, error: 'bad_params', message: err.message });
        }
        if (plan.totalCount > MAX_STEPS_PER_JOB) {
            return res.status(400).json({ ok: false, error: 'too_many_steps', message: `El job genera ${plan.totalCount} steps; máximo permitido: ${MAX_STEPS_PER_JOB}. Usá un chunk_size más grande.` });
        }
        if (plan.totalCount === 0) {
            return res.status(400).json({ ok: false, error: 'empty_job', message: 'El job no tiene work — nada que procesar.' });
        }

        try {
            await tx(async (client) => {
                const ins = await client.query(
                    `INSERT INTO jobs (public_id, account_id, type, status, input, steps_total)
                     VALUES ($1, $2, $3, 'pending', $4, $5)
                     RETURNING id`,
                    [jobPublic, req.account.id, type, JSON.stringify(params), plan.totalCount]
                );
                const jobId = ins.rows[0].id;
                const values = [];
                const placeholders = [];
                let p = 1;
                for (const s of plan.steps) {
                    const stepPublic = generatePublicId('stp');
                    placeholders.push(`($${p++}, $${p++}, $${p++}, 'queued', $${p++})`);
                    values.push(stepPublic, jobId, s.seq, JSON.stringify(s.input));
                }
                await client.query(
                    `INSERT INTO job_steps (public_id, job_id, seq, status, input)
                     VALUES ${placeholders.join(',')}`,
                    values
                );
            });
        } catch (err) {
            console.error('[v1/jobs] create error:', err);
            return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
        }

        return res.json({
            ok: true,
            job_id: jobPublic,
            type,
            status: 'pending',
            steps_total: plan.totalCount,
        });
    });

    // -------------------------------------------------------------------------
    // GET /v1/jobs/:job_id
    // Respuesta:
    //   { ok: true, job: { id, type, status, steps_total, steps_done, steps_failed,
    //                      created_at, started_at, finished_at, message, result } }
    // -------------------------------------------------------------------------
    app.get(p('/v1/jobs/:job_id'), authAccount, async (req, res) => {
        const r = await query(
            `SELECT public_id, type, status, steps_total, steps_done, steps_failed,
                    input, result, created_at, started_at, finished_at, message
             FROM jobs
             WHERE public_id = $1 AND account_id = $2`,
            [req.params.job_id, req.account.id]
        );
        if (!r.rowCount) return res.status(404).json({ ok: false, error: 'not_found' });
        const j = r.rows[0];
        return res.json({
            ok: true,
            job: {
                id: j.public_id,
                type: j.type,
                status: j.status,
                steps_total: j.steps_total,
                steps_done: j.steps_done,
                steps_failed: j.steps_failed,
                input: j.input,
                result: j.result,
                created_at: j.created_at,
                started_at: j.started_at,
                finished_at: j.finished_at,
                message: j.message,
            },
        });
    });

    // -------------------------------------------------------------------------
    // POST /v1/jobs/:job_id/next-batch
    // Devuelve el próximo step disponible (queued) y lo marca como leased.
    // Si no hay más → ok: true, done: true.
    //
    // El plugin debe procesar el step y luego llamar /report. Si tarda más del
    // lease (STEP_LEASE_SEC), otro pull puede tomarlo de nuevo (idempotencia).
    // -------------------------------------------------------------------------
    app.post(p('/v1/jobs/:job_id/next-batch'), authAccount, async (req, res) => {
        // 1) Validar que el job pertenece a esta cuenta y no está finalizado.
        const j = await query(
            `SELECT id, status FROM jobs WHERE public_id = $1 AND account_id = $2`,
            [req.params.job_id, req.account.id]
        );
        if (!j.rowCount) return res.status(404).json({ ok: false, error: 'not_found' });
        const jobRow = j.rows[0];
        if (['done', 'failed', 'cancelled'].includes(jobRow.status)) {
            return res.json({ ok: true, done: true, status: jobRow.status });
        }

        // 2) Tomar el primer step disponible (queued) o leased-expirado.
        //    UPDATE ... RETURNING para atomicidad sin race condition.
        const leaseUntil = new Date(Date.now() + STEP_LEASE_SEC * 1000);
        const upd = await query(
            `UPDATE job_steps SET
                status = 'leased',
                leased_until = $2,
                attempts = attempts + 1,
                started_at = COALESCE(started_at, NOW())
             WHERE id = (
                SELECT id FROM job_steps
                WHERE job_id = $1
                  AND (status = 'queued' OR (status = 'leased' AND leased_until < NOW()))
                ORDER BY seq ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
             )
             RETURNING public_id, seq, input`,
            [jobRow.id, leaseUntil]
        );

        if (!upd.rowCount) {
            // No quedan steps. Marcar el job como done si todo finalizó.
            await query(
                `UPDATE jobs SET status = 'done', finished_at = NOW(),
                                 message = COALESCE(message, 'Job completado.')
                 WHERE id = $1 AND status NOT IN ('done','failed','cancelled')
                   AND NOT EXISTS (
                       SELECT 1 FROM job_steps WHERE job_id = $1 AND status IN ('queued','leased')
                   )`,
                [jobRow.id]
            );
            return res.json({ ok: true, done: true });
        }

        // 3) Marcar job como running si era pending (primer step tomado).
        if (jobRow.status === 'pending') {
            await query(
                `UPDATE jobs SET status = 'running', started_at = COALESCE(started_at, NOW())
                 WHERE id = $1 AND status = 'pending'`,
                [jobRow.id]
            );
        }

        const step = upd.rows[0];
        return res.json({
            ok: true,
            done: false,
            step: {
                id: step.public_id,
                seq: step.seq,
                input: step.input,
                lease_expires_at: leaseUntil.toISOString(),
            },
        });
    });

    // -------------------------------------------------------------------------
    // POST /v1/jobs/:job_id/report
    // Body:
    //   {
    //     step_id: "stp_...",
    //     result: 'done' | 'failed' | 'skipped',
    //     output: {...},
    //     error?: string
    //   }
    // Respuesta:
    //   { ok: true, job: { steps_done, steps_failed, status, message } }
    // -------------------------------------------------------------------------
    app.post(p('/v1/jobs/:job_id/report'), authAccount, async (req, res) => {
        const body = req.body || {};
        const stepId = String(body.step_id || '');
        const result = String(body.result  || '');
        const output = body.output || {};
        const errorMsg = body.error ? String(body.error).slice(0, 1024) : null;

        if (!stepId || !['done','failed','skipped'].includes(result)) {
            return res.status(400).json({ ok: false, error: 'bad_params' });
        }

        let updated;
        try {
            updated = await tx(async (client) => {
                // Cargar job + step + chequear ownership.
                const j = await client.query(
                    `SELECT id, status FROM jobs WHERE public_id = $1 AND account_id = $2 FOR UPDATE`,
                    [req.params.job_id, req.account.id]
                );
                if (!j.rowCount) throw new Error('job_not_found');
                const job = j.rows[0];

                const s = await client.query(
                    `SELECT id, status FROM job_steps
                     WHERE public_id = $1 AND job_id = $2 FOR UPDATE`,
                    [stepId, job.id]
                );
                if (!s.rowCount) throw new Error('step_not_found');
                const step = s.rows[0];
                if (['done','failed','skipped'].includes(step.status)) {
                    // Idempotente: si ya está finalizado, no re-procesamos.
                    // Devolvemos el job actualizado sin cambios.
                } else {
                    await client.query(
                        `UPDATE job_steps SET
                            status = $2,
                            output = $3,
                            last_error = $4,
                            finished_at = NOW()
                         WHERE id = $1`,
                        [step.id, result, JSON.stringify(output), errorMsg]
                    );
                    // Actualizar counters del job.
                    if (result === 'done' || result === 'skipped') {
                        await client.query(`UPDATE jobs SET steps_done = steps_done + 1 WHERE id = $1`, [job.id]);
                    } else if (result === 'failed') {
                        await client.query(`UPDATE jobs SET steps_failed = steps_failed + 1, message = $2 WHERE id = $1`, [job.id, errorMsg]);
                    }
                }

                // ¿Quedan steps pendientes?
                const pending = await client.query(
                    `SELECT COUNT(*) AS n FROM job_steps WHERE job_id = $1 AND status IN ('queued','leased')`,
                    [job.id]
                );
                const remaining = Number(pending.rows[0].n);
                if (remaining === 0) {
                    // Job terminado. Decidir done vs failed.
                    const counts = await client.query(
                        `SELECT steps_total, steps_done, steps_failed FROM jobs WHERE id = $1`,
                        [job.id]
                    );
                    const c = counts.rows[0];
                    const allOk = c.steps_failed === 0;
                    await client.query(
                        `UPDATE jobs SET status = $2, finished_at = NOW(),
                                         message = COALESCE(message, $3)
                         WHERE id = $1`,
                        [job.id, allOk ? 'done' : 'failed', allOk ? 'Job completado.' : 'Job completado con errores.']
                    );
                }
                const fin = await client.query(
                    `SELECT status, steps_total, steps_done, steps_failed, message FROM jobs WHERE id = $1`,
                    [job.id]
                );
                return fin.rows[0];
            });
        } catch (err) {
            const code = (err.message === 'job_not_found' || err.message === 'step_not_found') ? 404 : 500;
            return res.status(code).json({ ok: false, error: err.message });
        }

        return res.json({
            ok: true,
            job: {
                status: updated.status,
                steps_total: updated.steps_total,
                steps_done: updated.steps_done,
                steps_failed: updated.steps_failed,
                message: updated.message,
            },
        });
    });

    // -------------------------------------------------------------------------
    // GET /v1/jobs/:job_id/results?offset=&limit=
    // Devuelve los items que el worker sincronizó para este job, paginados.
    // El plugin los baja en lotes y los aplica a su wf_ml_items local.
    //
    // Idempotente: no marca nada al leer. El plugin puede re-bajar sin riesgo
    // (su upsert local es idempotente). Para liberar espacio, cuando el plugin
    // termina de bajar todo llama a POST /v1/jobs/:id/ack.
    //
    // Respuesta:
    //   { ok: true, items: [ <item_data>, ... ], total: N, offset, limit }
    // -------------------------------------------------------------------------
    app.get(p('/v1/jobs/:job_id/results'), authAccount, async (req, res) => {
        const j = await query(
            `SELECT id FROM jobs WHERE public_id = $1 AND account_id = $2`,
            [req.params.job_id, req.account.id]
        );
        if (!j.rowCount) return res.status(404).json({ ok: false, error: 'not_found' });
        const jobId = j.rows[0].id;

        const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
        const limit  = Math.max(1, Math.min(1000, parseInt(req.query.limit, 10) || 500));

        const totalR = await query(
            `SELECT COUNT(*) AS n FROM synced_items WHERE job_id = $1`,
            [jobId]
        );
        const total = Number(totalR.rows[0].n);

        const rowsR = await query(
            `SELECT item_data FROM synced_items
             WHERE job_id = $1
             ORDER BY id ASC
             LIMIT $2 OFFSET $3`,
            [jobId, limit, offset]
        );
        return res.json({
            ok: true,
            items: rowsR.rows.map((r) => r.item_data),
            total,
            offset,
            limit,
        });
    });

    // -------------------------------------------------------------------------
    // POST /v1/jobs/:job_id/ack
    // El plugin confirma que bajó y aplicó todos los resultados. Marcamos los
    // synced_items como delivered para que el cron de retención los limpie.
    // -------------------------------------------------------------------------
    app.post(p('/v1/jobs/:job_id/ack'), authAccount, async (req, res) => {
        const j = await query(
            `SELECT id FROM jobs WHERE public_id = $1 AND account_id = $2`,
            [req.params.job_id, req.account.id]
        );
        if (!j.rowCount) return res.status(404).json({ ok: false, error: 'not_found' });
        const r = await query(
            `UPDATE synced_items SET delivered_at = NOW()
             WHERE job_id = $1 AND delivered_at IS NULL`,
            [j.rows[0].id]
        );
        return res.json({ ok: true, marked: r.rowCount });
    });

    // -------------------------------------------------------------------------
    // POST /v1/jobs/:job_id/cancel
    // Marca el job y todos sus steps queued/leased como cancelled.
    // -------------------------------------------------------------------------
    app.post(p('/v1/jobs/:job_id/cancel'), authAccount, async (req, res) => {
        try {
            const r = await query(
                `UPDATE jobs SET status = 'cancelled', finished_at = NOW(),
                                 message = COALESCE(message, 'Cancelado por el usuario.')
                 WHERE public_id = $1 AND account_id = $2
                   AND status IN ('pending','running')
                 RETURNING id`,
                [req.params.job_id, req.account.id]
            );
            if (!r.rowCount) return res.status(404).json({ ok: false, error: 'not_cancelable' });
            await query(
                `UPDATE job_steps SET status = 'skipped', last_error = 'cancelled', finished_at = NOW()
                 WHERE job_id = $1 AND status IN ('queued','leased')`,
                [r.rows[0].id]
            );
            return res.json({ ok: true, cancelled: true });
        } catch (err) {
            return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
        }
    });
}

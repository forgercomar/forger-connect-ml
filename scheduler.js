/**
 * scheduler.js — Cron de sincronización automática del Central Orchestrator.
 *
 * El servicio de fondo 24/7: cada cierto tiempo revisa TODAS las cuentas
 * activas y, para las que hace rato no se sincronizan, encola un job de
 * sync. El worker (worker.js) después lo procesa como cualquier otro job.
 *
 * Modelo:
 *
 *   [scheduler] cada CHECK_INTERVAL ms:
 *       busca cuentas activas SIN sync reciente y SIN job en curso
 *       → INSERT job sync_full (input.source = 'cron')
 *   [worker]    toma el job → pagina ML → llena synced_items
 *   [plugin]    en su próximo page-load pregunta GET /v1/sync/pending
 *               → baja los resultados que el cron dejó listos
 *
 * El scheduler NO sincroniza él mismo: solo CREA jobs. Así reusa todo el
 * worker y el lock SKIP LOCKED ya garantiza que no se doble-procesen.
 *
 * Auto-regulación: una cuenta se re-encola recién cuando su último job de
 * sync (de cualquier origen — manual o cron, exitoso o fallido) es más
 * viejo que INTERVAL_HOURS. Así un sync manual reciente "cuenta" y el cron
 * no duplica trabajo; y un job fallido no se reintenta en loop cerrado.
 *
 * El scheduler corre DOS loops independientes:
 *   - autosync:  cada cuenta sin sync reciente → job sync_full periódico.
 *   - webhook debouncer: agrupa los webhook_events pendientes por cuenta y
 *     encola un job sync_incremental targeted con la lista de items.
 *
 * Variables de entorno:
 *   WFML_AUTOSYNC_ENABLED         '0' apaga el cron de autosync (default: on)
 *   WFML_AUTOSYNC_INTERVAL_HOURS  cada cuántas horas resincronizar una cuenta
 *                                 (default 6)
 *   WFML_AUTOSYNC_CHECK_INTERVAL  ms entre chequeos del autosync (default
 *                                 600000 = 10 min)
 *   WFML_WEBHOOK_ENABLED          '0' apaga el debouncer de webhooks (default: on)
 *   WFML_WEBHOOK_BATCH_INTERVAL   ms entre agrupaciones de webhooks (default
 *                                 60000 = 1 min). Más bajo = más "tiempo real"
 *                                 pero más jobs; el debounce existe para no
 *                                 disparar un job por cada webhook suelto.
 *
 * @module scheduler
 */

import { query } from './db.js';
import { generatePublicId } from './auth.js';

const AUTOSYNC_ENABLED = process.env.WFML_AUTOSYNC_ENABLED !== '0';
const INTERVAL_HOURS   = Math.max(1, Number(process.env.WFML_AUTOSYNC_INTERVAL_HOURS) || 6);
const CHECK_INTERVAL   = Math.max(60000, Number(process.env.WFML_AUTOSYNC_CHECK_INTERVAL) || 600000);

const WEBHOOK_ENABLED        = process.env.WFML_WEBHOOK_ENABLED !== '0';
const WEBHOOK_BATCH_INTERVAL = Math.max(15000, Number(process.env.WFML_WEBHOOK_BATCH_INTERVAL) || 60000);

// Delay del primer chequeo — le da tiempo a la DB y al worker a estar listos
// después de un deploy antes de empezar a encolar.
const FIRST_RUN_DELAY = 30000;

// Evita que dos chequeos del mismo loop se solapen si la DB está lenta.
let _busy = false;
let _webhookBusy = false;

/**
 * Busca las cuentas activas que necesitan un sync automático y encola un
 * job sync_full para cada una. Devuelve cuántos jobs creó.
 */
async function scheduleDueAccounts() {
    // Cuentas activas que:
    //   (a) no tienen un job de sync pending/running (no pisar trabajo en curso), y
    //   (b) no tuvieron NINGÚN job de sync en las últimas INTERVAL_HOURS
    //       (ni manual ni de cron) — o nunca tuvieron uno.
    const due = await query(
        `SELECT a.id, a.public_id
         FROM accounts a
         WHERE a.revoked_at IS NULL
           AND NOT EXISTS (
               SELECT 1 FROM jobs j
               WHERE j.account_id = a.id
                 AND j.type IN ('sync_full', 'sync_incremental')
                 AND j.status IN ('pending', 'running')
           )
           AND NOT EXISTS (
               SELECT 1 FROM jobs j
               WHERE j.account_id = a.id
                 AND j.type IN ('sync_full', 'sync_incremental')
                 AND j.created_at > NOW() - ($1 || ' hours')::interval
           )`,
        [String(INTERVAL_HOURS)]
    );

    if (!due.rowCount) return 0;

    let created = 0;
    for (const acc of due.rows) {
        try {
            const jobPublic = generatePublicId('job');
            await query(
                `INSERT INTO jobs (public_id, account_id, type, status, input, steps_total)
                 VALUES ($1, $2, 'sync_full', 'pending', $3, 0)`,
                [jobPublic, acc.id, JSON.stringify({ source: 'cron' })]
            );
            created++;
            console.log(`[scheduler] encolado sync automático ${jobPublic} para cuenta ${acc.public_id}`);
        } catch (err) {
            console.error(`[scheduler] no se pudo encolar para cuenta ${acc.public_id}:`, err.message);
        }
    }
    return created;
}

async function tick() {
    if (_busy) return;
    _busy = true;
    try {
        const n = await scheduleDueAccounts();
        if (n > 0) console.log(`[scheduler] ${n} job(s) de sync automático encolado(s)`);
    } catch (err) {
        console.error('[scheduler] tick error:', err.message);
    } finally {
        _busy = false;
    }
}

// ----------------------------------------------------------------------------
// Webhook debouncer
// ----------------------------------------------------------------------------

/**
 * Agrupa los webhook_events pendientes por cuenta y encola un job
 * sync_incremental targeted (input.ml_item_ids) por cada cuenta con cambios.
 *
 * Orden seguro: leemos los pendientes, creamos el job y RECIÉN ahí marcamos
 * esos eventos como procesados. Si la creación del job falla, los eventos
 * quedan sin marcar y se reintentan en el próximo tick — sin pérdida. Un
 * webhook que llega entre el SELECT y el UPDATE no estaba en el batch, así
 * que tampoco se pierde: lo toma la próxima vuelta.
 *
 * @returns {Promise<number>} cantidad de jobs encolados.
 */
async function processWebhookBatch() {
    const pend = await query(
        `SELECT id, account_id, ml_item_id
         FROM webhook_events
         WHERE processed_at IS NULL
         ORDER BY account_id, id
         LIMIT 5000`
    );
    if (!pend.rowCount) return 0;

    // Agrupar por cuenta: items únicos + ids de evento a marcar.
    const byAccount = new Map();
    for (const row of pend.rows) {
        let g = byAccount.get(row.account_id);
        if (!g) { g = { itemIds: new Set(), eventIds: [] }; byAccount.set(row.account_id, g); }
        g.itemIds.add(row.ml_item_id);
        g.eventIds.push(row.id);
    }

    let jobs = 0;
    for (const [accountId, g] of byAccount) {
        const itemIds = [...g.itemIds];
        try {
            const jobPublic = generatePublicId('job');
            await query(
                `INSERT INTO jobs (public_id, account_id, type, status, input, steps_total)
                 VALUES ($1, $2, 'sync_incremental', 'pending', $3, 0)`,
                [jobPublic, accountId, JSON.stringify({ source: 'webhook', ml_item_ids: itemIds })]
            );
            // Job creado OK → marcar SOLO esos eventos como procesados.
            await query(
                `UPDATE webhook_events SET processed_at = NOW() WHERE id = ANY($1::bigint[])`,
                [g.eventIds]
            );
            jobs++;
            console.log(`[scheduler] webhook batch → job ${jobPublic} (cuenta ${accountId}, ${itemIds.length} item(s))`);
        } catch (err) {
            console.error(`[scheduler] no se pudo encolar webhook batch cuenta ${accountId}:`, err.message);
            // No marcamos processed → se reintenta en el próximo tick.
        }
    }
    return jobs;
}

async function webhookTick() {
    if (_webhookBusy) return;
    _webhookBusy = true;
    try {
        await processWebhookBatch();
    } catch (err) {
        console.error('[scheduler] webhook tick error:', err.message);
    } finally {
        _webhookBusy = false;
    }
}

// ----------------------------------------------------------------------------
// Arranque
// ----------------------------------------------------------------------------

/**
 * Arranca los loops del scheduler. Llamado una vez desde server.js.
 */
export function startScheduler() {
    // Loop 1 — autosync periódico.
    if (AUTOSYNC_ENABLED) {
        console.log(`[scheduler] autosync — resync cada ${INTERVAL_HOURS}h, chequeo cada ${Math.round(CHECK_INTERVAL / 1000)}s`);
        setTimeout(() => {
            tick().catch((e) => console.error('[scheduler] first autosync tick uncaught:', e));
            setInterval(() => { tick().catch((e) => console.error('[scheduler] autosync tick uncaught:', e)); }, CHECK_INTERVAL);
        }, FIRST_RUN_DELAY);
    } else {
        console.log('[scheduler] autosync deshabilitado (WFML_AUTOSYNC_ENABLED=0)');
    }

    // Loop 2 — webhook debouncer.
    if (WEBHOOK_ENABLED) {
        console.log(`[scheduler] webhook debouncer — agrupando cada ${Math.round(WEBHOOK_BATCH_INTERVAL / 1000)}s`);
        setTimeout(() => {
            webhookTick().catch((e) => console.error('[scheduler] first webhook tick uncaught:', e));
            setInterval(() => { webhookTick().catch((e) => console.error('[scheduler] webhook tick uncaught:', e)); }, WEBHOOK_BATCH_INTERVAL);
        }, FIRST_RUN_DELAY);
    } else {
        console.log('[scheduler] webhook debouncer deshabilitado (WFML_WEBHOOK_ENABLED=0)');
    }
}

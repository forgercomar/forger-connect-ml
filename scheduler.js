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
 * Variables de entorno:
 *   WFML_AUTOSYNC_ENABLED         '0' apaga el cron (default: encendido)
 *   WFML_AUTOSYNC_INTERVAL_HOURS  cada cuántas horas resincronizar una cuenta
 *                                 (default 6)
 *   WFML_AUTOSYNC_CHECK_INTERVAL  ms entre chequeos del scheduler (default
 *                                 600000 = 10 min). El chequeo es barato:
 *                                 una query + N inserts.
 *
 * @module scheduler
 */

import { query } from './db.js';
import { generatePublicId } from './auth.js';

const AUTOSYNC_ENABLED = process.env.WFML_AUTOSYNC_ENABLED !== '0';
const INTERVAL_HOURS   = Math.max(1, Number(process.env.WFML_AUTOSYNC_INTERVAL_HOURS) || 6);
const CHECK_INTERVAL   = Math.max(60000, Number(process.env.WFML_AUTOSYNC_CHECK_INTERVAL) || 600000);

// Delay del primer chequeo — le da tiempo a la DB y al worker a estar listos
// después de un deploy antes de empezar a encolar.
const FIRST_RUN_DELAY = 30000;

// Evita que dos chequeos se solapen si la DB está lenta.
let _busy = false;

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

/**
 * Arranca el loop del scheduler. Llamado una vez desde server.js.
 */
export function startScheduler() {
    if (!AUTOSYNC_ENABLED) {
        console.log('[scheduler] deshabilitado (WFML_AUTOSYNC_ENABLED=0)');
        return;
    }
    console.log(`[scheduler] arrancando — resync cada ${INTERVAL_HOURS}h, chequeo cada ${Math.round(CHECK_INTERVAL / 1000)}s`);
    setTimeout(() => {
        tick().catch((e) => console.error('[scheduler] first tick uncaught:', e));
        setInterval(() => { tick().catch((e) => console.error('[scheduler] tick uncaught:', e)); }, CHECK_INTERVAL);
    }, FIRST_RUN_DELAY);
}

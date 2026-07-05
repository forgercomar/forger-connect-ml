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
 *   - autosync:  cada cuenta sin sync reciente → job sync_incremental; cada
 *     FULL_HOURS uno de esos syncs es un sync_full de cobertura total (la red
 *     de seguridad que recupera lo que webhooks + incremental dejaron pasar).
 *   - webhook debouncer: agrupa los webhook_events pendientes por cuenta y
 *     encola un job sync_incremental targeted con la lista de items.
 *
 * Variables de entorno:
 *   WFML_AUTOSYNC_ENABLED         '0' apaga el cron de autosync (default: on)
 *   WFML_AUTOSYNC_INTERVAL_HOURS  cada cuántas horas resincronizar una cuenta
 *                                 (default 6)
 *   WFML_AUTOSYNC_FULL_HOURS      cada cuántas horas el sync periódico es un
 *                                 sync_full de cobertura total (default 24);
 *                                 entre fulls el cron encola sync_incremental
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
import { getValidAccessToken, mlGetOrder, mlSearchOrders, mlGetMessage, mlGetQuestion } from './ml-api.js';
import { enrichOrder, upsertOrderSnapshot } from './orders-snapshot.js';

const AUTOSYNC_ENABLED = process.env.WFML_AUTOSYNC_ENABLED !== '0';
const INTERVAL_HOURS   = Math.max(1, Number(process.env.WFML_AUTOSYNC_INTERVAL_HOURS) || 6);
const CHECK_INTERVAL   = Math.max(60000, Number(process.env.WFML_AUTOSYNC_CHECK_INTERVAL) || 600000);
// Cada cuántas horas el sync periódico es un sync_full de cobertura total.
// Entre fulls el cron encola sync_incremental (mucho más liviano).
const FULL_HOURS       = Math.max(INTERVAL_HOURS, Number(process.env.WFML_AUTOSYNC_FULL_HOURS) || 24);

const WEBHOOK_ENABLED        = process.env.WFML_WEBHOOK_ENABLED !== '0';
const WEBHOOK_BATCH_INTERVAL = Math.max(15000, Number(process.env.WFML_WEBHOOK_BATCH_INTERVAL) || 60000);

const ORDER_ENABLED  = process.env.WFML_ORDER_ENABLED !== '0';
const ORDER_INTERVAL = Math.max(15000, Number(process.env.WFML_ORDER_INTERVAL) || 60000);
// Mensajería + Preguntas (M0, v2.9.0): mismo modelo que las órdenes.
const MSG_ENABLED    = process.env.WFML_MSG_ENABLED !== '0';
const MSG_INTERVAL   = Math.max(15000, Number(process.env.WFML_MSG_INTERVAL) || 60000);

// Backfill histórico de órdenes (Ventas ML, F0): procesa jobs 'orders_backfill'
// en su propio loop — NO en el worker, para que un backfill de miles de órdenes
// no bloquee syncs ni pushes (el worker es serial).
const BACKFILL_ENABLED        = process.env.WFML_BACKFILL_ENABLED !== '0';
const BACKFILL_CHECK_INTERVAL = Math.max(15000, Number(process.env.WFML_BACKFILL_CHECK_INTERVAL) || 60000);
const BACKFILL_PAGE           = 50;   // cap de ML en orders/search
const BACKFILL_OFFSET_CAP     = 1000; // pasado esto se re-ventanea por fecha (cap de offset de ML)
const BACKFILL_PAUSE_MS       = Math.max(0, Number(process.env.WFML_BACKFILL_PAUSE_MS ?? 150) || 0);
// El shipment se enriquece solo para órdenes recientes (el estado de envío es
// operativo); para las viejas alcanza con los tags de la orden (delivered/...).
const BACKFILL_SHIPMENT_DAYS  = Math.max(0, Number(process.env.WFML_BACKFILL_SHIPMENT_DAYS) || 45);

// Retención: purga las filas de cola YA ENTREGADAS/PROCESADAS con más de
// RETENTION_DAYS días (order_events entregadas, synced_items entregados,
// webhook_events procesados). Nunca toca filas sin entregar ni los
// order_snapshots (esos son el historial de Ventas ML, se conservan).
const RETENTION_ENABLED        = process.env.WFML_RETENTION_ENABLED !== '0';
const RETENTION_DAYS           = Math.max(7, Number(process.env.WFML_RETENTION_DAYS) || 30);
const RETENTION_CHECK_INTERVAL = Math.max(3600000, Number(process.env.WFML_RETENTION_CHECK_INTERVAL) || 6 * 3600000);

// Janitor de jobs zombie: si el worker crashea a mitad de un job, queda en
// status='running' para siempre porque claimJob() filtra status='pending'. Este
// loop marca como 'failed' los jobs con last_seen_at viejo para que el plugin
// que estaba polleando vea el error y reintente si corresponde.
//
// Threshold conservador (15 min): worker.js updatea last_seen_at en CADA step
// (sync) o CADA PUT (push), o sea ~1-2s entre updates. 15 min sin update es
// señal inequívoca de crash. NO se rescata a 'pending' para evitar doble
// procesamiento (un PUT que ML ya recibió no debe re-PUT-earse).
const ZOMBIE_ENABLED         = process.env.WFML_ZOMBIE_RECLAIM_ENABLED !== '0';
const ZOMBIE_TIMEOUT_MIN     = Math.max(5, Number(process.env.WFML_ZOMBIE_TIMEOUT_MIN) || 15);
const ZOMBIE_CHECK_INTERVAL  = Math.max(60000, Number(process.env.WFML_ZOMBIE_CHECK_INTERVAL) || 5 * 60_000);

// Delay del primer chequeo — le da tiempo a la DB y al worker a estar listos
// después de un deploy antes de empezar a encolar.
const FIRST_RUN_DELAY = 30000;

// Evita que dos chequeos del mismo loop se solapen si la DB está lenta.
let _busy = false;
let _webhookBusy = false;
let _orderBusy = false;
let _msgBusy = false;
let _questionBusy = false;
let _zombieBusy = false;
let _backfillBusy = false;
let _retentionBusy = false;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Busca las cuentas activas que necesitan un sync automático y encola un job
 * para cada una. Por defecto encola sync_incremental; si la cuenta no tuvo un
 * sync_full exitoso en las últimas FULL_HOURS, encola sync_full (red de
 * seguridad). Devuelve cuántos jobs creó.
 */
async function scheduleDueAccounts() {
    // Cuentas activas que:
    //   (a) no tienen un job de sync pending/running (no pisar trabajo en curso), y
    //   (b) no tuvieron NINGÚN job de sync en las últimas INTERVAL_HOURS
    //       (ni manual ni de cron) — o nunca tuvieron uno.
    // `needs_full` = no hubo un sync_full exitoso en las últimas FULL_HOURS
    //   (incluye la cuenta que nunca se sincronizó) → toca un full.
    const due = await query(
        `SELECT a.id, a.public_id,
                NOT EXISTS (
                    SELECT 1 FROM jobs j
                    WHERE j.account_id = a.id
                      AND j.type = 'sync_full'
                      AND j.status = 'done'
                      AND j.created_at > NOW() - ($2 || ' hours')::interval
                ) AS needs_full
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
        [String(INTERVAL_HOURS), String(FULL_HOURS)]
    );

    if (!due.rowCount) return 0;

    let created = 0;
    for (const acc of due.rows) {
        const type = acc.needs_full ? 'sync_full' : 'sync_incremental';
        try {
            const jobPublic = generatePublicId('job');
            await query(
                `INSERT INTO jobs (public_id, account_id, type, status, input, steps_total)
                 VALUES ($1, $2, $3, 'pending', $4, 0)`,
                [jobPublic, acc.id, type, JSON.stringify({ source: 'cron' })]
            );
            created++;
            console.log(`[scheduler] encolado ${type} automático ${jobPublic} para cuenta ${acc.public_id}`);
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
// Procesador de órdenes (ledger de stock)
// ----------------------------------------------------------------------------

/**
 * Extrae los items vendidos de una orden ML en el shape que consume el plugin.
 */
function extractOrderItems(order) {
    const items = Array.isArray(order.order_items) ? order.order_items : [];
    return items.map((oi) => {
        const it = (oi && oi.item) || {};
        return {
            sku:          String(it.seller_sku || it.seller_custom_field || ''),
            quantity:     Number(oi.quantity) || 0,
            ml_item_id:   String(it.id || ''),
            variation_id: it.variation_id != null ? Number(it.variation_id) : null,
        };
    });
}

/**
 * Toma las order_events sin procesar, baja cada orden de ML y guarda en la
 * fila su estado + items vendidos. El plugin después las baja y las aplica a
 * su ledger de stock.
 *
 * Dedup: varios webhooks de la misma orden (la orden cambia de estado varias
 * veces) se procesan bajando la orden UNA vez — todas las filas de ese
 * ml_order_id se completan juntas. La idempotencia real (no descontar dos
 * veces) la garantiza el plugin con el ml_order_id como clave en su log.
 *
 * Si bajar la orden falla, la fila queda sin procesar y se reintenta en el
 * próximo tick — no se pierde la venta.
 */
async function processOrderEvents() {
    const pend = await query(
        `SELECT id, account_id, ml_order_id
         FROM order_events
         WHERE processed_at IS NULL
         ORDER BY account_id, id
         LIMIT 500`
    );
    if (!pend.rowCount) return 0;

    // Agrupar por cuenta; dentro de cada cuenta, dedup por ml_order_id.
    const byAccount = new Map();
    for (const row of pend.rows) {
        let orders = byAccount.get(row.account_id);
        if (!orders) { orders = new Map(); byAccount.set(row.account_id, orders); }
        let evIds = orders.get(row.ml_order_id);
        if (!evIds) { evIds = []; orders.set(row.ml_order_id, evIds); }
        evIds.push(row.id);
    }

    let processed = 0;
    for (const [accountId, orders] of byAccount) {
        let account, token;
        try {
            const accR = await query(`SELECT * FROM accounts WHERE id = $1`, [accountId]);
            if (!accR.rowCount || accR.rows[0].revoked_at) continue;
            account = accR.rows[0];
            token = await getValidAccessToken(account);
        } catch (err) {
            console.error(`[scheduler] orders: cuenta ${accountId} sin token — se reintenta:`, err.message);
            continue;
        }
        for (const [mlOrderId, evIds] of orders) {
            try {
                const order = await mlGetOrder(account, token, mlOrderId);
                const status = String(order.status || '');
                const items = extractOrderItems(order);
                // Ventas ML (F0): snapshot completo ANTES de marcar procesada,
                // así /v1/orders/pending ya lo encuentra al entregar. Tolerante:
                // si el snapshot falla, el stock no queda rehén — la orden se
                // entrega igual (sin order/billing) y un evento futuro lo completa.
                try {
                    const enrich = await enrichOrder(account, token, order);
                    await upsertOrderSnapshot(accountId, order, enrich);
                } catch (err) {
                    console.warn(`[scheduler] snapshot de orden ${mlOrderId} falló (la orden sigue):`, err.message);
                }
                await query(
                    `UPDATE order_events
                     SET processed_at = NOW(), order_status = $2, items_json = $3, error = NULL
                     WHERE id = ANY($1::bigint[])`,
                    [evIds, status, JSON.stringify(items)]
                );
                processed++;
                console.log(`[scheduler] orden ${mlOrderId} procesada — status=${status}, ${items.length} item(s)`);
            } catch (err) {
                // No marcamos processed_at → se reintenta el próximo tick.
                console.error(`[scheduler] orden ${mlOrderId} falló (se reintenta):`, err.message);
            }
        }
    }
    return processed;
}

async function orderTick() {
    if (_orderBusy) return;
    _orderBusy = true;
    try {
        const n = await processOrderEvents();
        if (n > 0) console.log(`[scheduler] ${n} orden(es) procesada(s)`);
    } catch (err) {
        console.error('[scheduler] order tick error:', err.message);
    } finally {
        _orderBusy = false;
    }
}

// ----------------------------------------------------------------------------
// Mensajería post-venta + Preguntas pre-venta (M0, v2.9.0)
//
// Mismo modelo que las órdenes: el webhook encola solo el id; estos ticks
// bajan el CONTENIDO de ML con el token custodiado y dejan el payload CRUDO
// en la cola para que el plugin lo baje con ack. El central NO conserva
// conversaciones (decisión del dueño 2026-07-05): es cola de tránsito y la
// retención purga lo entregado — el historial vivo queda en el WP del cliente.
// ----------------------------------------------------------------------------

async function processMessageEvents() {
    const pend = await query(
        `SELECT id, account_id, ml_message_id
         FROM message_events
         WHERE processed_at IS NULL
         ORDER BY account_id, id
         LIMIT 200`
    );
    if (!pend.rowCount) return 0;
    // Agrupar por cuenta; dedup por mensaje (ML puede webhookear repetido).
    const byAccount = new Map();
    for (const row of pend.rows) {
        let msgs = byAccount.get(row.account_id);
        if (!msgs) { msgs = new Map(); byAccount.set(row.account_id, msgs); }
        let evIds = msgs.get(row.ml_message_id);
        if (!evIds) { evIds = []; msgs.set(row.ml_message_id, evIds); }
        evIds.push(row.id);
    }
    let processed = 0;
    for (const [accountId, msgs] of byAccount) {
        let account, token;
        try {
            const accR = await query(`SELECT * FROM accounts WHERE id = $1`, [accountId]);
            if (!accR.rowCount || accR.rows[0].revoked_at) continue;
            account = accR.rows[0];
            token = await getValidAccessToken(account);
        } catch (err) {
            console.error(`[scheduler] mensajes: cuenta ${accountId} sin token — se reintenta:`, err.message);
            continue;
        }
        for (const [mlMessageId, evIds] of msgs) {
            try {
                const msg = await mlGetMessage(account, token, mlMessageId);
                await query(
                    `UPDATE message_events
                     SET processed_at = NOW(), payload_json = $2, error = NULL
                     WHERE id = ANY($1::bigint[])`,
                    [evIds, JSON.stringify(msg)]
                );
                processed++;
            } catch (err) {
                // No se marca processed_at → se reintenta el próximo tick.
                console.error(`[scheduler] mensaje ${mlMessageId} falló (se reintenta):`, err.message);
            }
        }
    }
    return processed;
}

async function messageTick() {
    if (_msgBusy) return;
    _msgBusy = true;
    try {
        const n = await processMessageEvents();
        if (n > 0) console.log(`[scheduler] ${n} mensaje(s) procesado(s)`);
    } catch (err) {
        console.error('[scheduler] message tick error:', err.message);
    } finally {
        _msgBusy = false;
    }
}

async function processQuestionEvents() {
    const pend = await query(
        `SELECT id, account_id, ml_question_id
         FROM question_events
         WHERE processed_at IS NULL
         ORDER BY account_id, id
         LIMIT 200`
    );
    if (!pend.rowCount) return 0;
    const byAccount = new Map();
    for (const row of pend.rows) {
        let qs = byAccount.get(row.account_id);
        if (!qs) { qs = new Map(); byAccount.set(row.account_id, qs); }
        let evIds = qs.get(row.ml_question_id);
        if (!evIds) { evIds = []; qs.set(row.ml_question_id, evIds); }
        evIds.push(row.id);
    }
    let processed = 0;
    for (const [accountId, qs] of byAccount) {
        let account, token;
        try {
            const accR = await query(`SELECT * FROM accounts WHERE id = $1`, [accountId]);
            if (!accR.rowCount || accR.rows[0].revoked_at) continue;
            account = accR.rows[0];
            token = await getValidAccessToken(account);
        } catch (err) {
            console.error(`[scheduler] preguntas: cuenta ${accountId} sin token — se reintenta:`, err.message);
            continue;
        }
        for (const [mlQuestionId, evIds] of qs) {
            try {
                const q = await mlGetQuestion(account, token, mlQuestionId);
                await query(
                    `UPDATE question_events
                     SET processed_at = NOW(), payload_json = $2, error = NULL
                     WHERE id = ANY($1::bigint[])`,
                    [evIds, JSON.stringify(q)]
                );
                processed++;
            } catch (err) {
                console.error(`[scheduler] pregunta ${mlQuestionId} falló (se reintenta):`, err.message);
            }
        }
    }
    return processed;
}

async function questionTick() {
    if (_questionBusy) return;
    _questionBusy = true;
    try {
        const n = await processQuestionEvents();
        if (n > 0) console.log(`[scheduler] ${n} pregunta(s) procesada(s)`);
    } catch (err) {
        console.error('[scheduler] question tick error:', err.message);
    } finally {
        _questionBusy = false;
    }
}

// ----------------------------------------------------------------------------
// Backfill histórico de órdenes (Ventas ML, F0)
// ----------------------------------------------------------------------------

/**
 * Toma un job 'orders_backfill' pending. Mismo lock SKIP LOCKED que el worker,
 * pero acá — el worker no conoce este tipo (su claimJob no lo lista) y así un
 * backfill largo nunca bloquea syncs ni pushes. last_seen_at se sella al claim
 * para que el janitor zombie cubra un crash inmediato.
 */
async function claimBackfillJob() {
    const r = await query(
        `UPDATE jobs SET status = 'running',
                         started_at = COALESCE(started_at, NOW()),
                         last_seen_at = NOW()
         WHERE id = (
            SELECT id FROM jobs
            WHERE status = 'pending' AND type = 'orders_backfill'
            ORDER BY created_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
         )
         RETURNING id, public_id, account_id, input, started_at`
    );
    return r.rowCount ? r.rows[0] : null;
}

/** ¿El job sigue vivo? (cancelable desde /v1/jobs/:id/cancel) */
async function backfillJobActive(jobId) {
    const r = await query(`SELECT status FROM jobs WHERE id = $1`, [jobId]);
    return r.rowCount > 0 && r.rows[0].status === 'running';
}

/**
 * Importa el historial de órdenes ML de una cuenta a order_snapshots.
 *
 * Pagina /orders/search de la más nueva a la más vieja (sort=date_desc) desde
 * hace `input.months` meses. ML capa el offset, así que al acercarse al cap se
 * "re-ventanea": el `to` de la ventana pasa a ser el date_created más viejo
 * visto y el offset vuelve a 0. El solape del borde es inofensivo (upsert).
 *
 * Cada orden se enriquece con billing_info (siempre — datos fiscales para
 * facturar) y shipment (solo órdenes de los últimos BACKFILL_SHIPMENT_DAYS
 * días — el estado de envío es operativo, para las viejas alcanzan los tags).
 * Un fallo de enriquecimiento no frena la orden; un fallo de la orden no
 * frena el job (se loguea y sigue).
 */
async function processBackfillJob(job) {
    const accR = await query(`SELECT * FROM accounts WHERE id = $1`, [job.account_id]);
    if (!accR.rowCount) throw new Error('cuenta no encontrada');
    const account = accR.rows[0];
    if (account.revoked_at) throw new Error('cuenta revocada');
    const token = await getValidAccessToken(account);

    const input  = (job.input && typeof job.input === 'object') ? job.input : {};
    const months = Math.min(24, Math.max(1, Number(input.months) || 12));
    const fromD  = new Date();
    fromD.setMonth(fromD.getMonth() - months);
    const fromIso      = fromD.toISOString().replace('Z', '-00:00'); // formato de fecha que ML documenta
    const shipCutoffMs = Date.now() - BACKFILL_SHIPMENT_DAYS * 86400000;

    let windowTo = null;   // 'to' de la ventana actual (null = hasta hoy)
    let prevWindowTo = null;
    let offset = 0;
    let orders = 0, pages = 0, billingMiss = 0, shipments = 0;

    for (;;) {
        if (!(await backfillJobActive(job.id))) {
            console.log(`[scheduler] backfill ${job.public_id} cancelado a mitad — corto.`);
            return;
        }
        const page = await mlSearchOrders(account, token, {
            from: fromIso, to: windowTo, offset, limit: BACKFILL_PAGE, sort: 'date_desc',
        });
        if (pages === 0) {
            await query(
                `UPDATE jobs SET steps_total = $2, message = $3 WHERE id = $1`,
                [job.id, Math.max(1, Math.ceil(page.total / BACKFILL_PAGE)),
                 `Importando ${page.total} venta(s) de Mercado Libre (últimos ${months} meses)...`]
            );
        }
        if (!page.results.length) break;

        let oldest = null; // date_created más viejo de la página (para re-ventanear)
        for (const order of page.results) {
            if (!order || order.id == null) continue;
            const dcMs = order.date_created ? new Date(order.date_created).getTime() : 0;
            if (dcMs && (!oldest || dcMs < oldest.ms)) oldest = { ms: dcMs, iso: String(order.date_created) };
            try {
                const enrich = await enrichOrder(account, token, order, {
                    shipment: dcMs >= shipCutoffMs,
                });
                if (!enrich.billing) billingMiss++;
                if (enrich.shipment) shipments++;
                await upsertOrderSnapshot(job.account_id, order, enrich);
                orders++;
            } catch (err) {
                console.error(`[scheduler] backfill orden ${order.id} falló (sigue):`, err.message);
            }
            if (BACKFILL_PAUSE_MS) await sleep(BACKFILL_PAUSE_MS);
        }
        pages++;
        await query(
            `UPDATE jobs SET steps_done = $2, message = $3, last_seen_at = NOW() WHERE id = $1`,
            [job.id, pages, `Importadas ${orders} venta(s)...`]
        );

        if (page.results.length < BACKFILL_PAGE) break; // última página — no hay más viejas

        offset += BACKFILL_PAGE;
        if (offset + BACKFILL_PAGE > BACKFILL_OFFSET_CAP) {
            // Cap de offset de ML → re-ventanear desde la fecha más vieja vista.
            if (!oldest) break;
            if (oldest.iso === prevWindowTo) break; // sin progreso → cortar
            prevWindowTo = windowTo = oldest.iso;
            offset = 0;
        }
    }

    await query(
        `UPDATE jobs SET status = 'done', finished_at = NOW(), result = $2, message = $3
         WHERE id = $1 AND status = 'running'`,
        [job.id,
         JSON.stringify({ mode: 'orders_backfill', months, orders, pages, billing_missing: billingMiss, shipments }),
         `Historial importado: ${orders} venta(s) de los últimos ${months} meses.`]
    );
    console.log(`[scheduler] backfill ${job.public_id} done — ${orders} órdenes, ${pages} página(s), ${billingMiss} sin billing`);
}

async function backfillTick() {
    if (_backfillBusy) return;
    _backfillBusy = true;
    try {
        const job = await claimBackfillJob();
        if (!job) return;
        console.log(`[scheduler] tomando backfill ${job.public_id}`);
        try {
            await processBackfillJob(job);
        } catch (err) {
            console.error(`[scheduler] backfill ${job.public_id} falló:`, err.message);
            await query(
                `UPDATE jobs SET status = 'failed', finished_at = NOW(), message = $2
                 WHERE id = $1 AND status = 'running'`,
                [job.id, 'Error: ' + err.message]
            );
        }
    } catch (err) {
        console.error('[scheduler] backfill tick error:', err.message);
    } finally {
        _backfillBusy = false;
    }
}

// ----------------------------------------------------------------------------
// Retención de colas entregadas
// ----------------------------------------------------------------------------

/**
 * Purga por lotes las filas de cola que ya cumplieron su ciclo hace más de
 * RETENTION_DAYS días. Solo filas ENTREGADAS (order_events/synced_items) o
 * PROCESADAS (webhook_events) — lo pendiente no se toca jamás, y los
 * order_snapshots tampoco (son el historial de Ventas ML). Antes de esto no
 * había NINGUNA retención y las tres tablas crecían sin límite.
 */
async function purgeDeliveredRows() {
    const targets = [
        ['order_events',
         `DELETE FROM order_events WHERE id IN (
             SELECT id FROM order_events
             WHERE delivered_at IS NOT NULL AND delivered_at < NOW() - ($1 || ' days')::interval
             LIMIT 5000)`],
        ['synced_items',
         `DELETE FROM synced_items WHERE id IN (
             SELECT id FROM synced_items
             WHERE delivered_at IS NOT NULL AND delivered_at < NOW() - ($1 || ' days')::interval
             LIMIT 5000)`],
        ['webhook_events',
         `DELETE FROM webhook_events WHERE id IN (
             SELECT id FROM webhook_events
             WHERE processed_at IS NOT NULL AND processed_at < NOW() - ($1 || ' days')::interval
             LIMIT 5000)`],
        // Mensajería/Preguntas (M0): el central es cola de tránsito — lo
        // entregado se purga; las conversaciones viven en el WP del cliente.
        ['message_events',
         `DELETE FROM message_events WHERE id IN (
             SELECT id FROM message_events
             WHERE delivered_at IS NOT NULL AND delivered_at < NOW() - ($1 || ' days')::interval
             LIMIT 5000)`],
        ['question_events',
         `DELETE FROM question_events WHERE id IN (
             SELECT id FROM question_events
             WHERE delivered_at IS NOT NULL AND delivered_at < NOW() - ($1 || ' days')::interval
             LIMIT 5000)`],
    ];
    for (const [name, sql] of targets) {
        const r = await query(sql, [String(RETENTION_DAYS)]);
        if (r.rowCount) {
            console.log(`[scheduler] retención — ${r.rowCount} fila(s) purgadas de ${name} (>${RETENTION_DAYS}d entregadas)`);
        }
    }
}

async function retentionTick() {
    if (_retentionBusy) return;
    _retentionBusy = true;
    try {
        await purgeDeliveredRows();
    } catch (err) {
        console.error('[scheduler] retention tick error:', err.message);
    } finally {
        _retentionBusy = false;
    }
}

// ----------------------------------------------------------------------------
// Janitor de jobs zombie
// ----------------------------------------------------------------------------

/**
 * Marca como 'failed' los jobs en status='running' cuyo last_seen_at quedó
 * desfasado por más de ZOMBIE_TIMEOUT_MIN minutos. Esto pasa cuando el worker
 * crashea/reinicia a mitad de un job: claimJob() solo toma 'pending', así que
 * el job queda colgado y el plugin pollea infinitamente.
 *
 * Conservador a propósito:
 *   - No revive a 'pending' (evita doble PUT a ML).
 *   - Requiere last_seen_at IS NOT NULL para no matar jobs que recién empezaron
 *     y todavía no escribieron el campo (los `claimJob` setea started_at pero
 *     NOT last_seen_at hasta el primer step).
 *   - Threshold ≥ 5min (clamp) — operación normal updatea last_seen_at cada PUT.
 *
 * @returns {Promise<number>} cantidad de jobs marcados.
 */
async function reclaimZombieJobs() {
    const r = await query(
        `UPDATE jobs
         SET status = 'failed',
             finished_at = NOW(),
             message = COALESCE(NULLIF(message, ''), 'Worker timeout') || ' [reclaimed: sin actividad >${ZOMBIE_TIMEOUT_MIN}min]'
         WHERE status = 'running'
           AND last_seen_at IS NOT NULL
           AND last_seen_at < NOW() - ($1 || ' minutes')::interval
         RETURNING public_id, type`,
        [String(ZOMBIE_TIMEOUT_MIN)]
    );
    if (r.rowCount) {
        const ids = r.rows.map((j) => `${j.public_id}(${j.type})`).join(', ');
        console.warn(`[scheduler] zombie reclaim — ${r.rowCount} job(s) marcados failed: ${ids}`);
    }
    return r.rowCount;
}

async function zombieTick() {
    if (_zombieBusy) return;
    _zombieBusy = true;
    try {
        await reclaimZombieJobs();
    } catch (err) {
        console.error('[scheduler] zombie tick error:', err.message);
    } finally {
        _zombieBusy = false;
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

    // Loop 3 — procesador de órdenes (ledger de stock).
    if (ORDER_ENABLED) {
        console.log(`[scheduler] procesador de órdenes — cada ${Math.round(ORDER_INTERVAL / 1000)}s`);
        setTimeout(() => {
            orderTick().catch((e) => console.error('[scheduler] first order tick uncaught:', e));
            setInterval(() => { orderTick().catch((e) => console.error('[scheduler] order tick uncaught:', e)); }, ORDER_INTERVAL);
        }, FIRST_RUN_DELAY);
    } else {
        console.log('[scheduler] procesador de órdenes deshabilitado (WFML_ORDER_ENABLED=0)');
    }

    // Loop 4 — backfill histórico de órdenes (Ventas ML).
    if (BACKFILL_ENABLED) {
        console.log(`[scheduler] backfill de órdenes — chequeo cada ${Math.round(BACKFILL_CHECK_INTERVAL / 1000)}s`);
        setTimeout(() => {
            backfillTick().catch((e) => console.error('[scheduler] first backfill tick uncaught:', e));
            setInterval(() => { backfillTick().catch((e) => console.error('[scheduler] backfill tick uncaught:', e)); }, BACKFILL_CHECK_INTERVAL);
        }, FIRST_RUN_DELAY);
    } else {
        console.log('[scheduler] backfill de órdenes deshabilitado (WFML_BACKFILL_ENABLED=0)');
    }

    // Loop 5 — retención de colas entregadas.
    if (RETENTION_ENABLED) {
        console.log(`[scheduler] retención — purga entregadas >${RETENTION_DAYS}d, chequeo cada ${Math.round(RETENTION_CHECK_INTERVAL / 3600000)}h`);
        setTimeout(() => {
            retentionTick().catch((e) => console.error('[scheduler] first retention tick uncaught:', e));
            setInterval(() => { retentionTick().catch((e) => console.error('[scheduler] retention tick uncaught:', e)); }, RETENTION_CHECK_INTERVAL);
        }, FIRST_RUN_DELAY);
    } else {
        console.log('[scheduler] retención deshabilitada (WFML_RETENTION_ENABLED=0)');
    }

    // Loop 7 — mensajería + preguntas (M0, v2.9.0).
    if (MSG_ENABLED) {
        console.log(`[scheduler] mensajería/preguntas — cada ${Math.round(MSG_INTERVAL / 1000)}s`);
        setTimeout(() => {
            messageTick().catch((e) => console.error('[scheduler] first message tick uncaught:', e));
            questionTick().catch((e) => console.error('[scheduler] first question tick uncaught:', e));
            setInterval(() => { messageTick().catch((e) => console.error('[scheduler] message tick uncaught:', e)); }, MSG_INTERVAL);
            setInterval(() => { questionTick().catch((e) => console.error('[scheduler] question tick uncaught:', e)); }, MSG_INTERVAL);
        }, FIRST_RUN_DELAY);
    } else {
        console.log('[scheduler] mensajería/preguntas deshabilitado (WFML_MSG_ENABLED=0)');
    }

    // Loop 6 — janitor de jobs zombie.
    if (ZOMBIE_ENABLED) {
        console.log(`[scheduler] zombie reclaim — chequeo cada ${Math.round(ZOMBIE_CHECK_INTERVAL / 1000)}s, timeout ${ZOMBIE_TIMEOUT_MIN}min`);
        setTimeout(() => {
            zombieTick().catch((e) => console.error('[scheduler] first zombie tick uncaught:', e));
            setInterval(() => { zombieTick().catch((e) => console.error('[scheduler] zombie tick uncaught:', e)); }, ZOMBIE_CHECK_INTERVAL);
        }, FIRST_RUN_DELAY);
    } else {
        console.log('[scheduler] zombie reclaim deshabilitado (WFML_ZOMBIE_RECLAIM_ENABLED=0)');
    }
}

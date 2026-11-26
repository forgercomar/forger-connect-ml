/**
 * order-sweep.js — Barrido periódico de órdenes: la red de los avisos perdidos (v2.11.0).
 *
 * El camino normal de una venta es el aviso orders_v2 de ML → order_events → el
 * loop de órdenes la baja → el sistema la drena. Si el aviso no llega (el
 * conector caído más de una hora: ML reintenta durante una hora y después lo
 * descarta, developers.mercadolibre.com.ar/es_ar/productos-recibe-notificaciones),
 * esa venta no entraba nunca. Este loop cierra el hueco:
 *
 *   cada WFML_ORDER_SWEEP_INTERVAL, por cada cuenta activa y sin reauth_required_at,
 *   le pide a ML las órdenes ACTUALIZADAS desde su cursor (con un solapamiento),
 *   y encola en order_events —por el mismo camino que el aviso— la que no tiene
 *   ningún rastro en la cola o en los snapshots, o la que ML tiene en una versión
 *   más nueva que la que ya se procesó. El resto (loop de órdenes, snapshot,
 *   /v1/orders/pending, el ack) no cambia.
 *
 * La búsqueda: GET /orders/search?seller=&order.date_last_updated.from=&...to=
 * (gestiona-ventas, «Filtrar órdenes»). ML usa la fecha hasta la HORA y descarta
 * minutos y segundos, así que se pide desde el comienzo de la hora y hasta una
 * hora después del final de la ventana: trae de más, nunca de menos. Lo que ya
 * está en la cola se saltea (idempotente: una orden que ya entró no se duplica,
 * y el sistema aplica cada orden una sola vez por su ml_order_id).
 *
 * El cursor (db/013, order_sweeps.cursor_at) avanza ventana por ventana: una
 * falla a mitad de una recuperación larga no la vuelve a empezar de cero. Las
 * órdenes actualizadas en los últimos WFML_ORDER_SWEEP_GRACE_SEC no se tocan
 * todavía (su aviso puede estar en camino): quedan para la pasada siguiente.
 *
 * Nunca se barre antes del alta de la cuenta en el conector (accounts.created_at):
 * una venta anterior no puede haberse perdido acá, y encolarla la haría entrar al
 * sistema como venta en vivo (con reserva de stock).
 *
 * Límites: un 429 de ML corta la pasada de ESA cuenta y la saltea un tiempo
 * creciente (espera exponencial, tope 30 min); entre página y página hay una
 * pausa (WFML_ORDER_SWEEP_PAUSE_MS). El token, el de siempre (getValidAccessToken
 * + el reintento ante 401 de mlGet).
 *
 * Variables (todas opcionales):
 *   WFML_ORDER_SWEEP_ENABLED      '0' lo apaga (default: prendido)
 *   WFML_ORDER_SWEEP_INTERVAL     ms entre pasadas (default 300000 = 5 min; mínimo 15000)
 *   WFML_ORDER_SWEEP_OVERLAP_MIN  minutos de solapamiento con la pasada anterior (default 10)
 *   WFML_ORDER_SWEEP_GRACE_SEC    segundos que se le dan al aviso antes de barrer una orden (default 120)
 *   WFML_ORDER_SWEEP_MAX_HOURS    tope hacia atrás, la primera vez o después de una caída larga (default 72)
 *   WFML_ORDER_SWEEP_WINDOW_MIN   tamaño de cada ventana de una recuperación larga (default 360)
 *   WFML_ORDER_SWEEP_PAUSE_MS     pausa entre páginas de ML (default 250)
 *
 * @module order-sweep
 */

import { query } from './db.js';
import { getValidAccessToken, mlSearchOrders } from './ml-api.js';

const entero = (v, def, min, max) => {
    if (v === undefined || v === null || String(v).trim() === '') return def;
    const n = Math.floor(Number(v));
    if (!Number.isFinite(n)) return def;
    return Math.min(max, Math.max(min, n));
};

export const SWEEP = {
    enabled:    process.env.WFML_ORDER_SWEEP_ENABLED !== '0',
    intervalMs: entero(process.env.WFML_ORDER_SWEEP_INTERVAL, 300000, 15000, 24 * 3600000),
    overlapMin: entero(process.env.WFML_ORDER_SWEEP_OVERLAP_MIN, 10, 1, 24 * 60),
    graceSec:   entero(process.env.WFML_ORDER_SWEEP_GRACE_SEC, 120, 0, 3600),
    maxHours:   entero(process.env.WFML_ORDER_SWEEP_MAX_HOURS, 72, 1, 24 * 30),
    windowMin:  entero(process.env.WFML_ORDER_SWEEP_WINDOW_MIN, 360, 60, 24 * 60),
    pauseMs:    entero(process.env.WFML_ORDER_SWEEP_PAUSE_MS, 250, 0, 10000),
};

const PAGE = 50;          // tope de ML en orders/search
const OFFSET_CAP = 1000;  // más que esto en una ventana de una hora: se registra y se sigue
const HORA = 3600000;
const FIRST_RUN_DELAY = 30000;
const BACKOFF_MAX = 30 * 60000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Comienzo de la hora (ML filtra por fecha hasta la hora). */
export function floorHour(ms) {
    return Math.floor(ms / HORA) * HORA;
}

/** Fecha en el formato que documenta ML: 2015-07-01T00:00:00.000-00:00. */
export function mlIso(ms) {
    return new Date(ms).toISOString().replace('Z', '-00:00');
}

/** Ventanas consecutivas [from, to) de hasta windowMin minutos que cubren [startMs, endMs). */
export function planWindows(startMs, endMs, windowMin = SWEEP.windowMin) {
    const out = [];
    const step = Math.max(60, windowMin) * 60000;
    for (let a = startMs; a < endMs; a += step) out.push({ from: a, to: Math.min(endMs, a + step) });
    return out;
}

/** Los parámetros de ML para una ventana: desde el comienzo de su hora y hasta una hora después de su final. */
export function mlRange(win) {
    return { updatedFrom: mlIso(floorHour(win.from)), updatedTo: mlIso(floorHour(win.to) + HORA) };
}

const ms = (v) => {
    const t = Date.parse(String(v || ''));
    return Number.isFinite(t) ? t : null;
};

/** Última actualización de una orden de ML (last_updated o date_last_updated, la mayor). */
export function orderUpdatedMs(o) {
    const a = ms(o && o.last_updated), b = ms(o && o.date_last_updated);
    if (a === null) return b;
    if (b === null) return a;
    return Math.max(a, b);
}

/**
 * Qué hacer con una orden que devolvió ML.
 *   ev: { pending: bool, lastProcessedMs: number|null } de order_events (o undefined)
 *   sn: { last_updated, date_last_updated, status } del snapshot (o undefined)
 * Devuelve 'reciente' | 'en_cola' | 'nueva' | 'cambio' | 'al_dia'.
 */
export function classifyOrder(o, ev, sn, horizonMs) {
    const lu = orderUpdatedMs(o);
    if (lu !== null && lu > horizonMs) return 'reciente';
    if (ev && ev.pending) return 'en_cola';
    if (!ev && !sn) return 'nueva';
    if (sn) {
        if (o.status && sn.status && String(o.status) !== String(sn.status)) return 'cambio';
        let comunes = 0, mas_nueva = false;
        for (const f of ['last_updated', 'date_last_updated']) {
            const a = ms(o[f]), b = ms(sn[f]);
            if (a === null || b === null) continue;
            comunes++;
            if (a > b) mas_nueva = true;
        }
        if (comunes) return mas_nueva ? 'cambio' : 'al_dia';
    }
    if (lu === null) return 'al_dia';
    if (ev && ev.lastProcessedMs !== null && ev.lastProcessedMs >= lu) return 'al_dia';
    return 'cambio';
}

/** Rastros de estas órdenes en la cola y en los snapshots de la cuenta. */
async function lookup(accountId, ids) {
    const ev = await query(
        `SELECT ml_order_id, bool_or(processed_at IS NULL) AS pendiente, MAX(processed_at) AS ultima
         FROM order_events
         WHERE account_id = $1 AND ml_order_id = ANY($2::varchar[])
         GROUP BY ml_order_id`,
        [accountId, ids]
    );
    const sn = await query(
        `SELECT ml_order_id, order_json->>'last_updated' AS lu, order_json->>'date_last_updated' AS dlu,
                order_json->>'status' AS st
         FROM order_snapshots
         WHERE account_id = $1 AND ml_order_id = ANY($2::varchar[])`,
        [accountId, ids]
    );
    const eventos = new Map(ev.rows.map((f) => [String(f.ml_order_id), {
        pending: !!f.pendiente,
        lastProcessedMs: f.ultima ? new Date(f.ultima).getTime() : null,
    }]));
    const snaps = new Map(sn.rows.map((f) => [String(f.ml_order_id), {
        last_updated: f.lu, date_last_updated: f.dlu, status: f.st,
    }]));
    return { eventos, snaps };
}

/** Clasifica una página de ML y encola lo que falta (mismo INSERT que el aviso, con source='sweep'). */
export async function processPage(accountId, orders, horizonMs, stats) {
    const lista = orders.filter((o) => o && o.id != null);
    if (!lista.length) return;
    const ids = [...new Set(lista.map((o) => String(o.id)))];
    const { eventos, snaps } = await lookup(accountId, ids);
    const encolar = [];
    if (!stats.vistos) stats.vistos = new Set();
    for (const o of lista) {
        const id = String(o.id);
        // Las ventanas se solapan (la hora de más): una orden se cuenta y se decide una sola vez por pasada.
        if (stats.vistos.has(id)) continue;
        stats.vistos.add(id);
        stats.seen++;
        const c = classifyOrder(o, eventos.get(id), snaps.get(id), horizonMs);
        if (c === 'nueva') { stats.recoveredNew++; encolar.push(id); }
        else if (c === 'cambio') { stats.recoveredChanges++; encolar.push(id); }
        else if (c === 'reciente') stats.recent++;
    }
    if (!encolar.length) return;
    await query(
        `INSERT INTO order_events (account_id, ml_order_id, source)
         SELECT $1, x, 'sweep' FROM unnest($2::varchar[]) AS x`,
        [accountId, encolar]
    );
    stats.enqueued += encolar.length;
    stats.ids.push(...encolar);
}

/** Recorre una ventana. Si ML dice que hay más de lo que se puede paginar, la parte en ventanas de una hora. */
async function sweepWindow(account, token, win, horizonMs, stats) {
    let offset = 0;
    for (;;) {
        const page = await mlSearchOrders(account, token, { ...mlRange(win), offset, limit: PAGE, sort: 'date_asc' });
        if (offset === 0 && page.total > OFFSET_CAP && (win.to - win.from) > HORA) {
            for (const sub of planWindows(win.from, win.to, 60)) {
                await sweepWindow(account, token, sub, horizonMs, stats);
            }
            return;
        }
        stats.pages++;
        await processPage(account.id, page.results, horizonMs, stats);
        offset += page.results.length;
        if (page.results.length < PAGE || offset >= page.total) return;
        if (offset >= OFFSET_CAP) {
            stats.truncated = true;
            console.warn(`[sweep] cuenta ${account.public_id}: más de ${OFFSET_CAP} órdenes actualizadas en una hora (${mlRange(win).updatedFrom}); se revisaron las primeras`);
            return;
        }
        if (SWEEP.pauseMs) await sleep(SWEEP.pauseMs);
    }
}

async function saveRow(accountId, fields) {
    await query(
        `INSERT INTO order_sweeps (account_id, cursor_at, last_run_at, last_ok_at, last_error,
                                   last_seen, last_enqueued, last_recovered_new, last_recovered_changes,
                                   total_recovered_new, total_recovered_changes, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $8, $9, NOW())
         ON CONFLICT (account_id) DO UPDATE SET
             cursor_at   = GREATEST(order_sweeps.cursor_at, EXCLUDED.cursor_at),
             last_run_at = COALESCE(EXCLUDED.last_run_at, order_sweeps.last_run_at),
             last_ok_at  = COALESCE(EXCLUDED.last_ok_at, order_sweeps.last_ok_at),
             last_error  = EXCLUDED.last_error,
             last_seen   = EXCLUDED.last_seen,
             last_enqueued = EXCLUDED.last_enqueued,
             last_recovered_new     = EXCLUDED.last_recovered_new,
             last_recovered_changes = EXCLUDED.last_recovered_changes,
             total_recovered_new     = order_sweeps.total_recovered_new + EXCLUDED.last_recovered_new,
             total_recovered_changes = order_sweeps.total_recovered_changes + EXCLUDED.last_recovered_changes,
             updated_at  = NOW()`,
        [accountId, new Date(fields.cursorMs).toISOString(),
         fields.runAt ? new Date(fields.runAt).toISOString() : null,
         fields.okAt ? new Date(fields.okAt).toISOString() : null,
         fields.error || null,
         fields.seen || 0, fields.enqueued || 0, fields.recoveredNew || 0, fields.recoveredChanges || 0]
    );
}

const _backoff = new Map();   // account_id → { until, fails }

/**
 * Una pasada del barrido para UNA cuenta. Devuelve las estadísticas
 * ({ seen, enqueued, recoveredNew, recoveredChanges, recent, pages, windows, ids, error }).
 */
export async function sweepAccount(account, nowMs = Date.now()) {
    const stats = { seen: 0, enqueued: 0, recoveredNew: 0, recoveredChanges: 0, recent: 0, pages: 0, windows: 0, ids: [], truncated: false, error: null, vistos: new Set() };
    const horizonMs = nowMs - SWEEP.graceSec * 1000;
    const capMs = nowMs - SWEEP.maxHours * HORA;
    const createdMs = account.created_at ? new Date(account.created_at).getTime() : capMs;

    const prev = await query(`SELECT cursor_at FROM order_sweeps WHERE account_id = $1`, [account.id]);
    const cursorMs = prev.rowCount ? new Date(prev.rows[0].cursor_at).getTime() : null;
    let start = cursorMs !== null ? cursorMs - SWEEP.overlapMin * 60000 : capMs;
    if (start < capMs) {
        if (cursorMs !== null) {
            console.warn(`[sweep] cuenta ${account.public_id}: el último barrido llegó hasta ${new Date(cursorMs).toISOString()}; se barren sólo las últimas ${SWEEP.maxHours} h (WFML_ORDER_SWEEP_MAX_HOURS)`);
        }
        start = capMs;
    }
    if (start < createdMs) start = createdMs;

    let cursorHecho = cursorMs !== null ? cursorMs : Math.min(start, horizonMs);
    try {
        if (start < horizonMs) {
            const token = await getValidAccessToken(account);
            for (const win of planWindows(start, horizonMs)) {
                stats.windows++;
                await sweepWindow(account, token, win, horizonMs, stats);
                cursorHecho = Math.max(cursorHecho, win.to);
                await saveRow(account.id, { cursorMs: cursorHecho });
            }
        }
        cursorHecho = Math.max(cursorHecho, horizonMs);
        await saveRow(account.id, { cursorMs: cursorHecho, runAt: nowMs, okAt: nowMs, error: null, ...stats });
        _backoff.delete(account.id);
    } catch (err) {
        const status = Number(err && err.status) || 0;
        stats.error = status === 429 ? 'rate_limited' : (status ? `ml_http_${status}` : 'error');
        const msg = String((err && err.message) || err).slice(0, 300);
        await saveRow(account.id, { cursorMs: cursorHecho, runAt: nowMs, okAt: null, error: `${stats.error}: ${msg}`, ...stats })
            .catch((e) => console.error(`[sweep] cuenta ${account.public_id}: no se pudo guardar el cursor:`, e.message));
        if (status === 429) {
            const b = _backoff.get(account.id) || { fails: 0 };
            b.fails++;
            b.until = Date.now() + Math.min(BACKOFF_MAX, SWEEP.intervalMs * 2 ** b.fails);
            _backoff.set(account.id, b);
            console.warn(`[sweep] cuenta ${account.public_id}: ML contestó 429; se saltea hasta ${new Date(b.until).toISOString()}`);
        } else {
            console.error(`[sweep] cuenta ${account.public_id}: la pasada falló (se reintenta en la próxima):`, msg);
        }
    }
    if (stats.enqueued) {
        console.log(`[sweep] cuenta ${account.public_id}: ML devolvió ${stats.seen} orden(es) actualizada(s); se encolaron ${stats.enqueued} que el aviso no había traído (${stats.recoveredNew} nueva(s), ${stats.recoveredChanges} cambio(s)): ${stats.ids.slice(0, 20).join(', ')}${stats.ids.length > 20 ? '…' : ''}`);
    }
    return stats;
}

/** Una pasada por todas las cuentas activas sin reauth_required_at. */
export async function sweepAll(nowMs = Date.now()) {
    const r = await query(
        `SELECT * FROM accounts
         WHERE revoked_at IS NULL AND reauth_required_at IS NULL
         ORDER BY id`
    );
    const total = { accounts: 0, enqueued: 0, recoveredNew: 0, recoveredChanges: 0, errors: 0 };
    for (const account of r.rows) {
        const b = _backoff.get(account.id);
        if (b && b.until > Date.now()) continue;
        total.accounts++;
        const s = await sweepAccount(account, nowMs);
        total.enqueued += s.enqueued;
        total.recoveredNew += s.recoveredNew;
        total.recoveredChanges += s.recoveredChanges;
        if (s.error) total.errors++;
    }
    return total;
}

let _busy = false;

async function sweepTick() {
    if (_busy) return;
    _busy = true;
    try {
        await sweepAll();
    } catch (err) {
        console.error('[sweep] tick error:', err.message);
    } finally {
        _busy = false;
    }
}

/** Arranca el loop (lo llama startScheduler). El primer paso, a los 30 s: recupera lo que pasó con el conector caído. */
export function startOrderSweep() {
    if (!SWEEP.enabled) {
        console.log('[scheduler] barrido de órdenes deshabilitado (WFML_ORDER_SWEEP_ENABLED=0)');
        return;
    }
    console.log(`[scheduler] barrido de órdenes — cada ${Math.round(SWEEP.intervalMs / 1000)}s, solapamiento ${SWEEP.overlapMin} min, espera ${SWEEP.graceSec}s, tope ${SWEEP.maxHours} h`);
    setTimeout(() => {
        sweepTick().catch((e) => console.error('[sweep] first tick uncaught:', e));
        setInterval(() => { sweepTick().catch((e) => console.error('[sweep] tick uncaught:', e)); }, SWEEP.intervalMs);
    }, FIRST_RUN_DELAY);
}

/** Para las pruebas: vacía la espera por 429. */
export function _resetBackoff() { _backoff.clear(); }

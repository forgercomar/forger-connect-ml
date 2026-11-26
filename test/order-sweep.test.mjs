/**
 * order-sweep.test.mjs — v2.11.0: el barrido periódico de órdenes (order-sweep.js).
 *
 * Ejercita el CÓDIGO REAL del barrido sin Postgres ni API de ML: mockea db.js
 * (colas y cursor en memoria) y ml-api.js (un /orders/search que filtra por
 * order.date_last_updated.from/to truncando a la hora, como dice la
 * documentación de ML) con mock.module de node:test.
 *
 * Correr desde la raíz del repo del central:
 *   node --experimental-test-module-mocks test/order-sweep.test.mjs
 *
 * Cubre:
 *   S1 fechas: comienzo de la hora, formato de ML y ventanas contiguas.
 *   S2 la clasificación de cada orden (reciente, en cola, nueva, cambio, al día).
 *   S3 primera pasada: encola la que falta y la que cambió (source='sweep'), no la
 *      que ya está, ni la que se actualizó hace segundos (su aviso puede venir).
 *   S4 idempotente: otra pasada no vuelve a encolar nada, ni con la orden en la
 *      cola ni ya procesada.
 *   S5 nunca antes del alta de la cuenta.
 *   S6 caída larga: desde el cursor con el tope de 72 h, ventana por ventana.
 *   S7 429: corta, no adelanta el cursor más allá de lo barrido y saltea la cuenta.
 *   S8 una cuenta que ML pide reconectar no se barre.
 *   S9 una ventana con más de lo que se puede paginar se parte en horas.
 */

import { mock } from 'node:test';

const ROOT = new URL('../', import.meta.url);
const M = (f) => new URL(f, ROOT).href;

process.env.WFML_ORDER_SWEEP_PAUSE_MS = '0';
process.env.WFML_ORDER_SWEEP_GRACE_SEC = '120';
process.env.WFML_ORDER_SWEEP_OVERLAP_MIN = '10';
process.env.WFML_ORDER_SWEEP_MAX_HOURS = '72';
process.env.WFML_ORDER_SWEEP_WINDOW_MIN = '360';

let OK = 0, FAIL = 0;
function check(name, cond, extra = '') {
    if (cond) { OK++; console.log(`  OK   ${name}`); }
    else      { FAIL++; console.log(`  FAIL ${name}${extra ? ' — ' + extra : ''}`); }
}

const HORA = 3600000;
const NOW = Date.UTC(2026, 10, 26, 15, 37, 12);   // 26-11-2026 15:37:12 UTC
const iso = (ms) => new Date(ms).toISOString().replace('Z', '-00:00');

// ---------------------------------------------------------------------------
// Mundo falso
// ---------------------------------------------------------------------------
const world = {
    accounts: [],
    events: [],        // { id, account_id, ml_order_id, processed_at, source }
    snaps: new Map(),  // `${acc}:${oid}` → order_json
    sweeps: new Map(), // account_id → fila
    ml: new Map(),     // seller → [orden]
    searches: [],      // parámetros de cada /orders/search
    fail429: false,
};
let evSeq = 1;
function reset() {
    world.accounts = []; world.events = []; world.snaps = new Map(); world.sweeps = new Map();
    world.ml = new Map(); world.searches = []; world.fail429 = false;
}
function cuenta(id, extra = {}) {
    const a = { id, public_id: 'acc_' + id, ml_user_id: 1000 + id, revoked_at: null, reauth_required_at: null,
                created_at: new Date(NOW - 30 * 24 * HORA).toISOString(), ...extra };
    world.accounts.push(a);
    return a;
}
function ordenML(acc, id, updatedMs, extra = {}) {
    const o = { id, status: 'paid', last_updated: iso(updatedMs), date_last_updated: iso(updatedMs), seller: { id: acc.ml_user_id }, ...extra };
    const l = world.ml.get(acc.ml_user_id) || [];
    l.push(o);
    world.ml.set(acc.ml_user_id, l);
    return o;
}
function evento(acc, oid, processedMs = null) {
    world.events.push({ id: evSeq++, account_id: acc.id, ml_order_id: String(oid), processed_at: processedMs ? new Date(processedMs) : null, source: null });
}
function snapshot(acc, oid, order) { world.snaps.set(`${acc.id}:${oid}`, JSON.parse(JSON.stringify(order))); }
const deSweep = (acc) => world.events.filter((e) => e.account_id === acc.id && e.source === 'sweep').map((e) => e.ml_order_id);

// ---------------------------------------------------------------------------
// Mock de db.js — enruta por forma del SQL
// ---------------------------------------------------------------------------
async function fakeQuery(sql, params = []) {
    const s = sql.replace(/\s+/g, ' ').trim();
    if (s.startsWith('SELECT * FROM accounts WHERE revoked_at IS NULL AND reauth_required_at IS NULL')) {
        const rows = world.accounts.filter((a) => !a.revoked_at && !a.reauth_required_at);
        return { rows, rowCount: rows.length };
    }
    if (s.startsWith('SELECT cursor_at FROM order_sweeps')) {
        const f = world.sweeps.get(params[0]);
        return f ? { rows: [{ cursor_at: f.cursor_at }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }
    if (s.startsWith('SELECT ml_order_id, bool_or(processed_at IS NULL)')) {
        const ids = new Set(params[1]);
        const g = new Map();
        for (const e of world.events) {
            if (e.account_id !== params[0] || !ids.has(e.ml_order_id)) continue;
            const x = g.get(e.ml_order_id) || { ml_order_id: e.ml_order_id, pendiente: false, ultima: null };
            if (!e.processed_at) x.pendiente = true;
            else if (!x.ultima || e.processed_at > x.ultima) x.ultima = e.processed_at;
            g.set(e.ml_order_id, x);
        }
        return { rows: [...g.values()], rowCount: g.size };
    }
    if (s.startsWith("SELECT ml_order_id, order_json->>'last_updated'")) {
        const rows = [];
        for (const id of params[1]) {
            const o = world.snaps.get(`${params[0]}:${id}`);
            if (o) rows.push({ ml_order_id: id, lu: o.last_updated || null, dlu: o.date_last_updated || null, st: o.status || null });
        }
        return { rows, rowCount: rows.length };
    }
    if (s.startsWith('INSERT INTO order_events (account_id, ml_order_id, source)')) {
        for (const id of params[1]) world.events.push({ id: evSeq++, account_id: params[0], ml_order_id: String(id), processed_at: null, source: 'sweep' });
        return { rows: [], rowCount: params[1].length };
    }
    if (s.startsWith('INSERT INTO order_sweeps')) {
        const prev = world.sweeps.get(params[0]);
        const cur = new Date(params[1]).getTime();
        const f = prev ? { ...prev } : { cursor_at: params[1], total_recovered_new: 0, total_recovered_changes: 0, last_run_at: null, last_ok_at: null };
        if (!prev || cur > new Date(prev.cursor_at).getTime()) f.cursor_at = params[1];
        if (params[2]) f.last_run_at = params[2];
        if (params[3]) f.last_ok_at = params[3];
        f.last_error = params[4];
        f.last_seen = params[5]; f.last_enqueued = params[6];
        f.last_recovered_new = params[7]; f.last_recovered_changes = params[8];
        f.total_recovered_new += params[7]; f.total_recovered_changes += params[8];
        world.sweeps.set(params[0], f);
        return { rows: [], rowCount: 1 };
    }
    throw new Error('SQL no previsto en la prueba: ' + s.slice(0, 120));
}
mock.module(M('db.js'), { namedExports: { query: fakeQuery, tx: async (fn) => fn({ query: fakeQuery }) } });

// ---------------------------------------------------------------------------
// Mock de ml-api.js: /orders/search con order.date_last_updated, truncado a la hora
// ---------------------------------------------------------------------------
const floorH = (ms) => Math.floor(ms / HORA) * HORA;
mock.module(M('ml-api.js'), {
    namedExports: {
        getValidAccessToken: async () => 'tok',
        mlSearchOrders: async (account, token, range) => {
            world.searches.push({ account: account.id, ...range });
            if (world.fail429 && world.searches.length > world.fail429) {
                const e = new Error('orders/search falló: HTTP 429 Too Many Requests');
                e.status = 429;
                throw e;
            }
            const desde = floorH(Date.parse(range.updatedFrom));
            const hasta = floorH(Date.parse(range.updatedTo));
            const todas = (world.ml.get(account.ml_user_id) || [])
                .filter((o) => { const t = Date.parse(o.last_updated); return t >= desde && t <= hasta; });
            const off = range.offset || 0, lim = range.limit || 50;
            return { results: todas.slice(off, off + lim), total: todas.length };
        },
    },
});

const sw = await import(M('order-sweep.js'));
const { floorHour, mlIso, planWindows, mlRange, classifyOrder, sweepAccount, sweepAll, _resetBackoff } = sw;

// S1 — fechas -------------------------------------------------------------
console.log('\n== S1 fechas y ventanas ==');
check('comienzo de la hora', floorHour(NOW) === Date.UTC(2026, 10, 26, 15, 0, 0));
check('formato de ML (…-00:00)', mlIso(Date.UTC(2015, 6, 1)) === '2015-07-01T00:00:00.000-00:00', mlIso(Date.UTC(2015, 6, 1)));
const r1 = mlRange({ from: NOW - 15 * 60000, to: NOW - 120000 });
check('desde el comienzo de la hora del inicio', r1.updatedFrom === '2026-11-26T15:00:00.000-00:00', r1.updatedFrom);
check('hasta una hora después del final (ML descarta minutos)', r1.updatedTo === '2026-11-26T16:00:00.000-00:00', r1.updatedTo);
const v = planWindows(NOW - 20 * HORA, NOW, 360);
check('ventanas de 6 h contiguas que cubren todo', v.length === 4 && v[0].from === NOW - 20 * HORA && v[3].to === NOW
    && v.every((w, i) => i === 0 || w.from === v[i - 1].to), JSON.stringify(v.map((w) => (w.to - w.from) / HORA)));

// S2 — clasificación ------------------------------------------------------
console.log('\n== S2 clasificación ==');
const H = NOW - 120000;
const o = (lu, extra = {}) => ({ id: 1, status: 'paid', last_updated: iso(lu), date_last_updated: iso(lu), ...extra });
check('actualizada hace segundos: reciente', classifyOrder(o(NOW - 30000), undefined, undefined, H) === 'reciente');
check('con un aviso sin bajar: en cola', classifyOrder(o(NOW - HORA), { pending: true, lastProcessedMs: null }, undefined, H) === 'en_cola');
check('sin ningún rastro: nueva', classifyOrder(o(NOW - HORA), undefined, undefined, H) === 'nueva');
check('snapshot con la misma versión: al día', classifyOrder(o(NOW - HORA), { pending: false, lastProcessedMs: NOW - HORA + 5000 }, o(NOW - HORA), H) === 'al_dia');
check('snapshot más viejo: cambio', classifyOrder(o(NOW - HORA), { pending: false, lastProcessedMs: NOW - 2 * HORA }, o(NOW - 2 * HORA), H) === 'cambio');
check('otro estado (cancelada): cambio', classifyOrder(o(NOW - HORA, { status: 'cancelled' }), undefined, o(NOW - HORA), H) === 'cambio');
check('sin snapshot, procesada después del cambio: al día', classifyOrder(o(NOW - HORA), { pending: false, lastProcessedMs: NOW - HORA + 1000 }, undefined, H) === 'al_dia');
check('sin snapshot, procesada antes del cambio: cambio', classifyOrder(o(NOW - HORA), { pending: false, lastProcessedMs: NOW - 2 * HORA }, undefined, H) === 'cambio');
check('snapshot del historial sin date_last_updated: compara last_updated', classifyOrder(o(NOW - HORA), undefined, { last_updated: iso(NOW - HORA), status: 'paid' }, H) === 'al_dia');

// S3 — primera pasada -------------------------------------------------------
console.log('\n== S3 primera pasada ==');
reset(); _resetBackoff();
const A = cuenta(7);
const ya = ordenML(A, 101, NOW - 40 * 60000); evento(A, 101, NOW - 39 * 60000); snapshot(A, 101, ya);
ordenML(A, 102, NOW - 35 * 60000);                                                  // el aviso nunca llegó
const vieja = ordenML(A, 103, NOW - 30 * 60000, { status: 'cancelled' });
evento(A, 103, NOW - 3 * HORA); snapshot(A, 103, { ...vieja, status: 'paid', last_updated: iso(NOW - 3 * HORA), date_last_updated: iso(NOW - 3 * HORA) });
ordenML(A, 104, NOW - 30000);                                                       // hace 30 s: su aviso puede venir
ordenML(A, 105, NOW - 50 * HORA);                                                   // dentro del tope, sin aviso
const s3 = await sweepAccount(A, NOW);
check('encola la que faltaba y la que cambió', JSON.stringify(deSweep(A).sort()) === JSON.stringify(['102', '103', '105']), JSON.stringify(deSweep(A)));
check('no encola la que ya estaba ni la reciente', !deSweep(A).includes('101') && !deSweep(A).includes('104'));
check('cuenta 2 nuevas y 1 cambio', s3.recoveredNew === 2 && s3.recoveredChanges === 1 && s3.enqueued === 3 && s3.recent === 1, JSON.stringify(s3));
const f3 = world.sweeps.get(7);
check('el cursor queda en ahora − la espera', f3 && new Date(f3.cursor_at).getTime() === NOW - 120000, f3 && f3.cursor_at);
check('la fila guarda lo recuperado y la pasada buena', f3.total_recovered_new === 2 && f3.total_recovered_changes === 1 && f3.last_error === null && !!f3.last_ok_at, JSON.stringify(f3));
check('la primera vez barre las últimas 72 h', world.searches.length > 0 && Date.parse(world.searches[0].updatedFrom) === floorH(NOW - 72 * HORA), world.searches[0] && world.searches[0].updatedFrom);

// S4 — idempotente ----------------------------------------------------------
console.log('\n== S4 otra pasada no duplica ==');
world.searches = [];
const n0 = world.events.length;
const s4a = await sweepAccount(A, NOW + 5 * 60000);
check('con las órdenes todavía en la cola: no encola nada', world.events.length === n0 + 1 && deSweep(A).filter((x) => x === '104').length === 1, `eventos ${n0} → ${world.events.length}: ${JSON.stringify(deSweep(A))}`);
check('la reciente de la pasada anterior entra en ésta (una vez)', s4a.recoveredNew === 1 && s4a.enqueued === 1, JSON.stringify(s4a));
check('la segunda pasada pide desde el cursor − 10 min', Date.parse(world.searches[0].updatedFrom) === floorH(NOW - 120000 - 10 * 60000), world.searches[0].updatedFrom);
for (const e of world.events) {
    if (e.processed_at) continue;
    e.processed_at = new Date(NOW + 6 * 60000);
    const om = world.ml.get(A.ml_user_id).find((x) => String(x.id) === e.ml_order_id);
    if (om) snapshot(A, e.ml_order_id, om);
}
const n1 = world.events.length;
const s4b = await sweepAccount(A, NOW + 10 * 60000);
check('ya procesadas: no encola nada', world.events.length === n1 && s4b.enqueued === 0, JSON.stringify(s4b));

// S5 — nunca antes del alta --------------------------------------------------
console.log('\n== S5 alta de la cuenta ==');
reset(); _resetBackoff();
const B = cuenta(8, { created_at: new Date(NOW - 2 * HORA).toISOString() });
ordenML(B, 201, NOW - 5 * HORA);          // de antes de conectar la cuenta
ordenML(B, 202, NOW - HORA);
await sweepAccount(B, NOW);
check('no pide a ML antes del alta', Date.parse(world.searches[0].updatedFrom) === floorH(NOW - 2 * HORA), world.searches[0].updatedFrom);
check('sólo encola la posterior al alta', JSON.stringify(deSweep(B)) === JSON.stringify(['202']), JSON.stringify(deSweep(B)));

// S6 — caída larga ------------------------------------------------------------
console.log('\n== S6 caída larga: desde el cursor, con tope ==');
reset(); _resetBackoff();
const C = cuenta(9);
world.sweeps.set(9, { cursor_at: new Date(NOW - 100 * HORA).toISOString(), total_recovered_new: 0, total_recovered_changes: 0 });
for (let h = 1; h <= 90; h += 4) ordenML(C, 300 + h, NOW - h * HORA);
const s6 = await sweepAccount(C, NOW);
const esperadas = (world.ml.get(C.ml_user_id) || []).filter((x) => Date.parse(x.last_updated) >= floorH(NOW - 72 * HORA)).map((x) => String(x.id));
check('encola todas las de las últimas 72 h (y ninguna anterior)', JSON.stringify(deSweep(C).sort()) === JSON.stringify(esperadas.sort()), `${deSweep(C).length} de ${esperadas.length}`);
check('en ventanas de 6 h', s6.windows === 12, String(s6.windows));
check('el cursor llega a ahora − la espera', new Date(world.sweeps.get(9).cursor_at).getTime() === NOW - 120000);

// S7 — 429 ---------------------------------------------------------------------
console.log('\n== S7 ML contesta 429 ==');
reset(); _resetBackoff();
const D = cuenta(10);
world.sweeps.set(10, { cursor_at: new Date(NOW - 30 * HORA).toISOString(), total_recovered_new: 0, total_recovered_changes: 0 });
for (let h = 1; h <= 29; h += 2) ordenML(D, 400 + h, NOW - h * HORA);
world.fail429 = 2;   // las dos primeras búsquedas andan; después, 429
const s7 = await sweepAccount(D, NOW);
const f7 = world.sweeps.get(10);
check('la pasada termina con rate_limited', s7.error === 'rate_limited' && /^rate_limited/.test(f7.last_error || ''), JSON.stringify({ e: s7.error, f: f7.last_error }));
check('el cursor avanza sólo lo barrido (dos ventanas)', new Date(f7.cursor_at).getTime() === NOW - 30 * HORA - 10 * 60000 + 2 * 6 * HORA, f7.cursor_at);
check('lo que se encoló antes del 429 queda (y se cuenta)', deSweep(D).length > 0 && f7.total_recovered_new === deSweep(D).length, `${deSweep(D).length} / ${f7.total_recovered_new}`);
world.searches = [];
world.fail429 = false;
await sweepAll(NOW + 60000);
check('la pasada siguiente saltea la cuenta (espera por el 429)', world.searches.length === 0, String(world.searches.length));
_resetBackoff();
await sweepAll(NOW + 60000);
check('pasada la espera, sigue desde su cursor', world.searches.length > 0 && Date.parse(world.searches[0].updatedFrom) === floorH(new Date(f7.cursor_at).getTime() - 10 * 60000), world.searches[0] && world.searches[0].updatedFrom);

// S8 — reconectar ----------------------------------------------------------------
console.log('\n== S8 cuenta para reconectar ==');
reset(); _resetBackoff();
const E = cuenta(11, { reauth_required_at: new Date(NOW - HORA).toISOString() });
ordenML(E, 501, NOW - HORA);
const t8 = await sweepAll(NOW);
check('no se le pide nada a ML ni se encola', t8.accounts === 0 && world.searches.length === 0 && deSweep(E).length === 0, JSON.stringify(t8));

// S9 — ventana con demasiadas órdenes ----------------------------------------------
console.log('\n== S9 ventana que no se puede paginar entera ==');
reset(); _resetBackoff();
const F = cuenta(12);
world.sweeps.set(12, { cursor_at: new Date(NOW - 7 * HORA).toISOString(), total_recovered_new: 0, total_recovered_changes: 0 });
for (let i = 0; i < 1200; i++) ordenML(F, 10000 + i, NOW - 6 * HORA + Math.floor(i * 5 * HORA / 1200));
const s9 = await sweepAccount(F, NOW);
check('se parte en ventanas de una hora y entran todas', deSweep(F).length === 1200 && !s9.truncated, `${deSweep(F).length} truncada=${s9.truncated}`);
check('sin repetir ninguna', new Set(deSweep(F)).size === deSweep(F).length);

console.log(`\n${OK} OK, ${FAIL} FAIL`);
process.exit(FAIL ? 1 : 0);

/**
 * worker-pc.test.mjs — v2.10.0: el worker con sellers grandes.
 *
 * Ejercita el CÓDIGO REAL de worker.js sin Postgres ni API de ML: mockea
 * db.js, ml-api.js y license-context.js con mock.module de node:test y mueve
 * los dos loops con fake timers.
 *
 * Correr desde la raíz del repo del central:
 *   node --experimental-test-module-mocks test/worker-pc.test.mjs
 *
 * Cubre:
 *   T1 full sync de 2.500 publicaciones → modo scan: pagina con scroll_id hasta
 *      la página vacía, cada id entra UNA vez en staging, 25 páginas + 1 vacía.
 *   T2 full sync de 300 → modo offset de siempre, sin scan.
 *   T3 incremental con 1.500 modificadas → corta limpio en el tope de offset de
 *      ML (1.000) y marca capped, en vez de fallar el job.
 *   T4 un push NO espera detrás de un full sync largo: los dos loops reclaman
 *      cada uno lo suyo (push termina mientras el sync sigue corriendo).
 *   T5 push de 60 ítems → resultado parcial persistido cada 25 y al final.
 */

import { mock } from 'node:test';

const ROOT = new URL('../', import.meta.url);
const M = (f) => new URL(f, ROOT).href;

process.env.WFML_WORKER_INTERVAL     = '2000';
process.env.WFML_PUSH_INTERVAL       = '1000';
process.env.WFML_PUSH_PROGRESS_EVERY = '25';
process.env.WFML_SCAN_THRESHOLD      = '1000';
process.env.WFML_SCAN_LIMIT          = '100';
process.env.WFML_SYNC_CHUNK          = '50';

let OK = 0, FAIL = 0;
function check(name, cond, extra = '') {
    if (cond) { OK++; console.log(`  OK   ${name}`); }
    else      { FAIL++; console.log(`  FAIL ${name}${extra ? ' — ' + extra : ''}`); }
}

// ---------------------------------------------------------------------------
// Mundo falso
// ---------------------------------------------------------------------------
const now = Date.now();
const world = {
    account: { id: 7, public_id: 'acc_pc', ml_user_id: 1001, revoked_at: null, last_sync_at: null },
    jobs: [],
    synced: [],            // ids insertados en synced_items
    progress: [],          // { jobId, done, partial }
    puts: [],              // ml_item_ids pusheados
    calls: { search: [], scan: [], getItems: 0 },
    catalog: [],           // ids del seller (strings)
    gate: null,            // promesa que frena mlGetItems (T4)
};
let nextJobId = 1;
function addJob(type, input = {}) {
    const j = { id: nextJobId++, public_id: 'job_' + type + '_' + nextJobId, account_id: 7, type,
                status: 'pending', input, started_at: null, created_at: new Date(now + nextJobId),
                steps_total: 0, steps_done: 0, message: null, result: null };
    world.jobs.push(j);
    return j;
}
function catalogOf(n) { return Array.from({ length: n }, (_, i) => 'MLA' + (100000 + i)); }

// ---------------------------------------------------------------------------
// Mock de db.js — enruta por forma del SQL
// ---------------------------------------------------------------------------
async function fakeQuery(sql, params = []) {
    const s = sql.replace(/\s+/g, ' ').trim();
    if (s.startsWith("UPDATE jobs SET status = 'running'")) {
        // El worker viejo (un solo loop) no manda tipos: cualquiera. Así la prueba
        // también corre contra el código anterior y se ve qué medía (mutación).
        const types = Array.isArray(params[1]) ? params[1] : ['sync_full', 'sync_incremental', 'push'];
        const j = world.jobs.find((x) => x.status === 'pending' && types.includes(x.type));
        if (!j) return { rows: [], rowCount: 0 };
        j.status = 'running'; j.started_at = j.started_at || new Date();
        return { rows: [{ id: j.id, public_id: j.public_id, account_id: j.account_id, type: j.type,
                          input: j.input, started_at: j.started_at, created_at: j.created_at }], rowCount: 1 };
    }
    if (s.startsWith('SELECT * FROM accounts WHERE id =')) {
        return { rows: [world.account], rowCount: 1 };
    }
    if (s.startsWith('SELECT status FROM jobs WHERE id =')) {
        const j = world.jobs.find((x) => x.id === params[0]);
        return j ? { rows: [{ status: j.status }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }
    if (s.startsWith('UPDATE jobs SET steps_total =')) {
        const j = world.jobs.find((x) => x.id === params[0]);
        if (j) { j.steps_total = params[1]; j.message = params[2]; }
        return { rows: [], rowCount: 1 };
    }
    if (s.startsWith('UPDATE jobs SET steps_done =')) {
        const j = world.jobs.find((x) => x.id === params[0]);
        if (j) { j.steps_done = params[1]; j.message = params[2]; }
        const partial = params.length > 3 && params[3] ? JSON.parse(params[3]) : null;
        world.progress.push({ jobId: params[0], done: params[1], partial });
        return { rows: [], rowCount: 1 };
    }
    if (s.startsWith('INSERT INTO synced_items')) {
        for (let i = 0; i < params.length; i += 5) world.synced.push(String(params[i + 2]));
        return { rows: [], rowCount: params.length / 5 };
    }
    if (s.startsWith("UPDATE jobs SET status = 'done'")) {
        const j = world.jobs.find((x) => x.id === params[0]);
        if (j && j.status === 'running') { j.status = 'done'; j.result = JSON.parse(params[1]); j.message = params[2]; }
        return { rows: [], rowCount: 1 };
    }
    if (s.startsWith("UPDATE jobs SET status = 'failed'")) {
        const j = world.jobs.find((x) => x.id === params[0]);
        if (j && j.status === 'running') { j.status = 'failed'; j.message = params[1]; }
        return { rows: [], rowCount: 1 };
    }
    if (s.startsWith('UPDATE accounts SET last_sync_at')) {
        world.account.last_sync_at = params[1];
        return { rows: [], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
}
mock.module(M('db.js'), { namedExports: { query: fakeQuery, tx: async (fn) => fn({ query: fakeQuery }) } });
mock.module(M('license-context.js'), { namedExports: { accountLicenseVerdict: () => ({ blocked: false }) } });

// ---------------------------------------------------------------------------
// Mock de ml-api.js
// ---------------------------------------------------------------------------
const ML_OFFSET_CAP = 1000;
const scrolls = new Map(); // scroll_id → cursor
mock.module(M('ml-api.js'), {
    namedExports: {
        ML_BATCH_SIZE: 20,
        getValidAccessToken: async () => 'tok',
        mlSearchItems: async (account, token, offset, limit, orders = '') => {
            world.calls.search.push({ offset, limit, orders });
            if (offset >= ML_OFFSET_CAP) throw new Error('items/search falló: HTTP 400 offset cap');
            const ids = world.catalog.slice(offset, offset + limit);
            return { ids, total: world.catalog.length };
        },
        mlSearchItemsScan: async (account, token, scrollId, limit) => {
            world.calls.scan.push({ scrollId, limit });
            let id = scrollId;
            if (!id) { id = 'scr-' + (scrolls.size + 1); scrolls.set(id, 0); }
            const cur = scrolls.get(id) || 0;
            const ids = world.catalog.slice(cur, cur + limit);
            scrolls.set(id, cur + ids.length);
            return { ids, total: world.catalog.length, scroll_id: id };
        },
        mlGetItems: async (account, token, ids) => {
            world.calls.getItems++;
            if (world.gate) await world.gate;
            return ids.map((id) => ({ id, title: 't ' + id, price: 1, available_quantity: 1,
                                      last_updated: new Date(now).toISOString() }));
        },
        mlUpdateItem: async (account, token, id, body) => {
            world.puts.push(id);
            return { ok: true, status: 200, data: {} };
        },
    },
});

// ---------------------------------------------------------------------------
// Arranque con fake timers
// ---------------------------------------------------------------------------
mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
const { startWorker } = await import(M('worker.js'));
startWorker();

async function settle(rounds = 4000) {
    for (let i = 0; i < rounds; i++) await new Promise(setImmediate);
}
async function runSyncLoop() { mock.timers.tick(2000); await settle(); }
function resetWorld() {
    world.jobs = []; world.synced = []; world.progress = []; world.puts = [];
    world.calls = { search: [], scan: [], getItems: 0 }; world.gate = null;
    scrolls.clear();
}

// T1 — full sync con scan --------------------------------------------------
console.log('\n== T1 full sync 2.500 → scan ==');
resetWorld();
world.account.last_sync_at = null;
world.catalog = catalogOf(2500);
const j1 = addJob('sync_full', { source: 'cron' });
await runSyncLoop();
check('job done', j1.status === 'done', j1.message);
check('modo full_scan', j1.result && j1.result.mode === 'full_scan');
check('2.500 sincronizadas', j1.result && j1.result.items_synced === 2500, String(j1.result && j1.result.items_synced));
check('cada id UNA vez en staging', new Set(world.synced).size === 2500 && world.synced.length === 2500, `${world.synced.length}/${new Set(world.synced).size}`);
check('25 páginas scan + 1 vacía', world.calls.scan.length === 26, String(world.calls.scan.length));
check('el scroll_id se reenvía', world.calls.scan.slice(1).every((c) => c.scrollId === 'scr-1'));
check('una sola búsqueda por offset (solo el total)', world.calls.search.length === 1, String(world.calls.search.length));
check('steps_total = 25', j1.steps_total === 25, String(j1.steps_total));
check('watermark avanzó', !!world.account.last_sync_at);

// T2 — full sync chico, offset ------------------------------------------
console.log('\n== T2 full sync 300 → offset ==');
resetWorld();
world.account.last_sync_at = null;
world.catalog = catalogOf(300);
const j2 = addJob('sync_full', { source: 'cron' });
await runSyncLoop();
check('job done', j2.status === 'done', j2.message);
check('modo full (offset)', j2.result && j2.result.mode === 'full');
check('300 sincronizadas', j2.result && j2.result.items_synced === 300);
check('sin llamadas scan', world.calls.scan.length === 0);
check('6 búsquedas por offset', world.calls.search.length === 6, String(world.calls.search.length));

// T3 — incremental que pega en el tope ------------------------------------
console.log('\n== T3 incremental 1.500 modificadas → tope de offset ==');
resetWorld();
world.account.last_sync_at = new Date(now - 86400000).toISOString();
world.catalog = catalogOf(1500);
const j3 = addJob('sync_incremental', { source: 'cron' });
await runSyncLoop();
check('job done (no failed)', j3.status === 'done', j3.message);
check('capped = true', j3.result && j3.result.capped === true);
check('1.000 revisadas', j3.result && j3.result.items_synced === 1000, String(j3.result && j3.result.items_synced));
check('nunca pidió offset >= 1000', world.calls.search.every((c) => c.offset < ML_OFFSET_CAP));

// T4 — el push no espera al sync ------------------------------------------
console.log('\n== T4 push mientras corre un full largo ==');
resetWorld();
world.account.last_sync_at = null;
world.catalog = catalogOf(2500);
let release;
world.gate = new Promise((r) => { release = r; });
const j4s = addJob('sync_full', { source: 'cron' });
const j4p = addJob('push', { pushes: [{ ml_item_id: 'MLA1', body: { available_quantity: 3 } }] });
mock.timers.tick(2000);   // dispara el loop de push (1000, 2000) y el de sync (2000)
await settle();
check('el sync quedó corriendo (frenado en ML)', j4s.status === 'running', j4s.status);
check('el push terminó igual', j4p.status === 'done', j4p.status);
check('PUT ejecutado', world.puts.length === 1);
release();
world.gate = null;
await settle();
check('el sync terminó después', j4s.status === 'done', j4s.status);

// T5 — push parcial persistido ---------------------------------------------
console.log('\n== T5 push de 60 → resultado parcial cada 25 ==');
resetWorld();
const pushes = Array.from({ length: 60 }, (_, i) => ({ ml_item_id: 'MLA' + i, body: { price: i } }));
const j5 = addJob('push', { pushes });
mock.timers.tick(1000);
await settle();
check('job done', j5.status === 'done', j5.message);
const partials = world.progress.filter((p) => p.jobId === j5.id && p.partial);
check('parciales en 25, 50 y 60', partials.map((p) => p.done).join(',') === '25,50,60', partials.map((p) => p.done).join(','));
check('parcial marcado partial:true con items', partials.every((p) => p.partial.partial === true && p.partial.items.length === p.done));
check('resultado final completo', j5.result && j5.result.items.length === 60 && j5.result.pushed === 60 && !j5.result.partial);
check('60 PUT', world.puts.length === 60);

console.log(`\n${OK} OK, ${FAIL} FAIL`);
process.exit(FAIL ? 1 : 0);

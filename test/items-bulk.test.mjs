/**
 * items-bulk.test.mjs — v2.10.2: la lectura masiva de publicaciones va por
 * /items/bulk con vuelta a /items?ids= (ML deprecó la vieja).
 *
 * Ejercita el CÓDIGO REAL de ml-api.js (mlGetItems, mlGet, getValidAccessToken
 * con el auth.js real) y del worker (full por offset, full por scan, incremental
 * y targeted) contra un Mercado Libre FALSO: globalThis.fetch se reemplaza antes
 * de importar nada y todo pedido queda anotado; uno que el falso no conoce (o el
 * renuevo del token) hace fallar la prueba. db.js y license-context.js van con
 * mock.module, como en worker-pc.test.mjs. Ningún pedido sale de la máquina.
 *
 * Correr desde la raíz del repo del central:
 *   node --test --experimental-test-module-mocks test/items-bulk.test.mjs
 * Todo el directorio (Node 22+ no acepta «test/» como argumento):
 *   node --test --experimental-test-module-mocks
 *
 * Cubre:
 *   A0 CONTROL  el ML es el falso (la base sigue siendo api.mercadolibre.com), el
 *               token sale del auth.js real sin renovar, el Bearer viaja.
 *   B1 CONTROL  ML_ITEMS_LECTURA=ids = la lectura de hoy: sólo /items?ids= con los
 *               18 campos; 0 pedidos a /items/bulk.
 *   B2  misma respuesta → lo mismo que hoy por /items/bulk (ids y attributes=body.<18>).
 *   B3  la nueva falla (HTTP 410/404/429/500/401, no lista, vacía, no JSON, sin
 *       body, sin campos, otros ids, sin code, error de red) → la vieja con el
 *       mismo resultado y el memo (1 pedido a la nueva y 3 a la vieja por job).
 *   B3c el job siguiente vuelve a la nueva.
 *   B4  la nueva a medias (sin body, campos que faltan, uno que no vino, un 404)
 *       → la tanda ENTERA con la vieja (nada de la nueva).
 *   B4c a medias y la vieja falla (500) → Error como hoy.
 *   B4d a medias y la vieja ya no existe (410) → lo válido de la nueva; después, sólo la nueva.
 *   B5  la vieja deja de existir a mitad del job (memo en la vieja) → esa tanda y
 *       las siguientes con la nueva.
 *   B6  las dos fallan → el mismo Error que hoy.
 *   B7  un 401 de la nueva no renueva el token (cae a la vieja); CONTROL B7b: la
 *       vieja lo sigue renovando como hoy.
 *   B8  el interruptor se lee en cada llamada ('IDS', ' ids ' → vieja; otro → nueva).
 *   B9  el registro: una línea por job y por cambio, sin token, ids, títulos, SKU
 *       ni datos del vendedor.
 *   B10 otra cuenta: el memo de una no toca a la otra.
 *   W1-W4 el worker REAL: full offset, full scan, incremental y targeted dejan en
 *       synced_items lo mismo byte a byte con las dos lecturas, y un pedido por tanda.
 *   W5 CONTROL  la comparación ve una diferencia (la nueva con otros títulos).
 *   W6  full con la nueva caída: lo mismo que hoy, una sola vuelta por job.
 *   W7  las dos caen en la tanda 2: el job falla con el mismo mensaje que hoy.
 *   W8  memo por job: el job siguiente vuelve a la nueva.
 */

import { mock } from 'node:test';
import crypto from 'node:crypto';

const ROOT = new URL('../', import.meta.url);
const M = (f) => new URL(f, ROOT).href;

// ---------------------------------------------------------------------------
// Entorno (antes de importar: ml-api.js y worker.js leen el entorno al cargar)
// ---------------------------------------------------------------------------
process.env.WFML_TOKEN_KEY      = crypto.randomBytes(32).toString('base64');
delete process.env.WFML_TOKEN_KEY_PREV;
process.env.ML_CLIENT_ID        = 'app-falsa-ml-bulk';      // un renuevo pegaría al falso (y se nota)
process.env.ML_CLIENT_SECRET    = 'secreto-falso-ml-bulk';
process.env.WFML_WORKER_INTERVAL = '2000';
process.env.WFML_PUSH_INTERVAL   = '1000';
process.env.WFML_SYNC_CHUNK      = '10';
process.env.WFML_SCAN_THRESHOLD  = '30';
process.env.WFML_SCAN_LIMIT      = '25';
delete process.env.ML_ITEMS_LECTURA;

let OK = 0, FAIL = 0;
const out = (s) => process.stdout.write(s + '\n');
function check(name, cond, extra = '') {
    if (cond) { OK++; out(`  OK   ${name}`); }
    else      { FAIL++; out(`  FAIL ${name}${extra ? ' — ' + extra : ''}`); }
}

// Todo lo que el código escribe en la consola queda acá (el registro se mide).
const LOG = [];
for (const k of ['log', 'warn', 'error', 'info']) {
    console[k] = (...a) => { LOG.push({ k, s: a.map((x) => (x instanceof Error ? x.message : String(x))).join(' ') }); };
}
const itemsLog = (desde = 0) => LOG.slice(desde).filter((l) => l.s.startsWith('[items]'));

// ---------------------------------------------------------------------------
// Mercado Libre falso
// ---------------------------------------------------------------------------
const TOKEN  = 'APP_USR-5566778899-TOKEN-SECRETO-ML-BULK';
const SELLER = { id: 1234567, nickname: 'VENDEDOR_SECRETO_PC' };
const ATTRS  = ['id', 'title', 'seller_custom_field', 'price', 'available_quantity',
                'sold_quantity', 'status', 'permalink', 'thumbnail', 'has_variations',
                'variations', 'listing_type_id', 'category_id', 'sale_terms',
                'installments', 'catalog_product_id', 'date_created', 'last_updated'];
const NOW = Date.now();

function crearItem(n, vars, lu) {
    const id = 'MLA' + (700000 + n);
    const variations = Array.from({ length: vars }, (_, k) => ({
        id: 900000 + n * 10 + k, price: 1000 + n, available_quantity: k + 1, sold_quantity: k,
        seller_custom_field: `SKU-SECRETO-${n}-${k}`, picture_ids: [`${n}-PIC-${k}`],
        attribute_combinations: [{ id: 'COLOR', name: 'Color', value_id: 'c' + k, value_name: ['Rojo', 'Azul', 'Verde'][k % 3] }],
    }));
    return {
        id, title: `Título secreto ${n}`, seller_id: SELLER.id, seller_custom_field: vars ? null : `SKU-SECRETO-${n}`,
        price: 1500 + n, available_quantity: 3 + (n % 5), sold_quantity: n % 7, status: n % 9 === 0 ? 'paused' : 'active',
        permalink: `https://articulo.mercadolibre.com.ar/${id}`, thumbnail: `http://http2.mlstatic.com/D_${n}-I.jpg`,
        has_variations: vars > 0, variations, listing_type_id: n % 2 ? 'gold_special' : 'gold_pro',
        category_id: 'MLA1234', sale_terms: [{ id: 'WARRANTY_TYPE', value_name: 'Garantía del vendedor' }],
        installments: n % 3 ? { quantity: 6, rate: 0 } : null, catalog_product_id: null,
        date_created: '2026-01-01T00:00:00.000Z', last_updated: new Date(lu).toISOString(),
        attributes: [{ id: 'SELLER_SKU', value_name: `SKU-SECRETO-${n}` }], pictures: [{ id: `${n}-PIC` }],
    };
}

const ML = {
    items: new Map(),        // id → publicación completa
    orden: [],               // ids del vendedor (orden por defecto)
    nueva: 'igual',          // modo de /items/bulk, o (n) => modo
    vieja: 'igual',          // modo de /items?ids=, o (n) => modo
    n: { bulk: 0, ids: 0 },
    calls: [],               // { tipo, auth, attributes } del caso en curso
    todos: [],               // todos los pedidos de la prueba entera
    scroll: new Map(),       // scroll_id → cursor
    nScroll: 0,
};
function catalogo(cant, opts = {}) {
    ML.items.clear(); ML.orden = [];
    for (let i = 1; i <= cant; i++) {
        const fresca = opts.frescas ? i <= opts.frescas : true;
        const lu = fresca ? NOW - 60_000 * (i + 1) : NOW - 10 * 86_400_000 - i * 60_000;
        const it = crearItem(i, i % 4 === 0 ? (i % 8 === 0 ? 3 : 2) : 0, lu);
        ML.items.set(it.id, it); ML.orden.push(it.id);
    }
}
function reset(nueva = 'igual', vieja = 'igual') {
    ML.nueva = nueva; ML.vieja = vieja; ML.n = { bulk: 0, ids: 0 }; ML.calls = [];
}
function anotar(c) { ML.calls.push(c); ML.todos.push(c); }
const cuenta = (tipo, auth = null) => ML.calls.filter((c) => c.tipo === tipo && (auth === null || c.auth === auth)).length;

function pick(it, attrs) {
    const o = {};
    for (const a of attrs) if (Object.prototype.hasOwnProperty.call(it, a)) o[a] = it[a];
    return o;
}
function envoltorios(ids, attrs) {
    return ids.map((id) => (ML.items.has(id)
        ? { code: 200, body: pick(ML.items.get(id), attrs) }
        : { code: 404, body: { message: `Item with id ${id} not found`, error: 'not_found', status: 404, cause: [] } }));
}
const json = (status, data) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });
const marcar = (w) => (w.code === 200 ? { ...w, body: { ...w.body, title: 'NUEVA·' + w.body.title } } : w);

function responder(modo, ids, attrs) {
    if (modo && typeof modo === 'object' && modo.status) return json(modo.status, { message: 'falso', error: 'falso', status: modo.status, cause: [] });
    const env = envoltorios(ids, attrs);
    switch (modo) {
        case 'igual':            return json(200, env);
        case 'marcada':          return json(200, env.map(marcar));
        case 'no_lista':         return json(200, { results: env });
        case 'vacia':            return json(200, []);
        case 'no_json':          return new Response('<html>no es JSON</html>', { status: 200, headers: { 'content-type': 'text/html' } });
        case 'sin_body':         return json(200, env.map((w) => ({ code: w.code })));
        case 'sin_campos':       return json(200, env.map((w) => { const b = { ...w.body }; delete b.variations; return { code: w.code, body: b }; }));
        case 'otros_ids':        return json(200, env.map((w, i) => ({ code: 200, body: { ...w.body, id: 'MLA' + (100 + i) } })));
        case 'sin_code':         return json(200, env.map((w) => ({ body: w.body })));
        case 'parcial_sin_body': return json(200, env.map((w, i) => (i === 0 ? { code: 200 } : marcar(w))));
        case 'parcial_campos':   return json(200, env.map((w, i) => { const m = marcar(w); if (i === 0) { const b = { ...m.body }; delete b.price; return { code: 200, body: b }; } return m; }));
        case 'parcial_falta':    return json(200, env.slice(0, -1).map(marcar));
        case 'parcial_404':      return json(200, env.map((w, i) => (i === 0 ? { code: 404, body: { message: 'not found', error: 'not_found', status: 404, cause: [] } } : marcar(w))));
        default:                 throw new Error('modo desconocido del ML falso: ' + JSON.stringify(modo));
    }
}

async function fakeFetch(url, opts = {}) {
    const u = new URL(String(url));
    const auth = (opts.headers && (opts.headers.Authorization || opts.headers.authorization)) || '';
    if (u.host !== 'api.mercadolibre.com') { anotar({ tipo: 'otro', auth, url: String(url) }); return json(599, { message: 'host desconocido' }); }
    if (u.pathname === '/oauth/token') {
        anotar({ tipo: 'oauth', auth });
        return json(200, { access_token: 'APP_USR-RENOVADO-FALSO', refresh_token: 'TG-RENOVADO-FALSO', expires_in: 21600 });
    }
    if (u.pathname === '/items' || u.pathname === '/items/bulk') {
        const tipo = u.pathname === '/items' ? 'ids' : 'bulk';
        const attributes = u.searchParams.get('attributes') || '';
        anotar({ tipo, auth, attributes, idsParam: u.searchParams.get('ids') || '' });
        const n = ++ML.n[tipo];
        let modo = tipo === 'bulk' ? ML.nueva : ML.vieja;
        if (typeof modo === 'function') modo = modo(n);
        if (modo === 'red') throw new TypeError('fetch failed');
        const ids = (u.searchParams.get('ids') || '').split(',').filter(Boolean);
        const attrs = attributes.split(',').filter(Boolean).map((a) => (tipo === 'bulk' && a.startsWith('body.') ? a.slice(5) : a));
        return responder(modo, ids, attrs);
    }
    const mm = u.pathname.match(/^\/users\/(\d+)\/items\/search$/);
    if (mm) {
        const p = u.searchParams;
        if (p.get('search_type') === 'scan') {
            anotar({ tipo: 'scan', auth });
            const lim = Number(p.get('limit')) || 100;
            const sid = p.get('scroll_id') || ('scroll-falso-' + (++ML.nScroll));
            const cur = ML.scroll.get(sid) || 0;
            const ids = ML.orden.slice(cur, cur + lim);
            ML.scroll.set(sid, cur + ids.length);
            return json(200, { results: ids, paging: { total: ML.orden.length }, scroll_id: sid });
        }
        anotar({ tipo: 'search', auth });
        const off = Number(p.get('offset')) || 0;
        const lim = Number(p.get('limit')) || 50;
        let ids = ML.orden.slice();
        if (p.get('orders') === 'last_updated_desc') {
            ids.sort((a, b) => new Date(ML.items.get(b).last_updated) - new Date(ML.items.get(a).last_updated));
        }
        return json(200, { results: ids.slice(off, off + lim), paging: { total: ids.length } });
    }
    anotar({ tipo: 'otro', auth, url: u.pathname });
    return json(599, { message: 'ruta desconocida del falso' });
}
globalThis.fetch = fakeFetch;

// ---------------------------------------------------------------------------
// db.js y license-context.js falsos (el worker y el renuevo del token)
// ---------------------------------------------------------------------------
const world = { accounts: new Map(), jobs: [], synced: [] };
let nextJobId = 1;
async function fakeQuery(sql, params = []) {
    const s = sql.replace(/\s+/g, ' ').trim();
    if (s.startsWith("UPDATE jobs SET status = 'running'")) {
        const types = Array.isArray(params[1]) ? params[1] : ['sync_full', 'sync_incremental', 'push'];
        const j = world.jobs.find((x) => x.status === 'pending' && types.includes(x.type));
        if (!j) return { rows: [], rowCount: 0 };
        j.status = 'running'; j.started_at = j.started_at || new Date();
        return { rows: [{ id: j.id, public_id: j.public_id, account_id: j.account_id, type: j.type,
                          input: j.input, started_at: j.started_at, created_at: j.created_at }], rowCount: 1 };
    }
    if (s.startsWith('SELECT * FROM accounts WHERE id =')) {
        const a = world.accounts.get(params[0]);
        // Como pg: una fila NUEVA en cada consulta (el memo de la lectura es por objeto = por job).
        return a ? { rows: [{ ...a }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }
    if (s.startsWith('SELECT status FROM jobs WHERE id =')) {
        const j = world.jobs.find((x) => x.id === params[0]);
        return j ? { rows: [{ status: j.status }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }
    if (s.startsWith('UPDATE jobs SET steps_total =') || s.startsWith('UPDATE jobs SET steps_done =')) {
        return { rows: [], rowCount: 1 };
    }
    if (s.startsWith('INSERT INTO synced_items')) {
        for (let i = 0; i < params.length; i += 5) {
            world.synced.push({ account_id: params[i], ml_item_id: params[i + 2], variation_id: params[i + 3], item_data: params[i + 4] });
        }
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
        const a = world.accounts.get(params[0]);
        if (a) a.last_sync_at = params[1];
        return { rows: [], rowCount: 1 };
    }
    if (s.startsWith('UPDATE accounts SET access_token_enc')) {
        return { rows: [], rowCount: 1 };   // renuevo del token (B7b)
    }
    return { rows: [], rowCount: 0 };
}
mock.module(M('db.js'), { namedExports: { query: fakeQuery, tx: async (fn) => fn({ query: fakeQuery }) } });
mock.module(M('license-context.js'), { namedExports: { accountLicenseVerdict: () => ({ blocked: false }) } });

const { encryptToken } = await import(M('auth.js'));
const { mlGetItems, getValidAccessToken } = await import(M('ml-api.js'));

function nuevaCuenta(id = 7, publicId = 'acc_prueba') {
    const acc = encryptToken(TOKEN);
    const ref = encryptToken('TG-REFRESH-SECRETO');
    return {
        id, public_id: publicId, ml_user_id: SELLER.id, nickname: SELLER.nickname, revoked_at: null, last_sync_at: null,
        access_token_enc: acc.ciphertext, access_token_iv: acc.iv,
        access_expires_at: new Date(NOW + 5 * 3600_000).toISOString(),
        refresh_token_enc: ref.ciphertext, refresh_token_iv: ref.iv,
    };
}

// Lo que devuelve la lectura de hoy, calculado aparte: los body con code 200, en orden.
const esperado = (ids) => ids.filter((id) => ML.items.has(id)).map((id) => pick(ML.items.get(id), ATTRS));
const J = (x) => JSON.stringify(x);
const tandas = (ids) => { const t = []; for (let i = 0; i < ids.length; i += 20) t.push(ids.slice(i, i + 20)); return t; };

/** Un «job» directo: las tandas con la MISMA cuenta (el memo vive con ella). */
async function leerJob(acc, ids, token = TOKEN) {
    const items = [];
    for (const t of tandas(ids)) items.push(...await mlGetItems(acc, token, t));
    return items;
}
async function leerTanda(acc, ids, token = TOKEN) {
    try { return { items: await mlGetItems(acc, token, ids), err: null }; }
    catch (e) { return { items: null, err: e }; }
}

// ===========================================================================
// Parte A — mlGetItems directo
// ===========================================================================
catalogo(45);
const IDS = ML.orden.slice();          // 45 → tandas de 20, 20 y 5
const ESP = esperado(IDS);

out('\n== A0 CONTROL: el ML falso, el token real sin renovar ==');
reset();
{
    const acc = nuevaCuenta();
    const tok = await getValidAccessToken(acc);
    check('A0 el token sale del auth.js real (cacheado, sin renovar)', tok === TOKEN);
    const r = await leerJob(acc, IDS.slice(0, 5));
    check('A0 globalThis.fetch es el falso y la base sigue siendo api.mercadolibre.com', globalThis.fetch === fakeFetch && cuenta('bulk') === 1 && cuenta('otro') === 0);
    check('A0 viaja el Bearer del token', ML.calls.every((c) => c.auth === `Bearer ${TOKEN}`));
    check('A0 sin renuevo del token', cuenta('oauth') === 0);
    check('A0 devuelve 5 publicaciones', r.length === 5);
}

out('\n== B1 CONTROL: ML_ITEMS_LECTURA=ids = la lectura de hoy ==');
reset();
process.env.ML_ITEMS_LECTURA = 'ids';
const L0 = LOG.length;
const HOY = await leerJob(nuevaCuenta(), IDS);
check('B1 tres pedidos a /items?ids= y ninguno a /items/bulk', cuenta('ids') === 3 && cuenta('bulk') === 0, `${cuenta('ids')}/${cuenta('bulk')}`);
check('B1 los 18 campos de siempre, sin prefijo', ML.calls.every((c) => c.attributes === ATTRS.join(',')));
check('B1 los ids pedidos, de a 20', J(ML.calls.map((c) => c.idsParam)) === J(tandas(IDS).map((t) => t.join(','))));
check('B1 = lo de hoy (los body con code 200, en orden)', J(HOY) === J(ESP));
check('B1 el registro dice que va por la vieja (una línea)', itemsLog(L0).length === 1 && itemsLog(L0)[0].s.includes('lectura /items?ids= (ML_ITEMS_LECTURA=ids)'), J(itemsLog(L0)));
delete process.env.ML_ITEMS_LECTURA;

out('\n== B2 misma respuesta → lo mismo por /items/bulk ==');
reset();
{
    const L1 = LOG.length;
    const r = await leerJob(nuevaCuenta(), IDS);
    check('B2 tres pedidos a /items/bulk y ninguno a la vieja', cuenta('bulk') === 3 && cuenta('ids') === 0, `${cuenta('bulk')}/${cuenta('ids')}`);
    check('B2 attributes=body.<los 18>', ML.calls.every((c) => c.attributes === ATTRS.map((a) => 'body.' + a).join(',')));
    check('B2 los mismos ids, de a 20', J(ML.calls.map((c) => c.idsParam)) === J(tandas(IDS).map((t) => t.join(','))));
    check('B2 IDÉNTICO a la lectura de hoy (byte a byte)', J(r) === J(HOY));
    const l = itemsLog(L1);
    check('B2 el registro: UNA línea «lectura /items/bulk» por job', l.length === 1 && l[0].k === 'log' && l[0].s === '[items] cuenta acc_prueba: lectura /items/bulk', J(l));
}

out('\n== B3 la nueva falla → la vieja, con memo ==');
const FALLAS = [
    [{ status: 410 }, 'http_410'], [{ status: 404 }, 'http_404'], [{ status: 429 }, 'http_429'], [{ status: 500 }, 'http_500'],
    [{ status: 401 }, 'http_401'], ['no_lista', 'forma_no_lista'], ['vacia', 'sin_pedidos'], ['no_json', 'forma_no_lista'],
    ['sin_body', 'envoltorios_sin_body'], ['sin_campos', 'sin_campos'], ['otros_ids', 'sin_pedidos'], ['sin_code', 'sin_pedidos'],
    ['red', 'http_0'],
];
for (const [modo, motivo] of FALLAS) {
    reset(modo);
    const L2 = LOG.length;
    let r = null, err = null;
    try { r = await leerJob(nuevaCuenta(), IDS); } catch (e) { err = e; }
    const nombre = typeof modo === 'object' ? 'HTTP ' + modo.status : modo;
    check(`B3 ${nombre}: lo mismo que hoy`, !err && J(r) === J(HOY), err ? err.message : '');
    check(`B3 ${nombre}: 1 pedido a la nueva y 3 a la vieja (memo, sin duplicar)`, cuenta('bulk') === 1 && cuenta('ids') === 3, `${cuenta('bulk')}/${cuenta('ids')}`);
    const l = itemsLog(L2);
    check(`B3 ${nombre}: el registro dice por qué (${motivo})`, l.length === 1 && l[0].k === 'warn' && l[0].s === `[items] cuenta acc_prueba: /items/bulk ${motivo} → /items?ids= ok`, J(l));
}
check('B3 ningún renuevo del token (tampoco con el 401 de la nueva)', cuenta('oauth') === 0);

out('\n== B3c el job siguiente vuelve a la nueva ==');
reset((n) => (n === 1 ? { status: 500 } : 'igual'));
{
    try { await leerJob(nuevaCuenta(), IDS); } catch (_) { /* lo mide la cuenta de pedidos */ }
    const a = [cuenta('bulk'), cuenta('ids')];
    const r = await leerJob(nuevaCuenta(), IDS);
    check('B3c job 1: 1 nueva / 3 vieja; job 2: 3 nueva / 0 vieja', a[0] === 1 && a[1] === 3 && cuenta('bulk') === 4 && cuenta('ids') === 3, `${a} → ${cuenta('bulk')}/${cuenta('ids')}`);
    check('B3c job 2 = lo de hoy', J(r) === J(HOY));
}

out('\n== B4 la nueva a medias → la tanda entera con la vieja ==');
for (const modo of ['parcial_sin_body', 'parcial_campos', 'parcial_falta', 'parcial_404']) {
    reset(modo);
    const L3 = LOG.length;
    let r = null, err = null;
    try { r = await leerJob(nuevaCuenta(), IDS); } catch (e) { err = e; }
    check(`B4 ${modo}: lo mismo que hoy`, !err && J(r) === J(HOY), err ? err.message : '');
    check(`B4 ${modo}: nada de la nueva se mezcla`, !!r && !r.some((it) => String(it.title).startsWith('NUEVA·')));
    check(`B4 ${modo}: 1 nueva / 3 vieja`, cuenta('bulk') === 1 && cuenta('ids') === 3, `${cuenta('bulk')}/${cuenta('ids')}`);
    const l = itemsLog(L3);
    check(`B4 ${modo}: el registro dice parcial_19_de_20`, l.length === 1 && l[0].s.endsWith('/items/bulk parcial_19_de_20 → /items?ids= ok'), J(l));
}

out('\n== B4c a medias y la vieja falla → Error como hoy ==');
reset('parcial_campos', (n) => (n === 1 ? { status: 500 } : 'igual'));
{
    const acc = nuevaCuenta();
    const t = tandas(IDS);
    const a = await leerTanda(acc, t[0]);
    check('B4c la tanda falla con el mismo Error que hoy', a.err && a.err.message === 'items multi-get falló: HTTP 500', a.err ? a.err.message : J(a.items && a.items.length));
    const b = await leerTanda(acc, t[1]);
    check('B4c la tanda siguiente del mismo job va directo a la vieja', !b.err && J(b.items) === J(esperado(t[1])) && cuenta('bulk') === 1 && cuenta('ids') === 2, `${cuenta('bulk')}/${cuenta('ids')}`);
}

out('\n== B4d a medias y la vieja ya no existe (410) → lo válido de la nueva ==');
reset('parcial_falta', { status: 410 });
{
    const acc = nuevaCuenta();
    const t = tandas(IDS);
    const a = await leerTanda(acc, t[0]);
    check('B4d la tanda devuelve las 19 válidas de la nueva (sin inventar la que faltó)', !a.err && a.items.length === 19 && a.items.every((it) => it.title.startsWith('NUEVA·')) && J(a.items.map((i) => i.id)) === J(t[0].slice(0, 19)), a.err ? a.err.message : String(a.items.length));
    ML.nueva = 'igual';
    const b = await leerTanda(acc, t[1]);
    check('B4d después, sólo la nueva (sin vuelta)', !b.err && J(b.items) === J(esperado(t[1])) && cuenta('bulk') === 2 && cuenta('ids') === 1, `${cuenta('bulk')}/${cuenta('ids')}`);
}

out('\n== B5 la vieja deja de existir a mitad del job ==');
reset((n) => (n === 1 ? { status: 429 } : 'igual'), (n) => (n === 1 ? 'igual' : { status: 410 }));
{
    const L4 = LOG.length;
    let r = null, err = null;
    try { r = await leerJob(nuevaCuenta(), IDS); } catch (e) { err = e; }
    check('B5 el job entero sale igual que hoy', !err && J(r) === J(HOY), err ? err.message : '');
    check('B5 tanda 1: nueva 429 → vieja; tanda 2: vieja 410 → nueva; tanda 3: nueva (3 nueva / 2 vieja)', cuenta('bulk') === 3 && cuenta('ids') === 2, `${cuenta('bulk')}/${cuenta('ids')}`);
    const l = itemsLog(L4).map((x) => x.s);
    check('B5 el registro lo anota', l.length === 3 && l[0].endsWith('/items/bulk http_429 → /items?ids= ok')
        && l[1].endsWith('/items?ids= http_410 → /items/bulk (la vieja ya no existe)') && l[2].endsWith('lectura /items/bulk'), J(l));
}
reset({ status: 500 }, { status: 410 });
{
    const acc = nuevaCuenta();
    const a = await leerTanda(acc, IDS.slice(0, 20));
    check('B5c la nueva falla y la vieja ya no existe → Error (como hoy, nada que leer)', a.err && a.err.message === 'items multi-get falló: HTTP 410', a.err ? a.err.message : 'sin error');
    ML.nueva = 'igual';
    const b = await leerTanda(acc, IDS.slice(20, 40));
    check('B5c el resto del job, sólo la nueva', !b.err && J(b.items) === J(esperado(IDS.slice(20, 40))) && cuenta('bulk') === 2 && cuenta('ids') === 1, `${cuenta('bulk')}/${cuenta('ids')}`);
}

out('\n== B6 las dos fallan → el mismo Error que hoy ==');
reset({ status: 500 }, { status: 500 });
{
    const a = await leerTanda(nuevaCuenta(), IDS.slice(0, 20));
    process.env.ML_ITEMS_LECTURA = 'ids';
    const hoy = await leerTanda(nuevaCuenta(), IDS.slice(0, 20));
    delete process.env.ML_ITEMS_LECTURA;
    check('B6 Error «items multi-get falló: HTTP 500», igual que hoy', a.err && hoy.err && a.err.message === hoy.err.message && a.err.message === 'items multi-get falló: HTTP 500', `${a.err && a.err.message} / ${hoy.err && hoy.err.message}`);
}

out('\n== B7 un 401 de la nueva no renueva el token ==');
reset({ status: 401 });
{
    const r = await leerJob(nuevaCuenta(), IDS);
    check('B7 la vieja responde y no hay renuevo', J(r) === J(HOY) && cuenta('oauth') === 0, `oauth=${cuenta('oauth')}`);
}
reset({ status: 500 }, (n) => (n === 1 ? { status: 401 } : 'igual'));
{
    const r = await leerJob(nuevaCuenta(), IDS);
    check('B7b CONTROL: la vieja sigue renovando ante un 401, como hoy (1 renuevo y reintento)', J(r) === J(HOY) && cuenta('oauth') === 1 && cuenta('ids') === 4, `oauth=${cuenta('oauth')} ids=${cuenta('ids')}`);
    check('B7b el reintento lleva el token renovado', ML.calls.filter((c) => c.tipo === 'ids')[1].auth === 'Bearer APP_USR-RENOVADO-FALSO');
}

out('\n== B8 el interruptor se lee en cada llamada ==');
for (const [val, tipo] of [['IDS', 'ids'], [' ids ', 'ids'], ['bulk', 'bulk'], ['', 'bulk'], ['cualquiera', 'bulk']]) {
    reset();
    process.env.ML_ITEMS_LECTURA = val;
    await leerTanda(nuevaCuenta(), IDS.slice(0, 5));
    check(`B8 ML_ITEMS_LECTURA=${J(val)} → ${tipo === 'ids' ? '/items?ids=' : '/items/bulk'}`, cuenta(tipo) === 1 && ML.calls.length === 1);
}
delete process.env.ML_ITEMS_LECTURA;

out('\n== B9 el registro no lleva token ni datos ==');
{
    const lineas = itemsLog(0).map((l) => l.s);
    const prohibidos = [TOKEN, 'APP_USR', 'MLA7', 'Título secreto', 'SKU-SECRETO', String(SELLER.id), SELLER.nickname, 'TG-'];
    const malas = lineas.filter((s) => prohibidos.some((p) => s.includes(p)));
    check('B9 hubo registro', lineas.length >= 20, String(lineas.length));
    check('B9 ninguna línea [items] con token, ids, títulos, SKU ni datos del vendedor', malas.length === 0, J(malas.slice(0, 3)));
    check('B9 el token no aparece en NADA de lo que se escribió en la consola', !LOG.some((l) => l.s.includes(TOKEN)));
}

out('\n== B10 otra cuenta: el memo de una no toca a la otra ==');
reset((n) => (n === 1 ? { status: 500 } : 'igual'));
{
    const a = nuevaCuenta(7, 'acc_a');
    const b = nuevaCuenta(8, 'acc_b');
    const t = tandas(IDS);
    await mlGetItems(a, 'TOKEN-A', t[0]);     // la nueva falla para A → A va a la vieja
    await mlGetItems(b, 'TOKEN-B', t[0]);
    await mlGetItems(a, 'TOKEN-A', t[1]);
    await mlGetItems(b, 'TOKEN-B', t[1]);
    check('B10 A: 1 nueva y 2 vieja', cuenta('bulk', 'Bearer TOKEN-A') === 1 && cuenta('ids', 'Bearer TOKEN-A') === 2);
    check('B10 B: 2 nueva y 0 vieja', cuenta('bulk', 'Bearer TOKEN-B') === 2 && cuenta('ids', 'Bearer TOKEN-B') === 0);
}

// ===========================================================================
// Parte W — el worker real con el ML falso
// ===========================================================================
mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
const { startWorker } = await import(M('worker.js'));
startWorker();
async function settle(rounds = 3000) { for (let i = 0; i < rounds; i++) await new Promise(setImmediate); }

world.accounts.set(7, nuevaCuenta(7, 'acc_pc'));
async function correrJob(type, input = {}) {
    const id = nextJobId++;
    const j = { id, public_id: 'job_' + type + '_' + id, account_id: 7, type, status: 'pending', input,
                started_at: null, created_at: new Date(NOW + id), result: null, message: null };
    world.jobs.push(j);
    world.synced = [];
    mock.timers.tick(2000);
    await settle();
    return { job: j, filas: world.synced.map((f) => J([f.account_id, f.ml_item_id, f.variation_id, f.item_data])) };
}
/** Corre el mismo job con la lectura de hoy (ids) y con la nueva; devuelve las dos corridas. */
async function hoyYNueva(type, input, prep, nueva = 'igual') {
    prep(); reset(); process.env.ML_ITEMS_LECTURA = 'ids';
    const hoy = await correrJob(type, input);
    const nHoy = { bulk: cuenta('bulk'), ids: cuenta('ids') };
    delete process.env.ML_ITEMS_LECTURA;
    prep(); reset(nueva);
    const nue = await correrJob(type, input);
    return { hoy, nue, nHoy, nNue: { bulk: cuenta('bulk'), ids: cuenta('ids') } };
}
const prepFull = (cant) => () => { catalogo(cant); world.accounts.get(7).last_sync_at = null; };
const prepInc = () => { catalogo(25, { frescas: 12 }); world.accounts.get(7).last_sync_at = new Date(NOW - 2 * 3600_000).toISOString(); };

const FLUJOS = [
    ['W1 full por offset (25)', 'sync_full', {}, prepFull(25), 3],
    ['W2 full por scan (45)', 'sync_full', {}, prepFull(45), 3],
    ['W3 incremental (12 de 25 modificadas)', 'sync_incremental', {}, prepInc, 2],
    ['W4 targeted (23)', 'sync_full', { ml_item_ids: null }, prepFull(30), 2],
];
const filasHoy = {};
for (const [nombre, type, input0, prep, tandasEsp] of FLUJOS) {
    out(`\n== ${nombre} ==`);
    const input = input0.ml_item_ids === null ? { ml_item_ids: (prep(), ML.orden.slice(3, 26)) } : input0;
    const { hoy, nue, nHoy, nNue } = await hoyYNueva(type, input, prep);
    filasHoy[nombre] = hoy;
    check(`${nombre}: los dos jobs terminan done`, hoy.job.status === 'done' && nue.job.status === 'done', `${hoy.job.status}/${nue.job.status} ${nue.job.message}`);
    check(`${nombre}: hay filas (padres y variantes)`, hoy.filas.length > 0 && hoy.filas.some((f) => JSON.parse(f)[2] !== null));
    check(`${nombre}: synced_items IDÉNTICO byte a byte con las dos lecturas`, J(nue.filas) === J(hoy.filas), `${nue.filas.length} vs ${hoy.filas.length}`);
    check(`${nombre}: el mismo resultado del job`, J(nue.job.result) === J(hoy.job.result) && nue.job.message === hoy.job.message, `${J(nue.job.result)} vs ${J(hoy.job.result)}`);
    check(`${nombre}: un pedido por tanda (hoy ${tandasEsp} a la vieja; ahora ${tandasEsp} a la nueva y 0 a la vieja)`,
        nHoy.ids === tandasEsp && nHoy.bulk === 0 && nNue.bulk === tandasEsp && nNue.ids === 0, `${J(nHoy)} ${J(nNue)}`);
}

out('\n== W5 CONTROL: la comparación ve una diferencia ==');
{
    const { hoy, nue } = await hoyYNueva('sync_full', {}, prepFull(25), 'marcada');
    check('W5 con otros títulos en la nueva, synced_items DIFIERE (las filas salen de la nueva)', nue.job.status === 'done' && J(nue.filas) !== J(hoy.filas) && nue.filas.some((f) => f.includes('NUEVA·')));
}

out('\n== W6 full con la nueva caída: lo mismo que hoy, una vuelta por job ==');
{
    const { hoy, nue, nNue } = await hoyYNueva('sync_full', {}, prepFull(45), { status: 500 });
    check('W6 synced_items IDÉNTICO', nue.job.status === 'done' && J(nue.filas) === J(hoy.filas));
    check('W6 1 pedido a la nueva y 3 a la vieja', nNue.bulk === 1 && nNue.ids === 3, J(nNue));
    const { hoy: h2, nue: n2 } = await hoyYNueva('sync_full', {}, prepFull(45), 'parcial_campos');
    check('W6 a medias: synced_items IDÉNTICO y nada de la nueva', n2.job.status === 'done' && J(n2.filas) === J(h2.filas) && !n2.filas.some((f) => f.includes('NUEVA·')));
}

out('\n== W7 las dos caen en la tanda 2: el job falla igual que hoy ==');
{
    prepFull(45)(); reset(undefined, (n) => (n === 2 ? { status: 500 } : 'igual'));
    process.env.ML_ITEMS_LECTURA = 'ids';
    const hoy = await correrJob('sync_full', {});
    delete process.env.ML_ITEMS_LECTURA;
    prepFull(45)(); reset({ status: 500 }, (n) => (n === 2 ? { status: 500 } : 'igual'));
    const nue = await correrJob('sync_full', {});
    check('W7 hoy: failed', hoy.job.status === 'failed', hoy.job.status);
    check('W7 ahora: failed con el mismo mensaje', nue.job.status === 'failed' && nue.job.message === hoy.job.message, `${nue.job.status} ${nue.job.message} / ${hoy.job.message}`);
    check('W7 el watermark no avanzó', world.accounts.get(7).last_sync_at === null);
}

out('\n== W8 memo por job: el job siguiente vuelve a la nueva ==');
{
    prepFull(25)(); reset((n) => (n === 1 ? { status: 500 } : 'igual'));
    const j1 = await correrJob('sync_full', {});
    const a = { bulk: cuenta('bulk'), ids: cuenta('ids') };
    const j2 = await correrJob('sync_full', {});
    check('W8 job 1: 1 nueva / 3 vieja; job 2: 3 nueva / 0 vieja más', j1.job.status === 'done' && j2.job.status === 'done'
        && a.bulk === 1 && a.ids === 3 && cuenta('bulk') === 4 && cuenta('ids') === 3, `${J(a)} → ${cuenta('bulk')}/${cuenta('ids')}`);
    check('W8 los dos jobs dejan lo mismo que hoy', J(j1.filas) === J(filasHoy['W1 full por offset (25)'].filas) && J(j2.filas) === J(j1.filas));
}

out('\n== Nada real ==');
const otros = ML.todos.filter((c) => c.tipo === 'otro');
check('ningún pedido fuera del ML falso ni a una ruta desconocida (en toda la prueba)', ML.todos.length > 100 && otros.length === 0, `${ML.todos.length} pedidos; ${J(otros.slice(0, 2))}`);
check('un solo renuevo del token en toda la prueba (el CONTROL B7b)', ML.todos.filter((c) => c.tipo === 'oauth').length === 1);
check('fetch sigue siendo el falso', globalThis.fetch === fakeFetch);
check('el token no aparece en nada de lo que se escribió en la consola (worker incluido)', !LOG.some((l) => l.s.includes(TOKEN)));

out(`\n${OK} OK, ${FAIL} FAIL`);
process.exit(FAIL ? 1 : 0);

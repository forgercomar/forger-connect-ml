/**
 * orders-labels.test.mjs — v2.10.3: GET /v1/orders/labels, las etiquetas de
 * Mercado Envíos EN LOTE (un solo pedido a ML con todos los envíos).
 *
 * Ejercita la RUTA REAL (routes-v1.js montada con mountV1 en un express de
 * verdad, con la firma HMAC real de auth.js) y el código real de ml-api.js
 * (mlGetShipmentLabels, mlGetRaw, getValidAccessToken) contra un Mercado Libre
 * FALSO: globalThis.fetch se reemplaza y todo pedido a api.mercadolibre.com
 * queda anotado; los pedidos a 127.0.0.1 (la prueba hablándole al express) van
 * por el fetch de verdad. db.js y license-context.js van con mock.module (la
 * base falsa filtra por account_id como Postgres). Nada sale de la máquina.
 *
 * Correr desde la raíz del repo del central:
 *   node --test --experimental-test-module-mocks test/orders-labels.test.mjs
 *
 * Cubre:
 *   C0 CONTROL  el ML es el falso, la firma real: sin firma 401, la firma de otra
 *               cuenta 401, la ruta vieja /v1/orders/label sigue igual.
 *   L1  lote PDF: UN pedido a ML con los tres envíos y response_type=pdf, con el
 *       token de la cuenta; devuelve el PDF tal cual y los tres incluidos.
 *   L2  ZPL: response_type=zpl2; ML entrega un ZIP (tipo zip) o el texto (tipo zpl).
 *   L3  órdenes de OTRA cuenta con la firma de ésta: «no_encontrada», nunca viajan
 *       a ML; la consulta a la base va con el id de la cuenta autenticada.
 *   L4  más de 50: 400 sin pedir nada a ML; 50 justas: un solo pedido.
 *   L5  dos órdenes del mismo carrito (mismo envío): el envío viaja una vez.
 *   L6  sin envío, Full e id inválido: a «faltaron» con su motivo; si no queda
 *       ninguna, 422 sin pedir nada a ML.
 *   L7  ML rechaza el lote nombrando un envío: se pide UNA vez más sin él.
 *   L8  ML con error 500 (o sin nombrar envíos): 502 con todas en «faltaron», sin reintento.
 *   L9  ML contesta 200 con algo que no es PDF / ZPL: 502.
 *   L10 formato desconocido o sin ids: 400.
 *   L11 el registro no lleva el token ni los ids.
 */

import { mock } from 'node:test';
import crypto from 'node:crypto';
import express from 'express';

const ROOT = new URL('../', import.meta.url);
const M = (f) => new URL(f, ROOT).href;

process.env.WFML_TOKEN_KEY   = crypto.randomBytes(32).toString('base64');
delete process.env.WFML_TOKEN_KEY_PREV;
process.env.ML_CLIENT_ID     = 'app-falsa-labels';
process.env.ML_CLIENT_SECRET = 'secreto-falso-labels';

let OK = 0, FAIL = 0;
const out = (s) => process.stdout.write(s + '\n');
function check(name, cond, extra = '') {
    if (cond) { OK++; out(`  OK   ${name}`); }
    else      { FAIL++; out(`  FAIL ${name}${extra ? ' — ' + extra : ''}`); }
}
const LOG = [];
for (const k of ['log', 'warn', 'error', 'info']) {
    console[k] = (...a) => { LOG.push(a.map((x) => (x instanceof Error ? x.message : String(x))).join(' ')); };
}

// ---------------------------------------------------------------------------
// Mercado Libre falso
// ---------------------------------------------------------------------------
const PDF = Buffer.from('%PDF-1.4\n% etiquetas falsas\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n', 'latin1');
const ZPL = Buffer.from('^XA^FO50,50^ADN,36,20^FDetiqueta falsa^FS^XZ\n', 'latin1');
const ZIP = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.from('zip falso con el txt')]);
const ML = { calls: [], modo: 'pdf' };
const realFetch = globalThis.fetch;
const bin = (status, buf, ct) => new Response(buf, { status, headers: { 'content-type': ct } });
const json = (status, data) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });

async function fakeFetch(url, opts = {}) {
    const u = new URL(String(url));
    if (u.hostname === '127.0.0.1') return realFetch(url, opts);
    const auth = (opts.headers && (opts.headers.Authorization || opts.headers.authorization)) || '';
    const ids = (u.searchParams.get('shipment_ids') || '').split(',').filter(Boolean);
    ML.calls.push({ host: u.host, path: u.pathname, auth, ids, tipo: u.searchParams.get('response_type') || '' });
    if (u.host !== 'api.mercadolibre.com') return json(599, { message: 'host desconocido' });
    if (u.pathname === '/oauth/token') return json(200, { access_token: 'APP_USR-RENOVADO', refresh_token: 'TG-R', expires_in: 21600 });
    if (u.pathname !== '/shipment_labels') return json(404, { message: 'ruta desconocida del falso' });
    let modo = ML.modo;
    if (typeof modo === 'function') modo = modo(ids, ML.calls.filter((c) => c.path === '/shipment_labels').length);
    switch (modo) {
        case 'pdf':      return bin(200, PDF, 'application/pdf');
        case 'zip':      return bin(200, ZIP, 'application/zip');
        case 'zpl':      return bin(200, ZPL, 'text/plain');
        case 'json200':  return json(200, { message: 'not a label' });
        case 'e500':     return json(500, { message: 'internal error', error: 'internal_error', status: 500 });
        case 'e400':     return json(400, { message: 'Invalid request', error: 'bad_request', status: 400, cause: [] });
        default:
            if (modo && modo.nombra) {
                return json(400, { message: `The following shipments are not printable: ${modo.nombra.join(',')}`, error: 'bad_request', status: 400, cause: modo.nombra.map((s) => ({ code: 'NOT_PRINTABLE', shipment_id: Number(s) })) });
            }
            throw new Error('modo desconocido del ML falso');
    }
}
globalThis.fetch = fakeFetch;

// ---------------------------------------------------------------------------
// Base falsa: cuentas y snapshots (filtra por account_id como Postgres)
// ---------------------------------------------------------------------------
const W = { accounts: new Map(), snaps: [], consultas: [] };
async function fakeQuery(sql, params = []) {
    const s = sql.replace(/\s+/g, ' ').trim();
    if (s.includes('FROM accounts WHERE public_id = $1')) {
        const a = [...W.accounts.values()].find((x) => x.public_id === params[0]);
        return a ? { rows: [{ ...a }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }
    if (s.startsWith('SELECT bump_account_last_seen')) return { rows: [], rowCount: 1 };
    if (s.includes('FROM order_snapshots') && s.includes('ANY($2::varchar[])')) {
        W.consultas.push({ cuenta: params[0], ids: params[1].slice() });
        const rows = W.snaps.filter((r) => r.account_id === params[0] && params[1].includes(r.ml_order_id)).map((r) => ({
            ml_order_id: r.ml_order_id, shipment_id: r.shipment_id == null ? null : String(r.shipment_id),
            ship_raw: r.order_json && r.order_json.shipping && r.order_json.shipping.id != null ? String(r.order_json.shipping.id) : null,
            logistic: (r.shipment_json && (r.shipment_json.logistic_type || (r.shipment_json.logistic && r.shipment_json.logistic.type))) || '',
        }));
        return { rows, rowCount: rows.length };
    }
    if (s.includes('FROM order_snapshots WHERE account_id = $1 AND ml_order_id = $2')) {
        const r = W.snaps.find((x) => x.account_id === params[0] && x.ml_order_id === params[1]);
        return r ? { rows: [{ shipment_id: r.shipment_id, order_json: r.order_json }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }
    if (s.startsWith('UPDATE accounts SET access_token_enc')) return { rows: [], rowCount: 1 };
    return { rows: [], rowCount: 0 };
}
mock.module(M('db.js'), { namedExports: { query: fakeQuery, tx: async (fn) => fn({ query: fakeQuery }) } });
mock.module(M('license-context.js'), { namedExports: { accountLicenseVerdict: () => ({ blocked: false }) } });

const { encryptToken, signRequest } = await import(M('auth.js'));
const { mountV1 } = await import(M('routes-v1.js'));

const TOKEN_A = 'APP_USR-111-TOKEN-SECRETO-A';
const TOKEN_B = 'APP_USR-222-TOKEN-SECRETO-B';
function cuenta(id, publicId, token) {
    const acc = encryptToken(token);
    const ref = encryptToken('TG-REFRESH-' + id);
    return {
        id, public_id: publicId, ml_user_id: 5000 + id, ml_nickname: 'VENDEDOR_' + id, ml_site_id: 'MLA', site_url: 'https://x',
        shared_secret: crypto.randomBytes(32).toString('base64'), revoked_at: null,
        last_valid_license_token_at: null, license_id: null, license_exp: null,
        access_token_enc: acc.ciphertext, access_token_iv: acc.iv, access_expires_at: new Date(Date.now() + 5 * 3600_000).toISOString(),
        refresh_token_enc: ref.ciphertext, refresh_token_iv: ref.iv,
    };
}
const A = cuenta(7, 'acc_aaaaaaaaaaaa', TOKEN_A);
const B = cuenta(8, 'acc_bbbbbbbbbbbb', TOKEN_B);
W.accounts.set(A.id, A); W.accounts.set(B.id, B);

function snap(account, ml, shipment, extra = {}) {
    W.snaps.push({ account_id: account.id, ml_order_id: String(ml), shipment_id: shipment,
        order_json: { id: Number(ml), shipping: shipment ? { id: shipment } : {} },
        shipment_json: extra.logistic ? { logistic_type: extra.logistic } : { logistic_type: 'cross_docking' } });
}
snap(A, '2000000000001', 44000000001);
snap(A, '2000000000002', 44000000002);
snap(A, '2000000000003', 44000000003);
snap(A, '2000000000004', 44000000004);            // carrito: comparte el envío con la 5
snap(A, '2000000000005', 44000000004);
snap(A, '2000000000006', null);                   // sin envío
snap(A, '2000000000007', 44000000007, { logistic: 'fulfillment' });
W.snaps.push({ account_id: A.id, ml_order_id: '2000000000008', shipment_id: null, order_json: { shipping: { id: 44000000008 } }, shipment_json: { logistic: { type: 'self_service' } } });
snap(B, '2000000000101', 44000000101);            // de la otra cuenta
snap(B, '2000000000102', 44000000102);
for (let i = 0; i < 51; i++) snap(A, String(2000000001000 + i), 45000000000 + i);

const app = express();
app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf.toString(); } }));
mountV1(app, { hubSecret: 'hub-falso' });
const server = await new Promise((ok) => { const s = app.listen(0, '127.0.0.1', () => ok(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;

async function pedir(acc, query, opts = {}) {
    const path = opts.path || '/connect-ml/v1/orders/labels';
    const ts = Math.floor(Date.now() / 1000);
    const firmaCon = opts.secretDe || acc;
    const headers = opts.sinFirma ? {} : {
        'X-Wfml-Account': acc.public_id, 'X-Wfml-Ts': String(ts), 'X-Wfml-Sig': signRequest(firmaCon.shared_secret, 'GET', path, ts, ''),
    };
    const r = await realFetch(`${BASE}${path}?${query}`, { headers });
    let data = null;
    try { data = await r.json(); } catch (_) { data = null; }
    return { status: r.status, data };
}
const reset = (modo = 'pdf') => { ML.calls = []; ML.modo = modo; W.consultas = []; };
const labelsCalls = () => ML.calls.filter((c) => c.path === '/shipment_labels');
const ids = (...n) => 'ml_order_ids=' + n.join(',');
const motivo = (d, id) => ((d && d.faltaron) || []).filter((f) => f.ml_order_id === id).map((f) => f.motivo).join('|');

try {
    out('\n== C0 CONTROL: ML falso, la firma real, la ruta vieja ==');
    reset();
    let r = await pedir(A, ids('2000000000001'), { sinFirma: true });
    check('C0 sin firma: 401', r.status === 401 && ML.calls.length === 0, String(r.status));
    r = await pedir(A, ids('2000000000001'), { secretDe: B });
    check('C0 firmado con el secreto de otra cuenta: 401 bad_signature', r.status === 401 && r.data && r.data.error === 'bad_signature' && ML.calls.length === 0, JSON.stringify(r.data));
    r = await pedir(A, 'ml_order_id=2000000000001', { path: '/connect-ml/v1/orders/label' });
    check('C0 la ruta vieja /v1/orders/label sigue igual (un PDF, un envío)', r.status === 200 && r.data.pdf_b64 === PDF.toString('base64') && labelsCalls().length === 1 && labelsCalls()[0].ids.join() === '44000000001' && labelsCalls()[0].tipo === 'pdf', JSON.stringify(labelsCalls()));
    check('C0 globalThis.fetch es el falso: ningún pedido fuera de api.mercadolibre.com', ML.calls.every((c) => c.host === 'api.mercadolibre.com'));

    out('\n== L1 lote PDF ==');
    reset();
    r = await pedir(A, ids('2000000000001', '2000000000002', '2000000000003') + '&formato=pdf');
    check('L1 200 ok, tipo pdf', r.status === 200 && r.data.ok === true && r.data.tipo === 'pdf' && r.data.formato === 'pdf', JSON.stringify(r.data).slice(0, 200));
    check('L1 UN solo pedido a ML con los tres envíos y response_type=pdf', labelsCalls().length === 1 && labelsCalls()[0].ids.join() === '44000000001,44000000002,44000000003' && labelsCalls()[0].tipo === 'pdf', JSON.stringify(labelsCalls()));
    check('L1 con el token de la cuenta autenticada', labelsCalls()[0].auth === `Bearer ${TOKEN_A}` && ML.calls.every((c) => c.path !== '/oauth/token'));
    check('L1 el PDF tal cual, los tres incluidos, nada faltó', Buffer.from(r.data.archivo_b64, 'base64').equals(PDF) && r.data.incluidos.join() === '2000000000001,2000000000002,2000000000003' && r.data.faltaron.length === 0);
    reset();
    r = await pedir(A, ids('2000000000001'));
    check('L1 sin formato = pdf', r.status === 200 && r.data.tipo === 'pdf' && labelsCalls()[0].tipo === 'pdf');

    out('\n== L2 ZPL ==');
    reset('zip');
    r = await pedir(A, ids('2000000000001', '2000000000002') + '&formato=zpl');
    check('L2 response_type=zpl2 y ML entrega un ZIP → tipo zip', r.status === 200 && r.data.tipo === 'zip' && r.data.formato === 'zpl' && labelsCalls()[0].tipo === 'zpl2' && Buffer.from(r.data.archivo_b64, 'base64').equals(ZIP), JSON.stringify(r.data).slice(0, 200));
    reset('zpl');
    r = await pedir(A, ids('2000000000001') + '&formato=zpl');
    check('L2 ML entrega el texto ZPL → tipo zpl', r.status === 200 && r.data.tipo === 'zpl' && Buffer.from(r.data.archivo_b64, 'base64').equals(ZPL));

    out('\n== L3 órdenes de otra cuenta ==');
    reset();
    r = await pedir(A, ids('2000000000001', '2000000000101', '2000000000102'));
    check('L3 las de la otra cuenta: no_encontrada', motivo(r.data, '2000000000101') === 'no_encontrada' && motivo(r.data, '2000000000102') === 'no_encontrada', JSON.stringify(r.data && r.data.faltaron));
    check('L3 a ML viaja sólo el envío de ésta', labelsCalls().length === 1 && labelsCalls()[0].ids.join() === '44000000001', JSON.stringify(labelsCalls()));
    check('L3 la consulta a la base va con el id de la cuenta autenticada', W.consultas.length === 1 && W.consultas[0].cuenta === A.id);
    reset();
    r = await pedir(B, ids('2000000000001', '2000000000002'));
    check('L3 la otra cuenta pidiendo las de ésta: 422, nada a ML', r.status === 422 && r.data.error === 'sin_etiquetas' && labelsCalls().length === 0 && motivo(r.data, '2000000000001') === 'no_encontrada', JSON.stringify(r.data));

    out('\n== L4 el tope de 50 ==');
    reset();
    const cincuentaYUno = Array.from({ length: 51 }, (_, i) => String(2000000001000 + i));
    r = await pedir(A, ids(...cincuentaYUno));
    check('L4 51 órdenes: 400 too_many y nada a ML', r.status === 400 && r.data.error === 'too_many' && r.data.max === 50 && ML.calls.length === 0, JSON.stringify(r.data));
    reset();
    r = await pedir(A, ids(...cincuentaYUno.slice(0, 50)));
    check('L4 50 justas: un solo pedido a ML con 50 envíos', r.status === 200 && labelsCalls().length === 1 && labelsCalls()[0].ids.length === 50 && r.data.incluidos.length === 50);
    reset();
    r = await pedir(A, ids(...cincuentaYUno.slice(0, 50), cincuentaYUno[0]));
    check('L4 repetidas no cuentan dos veces (50 + una repetida = 50)', r.status === 200 && labelsCalls()[0].ids.length === 50);

    out('\n== L5 un carrito: un envío ==');
    reset();
    r = await pedir(A, ids('2000000000004', '2000000000005', '2000000000008'));
    check('L5 el envío compartido viaja una vez (y el id del envío sale de la orden si falta en la columna)', labelsCalls().length === 1 && labelsCalls()[0].ids.join() === '44000000004,44000000008', JSON.stringify(labelsCalls()));
    check('L5 las dos órdenes del carrito incluidas', r.status === 200 && r.data.incluidos.join() === '2000000000004,2000000000005,2000000000008', JSON.stringify(r.data && r.data.incluidos));

    out('\n== L6 los que no se pueden pedir ==');
    reset();
    r = await pedir(A, ids('2000000000001', '2000000000006', '2000000000007', 'abc', '2000000009999'));
    check('L6 sin envío, Full, id inválido y no encontrada: a faltaron con su motivo', motivo(r.data, '2000000000006') === 'sin_envio' && motivo(r.data, '2000000000007') === 'full' && motivo(r.data, 'abc') === 'id_invalido' && motivo(r.data, '2000000009999') === 'no_encontrada', JSON.stringify(r.data && r.data.faltaron));
    check('L6 el resto sale igual (sólo el envío imprimible a ML)', r.status === 200 && labelsCalls().length === 1 && labelsCalls()[0].ids.join() === '44000000001' && r.data.incluidos.join() === '2000000000001');
    reset();
    r = await pedir(A, ids('2000000000006', '2000000000007'));
    check('L6 ninguna imprimible: 422 sin pedir nada a ML', r.status === 422 && r.data.error === 'sin_etiquetas' && ML.calls.length === 0 && r.data.faltaron.length === 2);

    out('\n== L7 ML rechaza nombrando un envío ==');
    reset((sids, n) => (n === 1 ? { nombra: ['44000000002'] } : 'pdf'));
    r = await pedir(A, ids('2000000000001', '2000000000002', '2000000000003'));
    check('L7 dos pedidos: el segundo sin el envío rechazado', labelsCalls().length === 2 && labelsCalls()[1].ids.join() === '44000000001,44000000003', JSON.stringify(labelsCalls()));
    check('L7 200 con la rechazada en faltaron (no_imprimible)', r.status === 200 && motivo(r.data, '2000000000002') === 'no_imprimible' && r.data.incluidos.join() === '2000000000001,2000000000003', JSON.stringify(r.data && r.data.faltaron));
    reset(() => ({ nombra: ['44000000002'] }));
    r = await pedir(A, ids('2000000000001', '2000000000002'));
    check('L7 si el segundo también falla: 502 y no hay un tercero', r.status === 502 && labelsCalls().length === 2 && r.data.faltaron.length === 2, `${r.status} ${labelsCalls().length}`);

    out('\n== L8 ML con error ==');
    reset('e500');
    r = await pedir(A, ids('2000000000001', '2000000000002'));
    check('L8 500: 502, todas en faltaron (ml_error), sin reintento', r.status === 502 && r.data.error === 'label_unavailable' && labelsCalls().length === 1 && motivo(r.data, '2000000000001') === 'ml_error' && motivo(r.data, '2000000000002') === 'ml_error', JSON.stringify(r.data));
    reset('e400');
    r = await pedir(A, ids('2000000000001', '2000000000002'));
    check('L8 400 sin nombrar envíos: 502 (no_imprimible), sin reintento', r.status === 502 && labelsCalls().length === 1 && motivo(r.data, '2000000000001') === 'no_imprimible');

    out('\n== L9 ML contesta algo que no es la etiqueta ==');
    reset('json200');
    r = await pedir(A, ids('2000000000001'));
    check('L9 pdf pedido y llega JSON: 502 label_not_pdf', r.status === 502 && r.data.error === 'label_not_pdf');
    reset('pdf');
    r = await pedir(A, ids('2000000000001') + '&formato=zpl');
    check('L9 zpl pedido y llega un PDF: 502 label_not_zpl', r.status === 502 && r.data.error === 'label_not_zpl');

    out('\n== L10 pedidos mal formados ==');
    reset();
    r = await pedir(A, ids('2000000000001') + '&formato=png');
    check('L10 formato desconocido: 400', r.status === 400 && ML.calls.length === 0);
    r = await pedir(A, 'ml_order_ids=');
    check('L10 sin ids: 400', r.status === 400 && ML.calls.length === 0);

    out('\n== L11 el registro ==');
    const todo = LOG.join('\n');
    check('L11 el registro no lleva tokens ni ids de órdenes o envíos', !todo.includes(TOKEN_A) && !todo.includes(TOKEN_B) && !/2000000000\d{3}|4400000000\d/.test(todo), todo.slice(0, 300));
} finally {
    server.close();
}

out(`\nORDERS-LABELS: ${OK} OK, ${FAIL} FAIL`);
if (FAIL) process.exitCode = 1;

/**
 * test/cuevaweb.test.mjs — EL MODO CUEVAWEB (conectar.cuevaweb.com.ar, cuevaweb.js), de punta a punta (12/11/2026).
 *
 * Levanta el server.js DE VERDAD (como proceso aparte, con su migrate.js) contra un Postgres de prueba, un Mercado
 * Libre + Mercado Pago de mentira (OAuth, tokens que ROTAN, /users/me) y una tienda de mentira que verifica la firma de
 * cada aviso con la clave de la tienda. Nada sale de la máquina.
 *
 *   DATABASE_URL_TEST=postgres://usuario:clave@127.0.0.1:5432/una_base_vacia \
 *     node --test test/cuevaweb.test.mjs
 *
 * Sin DATABASE_URL_TEST la prueba se SALTEA y lo dice. ⚠️ La base se usa entera: una base VACÍA y de prueba.
 * Puertos: 3040 (la central), 3043 (Mercado Libre y Mercado Pago de mentira), 3044 (la tienda de mentira).
 *
 * Mide:
 *   C0  sin CUEVAWEB_MODO: /cuevaweb/* no existe (404, también /decidir), la portada es la de Forger y /webhooks contesta
 *       como siempre
 *   C1  el panel registra una tienda (sin firma: 401; con firma: 200) y la clave queda CIFRADA en la base
 *   C2  la tienda con firma mala: 401; con la suya: su estado (nada conectado)
 *   C3  «Conectar con Mercado Libre»: el link firmado → la autorización de la app de CuevaWeb → la vuelta, que (13/11/2026)
 *       ya NO vuelve a la tienda: muestra «Confirmá tu cuenta de Mercado Libre» (200: la cuenta, el dominio y el nombre de
 *       la tienda, los logos y la animación, los dos botones; que no se pueda meter en un iframe ni quede en un caché) con
 *       la conexión pendiente; «Confirmar y conectar» → la tienda, con su paquete firmado (ok y la cuenta); el mismo link
 *       otra vez: «ya se usó»
 *   C3b (13/11/2026) el formulario de la pantalla: el mismo dos veces, adulterado (cada campo y la firma), vencido, del
 *       futuro, sin la decisión o desde otro sitio → 400 «La confirmación venció o ya se usó» sin tocar nada; uno firmado
 *       con la misma receta, sí pasa (el control)
 *   C4  confirmar con otro nonce: 409; con el del navegador: el token (sin el de renovación) y el app_id de CuevaWeb
 *   C5  el token: el mismo mientras vale; con ?forzar=1, uno nuevo (el de renovación ROTÓ en Mercado Libre)
 *   C6  un aviso de Mercado Libre a /webhooks → le llega a la tienda, firmado con SU clave → entregado
 *   C7  la tienda caída: el aviso queda pendiente con el error; la tienda lo trae (GET v1/avisos) y lo confirma (ack)
 *   C8  «Conectar con Mercado Pago» + confirmar: el token y la clave pública; un aviso de pago → a la tienda
 *   C9  el panel fuerza la renovación de Mercado Pago → token nuevo y la tienda recibe «mp_token»
 *   C10 la renovación sola: con menos de 30 días para vencer, se renueva sin que nadie lo pida
 *   C11 otra tienda no puede conectar la MISMA cuenta de Mercado Libre
 *   C12 desconectar: el token ya no se da (404); la baja del panel: la tienda ya no entra (401)
 *   (12/11/2026, la revisión)
 *   C13 el token forzado con `actual`: si el que falló no es el de acá (la tienda tenía uno viejo), no se gasta otra
 *       renovación; si es el de acá, se renueva
 *   C14 los avisos de Mercado Libre, revisados y con tope: un recurso gigante, un tópico raro o un usuario que no es un
 *       número no se guardan; del cuerpo sólo viaja lo esperado (el App ID como texto); (12/11/2026) el de «messages» con
 *       el id solo, sin barra (como lo manda Mercado Libre), llega
 *   C15 los avisos que trae la tienda: los nuevos primero; uno traído y no confirmado espera antes de volver; pasadas 12
 *       veces se descarta (el panel lo cuenta) y no tapa a los demás
 *   C16 los avisos de Mercado Pago: sin firma, con una mala o sin MP_WEBHOOK_SECRET → 401 y no se guarda nada; otro tipo
 *       que no es un pago → se ignora; un cuerpo de más de 64 KB → 413
 *   C17 las direcciones de prueba que no son de esta máquina se ignoran: el dueño va al Mercado Libre y al Mercado Pago
 *       de verdad
 *   (13/11/2026, la confirmación)
 *   C18 la MISMA cuenta otra vez: «Esta cuenta ya está conectada a esta tienda…»; una pantalla vieja (el dueño tocó el
 *       botón otra vez) ya no decide nada; «Cancelar (usar otra cuenta)» borra la pendiente, la tienda recibe «Cancelaste:
 *       no se conectó ninguna cuenta.», la conectada queda igual y el mismo «Cancelar» otra vez da 400
 *   C19 OTRA cuenta de Mercado Libre: «Hoy esta tienda está conectada con …»; un apodo con <script>, un correo y el nombre
 *       de la tienda con lo que hay que escapar, escapados
 *   C20 Mercado Pago: otra cuenta («Los cobros nuevos van a caer en esta cuenta.») y de prueba («Es una cuenta de prueba:
 *       no cobra de verdad.»)
 */
import { LOGOS_CW } from '../cuevaweb-logos.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const RAIZ = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const URL_DB = process.env.DATABASE_URL_TEST || '';
const PC = 3040, PF = 3043, PT = 3044;
const CENTRAL = `http://127.0.0.1:${PC}`;
const FALSO = `http://127.0.0.1:${PF}`;
const TIENDA = `http://127.0.0.1:${PT}`;
const espera = (ms) => new Promise((r) => setTimeout(r, ms));

const azar = (n) => crypto.randomBytes(n).toString('base64url');
const CLAVE_PANEL = azar(36);
const CLAVE_A = azar(36);
const CLAVE_B = azar(36);
const huella = (s) => crypto.createHash('sha256').update(String(s)).digest('base64url');
const hmac = (clave, texto) => crypto.createHmac('sha256', clave).update(texto).digest('base64url');
const idDe = (clave) => huella(`cuevaweb-conectar:${clave}`).slice(0, 32);
const firma = (clave, t, metodo, ruta, cuerpo) => hmac(clave, `${t}.${metodo}.${ruta}.${huella(cuerpo)}`);
const huellaDeToken = (token) => huella(`cuevaweb-token:${token}`).slice(0, 22);
const MP_SECRETO = crypto.randomBytes(24).toString('hex');
// la misma en cada arranque de la central (C17 la reinicia: tiene que poder leer lo que guardó)
const LLAVE_TOKENS = crypto.randomBytes(32).toString('base64');
const SECRETO_HUB = azar(32);

/** Un aviso de Mercado Pago como lo manda Mercado Pago: con su x-signature (buena, mala o ninguna) */
async function avisoMp(query, cuerpo, { firma: f = 'buena', dataId = cuerpo?.data?.id } = {}) {
    const ts = String(Math.floor(Date.now() / 1000));
    const rid = crypto.randomUUID();
    const v1 = crypto.createHmac('sha256', MP_SECRETO).update(`id:${String(dataId).toLowerCase()};request-id:${rid};ts:${ts};`).digest('hex');
    const h = { 'content-type': 'application/json', 'x-request-id': rid };
    if (f === 'buena') h['x-signature'] = `ts=${ts},v1=${v1}`;
    if (f === 'mala') h['x-signature'] = `ts=${ts},v1=${'0'.repeat(64)}`;
    const r = await fetch(`${CENTRAL}/cuevaweb/mp/avisos?${query}`, { method: 'POST', headers: h, body: typeof cuerpo === 'string' ? cuerpo : JSON.stringify(cuerpo) });
    return { status: r.status, datos: await r.json().catch(() => null) };
}

function pgEnv() {
    const u = new URL(URL_DB);
    return { PGHOST: u.hostname, PGPORT: u.port || '5432', PGUSER: decodeURIComponent(u.username), PGPASSWORD: decodeURIComponent(u.password), PGDATABASE: u.pathname.slice(1) };
}

// ── Mercado Libre y Mercado Pago de mentira ─────────────────────────────────────────────────────────────────────────
// (13/11/2026) el apodo, el correo y (Mercado Pago) si es de producción, a mano: la pantalla de confirmación los muestra
const F = {
    ml: { codigos: new Map(), access: null, refresh: null, renovaciones: 0, usuario: 777001, apodo: 'VENDEDOR_PRUEBA', correo: 'vendedor@ejemplo.com' },
    mp: { codigos: new Map(), access: null, refresh: null, renovaciones: 0, usuario: 555001, apodo: 'COBRADOR_PRUEBA', correo: 'cobros@ejemplo.com', vivo: true },
};
function falso() {
    let n = 0;
    return http.createServer(async (req, res) => {
        const u = new URL(req.url, FALSO);
        let crudo = '';
        for await (const parte of req) crudo += parte;
        const form = Object.fromEntries(new URLSearchParams(crudo));
        const json = (s, d) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(d)); };
        const lado = u.pathname.startsWith('/mp/') ? 'mp' : 'ml';
        const ruta = u.pathname.replace(/^\/(ml|mp)/, '');
        const k = F[lado];
        if (req.method === 'GET' && ruta === '/authorization') {
            const code = `code-${lado}-${++n}`;
            k.codigos.set(code, u.searchParams.get('redirect_uri'));
            k.ultimaAutorizacion = Object.fromEntries(u.searchParams);
            const v = new URL(u.searchParams.get('redirect_uri'));
            v.searchParams.set('code', code);
            v.searchParams.set('state', u.searchParams.get('state'));
            res.writeHead(302, { Location: v.toString() });
            return res.end();
        }
        if (req.method === 'POST' && ruta === '/oauth/token') {
            const app = lado === 'ml' ? ['APPML', 'SECRETOML'] : ['APPMP', 'SECRETOMP'];
            if (form.client_id !== app[0] || form.client_secret !== app[1]) return json(401, { error: 'invalid_client' });
            if (form.grant_type === 'authorization_code') {
                if (k.codigos.get(form.code) !== form.redirect_uri) return json(400, { error: 'invalid_grant', message: 'invalid_grant' });
                k.codigos.delete(form.code);
            } else if (form.grant_type === 'refresh_token') {
                if (form.refresh_token !== k.refresh) return json(400, { error: 'invalid_grant', message: 'invalid_grant' });
                k.renovaciones++;
            } else return json(400, { error: 'unsupported_grant_type' });
            k.access = `APP_USR-${lado}-acceso-${++n}`;
            k.refresh = `TG-${lado}-renovar-${++n}`;
            return json(200, lado === 'ml'
                ? { access_token: k.access, refresh_token: k.refresh, expires_in: 21600, user_id: k.usuario }
                : { access_token: k.access, refresh_token: k.refresh, expires_in: 15552000, user_id: k.usuario, public_key: `APP_USR-clave-publica-${n}`, live_mode: k.vivo });
        }
        if (req.method === 'GET' && ruta === '/users/me') {
            if (req.headers.authorization !== `Bearer ${k.access}`) return json(401, { message: 'invalid token' });
            return json(200, { id: k.usuario, nickname: k.apodo, email: k.correo, site_id: 'MLA' });
        }
        json(404, { message: 'no existe' });
    });
}

// ── la tienda de mentira: recibe los avisos y verifica la firma con SU clave ────────────────────────────────────────
const T = { recibidos: [], firmasMalas: 0, caida: false };
function tiendaFalsa() {
    return http.createServer(async (req, res) => {
        let crudo = '';
        for await (const parte of req) crudo += parte;
        const u = new URL(req.url, TIENDA);
        const json = (s, d) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(d)); };
        if (req.method === 'POST' && u.pathname === '/api/cuevaweb/conectar/aviso') {
            const t = String(req.headers['x-cuevaweb-tiempo'] || '');
            const f = String(req.headers['x-cuevaweb-firma'] || '');
            if (f !== firma(CLAVE_A, t, 'POST', u.pathname, crudo)) { T.firmasMalas++; return json(401, { ok: false }); }
            if (T.caida) return json(500, { ok: false, error: 'caída' });
            const d = JSON.parse(crudo);
            T.recibidos.push(...d.avisos);
            return json(200, { ok: true, hechos: d.avisos.map((a) => a.id) });
        }
        json(404, { ok: false });
    });
}

async function pedir(metodo, ruta, { clave, tienda, cuerpo, base = CENTRAL } = {}) {
    const texto = cuerpo === undefined ? '' : JSON.stringify(cuerpo);
    const h = { 'content-type': 'application/json' };
    if (clave) {
        const t = String(Date.now());
        h['x-cuevaweb-tiempo'] = t;
        h['x-cuevaweb-firma'] = firma(clave, t, metodo, ruta.split('?')[0], texto);
    }
    if (tienda) h['x-cuevaweb-tienda'] = idDe(tienda);
    const r = await fetch(base + ruta, { method: metodo, headers: h, body: metodo === 'GET' ? undefined : texto, redirect: 'manual' });
    return { status: r.status, datos: await r.json().catch(() => null), location: r.headers.get('location') };
}

function linkConectar(clave, servicio, n = azar(24)) {
    const d = Buffer.from(JSON.stringify({ s: servicio, v: servicio === 'ml' ? '/admin/mercadolibre/conexion' : '/admin/pagos', n, e: Date.now() + 10 * 60_000 })).toString('base64url');
    return { url: `${CENTRAL}/cuevaweb/conectar?t=${idDe(clave)}&d=${d}&f=${hmac(clave, `conectar.${d}`)}`, n };
}
/** (13/11/2026) conectar, la vuelta y la decisión comparten un límite: 40 pedidos cada 15 minutos por IP (y acá todo sale
 *  de 127.0.0.1). Se anota cuánto queda, así una prueba nueva que lo pase falla diciéndolo (y no con un 429 raro). */
let quedanConectar = null;
function anotarLimite(u, r) {
    const queda = r.headers.get('x-ratelimit-remaining');
    if (new URL(u).origin === CENTRAL && new URL(u).pathname.startsWith('/cuevaweb/') && queda != null) quedanConectar = Number(queda);
}
/** Si la dirección es la vuelta a la tienda (/api/conectar/vuelta), lo que trae: su paquete y si lo firmó con su clave. */
function vueltaDe(loc, base, clave) {
    const v = new URL(loc, base);
    if (v.pathname !== '/api/conectar/vuelta') return null;
    const d = v.searchParams.get('d');
    const f = v.searchParams.get('f');
    const valido = f === hmac(clave, `conectar.vuelta.${d}`);
    return { vuelta: v.pathname, valido, datos: JSON.parse(Buffer.from(d, 'base64url').toString('utf8')) };
}
const desescapar = (s) => s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
/** (13/11/2026) El formulario de la pantalla de confirmación: adónde va y sus campos ocultos (como los manda el navegador). */
function leerFormulario(html, base) {
    const accion = /<form method="POST" action="([^"]+)"/.exec(html);
    if (!accion) return null;
    const campos = {};
    for (const m of html.matchAll(/<input type="hidden" name="([a-z]+)" value="([^"]*)"/g)) campos[m[1]] = desescapar(m[2]);
    return { accion: new URL(desescapar(accion[1]), base).toString(), campos };
}
/** El dueño toca el botón de su tienda: el navegador sigue las redirecciones hasta la pantalla de confirmación de conectar
 *  (status 200, el HTML, los encabezados y el formulario) o, si algo falla antes, hasta volver a la tienda (sin entrar). */
async function irHasta(url, clave) {
    let u = url;
    for (let i = 0; i < 6; i++) {
        const r = await fetch(u, { redirect: 'manual' });
        anotarLimite(u, r);
        const loc = r.headers.get('location');
        if (!loc) {
            const html = await r.text();
            return { status: r.status, html, encabezados: r.headers, form: leerFormulario(html, u) };
        }
        const v = vueltaDe(loc, u, clave);
        if (v) return v;
        u = new URL(loc, u).toString();
    }
    throw new Error('demasiadas redirecciones');
}
/** En la pantalla, el dueño toca «Confirmar y conectar» (confirm) o «Cancelar (usar otra cuenta)» (cancel): el navegador
 *  manda el formulario (con `cambiar`, adulterado; sin `decision`, sin el botón) y vuelve a la tienda o muestra el error. */
async function decidir(form, decision, clave, { cambiar = {}, encabezados = {} } = {}) {
    const cuerpo = new URLSearchParams({ ...form.campos, ...cambiar });
    if (decision) cuerpo.set('decision', decision);
    const r = await fetch(form.accion, {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...encabezados }, body: cuerpo.toString(), redirect: 'manual',
    });
    anotarLimite(form.accion, r);
    const loc = r.headers.get('location');
    const v = loc ? vueltaDe(loc, form.accion, clave) : null;
    if (v) return { status: r.status, ...v };
    return { status: r.status, location: loc, html: await r.text() };
}
/** Todo junto: el botón de la tienda, la pantalla y uno de sus botones (si algo falla antes de la pantalla, la vuelta con
 *  el error, como antes). */
async function irYVolver(url, clave, decision = 'confirm') {
    const ida = await irHasta(url, clave);
    if (ida.vuelta) return ida;
    assert.equal(ida.status, 200, ida.html);
    assert.ok(ida.form, 'la pantalla trae el formulario');
    return { ...(await decidir(ida.form, decision, clave)), pantalla: ida };
}

let central = null;
const servidores = [];
const db = URL_DB ? new pg.Pool({ connectionString: URL_DB }) : null;

function arrancarCentral(extra) {
    const env = {
        ...process.env, ...pgEnv(), PORT: String(PC), BASE_URL: CENTRAL, DATA_DIR: path.join(os.tmpdir(), 'cml-cuevaweb-test'),
        ML_CLIENT_ID: 'APPML', ML_CLIENT_SECRET: 'SECRETOML', WFML_OAUTH_HUB_SECRET: SECRETO_HUB, WFML_TOKEN_KEY: LLAVE_TOKENS,
        MP_CLIENT_ID: 'APPMP', MP_CLIENT_SECRET: 'SECRETOMP', MP_WEBHOOK_SECRET: MP_SECRETO,
        ML_AUTH_DOMAIN: `${FALSO}/ml`, CUEVAWEB_ML_API_URL: `${FALSO}/ml`,
        MP_AUTH_DOMAIN: `${FALSO}/mp`, MP_TOKEN_URL: `${FALSO}/mp/oauth/token`, CUEVAWEB_MP_API_URL: `${FALSO}/mp`,
        CUEVAWEB_CONECTAR_CLAVE: CLAVE_PANEL, CUEVAWEB_AVISOS_CADA_MS: '1000', CUEVAWEB_RENOVAR_CADA_MS: '1500',
        LICENSE_ENFORCE: 'off',
        ...extra,
    };
    for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
    const p = spawn(process.execPath, ['server.js'], { cwd: RAIZ, env, stdio: ['ignore', 'pipe', 'pipe'] });
    p.log = '';
    p.stdout.on('data', (b) => { p.log += b; });
    p.stderr.on('data', (b) => { p.log += b; });
    return p;
}
async function hastaQueConteste() {
    for (let i = 0; i < 60; i++) {
        try { if ((await fetch(`${CENTRAL}/healthz`)).ok) return; } catch (_) { /* arrancando */ }
        await espera(250);
    }
    throw new Error('la central no levantó:\n' + (central && central.log));
}
async function apagarCentral() {
    if (!central) return;
    const p = central;
    central = null;
    p.kill();
    await new Promise((r) => p.once('exit', r));
}
async function hasta(fn, ms = 8000) {
    const t0 = Date.now();
    let v;
    while (Date.now() - t0 < ms) {
        v = await fn();
        if (v) return v;
        await espera(150);
    }
    return v;
}

test('el modo CuevaWeb de punta a punta', { skip: URL_DB ? false : 'sin DATABASE_URL_TEST (una base Postgres VACÍA de prueba)' }, async (t) => {
    // la base limpia y migrada (la misma migrate.js de producción)
    await db.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
    const m = spawnSync(process.execPath, ['migrate.js'], { cwd: RAIZ, env: { ...process.env, ...pgEnv() }, encoding: 'utf8' });
    assert.equal(m.status, 0, m.stdout + m.stderr);
    for (const [s, p] of [[falso(), PF], [tiendaFalsa(), PT]]) {
        await new Promise((r) => s.listen(p, '127.0.0.1', r));
        servidores.push(s);
    }

    try {
        await t.test('C0 sin CUEVAWEB_MODO: Forger como siempre', async () => {
            central = arrancarCentral({ CUEVAWEB_MODO: undefined });
            await hastaQueConteste();
            assert.equal((await fetch(`${CENTRAL}/cuevaweb/v1/estado`)).status, 404);
            assert.equal((await fetch(`${CENTRAL}/cuevaweb/conectar`)).status, 404);
            assert.equal((await fetch(`${CENTRAL}/cuevaweb/ml/decidir`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'decision=confirm' })).status, 404);
            assert.match(await (await fetch(`${CENTRAL}/`)).text(), /Forger/);
            const w = await fetch(`${CENTRAL}/webhooks`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ topic: 'orders_v2', resource: '/orders/1', user_id: 1, application_id: 'APPML' }) });
            assert.equal(w.status, 200);
            await apagarCentral();
        });

        central = arrancarCentral({ CUEVAWEB_MODO: '1' });
        await hastaQueConteste();

        await t.test('C1 el panel registra la tienda', async () => {
            assert.match(await (await fetch(`${CENTRAL}/`)).text(), /CuevaWeb/);
            const sin = await pedir('PUT', '/cuevaweb/panel/tiendas/tiendaA', { cuerpo: { url: TIENDA, clave: CLAVE_A, nombre: 'Tienda A' } });
            assert.equal(sin.status, 401);
            const r = await pedir('PUT', '/cuevaweb/panel/tiendas/tiendaA', { clave: CLAVE_PANEL, cuerpo: { url: TIENDA, clave: CLAVE_A, nombre: 'Tienda A' } });
            assert.equal(r.status, 200, JSON.stringify(r.datos));
            assert.equal(r.datos.tienda.url, TIENDA);
            const fila = (await db.query('SELECT clave, clave_id FROM cuevaweb_tiendas WHERE panel_id = $1', ['tiendaA'])).rows[0];
            assert.ok(fila.clave.startsWith('enc1:') && !fila.clave.includes(CLAVE_A), 'la clave guardada cifrada');
            assert.equal(fila.clave_id, idDe(CLAVE_A));
        });

        await t.test('C2 la tienda se identifica con su clave', async () => {
            assert.equal((await pedir('GET', '/cuevaweb/v1/estado', { clave: CLAVE_B, tienda: CLAVE_A })).status, 401);
            assert.equal((await pedir('GET', '/cuevaweb/v1/estado', { tienda: CLAVE_A })).status, 401);
            const r = await pedir('GET', '/cuevaweb/v1/estado', { clave: CLAVE_A, tienda: CLAVE_A });
            assert.equal(r.status, 200);
            assert.equal(r.datos.ml, null);
            assert.equal(r.datos.mp, null);
            assert.deepEqual(r.datos.disponibles, { ml: true, mp: true });
        });

        let nMl = '';
        let formMl = null;
        await t.test('C3 «Conectar con Mercado Libre»: la pantalla de confirmación y «Confirmar y conectar»', async () => {
            const { url, n } = linkConectar(CLAVE_A, 'ml');
            nMl = n;
            // (13/11/2026) la vuelta del OAuth ya NO vuelve a la tienda: muestra qué cuenta entró
            const ida = await irHasta(url, CLAVE_A);
            assert.ok(!ida.vuelta, `volvió a la tienda sin preguntar: ${JSON.stringify(ida.datos)}`);
            assert.equal(ida.status, 200, ida.html);
            assert.ok(ida.form, 'la pantalla trae el formulario');
            assert.equal(new URL(ida.form.accion).pathname, '/cuevaweb/ml/decidir');
            assert.deepEqual(Object.keys(ida.form.campos).sort(), ['f', 'jti', 'n', 't', 'ts', 'u', 'v']);
            const h = ida.html;
            assert.match(h, /<title>Confirmá tu cuenta de Mercado Libre · CuevaWeb<\/title>/);
            assert.match(h, /<h1>Confirmá tu cuenta de Mercado Libre<\/h1>/);
            assert.match(h, /<button type="submit" name="decision" value="cancel" class="btn btn-secondary">Cancelar \(usar otra cuenta\)<\/button>/);
            assert.match(h, /<button type="submit" name="decision" value="confirm" class="btn btn-primary">Confirmar y conectar<\/button>/);
            assert.match(h, /<span class="v big">VENDEDOR_PRUEBA<\/span>/, 'el apodo, grande');
            assert.ok(h.includes('vendedor@ejemplo.com'), 'el correo');
            assert.ok(h.includes('Argentina (MLA)'), 'el país');
            assert.ok(h.includes('<code>777001</code>'), 'el número de usuario');
            assert.ok(h.includes('<span class="site-pill">127.0.0.1:3044</span>'), 'el dominio de la tienda');
            assert.ok(h.includes('<span class="tienda">Tienda A</span>'), 'el nombre de la tienda');
            // (13/11/2026, la revisión) los logos van adentro de conectar (cuevaweb-logos.js), no de direcciones de afuera
            assert.ok(h.includes(`src="${LOGOS_CW.cuevaweb}"`) && h.includes(`src="${LOGOS_CW.ml}"`) && !h.includes('mlstatic') && !h.includes('cuevaweb.com.ar/img') && h.includes('<svg'), 'los logos (y la tienda, dibujada)');
            assert.ok(h.includes('Publicaciones en Mercado Libre') && h.includes('Capa de integración'));
            assert.ok(h.includes('@keyframes pulse') && h.includes('@keyframes flow') && h.includes('class="halo"'), 'la animación del trío');
            assert.ok(h.includes('#8b5cf6') && !/#E55B0F/i.test(h) && !/forger/i.test(h), 'la marca de CuevaWeb, nada de Forger');
            assert.ok(!h.includes('class="warnings"'), 'sin avisos: la tienda no tenía nada conectado');
            assert.ok(!h.includes(F.ml.access) && !h.includes(F.ml.refresh), 'los tokens nunca en la pantalla');
            // que no se pueda meter en un iframe (clickjacking) ni quede en un caché
            assert.equal(ida.encabezados.get('x-frame-options'), 'DENY');
            assert.match(ida.encabezados.get('content-security-policy') || '', /frame-ancestors 'none'/);
            assert.match(ida.encabezados.get('cache-control') || '', /no-store/);
            assert.equal(ida.encabezados.get('referrer-policy'), 'no-referrer');
            // la conexión, pendiente: la tienda todavía no recibió nada
            const filas = (await db.query(`SELECT estado, nonce FROM cuevaweb_conexiones WHERE servicio = 'ml'`)).rows;
            assert.deepEqual(filas.map((r) => r.estado), ['pendiente']);
            // (13/11/2026, la revisión) el nonce, MARCADO hasta que el dueño decida: /v1/confirmar no la encuentra todavía
            assert.equal(filas[0].nonce, '?' + n);
            // «Confirmar y conectar» → a la tienda, con su paquete firmado (ok, la cuenta y el usuario)
            formMl = ida.form;
            const v = await decidir(ida.form, 'confirm', CLAVE_A);
            assert.equal(v.status, 303);
            assert.equal(v.vuelta, '/api/conectar/vuelta');
            assert.ok(v.valido, 'el paquete de vuelta firmado con la clave de la tienda');
            assert.equal(v.datos.ok, true, JSON.stringify(v.datos));
            assert.equal(v.datos.n, n);
            assert.equal(v.datos.cuenta, 'VENDEDOR_PRUEBA');
            assert.equal(v.datos.usuario, '777001');
            assert.equal(v.datos.v, '/admin/mercadolibre/conexion');
            assert.equal(F.ml.ultimaAutorizacion.client_id, 'APPML');
            assert.equal(F.ml.ultimaAutorizacion.redirect_uri, `${CENTRAL}/cuevaweb/ml/volver`);
            const otraVez = await irYVolver(url, CLAVE_A);
            assert.equal(otraVez.datos.ok, false);
            assert.match(otraVez.datos.error, /ya se usó/);
        });

        await t.test('C3b el formulario: de un solo uso, firmado y con vencimiento (sin tocar nada)', async () => {
            const noVale = (r, que) => {
                assert.equal(r.status, 400, `${que}: ${r.status} ${JSON.stringify(r.datos || '')}`);
                assert.match(r.html, /La confirmación venció o ya se usó/, que);
                assert.match(r.html, /Volvé al panel de tu tienda y tocá el botón otra vez\./, que);
            };
            // el mismo formulario otra vez («Confirmar y conectar» ya se usó)
            noVale(await decidir(formMl, 'confirm', CLAVE_A), 'repetido');
            noVale(await decidir(formMl, 'cancel', CLAVE_A), 'repetido, con «Cancelar»');
            // la receta de la firma (la prueba conoce WFML_OAUTH_HUB_SECRET): uno nuevo, bien firmado
            const llave = crypto.createHmac('sha256', SECRETO_HUB).update('cuevaweb-decidir.v1').digest();
            const firmar = (c) => hmac(llave, JSON.stringify(['cw-decidir', c.t, 'ml', c.n, c.v, c.u, c.ts, c.jti]));
            const jtis = [];
            const nuevo = (cambios = {}) => {
                const c = { ...formMl.campos, jti: crypto.randomBytes(16).toString('hex'), ts: String(Math.floor(Date.now() / 1000)), ...cambios };
                jtis.push(c.jti);
                return { accion: formMl.accion, campos: { ...c, f: firmar(c) } };
            };
            // el control: uno firmado con la misma receta SÍ pasa (confirmar no cambia nada: la tienda es la que confirma)
            const control = await decidir(nuevo(), 'confirm', CLAVE_A);
            assert.equal(control.status, 303, control.html);
            assert.equal(control.datos.ok, true);
            const usado = jtis.pop();
            // vencido (16 minutos) y del futuro (5 minutos), bien firmados
            noVale(await decidir(nuevo({ ts: String(Math.floor(Date.now() / 1000) - 16 * 60) }), 'confirm', CLAVE_A), 'vencido');
            noVale(await decidir(nuevo({ ts: String(Math.floor(Date.now() / 1000) + 5 * 60) }), 'confirm', CLAVE_A), 'del futuro');
            // adulterado después de firmar: cada campo, y la firma
            for (const [k, v] of [['n', azar(24)], ['v', '/admin/pagos'], ['t', '999'], ['u', '999999'], ['ts', String(Math.floor(Date.now() / 1000) - 1)], ['jti', crypto.randomBytes(16).toString('hex')]]) {
                noVale(await decidir(nuevo(), 'confirm', CLAVE_A, { cambiar: { [k]: v } }), `adulterado: ${k}`);
            }
            const f = nuevo();
            noVale(await decidir(f, 'confirm', CLAVE_A, { cambiar: { f: f.campos.f.slice(0, -2) + (f.campos.f.endsWith('AA') ? 'BB' : 'AA') } }), 'la firma cambiada');
            // sin la decisión (ningún botón) y desde otro sitio
            noVale(await decidir(nuevo(), '', CLAVE_A), 'sin la decisión');
            noVale(await decidir(nuevo(), 'confirm', CLAVE_A, { encabezados: { 'sec-fetch-site': 'cross-site' } }), 'desde otro sitio');
            // nada se tocó: la pendiente sigue (con su nonce) y ninguno de los rechazados se gastó
            const p = (await db.query(`SELECT estado, nonce FROM cuevaweb_conexiones WHERE servicio = 'ml'`)).rows;
            assert.deepEqual(p.map((r) => [r.estado, r.nonce]), [['pendiente', nMl]]);
            const gastados = (await db.query(`SELECT nonce FROM request_nonces WHERE purpose = 'cw_decidir' AND nonce = ANY($1::text[])`, [jtis])).rows;
            assert.deepEqual(gastados, [], 'los rechazados no gastan su jti');
            assert.equal((await db.query(`SELECT COUNT(*)::int AS n FROM request_nonces WHERE purpose = 'cw_decidir' AND nonce = ANY($1::text[])`, [[usado, formMl.campos.jti]])).rows[0].n, 2, 'los que pasaron, sí');
        });

        let tokenMl = '';
        await t.test('C4 confirmar: sólo con el nonce del navegador', async () => {
            const mal = await pedir('POST', '/cuevaweb/v1/confirmar', { clave: CLAVE_A, tienda: CLAVE_A, cuerpo: { servicio: 'ml', n: azar(24) } });
            assert.equal(mal.status, 409);
            const r = await pedir('POST', '/cuevaweb/v1/confirmar', { clave: CLAVE_A, tienda: CLAVE_A, cuerpo: { servicio: 'ml', n: nMl } });
            assert.equal(r.status, 200, JSON.stringify(r.datos));
            assert.equal(r.datos.access_token, F.ml.access);
            assert.equal(r.datos.app_id, 'APPML');
            assert.equal(r.datos.usuario_id, '777001');
            assert.equal(r.datos.nombre, 'VENDEDOR_PRUEBA');
            assert.ok(!JSON.stringify(r.datos).includes(F.ml.refresh), 'nunca el de renovación');
            tokenMl = r.datos.access_token;
            const enc = (await db.query(`SELECT access_enc, refresh_enc FROM cuevaweb_conexiones WHERE servicio = 'ml'`)).rows[0];
            assert.ok(!enc.access_enc.includes('APP_USR') && !enc.refresh_enc.includes('TG-'), 'los tokens, cifrados');
        });

        await t.test('C5 el token: el mismo mientras vale; forzado, uno nuevo', async () => {
            const a = await pedir('GET', '/cuevaweb/v1/ml/token', { clave: CLAVE_A, tienda: CLAVE_A });
            assert.equal(a.datos.access_token, tokenMl);
            assert.equal(F.ml.renovaciones, 0);
            const b = await pedir('GET', '/cuevaweb/v1/ml/token?forzar=1', { clave: CLAVE_A, tienda: CLAVE_A });
            assert.equal(b.status, 200);
            assert.notEqual(b.datos.access_token, tokenMl);
            assert.equal(b.datos.access_token, F.ml.access);
            assert.equal(F.ml.renovaciones, 1);
            // dos forzados a la vez, recién renovado: ninguna renovación más (el de renovación sirve una sola vez)
            const [x, y] = await Promise.all([1, 2].map(() => pedir('GET', '/cuevaweb/v1/ml/token?forzar=1', { clave: CLAVE_A, tienda: CLAVE_A })));
            assert.equal(x.status, 200);
            assert.equal(y.status, 200);
            assert.equal(x.datos.access_token, b.datos.access_token);
            assert.equal(y.datos.access_token, b.datos.access_token);
            assert.equal(F.ml.renovaciones, 1);
        });

        await t.test('C13 el token forzado con `actual`: sólo se renueva si el que falló es el de acá', async () => {
            // fuera de los 20 segundos de «recién renovado»
            await db.query(`UPDATE cuevaweb_conexiones SET renovada = NOW() - INTERVAL '5 minutes' WHERE servicio = 'ml' AND estado = 'activa'`);
            const ahora = F.ml.access;
            const viejo = await pedir('GET', `/cuevaweb/v1/ml/token?forzar=1&actual=${huellaDeToken('APP_USR-uno-viejo-que-ya-no-sirve')}`, { clave: CLAVE_A, tienda: CLAVE_A });
            assert.equal(viejo.status, 200);
            assert.equal(viejo.datos.access_token, ahora, 'la tienda tenía uno viejo: se le da el de ahora');
            assert.equal(F.ml.renovaciones, 1, 'sin gastar otra renovación');
            const esteFallo = await pedir('GET', `/cuevaweb/v1/ml/token?forzar=1&actual=${huellaDeToken(ahora)}`, { clave: CLAVE_A, tienda: CLAVE_A });
            assert.equal(esteFallo.status, 200);
            assert.equal(F.ml.renovaciones, 2, 'el que falló es el de acá: se renueva');
            assert.notEqual(esteFallo.datos.access_token, ahora);
            assert.equal(esteFallo.datos.access_token, F.ml.access);
            tokenMl = esteFallo.datos.access_token;
        });

        // (13/11/2026, la confirmación) Después de C5 y C13: un OAuth nuevo le cambia los tokens al Mercado Libre de mentira
        // (guarda uno solo) y la conexión de la tienda ya no se renovaría; de acá en adelante, Mercado Libre no se renueva.
        await t.test('C18 la misma cuenta otra vez: el aviso y «Cancelar (usar otra cuenta)»', async () => {
            const activa = async () => (await db.query(`SELECT id, usuario_id, access_enc, refresh_enc, confirmada FROM cuevaweb_conexiones WHERE servicio = 'ml' AND estado = 'activa'`)).rows;
            const antes = await activa();
            assert.equal(antes.length, 1);
            // una pantalla que el dueño deja abierta… y vuelve a tocar el botón: otra vuelta, otra pendiente
            const vieja = await irHasta(linkConectar(CLAVE_A, 'ml').url, CLAVE_A);
            assert.equal(vieja.status, 200, vieja.html);
            const { url, n } = linkConectar(CLAVE_A, 'ml');
            const ida = await irHasta(url, CLAVE_A);
            assert.equal(ida.status, 200, ida.html);
            // la pantalla vieja ya no decide nada (su pendiente la reemplazó la nueva): 400 y la nueva sigue ahí
            const deLaVieja = await decidir(vieja.form, 'confirm', CLAVE_A);
            assert.equal(deLaVieja.status, 400, JSON.stringify(deLaVieja.datos || ''));
            assert.ok(ida.html.includes('<strong>⚠ Atención antes de confirmar:</strong>'));
            assert.ok(ida.html.includes('<li>Esta cuenta ya está conectada a esta tienda: confirmar sólo renueva el permiso (no duplica nada).</li>'));
            assert.ok(!ida.html.includes('Hoy esta tienda está conectada con'));
            assert.equal((await db.query(`SELECT COUNT(*)::int AS n FROM cuevaweb_conexiones WHERE servicio = 'ml' AND estado = 'pendiente' AND nonce = $1`, ['?' + n])).rows[0].n, 1);
            // «Cancelar (usar otra cuenta)» → la pendiente se borra y la tienda se entera
            const v = await decidir(ida.form, 'cancel', CLAVE_A);
            assert.equal(v.status, 303);
            assert.ok(v.valido, 'firmado con la clave de la tienda');
            assert.deepEqual({ ok: v.datos.ok, error: v.datos.error, n: v.datos.n, v: v.datos.v }, { ok: false, error: 'Cancelaste: no se conectó ninguna cuenta.', n, v: '/admin/mercadolibre/conexion' });
            assert.equal(v.datos.cuenta, undefined);
            assert.equal((await db.query(`SELECT COUNT(*)::int AS n FROM cuevaweb_conexiones WHERE servicio = 'ml' AND estado = 'pendiente'`)).rows[0].n, 0, 'la pendiente, borrada');
            assert.deepEqual(await activa(), antes, 'la conectada, igual que antes');
            // el mismo «Cancelar» otra vez: 400; y la tienda ya no la puede confirmar
            const otra = await decidir(ida.form, 'cancel', CLAVE_A);
            assert.equal(otra.status, 400);
            assert.match(otra.html, /La confirmación venció o ya se usó/);
            assert.equal((await pedir('POST', '/cuevaweb/v1/confirmar', { clave: CLAVE_A, tienda: CLAVE_A, cuerpo: { servicio: 'ml', n } })).status, 409);
            assert.deepEqual(await activa(), antes);
        });

        await t.test('C19 otra cuenta de Mercado Libre: el aviso, y lo de afuera escapado (un apodo con <script>)', async () => {
            // el nombre de la tienda con lo que hay que escapar (el panel la vuelve a registrar igual, con otro nombre)
            const nombreRaro = `Tienda <A> & "Cía" 'x'`;
            assert.equal((await pedir('PUT', '/cuevaweb/panel/tiendas/tiendaA', { clave: CLAVE_PANEL, cuerpo: { url: TIENDA, clave: CLAVE_A, nombre: nombreRaro } })).status, 200);
            const guardado = { usuario: F.ml.usuario, apodo: F.ml.apodo, correo: F.ml.correo };
            Object.assign(F.ml, { usuario: 777002, apodo: '<script>alert("apodo")</script>', correo: 'otra"><img src=x onerror=alert(1)>@ejemplo.com' });
            try {
                const ida = await irHasta(linkConectar(CLAVE_A, 'ml').url, CLAVE_A);
                assert.equal(ida.status, 200, ida.html);
                const h = ida.html;
                assert.ok(!h.includes('<script'), 'ningún <script> en la página');
                assert.ok(!h.includes('<img src=x'), 'el correo no entra como HTML');
                assert.ok(h.includes('<span class="v big">&lt;script&gt;alert(&quot;apodo&quot;)&lt;/script&gt;</span>'), 'el apodo, escapado');
                assert.ok(h.includes('otra&quot;&gt;&lt;img src=x onerror=alert(1)&gt;@ejemplo.com'), 'el correo, escapado');
                assert.ok(h.includes('<span class="tienda">Tienda &lt;A&gt; &amp; &quot;Cía&quot; &#39;x&#39;</span>'), 'el nombre de la tienda, escapado');
                assert.ok(h.includes('<span class="site-pill">127.0.0.1:3044</span>'), 'el dominio de la tienda');
                assert.ok(h.includes('<code>777002</code>'));
                assert.ok(h.includes('<li>Hoy esta tienda está conectada con <strong>VENDEDOR_PRUEBA</strong>. Si confirmás, se cambia por esta, salvo que la tienda ya haya traído publicaciones o ventas de esa cuenta: en ese caso no se cambia nada y primero hay que desconectarla.</li>'), 'el aviso de la otra cuenta');
                assert.ok(!h.includes('Los cobros nuevos'), 'eso es de Mercado Pago');
                assert.ok(!h.includes('Esta cuenta ya está conectada a esta tienda'));
                const v = await decidir(ida.form, 'cancel', CLAVE_A);
                assert.equal(v.datos.ok, false);
            } finally {
                Object.assign(F.ml, guardado);
            }
            assert.deepEqual((await db.query(`SELECT usuario_id, estado FROM cuevaweb_conexiones WHERE servicio = 'ml'`)).rows, [{ usuario_id: '777001', estado: 'activa' }], 'sigue la de antes');
            assert.equal((await pedir('PUT', '/cuevaweb/panel/tiendas/tiendaA', { clave: CLAVE_PANEL, cuerpo: { url: TIENDA, clave: CLAVE_A, nombre: 'Tienda A' } })).status, 200);
        });

        await t.test('C6 un aviso de Mercado Libre llega a la tienda, firmado', async () => {
            const w = await fetch(`${CENTRAL}/webhooks`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ _id: 'aviso-1', topic: 'orders_v2', resource: '/orders/2000001', user_id: 777001, application_id: 'APPML' }) });
            assert.equal(w.status, 200);
            const llego = await hasta(() => T.recibidos.find((a) => a.recurso === '/orders/2000001'));
            assert.ok(llego, 'llegó a la tienda');
            assert.equal(llego.origen, 'ml');
            assert.equal(llego.cuerpo.topic, 'orders_v2');
            assert.equal(T.firmasMalas, 0);
            const fila = await hasta(async () => (await db.query(`SELECT entregado FROM cuevaweb_avisos WHERE recurso = '/orders/2000001' AND entregado IS NOT NULL`)).rows[0]);
            assert.ok(fila, 'marcado como entregado');
            // de OTRA app: no se reenvía
            await fetch(`${CENTRAL}/webhooks`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ _id: 'aviso-2', topic: 'orders_v2', resource: '/orders/9', user_id: 777001, application_id: 'OTRA' }) });
            await espera(800);
            assert.equal((await db.query(`SELECT COUNT(*)::int AS n FROM cuevaweb_avisos WHERE recurso = '/orders/9'`)).rows[0].n, 0);
        });

        await t.test('C14 los avisos de Mercado Libre, revisados y con tope', async () => {
            const mandar = (b) => fetch(`${CENTRAL}/webhooks`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) });
            const gigante = `/orders/1${'A'.repeat(300_000)}`;
            for (const b of [
                { _id: 'aviso-g1', topic: 'orders_v2', resource: gigante, user_id: 777001, application_id: 'APPML' },
                { _id: 'aviso-g2', topic: 'x'.repeat(5000), resource: '/orders/31', user_id: 777001, application_id: 'APPML' },
                { _id: 'aviso-g3', topic: 'payments', resource: '/orders/32', user_id: 777001, application_id: 'APPML' },
                { _id: 'aviso-g4', topic: 'orders_v2', resource: '/orders/33', user_id: '777001 OR 1=1', application_id: 'APPML' },
                { _id: 'aviso-g5', topic: 'orders_v2', resource: { a: 1 }, user_id: 777001, application_id: 'APPML' },
            ]) assert.equal((await mandar(b)).status, 200, 'Mercado Libre siempre recibe un 200');
            // el bueno, con basura alrededor: sólo viaja lo esperado
            await mandar({ _id: 'z'.repeat(500), topic: 'questions', resource: '/questions/77', user_id: 777001, application_id: 'APPML', attempts: { muchos: 'x'.repeat(10_000) }, sent: 'y'.repeat(5000), received: '2026-11-12T10:00:00.000Z', otro: 'x'.repeat(20_000) });
            const llego = await hasta(() => T.recibidos.find((a) => a.recurso === '/questions/77'));
            assert.ok(llego, 'el bueno llegó');
            assert.deepEqual(Object.keys(llego.cuerpo).sort(), ['application_id', 'received', 'resource', 'topic', 'user_id'], JSON.stringify(llego.cuerpo).slice(0, 300));
            assert.equal(llego.cuerpo.application_id, 'APPML', 'el App ID como texto');
            const filas = (await db.query(`SELECT recurso, length(cuerpo::text) AS largo FROM cuevaweb_avisos`)).rows;
            assert.ok(!filas.some((f) => /^\/orders\/3[123]$/.test(f.recurso) || f.recurso.length > 200), JSON.stringify(filas.map((f) => f.recurso.slice(0, 40))));
            assert.ok(filas.every((f) => f.largo < 2048), 'ningún cuerpo grande');
            // (12/11/2026) «messages» llega con el id solo, sin barra (como lo manda Mercado Libre): tiene que llegar
            await mandar({ _id: 'aviso-msj-1', topic: 'messages', resource: 'bd5f7ef4a5a14d2cb8c6c6a4ec8c3e6c', user_id: 777001, application_id: 'APPML' });
            const mensaje = await hasta(() => T.recibidos.find((a) => a.recurso === 'bd5f7ef4a5a14d2cb8c6c6a4ec8c3e6c'));
            assert.ok(mensaje, 'el aviso de un mensaje (sin barra) llegó a la tienda');
            assert.equal(mensaje.tema, 'messages');
        });

        await t.test('C7 la tienda caída: pendiente → la tienda lo trae y lo confirma', async () => {
            T.caida = true;
            await fetch(`${CENTRAL}/webhooks`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ _id: 'aviso-3', topic: 'questions', resource: '/questions/31', user_id: 777001, application_id: 'APPML' }) });
            const conError = await hasta(async () => (await db.query(`SELECT error, intentos FROM cuevaweb_avisos WHERE recurso = '/questions/31' AND error IS NOT NULL`)).rows[0]);
            assert.ok(conError, 'quedó con el error');
            const p = await pedir('GET', '/cuevaweb/v1/avisos', { clave: CLAVE_A, tienda: CLAVE_A });
            const a = p.datos.avisos.find((x) => x.recurso === '/questions/31');
            assert.ok(a, JSON.stringify(p.datos));
            assert.equal(a.cuerpo.topic, 'questions');
            const ack = await pedir('POST', '/cuevaweb/v1/avisos/ack', { clave: CLAVE_A, tienda: CLAVE_A, cuerpo: { ids: [a.id] } });
            assert.equal(ack.datos.marcados, 1);
            const despues = await pedir('GET', '/cuevaweb/v1/avisos', { clave: CLAVE_A, tienda: CLAVE_A });
            assert.ok(!despues.datos.avisos.some((x) => x.id === a.id));
            T.caida = false;
        });

        await t.test('C15 los avisos que trae la tienda: los nuevos primero, sin trabarse', async () => {
            T.caida = true;
            try { await c15(); } finally { T.caida = false; }
        });
        async function c15() {
            const mandar = (n) => fetch(`${CENTRAL}/webhooks`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ _id: `aviso-c15-${n}`, topic: 'questions', resource: `/questions/15${n}`, user_id: 777001, application_id: 'APPML' }) });
            const conError = async (rec) => (await db.query(`SELECT 1 FROM cuevaweb_avisos WHERE recurso = $1 AND error IS NOT NULL`, [rec])).rowCount > 0;
            for (const n of [1, 2, 3]) {
                await mandar(n);
                assert.ok(await hasta(() => conError(`/questions/15${n}`)), `el ${n}, sin poder entregarse`);
            }
            const traer = async (limite) => (await pedir('GET', `/cuevaweb/v1/avisos?limite=${limite}`, { clave: CLAVE_A, tienda: CLAVE_A })).datos.avisos.map((a) => a.recurso);
            assert.deepEqual(await traer(2), ['/questions/151', '/questions/152']);
            // la tienda no los pudo hacer (no los confirma): no vuelven enseguida; viene el que faltaba
            assert.deepEqual(await traer(2), ['/questions/153']);
            // uno que la tienda ya trajo 5 veces sin poder hacerlo (y le toca otra vez) y uno nuevo: el nuevo, primero
            await db.query(`UPDATE cuevaweb_avisos SET traidas = 5, traido = NOW() - INTERVAL '3 hours' WHERE recurso = '/questions/152'`);
            await mandar(4);
            assert.ok(await hasta(() => conError('/questions/154')));
            assert.deepEqual(await traer(1), ['/questions/154'], 'el nuevo va primero');
            // traído 12 veces sin poder hacerlo (la última, hace más de 6 horas): se descarta y no vuelve
            await db.query(`UPDATE cuevaweb_avisos SET traidas = 12, traido = NOW() - INTERVAL '7 hours' WHERE recurso = '/questions/151'`);
            const cuarta = await traer(10);
            assert.ok(!cuarta.includes('/questions/151'), 'el descartado ya no viene');
            assert.ok(cuarta.includes('/questions/152'), 'el que esperaba, sí');
            const fila = (await db.query(`SELECT descartado, error FROM cuevaweb_avisos WHERE recurso = '/questions/151'`)).rows[0];
            assert.ok(fila.descartado && /Se descartó/.test(fila.error), JSON.stringify(fila));
            const e = await pedir('GET', '/cuevaweb/panel/tiendas/tiendaA', { clave: CLAVE_PANEL });
            assert.equal(e.datos.tienda.avisos.descartados, 1);
            // la tienda confirma los demás: al día (el descartado no cuenta como pendiente)
            const ids = (await db.query(`SELECT id FROM cuevaweb_avisos WHERE recurso LIKE '/questions/15_' AND entregado IS NULL AND descartado IS NULL`)).rows.map((r) => String(r.id));
            assert.equal(ids.length, 3);
            assert.equal((await pedir('POST', '/cuevaweb/v1/avisos/ack', { clave: CLAVE_A, tienda: CLAVE_A, cuerpo: { ids } })).datos.marcados, 3);
            assert.equal((await pedir('GET', '/cuevaweb/panel/tiendas/tiendaA', { clave: CLAVE_PANEL })).datos.tienda.avisos.pendientes, 0);
        }

        await t.test('C8 «Conectar con Mercado Pago» y su aviso de pago', async () => {
            const { url, n } = linkConectar(CLAVE_A, 'mp');
            const v = await irYVolver(url, CLAVE_A);
            // (13/11/2026) antes de volver, la pantalla: la cuenta de Mercado Pago, de producción y sin avisos
            const h = v.pantalla.html;
            assert.match(h, /<h1>Confirmá tu cuenta de Mercado Pago<\/h1>/);
            assert.match(h, /<span class="v big">COBRADOR_PRUEBA<\/span>/);
            assert.ok(h.includes('cobros@ejemplo.com') && h.includes('<code>555001</code>'));
            assert.ok(h.includes('Cobros con Mercado Pago') && h.includes(`src="${LOGOS_CW.mp}"`));
            assert.ok(h.includes('<span class="pill-mode pill-live">Producción · cobros reales</span>'));
            assert.ok(!h.includes('class="warnings"'), 'sin avisos');
            assert.ok(h.includes('cerrá la sesión en mercadopago.com.ar'));
            assert.equal(new URL(v.pantalla.form.accion).pathname, '/cuevaweb/mp/decidir');
            assert.equal(v.datos.ok, true, JSON.stringify(v.datos));
            assert.equal(v.datos.cuenta, 'COBRADOR_PRUEBA');
            assert.equal(v.datos.usuario, '555001');
            assert.equal(v.datos.v, '/admin/pagos');
            assert.equal(F.mp.ultimaAutorizacion.platform_id, 'mp');
            const r = await pedir('POST', '/cuevaweb/v1/confirmar', { clave: CLAVE_A, tienda: CLAVE_A, cuerpo: { servicio: 'mp', n } });
            assert.equal(r.status, 200, JSON.stringify(r.datos));
            assert.equal(r.datos.access_token, F.mp.access);
            assert.match(r.datos.clave_publica, /^APP_USR-clave-publica-/);
            assert.equal(r.datos.produccion, true);
            assert.ok(r.datos.vence > Date.now() + 100 * 86_400_000);
            const w = await avisoMp(`t=${idDe(CLAVE_A)}&data.id=8800123&type=payment`, { type: 'payment', action: 'payment.created', data: { id: '8800123' }, user_id: 555001 });
            assert.equal(w.status, 200);
            const llego = await hasta(() => T.recibidos.find((a) => a.origen === 'mp' && a.recurso === '8800123'));
            assert.ok(llego, 'el aviso de pago llegó');
            assert.equal(llego.tema, 'payment');
        });

        await t.test('C16 los avisos de Mercado Pago: sólo los pagos y sólo con la firma válida', async () => {
            const q = (id) => `t=${idDe(CLAVE_A)}&data.id=${id}&type=payment`;
            const cuerpo = (id) => ({ type: 'payment', action: 'payment.created', data: { id: String(id) }, user_id: 555001 });
            assert.equal((await avisoMp(q(8800201), cuerpo(8800201), { firma: 'ninguna' })).status, 401, 'sin firma');
            assert.equal((await avisoMp(q(8800202), cuerpo(8800202), { firma: 'mala' })).status, 401, 'con una firma mala');
            assert.equal((await avisoMp('data.id=8800203&type=payment', cuerpo(8800203), { firma: 'ninguna' })).status, 401, 'sin la t (por el user_id) y sin firma');
            const otro = await avisoMp(`t=${idDe(CLAVE_A)}&data.id=99&type=merchant_order`, { type: 'merchant_order', data: { id: '99' } });
            assert.equal(otro.status, 200);
            assert.equal(otro.datos.ignorado, true, 'lo que no es un pago, se ignora');
            assert.equal((await avisoMp(q(8800204), JSON.stringify({ ...cuerpo(8800204), relleno: 'x'.repeat(100_000) }), { dataId: 8800204 })).status, 413, 'uno de más de 64 KB ni se lee');
            // se rechazan ANTES de contestar: nada de eso quedó
            const n = (await db.query(`SELECT COUNT(*)::int AS n FROM cuevaweb_avisos WHERE recurso IN ('8800201', '8800202', '8800203', '8800204', '99')`)).rows[0].n;
            assert.equal(n, 0);
            // la buena pasa, y sólo con lo revisado (una acción rara no viaja)
            assert.equal((await avisoMp(q(8800205), { ...cuerpo(8800205), action: 'x'.repeat(500) })).status, 200);
            const llego = await hasta(() => T.recibidos.find((a) => a.origen === 'mp' && a.recurso === '8800205'));
            assert.ok(llego, 'la buena llegó');
            assert.equal(llego.cuerpo.action, undefined);
            assert.equal(llego.cuerpo.user_id, '555001');
        });

        await t.test('C9 el panel fuerza la renovación de Mercado Pago', async () => {
            const antes = F.mp.access;
            const r = await pedir('POST', '/cuevaweb/panel/tiendas/tiendaA/mp/renovar', { clave: CLAVE_PANEL });
            assert.equal(r.status, 200, JSON.stringify(r.datos));
            assert.ok(r.datos.tienda.mp.renovada);
            assert.equal(F.mp.renovaciones, 1);
            const tk = await pedir('GET', '/cuevaweb/v1/mp/token', { clave: CLAVE_A, tienda: CLAVE_A });
            assert.notEqual(tk.datos.access_token, antes);
            assert.equal(tk.datos.access_token, F.mp.access);
            assert.ok(await hasta(() => T.recibidos.find((a) => a.origen === 'cuevaweb' && a.tema === 'mp_token')), 'la tienda recibió «mp_token»');
        });

        await t.test('C10 la renovación sola, antes de vencer', async () => {
            await db.query(`UPDATE cuevaweb_conexiones SET vence = NOW() + INTERVAL '10 days' WHERE servicio = 'mp'`);
            const antes = F.mp.renovaciones;
            assert.ok(await hasta(() => F.mp.renovaciones > antes, 10_000), 'se renovó sola');
            const vence = (await db.query(`SELECT vence FROM cuevaweb_conexiones WHERE servicio = 'mp'`)).rows[0].vence;
            assert.ok(new Date(vence).getTime() > Date.now() + 100 * 86_400_000);
        });

        // (13/11/2026, la confirmación) Después de C9 y C10 (las renovaciones de Mercado Pago), por lo mismo que C18.
        await t.test('C20 Mercado Pago: otra cuenta y de prueba (los dos avisos), y se cancela', async () => {
            const guardado = { usuario: F.mp.usuario, apodo: F.mp.apodo, correo: F.mp.correo, vivo: F.mp.vivo };
            Object.assign(F.mp, { usuario: 555002, apodo: 'OTRO_COBRADOR', correo: 'otro@ejemplo.com', vivo: false });
            try {
                const ida = await irHasta(linkConectar(CLAVE_A, 'mp').url, CLAVE_A);
                assert.equal(ida.status, 200, ida.html);
                const h = ida.html;
                assert.match(h, /<h1>Confirmá tu cuenta de Mercado Pago<\/h1>/);
                assert.match(h, /<span class="v big">OTRO_COBRADOR<\/span>/);
                assert.ok(h.includes('otro@ejemplo.com') && h.includes('<code>555002</code>'));
                assert.ok(h.includes('<span class="pill-mode pill-test">Prueba · sin cobros reales</span>'), 'el modo: prueba');
                assert.ok(h.includes('<li>Hoy esta tienda está conectada con <strong>COBRADOR_PRUEBA</strong>. Si confirmás, se cambia por esta. Los cobros nuevos van a caer en esta cuenta.</li>'), 'el aviso de la otra cuenta');
                assert.ok(h.includes('<li>Es una cuenta de prueba: no cobra de verdad.</li>'), 'el aviso de prueba');
                assert.ok(!h.includes('Esta cuenta ya está conectada a esta tienda'));
                assert.equal(new URL(ida.form.accion).pathname, '/cuevaweb/mp/decidir');
                const v = await decidir(ida.form, 'cancel', CLAVE_A);
                assert.equal(v.status, 303);
                assert.equal(v.datos.ok, false);
                assert.equal(v.datos.error, 'Cancelaste: no se conectó ninguna cuenta.');
                assert.equal(v.datos.v, '/admin/pagos');
            } finally {
                Object.assign(F.mp, guardado);
            }
            assert.deepEqual((await db.query(`SELECT usuario_id, estado, produccion FROM cuevaweb_conexiones WHERE servicio = 'mp'`)).rows, [{ usuario_id: '555001', estado: 'activa', produccion: true }], 'sigue la de antes');
        });

        await t.test('C11 otra tienda no se lleva la misma cuenta de Mercado Libre', async () => {
            const r = await pedir('PUT', '/cuevaweb/panel/tiendas/tiendaB', { clave: CLAVE_PANEL, cuerpo: { url: 'http://127.0.0.1:3049', clave: CLAVE_B, nombre: 'Tienda B' } });
            assert.equal(r.status, 200);
            const repetida = await pedir('PUT', '/cuevaweb/panel/tiendas/tiendaC', { clave: CLAVE_PANEL, cuerpo: { url: 'http://127.0.0.1:3048', clave: CLAVE_B, nombre: 'Tienda C' } });
            assert.equal(repetida.status, 409);
            const { url } = linkConectar(CLAVE_B, 'ml');
            const v = await irYVolver(url, CLAVE_B);
            assert.equal(v.datos.ok, false);
            assert.match(v.datos.error, /ya está conectada a otra tienda/);
            // (13/11/2026) la última vuelta de esta central: las pruebas no se comieron el límite de conectar
            assert.ok(quedanConectar >= 3, `quedan ${quedanConectar} de 40 pedidos a conectar/volver/decidir: repartí las pruebas nuevas (el límite es por IP y cada 15 minutos)`);
        });

        await t.test('C12 desconectar y dar de baja', async () => {
            const d = await pedir('POST', '/cuevaweb/v1/desconectar', { clave: CLAVE_A, tienda: CLAVE_A, cuerpo: { servicio: 'ml' } });
            assert.equal(d.status, 200);
            assert.equal((await pedir('GET', '/cuevaweb/v1/ml/token', { clave: CLAVE_A, tienda: CLAVE_A })).status, 404);
            const e = await pedir('GET', '/cuevaweb/panel/tiendas/tiendaA', { clave: CLAVE_PANEL });
            assert.equal(e.datos.tienda.ml, null);
            assert.ok(e.datos.tienda.mp && e.datos.tienda.mp.conectada);
            assert.equal((await pedir('DELETE', '/cuevaweb/panel/tiendas/tiendaA', { clave: CLAVE_PANEL })).status, 200);
            assert.equal((await pedir('GET', '/cuevaweb/v1/estado', { clave: CLAVE_A, tienda: CLAVE_A })).status, 401);
        });

        await t.test('C17 las direcciones de prueba que no son de esta máquina se ignoran (y sin MP_WEBHOOK_SECRET no pasa ningún aviso de pago)', async () => {
            await apagarCentral();
            central = arrancarCentral({
                CUEVAWEB_MODO: '1', ML_AUTH_DOMAIN: 'https://auth.ejemplo.invalid', MP_AUTH_DOMAIN: 'http://10.1.2.3:8080',
                CUEVAWEB_ML_API_URL: 'https://api.ejemplo.invalid', MP_TOKEN_URL: 'http://10.1.2.3/oauth/token', CUEVAWEB_MP_API_URL: 'ftp://127.0.0.1',
                MP_WEBHOOK_SECRET: undefined,
            });
            await hastaQueConteste();
            for (const [s, deVerdad] of [['ml', 'https://auth.mercadolibre.com.ar/authorization?'], ['mp', 'https://auth.mercadopago.com/authorization?']]) {
                const r = await fetch(linkConectar(CLAVE_B, s).url, { redirect: 'manual' });
                assert.equal(r.status, 302);
                assert.ok(String(r.headers.get('location')).startsWith(deVerdad), `${s}: ${r.headers.get('location')}`);
            }
            for (const v of ['ML_AUTH_DOMAIN', 'MP_AUTH_DOMAIN', 'CUEVAWEB_ML_API_URL', 'MP_TOKEN_URL', 'CUEVAWEB_MP_API_URL']) {
                assert.match(central.log, new RegExp(`${v} no es una dirección de esta máquina`), v);
            }
            const sinClave = await avisoMp(`t=${idDe(CLAVE_B)}&data.id=8800301&type=payment`, { type: 'payment', data: { id: '8800301' } });
            assert.equal(sinClave.status, 401);
            assert.equal(sinClave.datos.error, 'sin_clave');
            assert.match(central.log, /falta MP_WEBHOOK_SECRET/);
        });
    } finally {
        await apagarCentral();
        for (const s of servidores) await new Promise((r) => s.close(r));
        await db.end();
    }
});

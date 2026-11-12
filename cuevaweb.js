/**
 * cuevaweb.js — EL MODO CUEVAWEB: conectar.cuevaweb.com.ar (12/11/2026, v2.11.0).
 *
 * Una SEGUNDA instalación de este mismo código, con una app de Mercado Libre y una de Mercado Pago a nombre de
 * CuevaWeb, conecta las tiendas de CuevaWeb (cada una es su propia instalación del producto CUEVAWEB) con un botón:
 * «Conectar con Mercado Libre» y «Conectar con Mercado Pago». Lo que hace acá:
 *   · el OAuth de Mercado Libre y de Mercado Pago con las apps de CuevaWeb. Los tokens quedan ACÁ, cifrados (esta
 *     central es la única que los renueva: el de renovación de Mercado Libre sirve una sola vez) y la tienda pide el
 *     suyo cuando lo necesita;
 *   · recibe los avisos (las notificaciones de Mercado Libre y de Mercado Pago) y se los reenvía a la tienda que
 *     corresponde, firmados con la clave de esa tienda; si no le llegan, la tienda los trae (pendientes) y los confirma
 *     (ack);
 *   · renueva los tokens de Mercado Pago antes de que venzan (el panel de CuevaWeb lo ve y puede forzarlo).
 * Las sincronizaciones (publicar, el stock, las ventas…) las sigue haciendo cada tienda, como siempre.
 *
 * TODO APAGADO DE FÁBRICA: sin CUEVAWEB_MODO=1 nada de esto se monta y Forger anda exactamente igual. La licencia
 * firmada de Forger no se usa acá: una tienda de CuevaWeb se identifica con la clave de su tienda.
 *
 * Quién habla con quién (las firmas son HMAC-SHA256 en base64url, las mismas de la API privada de la tienda):
 *   panel de CuevaWeb → acá   x-cuevaweb-tiempo + x-cuevaweb-firma, con CUEVAWEB_CONECTAR_CLAVE
 *   tienda → acá              x-cuevaweb-tienda (la huella de su clave) + tiempo + firma, con la clave de la tienda
 *   acá → tienda              POST <tienda>/api/cuevaweb/conectar/aviso, firmado con la clave de la tienda
 *   firma = HMAC(clave, `${tiempo}.${MÉTODO}.${ruta}.${sha256 base64url del cuerpo}`), con 5 minutos de margen
 * El navegador del dueño va y vuelve con paquetes firmados con la clave de su tienda (?d=…&f=…, como «Continuar con
 * Google» del panel), y la conexión queda PENDIENTE hasta que la tienda la confirma con el nonce de la cookie de ESE
 * navegador: nadie puede conectar su cuenta a una tienda ajena mandándole un link.
 *
 * Rutas (todas bajo /cuevaweb):
 *   GET  /cuevaweb/conectar?t=&d=&f=        el botón de la tienda: al OAuth de Mercado Libre o de Mercado Pago
 *   GET  /cuevaweb/ml/volver, /mp/volver    la vuelta del OAuth (las «Redirect URI» de las dos apps)
 *   POST /cuevaweb/mp/avisos[?t=]           las notificaciones de Mercado Pago (las de Mercado Libre llegan a /webhooks)
 *   tienda: POST v1/confirmar · GET v1/estado · GET v1/ml/token · GET v1/mp/token (?forzar=1&actual=<huella del suyo>)
 *           POST v1/desconectar · GET v1/avisos · POST v1/avisos/ack
 *   panel:  GET panel/estado · PUT|GET|DELETE panel/tiendas/:id · POST panel/tiendas/:id/mp/renovar
 *
 * (12/11/2026, la revisión) La clave que el panel le da a conectar NO es la CUEVAWEB_CLAVE de la tienda sino una derivada
 * (HMAC(CUEVAWEB_CLAVE, "cuevaweb-conectar.v1"): src/lib/cuevaweb/plataforma.ts de CUEVAWEB). Con ella la tienda sólo acepta
 * los avisos de conectar; su API privada, el soporte y «Continuar con Google» siguen pidiendo la de verdad. Acá no cambia
 * nada: para conectar, «la clave de la tienda» es ésa.
 *
 * Variables: CUEVAWEB_MODO=1, CUEVAWEB_CONECTAR_CLAVE (la misma en el panel), ML_CLIENT_ID/ML_CLIENT_SECRET y
 * MP_CLIENT_ID/MP_CLIENT_SECRET (las apps de CuevaWeb), BASE_URL (https://conectar.cuevaweb.com.ar), WFML_TOKEN_KEY,
 * MP_WEBHOOK_SECRET (la clave de los webhooks de la app de Mercado Pago: sin ella los avisos de pago se rechazan);
 * opcional: CUEVAWEB_MP_RENOVAR_DIAS (30).
 * Para los bancos: CUEVAWEB_ML_API_URL, CUEVAWEB_MP_API_URL, ML_AUTH_DOMAIN, MP_AUTH_DOMAIN, MP_TOKEN_URL (sólo valen
 * si son de esta máquina: localhost o 127.0.0.1), CUEVAWEB_AVISOS_CADA_MS y CUEVAWEB_RENOVAR_CADA_MS.
 */

import crypto from 'node:crypto';
import { query, tx } from './db.js';
import { encryptToken, decryptToken, sealSecret, openSecret } from './auth.js';
import { createRateLimiter } from './rate-limit.js';

// ─────────────────────────────────────────────────────────────── la configuración

/** ¿Esta instalación es conectar.cuevaweb.com.ar? */
export function cuevawebActivo() {
    return process.env.CUEVAWEB_MODO === '1';
}

const sinBarra = (u) => String(u || '').replace(/\/+$/, '');

/** (12/11/2026, la revisión) Las direcciones de Mercado Libre y de Mercado Pago se cambian SÓLO para los bancos: un Mercado
 *  Libre y un Mercado Pago de mentira en ESTA máquina (localhost, 127.0.0.1). Cualquier otra dirección (salvo las de
 *  verdad, con https) se ignora y se usa la de fábrica: un valor de prueba que quedó en el Entorno nunca recibe las claves
 *  de las apps de CuevaWeb ni los permisos de las tiendas. Se avisa una vez en el registro. */
const DE_ESTA_MAQUINA = new Set(['localhost', '127.0.0.1', '[::1]']);
const DE_VERDAD = /(^|\.)(mercadolibre|mercadopago)\.com(\.[a-z]{2})?$/;
const ignoradas = new Set();
export function direccionDePrueba(nombre, deFabrica) {
    const v = String(process.env[nombre] || '').trim();
    if (!v) return deFabrica;
    try {
        const u = new URL(v);
        if ((u.protocol === 'http:' || u.protocol === 'https:') && DE_ESTA_MAQUINA.has(u.hostname)) return v;
        if (u.protocol === 'https:' && DE_VERDAD.test(u.hostname)) return v;
    } catch (_) { /* no es una dirección */ }
    if (!ignoradas.has(nombre)) {
        ignoradas.add(nombre);
        console.warn(`[cuevaweb] ${nombre} no es una dirección de esta máquina ni de Mercado Libre / Mercado Pago: se ignora (es sólo para los bancos) y se usa ${deFabrica}.`);
    }
    return deFabrica;
}

function conf() {
    const e = process.env;
    const base = sinBarra(e.BASE_URL);
    return {
        base,
        ml: {
            clientId: (e.ML_CLIENT_ID || '').trim(),
            secret: (e.ML_CLIENT_SECRET || '').trim(),
            auth: sinBarra(direccionDePrueba('ML_AUTH_DOMAIN', 'https://auth.mercadolibre.com.ar')),
            api: sinBarra(direccionDePrueba('CUEVAWEB_ML_API_URL', 'https://api.mercadolibre.com')),
            vuelta: `${base}/cuevaweb/ml/volver`,
        },
        mp: {
            clientId: (e.MP_CLIENT_ID || '').trim(),
            secret: (e.MP_CLIENT_SECRET || '').trim(),
            auth: sinBarra(direccionDePrueba('MP_AUTH_DOMAIN', 'https://auth.mercadopago.com')),
            token: direccionDePrueba('MP_TOKEN_URL', 'https://api.mercadopago.com/oauth/token'),
            api: sinBarra(direccionDePrueba('CUEVAWEB_MP_API_URL', 'https://api.mercadopago.com')),
            scopes: e.MP_SCOPES || 'read write offline_access',
            vuelta: `${base}/cuevaweb/mp/volver`,
            webhookSecret: (e.MP_WEBHOOK_SECRET || '').trim(),
        },
        claveDelPanel: (e.CUEVAWEB_CONECTAR_CLAVE || '').trim(),
        renovarDias: Math.max(1, Number(e.CUEVAWEB_MP_RENOVAR_DIAS) || 30),
        avisosCadaMs: Math.max(1000, Number(e.CUEVAWEB_AVISOS_CADA_MS) || 30_000),
        renovarCadaMs: Math.max(1000, Number(e.CUEVAWEB_RENOVAR_CADA_MS) || 3_600_000),
    };
}

const NOMBRE = { ml: 'Mercado Libre', mp: 'Mercado Pago' };
const servicioListo = (s) => {
    const c = conf()[s];
    return !!(c && c.clientId && c.secret);
};
/** Más de esto, un aviso que no se pudo entregar queda para que la tienda lo traiga (ya no se reintenta solo). */
const MAX_INTENTOS = 12;
/** (12/11/2026, la revisión) Las veces que la tienda puede traer un aviso sin poder hacerlo (con esperas cada vez más
 *  largas entre una y otra: más o menos un día y medio); después, y a los 7 días de haber llegado, se DESCARTA: uno que la
 *  tienda no puede hacer nunca (un pago de otra cuenta, Mercado Pago ya desconectado) no tapa a los nuevos. */
const MAX_TRAIDAS = 12;
const DIAS_PARA_DESCARTAR = 7;

// ─────────────────────────────────────────────────────────────── las firmas

const huella = (s) => crypto.createHash('sha256').update(String(s)).digest('base64url');
const hmac = (clave, texto) => crypto.createHmac('sha256', clave).update(texto).digest('base64url');
function iguales(a, b) {
    const x = Buffer.from(String(a));
    const y = Buffer.from(String(b));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
}

/** Con qué se presenta una tienda: la huella de su clave (la tienda la calcula igual: src/lib/cuevaweb/conectar.ts). */
export function idDeClave(clave) {
    return huella(`cuevaweb-conectar:${clave}`).slice(0, 32);
}

function firmaPedido(clave, tiempo, metodo, ruta, cuerpo) {
    return hmac(clave, `${tiempo}.${String(metodo).toUpperCase()}.${ruta}.${huella(cuerpo || '')}`);
}
function pedidoValido(clave, tiempo, firma, metodo, ruta, cuerpo) {
    if (!tiempo || !firma || !/^\d{13}$/.test(String(tiempo))) return false;
    if (Math.abs(Date.now() - Number(tiempo)) > 5 * 60_000) return false;
    return iguales(firma, firmaPedido(clave, tiempo, metodo, ruta, cuerpo));
}
function encabezadosFirmados(clave, metodo, ruta, cuerpo) {
    const tiempo = String(Date.now());
    return { 'x-cuevaweb-tiempo': tiempo, 'x-cuevaweb-firma': firmaPedido(clave, tiempo, metodo, ruta, cuerpo) };
}
function firmarPaquete(clave, tipo, datos) {
    const d = Buffer.from(JSON.stringify(datos), 'utf8').toString('base64url');
    return { d, f: hmac(clave, `${tipo}.${d}`) };
}
function leerPaquete(clave, tipo, d, f) {
    if (typeof d !== 'string' || typeof f !== 'string' || !d || d.length > 4000) return null;
    if (!iguales(f, hmac(clave, `${tipo}.${d}`))) return null;
    try {
        return JSON.parse(Buffer.from(d, 'base64url').toString('utf8'));
    } catch (_) {
        return null;
    }
}

/** Adonde vuelve el dueño dentro de SU panel: una ruta de /admin, nunca otro sitio. */
function rutaSegura(v, siNo) {
    if (typeof v !== 'string' || !v.startsWith('/admin') || v.startsWith('//') || v.includes('\\') || v.length > 300) return siNo;
    return v;
}
const VUELTA_DE_FABRICA = { ml: '/admin/mercadolibre/conexion', mp: '/admin/pagos' };

// ─────────────────────────────────────────────────────────────── lo guardado

const cifrar = (token) => {
    const { ciphertext, iv } = encryptToken(String(token || ''));
    return { enc: ciphertext || null, iv: iv || null };
};
const descifrar = (enc, iv) => (enc && iv ? decryptToken(enc, iv) : null);

async function tiendaPorClaveId(id) {
    if (!/^[A-Za-z0-9_-]{16,64}$/.test(String(id || ''))) return null;
    const r = await query('SELECT * FROM cuevaweb_tiendas WHERE clave_id = $1 AND baja IS NULL', [String(id)]);
    return r.rows[0] || null;
}
async function tiendaPorPanelId(id) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(String(id || ''))) return null;
    const r = await query('SELECT * FROM cuevaweb_tiendas WHERE panel_id = $1', [String(id)]);
    return r.rows[0] || null;
}
async function tiendaPorId(id) {
    const r = await query('SELECT * FROM cuevaweb_tiendas WHERE id = $1', [id]);
    return r.rows[0] || null;
}
async function conexionActiva(tiendaId, servicio) {
    const r = await query(`SELECT * FROM cuevaweb_conexiones WHERE tienda_id = $1 AND servicio = $2 AND estado = 'activa'`, [tiendaId, servicio]);
    return r.rows[0] || null;
}
async function otraTiendaCon(servicio, usuarioId, tiendaId) {
    const r = await query(
        `SELECT t.nombre, t.url FROM cuevaweb_conexiones c JOIN cuevaweb_tiendas t ON t.id = c.tienda_id
          WHERE c.servicio = $1 AND c.usuario_id = $2 AND c.estado = 'activa' AND c.tienda_id <> $3 AND t.baja IS NULL
          LIMIT 1`,
        [servicio, String(usuarioId), tiendaId]
    );
    return r.rows[0] || null;
}

// ─────────────────────────────────────────────────────────────── Mercado Libre y Mercado Pago (el OAuth y los tokens)

class Problema extends Error {} // algo que se le puede decir al dueño tal cual
class Reconectar extends Error {} // el permiso ya no sirve: hay que volver a conectar

const mensajeDe = (d) => (d && typeof d === 'object' ? String(d.message || d.error_description || d.error || '') : '');

async function pedirFormulario(url, form) {
    try {
        const r = await fetch(url, {
            method: 'POST',
            headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams(form).toString(),
            signal: AbortSignal.timeout(15_000),
        });
        const texto = await r.text();
        let datos = null;
        try { datos = JSON.parse(texto); } catch (_) { datos = null; }
        return { ok: r.ok, status: r.status, datos };
    } catch (e) {
        return { ok: false, status: 0, datos: { message: /timeout|abort/i.test(e.message) ? 'no contestó a tiempo' : 'no se pudo conectar' } };
    }
}
async function pedirJson(url, token) {
    try {
        const r = await fetch(url, { headers: { Accept: 'application/json', Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(10_000) });
        return { ok: r.ok, status: r.status, datos: await r.json().catch(() => null) };
    } catch (_) {
        return { ok: false, status: 0, datos: null };
    }
}

function urlDeAutorizacion(servicio, estado) {
    const c = conf();
    if (servicio === 'ml') {
        const u = new URL(`${c.ml.auth}/authorization`);
        u.searchParams.set('response_type', 'code');
        u.searchParams.set('client_id', c.ml.clientId);
        u.searchParams.set('redirect_uri', c.ml.vuelta);
        u.searchParams.set('state', estado);
        return u.toString();
    }
    const u = new URL(`${c.mp.auth}/authorization`);
    u.searchParams.set('client_id', c.mp.clientId);
    u.searchParams.set('response_type', 'code');
    u.searchParams.set('platform_id', 'mp');
    u.searchParams.set('state', estado);
    u.searchParams.set('redirect_uri', c.mp.vuelta);
    u.searchParams.set('scope', c.mp.scopes);
    return u.toString();
}

/** El código de la vuelta → los tokens y quién es la cuenta. */
async function canjear(servicio, code) {
    const c = conf();
    if (servicio === 'ml') {
        const t = await pedirFormulario(`${c.ml.api}/oauth/token`, {
            grant_type: 'authorization_code', client_id: c.ml.clientId, client_secret: c.ml.secret, code, redirect_uri: c.ml.vuelta,
        });
        if (!t.ok || !t.datos || !t.datos.access_token) {
            const m = mensajeDe(t.datos) || `HTTP ${t.status}`;
            if (/code_verifier|code_challenge|pkce/i.test(m)) throw new Problema('La aplicación de Mercado Libre de CuevaWeb tiene tildado «Requiere PKCE». Avisanos y lo arreglamos.');
            throw new Problema(`Mercado Libre no aceptó la autorización (${m}). Probá de nuevo.`);
        }
        if (!t.datos.refresh_token) throw new Problema('La aplicación de Mercado Libre de CuevaWeb no tiene tildado «Refresh Token». Avisanos y lo arreglamos.');
        const me = await pedirJson(`${c.ml.api}/users/me`, t.datos.access_token);
        const u = (me.ok && me.datos) || {};
        const usuario = String(u.id || t.datos.user_id || '');
        if (!usuario) throw new Problema('No pudimos saber qué cuenta de Mercado Libre se conectó. Probá de nuevo.');
        return {
            usuario, nombre: String(u.nickname || ''), sitio: String(u.site_id || 'MLA'), clavePublica: '', produccion: true,
            access: String(t.datos.access_token), refresh: String(t.datos.refresh_token),
            vence: new Date(Date.now() + (Number(t.datos.expires_in) || 21600) * 1000),
        };
    }
    const t = await pedirFormulario(c.mp.token, {
        grant_type: 'authorization_code', client_id: c.mp.clientId, client_secret: c.mp.secret, code, redirect_uri: c.mp.vuelta,
    });
    if (!t.ok || !t.datos || !t.datos.access_token) {
        throw new Problema(`Mercado Pago no aceptó la autorización (${mensajeDe(t.datos) || `HTTP ${t.status}`}). Probá de nuevo.`);
    }
    if (!t.datos.refresh_token) throw new Problema('Mercado Pago no devolvió el permiso para renovar la conexión. Avisanos y lo arreglamos.');
    const me = await pedirJson(`${c.mp.api}/users/me`, t.datos.access_token);
    const u = (me.ok && me.datos) || {};
    const usuario = String(t.datos.user_id || u.id || '');
    if (!usuario) throw new Problema('No pudimos saber qué cuenta de Mercado Pago se conectó. Probá de nuevo.');
    const nombre = String(u.nickname || [u.first_name, u.last_name].filter(Boolean).join(' ') || u.email || '').trim();
    return {
        usuario, nombre, sitio: String(u.site_id || ''), clavePublica: String(t.datos.public_key || ''), produccion: t.datos.live_mode !== false,
        access: String(t.datos.access_token), refresh: String(t.datos.refresh_token),
        vence: new Date(Date.now() + (Number(t.datos.expires_in) || 15_552_000) * 1000),
    };
}

// de a una renovación por conexión (el de renovación de Mercado Libre sirve UNA vez: dos a la vez = una conexión muerta)
const renovando = new Map();

/** Renueva el token de una conexión (la fila fresca). Sin `forzar`, si otro ya lo renovó, devuelve ése. Con
 *  `evitarRepetir` (lo que piden las tiendas), uno renovado hace menos de 20 segundos tampoco se renueva otra vez: dos
 *  procesos de la tienda que reciben un 401 a la vez no gastan dos veces el permiso. */
function renovar(conexion, { forzar = false, margenMs = 0, evitarRepetir = false } = {}) {
    if (renovando.has(conexion.id)) return renovando.get(conexion.id);
    const p = (async () => {
        const fila = (await query('SELECT * FROM cuevaweb_conexiones WHERE id = $1', [conexion.id])).rows[0];
        if (!fila) throw new Reconectar(`${NOMBRE[conexion.servicio]} se desconectó: hay que volver a conectar.`);
        const reciente = evitarRepetir && fila.renovada && Date.now() - new Date(fila.renovada).getTime() < 20_000;
        const vigente = fila.vence && new Date(fila.vence).getTime() - Date.now() > margenMs;
        if ((!forzar || reciente) && vigente && descifrar(fila.access_enc, fila.access_iv)) return fila;
        const refresh = descifrar(fila.refresh_enc, fila.refresh_iv);
        if (!refresh) throw new Reconectar(`No hay un permiso guardado para ${NOMBRE[fila.servicio]}: hay que volver a conectar.`);
        const c = conf();
        const k = c[fila.servicio];
        const t = await pedirFormulario(fila.servicio === 'ml' ? `${k.api}/oauth/token` : k.token, {
            grant_type: 'refresh_token', client_id: k.clientId, client_secret: k.secret, refresh_token: refresh,
        });
        if (!t.ok || !t.datos || !t.datos.access_token) {
            // invalid_grant: el permiso venció, se usó o el dueño lo quitó. Lo demás (caído, la app mal) se reintenta.
            const muerto = t.status === 400 && /invalid_grant/i.test(JSON.stringify(t.datos || {}));
            const msg = muerto
                ? `${NOMBRE[fila.servicio]} cerró el permiso (venció o lo quitaron): hay que volver a conectar.`
                : `No se pudo renovar el permiso de ${NOMBRE[fila.servicio]} (${mensajeDe(t.datos) || `HTTP ${t.status}`}).`;
            await query('UPDATE cuevaweb_conexiones SET error = $2, error_en = NOW() WHERE id = $1', [fila.id, msg]);
            throw muerto ? new Reconectar(msg) : new Error(msg);
        }
        const a = cifrar(t.datos.access_token);
        const r = cifrar(t.datos.refresh_token || refresh); // ⚠️ siempre el nuevo: el anterior ya no sirve
        const segundos = Number(t.datos.expires_in) || (fila.servicio === 'ml' ? 21600 : 15_552_000);
        const nueva = await query(
            `UPDATE cuevaweb_conexiones
                SET access_enc = $2, access_iv = $3, refresh_enc = $4, refresh_iv = $5, vence = $6, renovada = NOW(),
                    error = NULL, error_en = NULL,
                    clave_publica = CASE WHEN $7 <> '' THEN $7 ELSE clave_publica END,
                    produccion = COALESCE($8, produccion)
              WHERE id = $1 RETURNING *`,
            [fila.id, a.enc, a.iv, r.enc, r.iv, new Date(Date.now() + segundos * 1000).toISOString(),
                String(t.datos.public_key || ''), typeof t.datos.live_mode === 'boolean' ? t.datos.live_mode : null]
        );
        return nueva.rows[0];
    })().finally(() => renovando.delete(conexion.id));
    renovando.set(conexion.id, p);
    return p;
}

/** La huella de un token (la tienda manda la del suyo al pedir uno forzado: así se sabe si el que falló es el de acá) */
export const huellaDeToken = (token) => huella(`cuevaweb-token:${token}`).slice(0, 22);

/** Un token vigente: Mercado Libre se renueva si le quedan menos de 15 minutos; Mercado Pago, si le queda menos de un día
 *  (normalmente lo renueva antes la vuelta de cada hora, a los 30 días de vencer). Con `forzar` (el token le dio 401 a la
 *  tienda) se renueva sí o sí, salvo que la tienda diga con `actual` (la huella del suyo) que el que falló no es el de acá:
 *  entonces la tienda tenía uno viejo y se le da el de ahora, sin gastar otra renovación. */
async function tokenVigente(conexion, forzarPedido, actual) {
    const margenMs = conexion.servicio === 'ml' ? 15 * 60_000 : 24 * 3_600_000;
    let fila = conexion;
    let forzar = forzarPedido;
    if (forzar && actual) {
        const vigente = descifrar(fila.access_enc, fila.access_iv);
        if (vigente && !iguales(huellaDeToken(vigente), String(actual))) forzar = false;
    }
    if (forzar || !fila.vence || new Date(fila.vence).getTime() - Date.now() <= margenMs || !descifrar(fila.access_enc, fila.access_iv)) {
        fila = await renovar(conexion, { forzar, margenMs, evitarRepetir: true });
    }
    const token = descifrar(fila.access_enc, fila.access_iv);
    if (!token) throw new Reconectar(`No se puede leer el permiso de ${NOMBRE[conexion.servicio]}: hay que volver a conectar.`);
    return { fila, token };
}

/** Lo que recibe la tienda: el token y de qué cuenta es (nunca el de renovación). */
function credenciales(c, token) {
    const vence = c.vence ? new Date(c.vence).getTime() : null;
    if (c.servicio === 'ml') {
        return { ok: true, servicio: 'ml', access_token: token, vence, usuario_id: c.usuario_id, nombre: c.nombre, sitio: c.sitio || 'MLA', app_id: conf().ml.clientId };
    }
    return { ok: true, servicio: 'mp', access_token: token, vence, usuario_id: c.usuario_id, nombre: c.nombre, clave_publica: c.clave_publica, produccion: !!c.produccion };
}

// ─────────────────────────────────────────────────────────────── los avisos para cada tienda

const enCola = new Map(); // tienda → el temporizador de la próxima entrega
const entregando = new Set();
const otraVez = new Set();

function programarEntrega(tiendaId, ms = 300) {
    if (enCola.has(tiendaId)) return;
    const t = setTimeout(() => {
        enCola.delete(tiendaId);
        entregar(tiendaId).catch((e) => console.error(`[cuevaweb] entregando avisos (tienda ${tiendaId}):`, e.message));
    }, ms);
    if (t.unref) t.unref();
    enCola.set(tiendaId, t);
}

const ESPERA_MIN = [1, 2, 5, 10, 30, 60, 120, 240, 360];
const esperaMin = (intentos) => ESPERA_MIN[Math.min(ESPERA_MIN.length - 1, Math.max(0, intentos - 1))];

/** Guarda un aviso para una tienda y lo manda. El mismo recurso todavía sin entregar no se repite (la tienda lo va a
 *  buscar a Mercado Libre o a Mercado Pago igual: lo que importa es que se entere). (12/11/2026, la revisión) Lo que llega
 *  acá ya viene revisado y CHICO (avisoDeMercadoLibre, los avisos de Mercado Pago): por las dudas, un recurso de más de
 *  200 letras o un cuerpo de más de 2 KB no se guarda. */
async function avisarTienda(tiendaId, origen, tema, recurso, cuerpo) {
    const rec = String(recurso || '');
    const texto = JSON.stringify(cuerpo || {});
    if (rec.length > 200 || String(tema).length > 64 || texto.length > 2048) {
        console.warn(`[cuevaweb] un aviso (${origen}) demasiado grande: no se guarda`);
        return null;
    }
    const ya = await query(
        `SELECT id FROM cuevaweb_avisos
          WHERE tienda_id = $1 AND origen = $2 AND tema = $3 AND recurso = $4 AND entregado IS NULL AND descartado IS NULL LIMIT 1`,
        [tiendaId, origen, tema, rec]
    );
    if (ya.rowCount) {
        programarEntrega(tiendaId);
        return ya.rows[0].id;
    }
    const r = await query(
        `INSERT INTO cuevaweb_avisos (tienda_id, origen, tema, recurso, cuerpo) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [tiendaId, origen, tema, rec, texto]
    );
    programarEntrega(tiendaId);
    return r.rows[0].id;
}

/** (12/11/2026, la revisión) Los avisos que la tienda no pudo hacer en MAX_TRAIDAS veces (la última, hace más de 6 horas) o
 *  que tienen más de DIAS_PARA_DESCARTAR días, se descartan (el panel los cuenta). De una tienda o de todas. */
async function descartarAvisos(tiendaId = null) {
    await query(
        `UPDATE cuevaweb_avisos
            SET descartado = NOW(),
                error = LEFT(CASE WHEN traidas >= $1::int THEN 'Se descartó: la tienda no lo pudo hacer en ' || traidas::text || ' intentos'
                                  ELSE 'Se descartó: no se pudo entregar en ' || $2::int::text || ' días' END
                             || COALESCE(' (' || error || ')', ''), 300)
          WHERE entregado IS NULL AND descartado IS NULL AND ($3::bigint IS NULL OR tienda_id = $3::bigint)
            AND ((traidas >= $1::int AND traido <= NOW() - INTERVAL '6 hours') OR recibido < NOW() - make_interval(days => $2::int))`,
        [MAX_TRAIDAS, DIAS_PARA_DESCARTAR, tiendaId]
    );
}

const RUTA_AVISO = '/api/cuevaweb/conectar/aviso';

/** Le manda a la tienda sus avisos pendientes (de a 20), firmados con su clave. La tienda contesta cuáles hizo. */
async function entregar(tiendaId) {
    if (entregando.has(tiendaId)) {
        otraVez.add(tiendaId);
        return;
    }
    entregando.add(tiendaId);
    try {
        for (let tanda = 0; tanda < 10; tanda++) {
            const t = await tiendaPorId(tiendaId);
            if (!t || t.baja) return;
            const clave = openSecret(t.clave);
            if (!clave) return;
            const avisos = (await query(
                `SELECT id, origen, tema, recurso, cuerpo, recibido, intentos FROM cuevaweb_avisos
                  WHERE tienda_id = $1 AND entregado IS NULL AND descartado IS NULL AND proximo <= NOW() AND intentos < $2
                  ORDER BY id LIMIT 20`,
                [tiendaId, MAX_INTENTOS]
            )).rows;
            if (!avisos.length) return;
            const cuerpo = JSON.stringify({ avisos: avisos.map((a) => ({ id: String(a.id), origen: a.origen, tema: a.tema, recurso: a.recurso, cuerpo: a.cuerpo, recibido: a.recibido })) });
            let hechos = [];
            let error = '';
            try {
                const r = await fetch(t.url + RUTA_AVISO, {
                    method: 'POST',
                    headers: { 'content-type': 'application/json', ...encabezadosFirmados(clave, 'POST', RUTA_AVISO, cuerpo) },
                    body: cuerpo,
                    redirect: 'manual',
                    signal: AbortSignal.timeout(20_000),
                });
                const datos = await r.json().catch(() => null);
                if (r.ok && datos && datos.ok) {
                    hechos = Array.isArray(datos.hechos) ? datos.hechos.map(String) : avisos.map((a) => String(a.id));
                    if (hechos.length < avisos.length) error = 'la tienda no lo pudo procesar (lo reintenta)';
                } else {
                    error = r.status === 401
                        ? 'la tienda no reconoce la clave (¿su CUEVAWEB_CLAVE es la del panel?)'
                        : r.status === 404
                            ? 'la tienda no tiene la conexión (¿le falta CUEVAWEB_CLAVE o es una versión anterior?)'
                            : (datos && datos.error) || `la tienda contestó ${r.status}`;
                }
            } catch (e) {
                error = /timeout|abort/i.test(e.message) ? 'la tienda no contestó a tiempo' : 'no se pudo llegar a la tienda';
            }
            const listos = new Set(hechos);
            const entregados = avisos.filter((a) => listos.has(String(a.id))).map((a) => a.id);
            if (entregados.length) {
                await query('UPDATE cuevaweb_avisos SET entregado = NOW(), error = NULL, intentos = intentos + 1 WHERE id = ANY($1::bigint[])', [entregados]);
            }
            for (const a of avisos.filter((x) => !listos.has(String(x.id)))) {
                await query(
                    `UPDATE cuevaweb_avisos SET intentos = intentos + 1, proximo = NOW() + make_interval(mins => $2), error = $3 WHERE id = $1`,
                    [a.id, esperaMin(a.intentos + 1), String(error || 'la tienda no lo pudo procesar').slice(0, 300)]
                );
            }
            if (!entregados.length) return;
        }
    } finally {
        entregando.delete(tiendaId);
        if (otraVez.delete(tiendaId)) programarEntrega(tiendaId, 200);
    }
}

/** Los tópicos que la tienda hace (src/lib/mercadolibre/avisos.ts): los demás no se le mandan. */
const TEMAS_ML = new Set(['orders_v2', 'orders', 'questions', 'messages', 'items', 'shipments', 'claims']);
/** Un recurso de Mercado Libre: «/orders/123», «/items/MLA123/prices», «/messages/abc», «/post-purchase/v1/claims/9»… */
const RECURSO_ML = /^\/[A-Za-z0-9_\-./?=&%:]{1,199}$/;
const entero = (v) => (Number.isInteger(v) && v >= 0 && v <= 1_000_000 ? v : undefined);
const fecha = (v) => (typeof v === 'string' && v.length <= 40 && !Number.isNaN(Date.parse(v)) ? v : undefined);

/** El aviso de Mercado Libre que llegó a /webhooks (server.js, después de su filtro de application_id y de repetidos):
 *  si el vendedor es de una tienda de CuevaWeb, se le reenvía. Los tópicos que la tienda hace (también «claims»).
 *  (12/11/2026, la revisión) Mercado Libre no firma sus avisos y /webhooks es público: sólo se guarda lo que se espera,
 *  revisado y con tope (el tópico de la lista, un recurso de hasta 200 letras, los números como números); nada más del
 *  cuerpo viaja. La tienda nunca le cree al aviso: con el recurso le pregunta a Mercado Libre. */
export async function avisoDeMercadoLibre(body) {
    if (!cuevawebActivo()) return false;
    const b = body && typeof body === 'object' ? body : {};
    const topic = typeof b.topic === 'string' ? b.topic : '';
    const resource = typeof b.resource === 'string' ? b.resource : '';
    const userId = b.user_id != null ? String(b.user_id) : '';
    if (!TEMAS_ML.has(topic) || !RECURSO_ML.test(resource) || !/^\d{1,20}$/.test(userId)) return false;
    const appId = b.application_id != null ? String(b.application_id) : '';
    if (appId && !/^[A-Za-z0-9_-]{1,40}$/.test(appId)) return false;
    const c = conf();
    if (c.ml.clientId && appId && appId !== c.ml.clientId) return false;
    const r = await query(
        `SELECT c.tienda_id FROM cuevaweb_conexiones c JOIN cuevaweb_tiendas t ON t.id = c.tienda_id
          WHERE c.servicio = 'ml' AND c.estado = 'activa' AND c.usuario_id = $1 AND t.baja IS NULL`,
        [userId]
    );
    if (!r.rowCount) return false;
    const cuerpo = {
        _id: typeof b._id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(b._id) ? b._id : undefined,
        topic, resource, user_id: Number(userId),
        // el App ID como texto: los de Mercado Libre tienen 16 cifras y como número pueden perder la última
        application_id: appId || undefined,
        attempts: entero(b.attempts), sent: fecha(b.sent), received: fecha(b.received),
    };
    for (const row of r.rows) await avisarTienda(row.tienda_id, 'ml', topic, resource, cuerpo);
    return true;
}

/** ¿La firma del aviso de Mercado Pago (x-signature) es de la app de CuevaWeb? (la misma cuenta que hace la tienda en
 *  src/lib/payments/mercadopago.ts; y la misma regla: sólo pasa 'valida') */
function firmaMp(req, dataId) {
    const secreto = conf().mp.webhookSecret;
    if (!secreto) return 'sin_clave';
    const firma = String(req.get('x-signature') || '');
    if (!firma) return 'sin_firma';
    let ts = '';
    let v1 = '';
    for (const parte of firma.split(',')) {
        const [k, v] = parte.split('=').map((s) => (s || '').trim());
        if (k === 'ts') ts = v;
        if (k === 'v1') v1 = v;
    }
    if (!ts || !v1) return 'mala';
    const id = /^[a-z0-9]+$/i.test(dataId) ? dataId.toLowerCase() : dataId;
    const requestId = req.get('x-request-id');
    let manifiesto = '';
    if (id) manifiesto += `id:${id};`;
    if (requestId) manifiesto += `request-id:${requestId};`;
    manifiesto += `ts:${ts};`;
    return iguales(crypto.createHmac('sha256', secreto).update(manifiesto).digest('hex'), v1) ? 'valida' : 'mala';
}

// ─────────────────────────────────────────────────────────────── las vueltas solas

async function reintentarEntregas() {
    const r = await query(
        `SELECT DISTINCT a.tienda_id FROM cuevaweb_avisos a JOIN cuevaweb_tiendas t ON t.id = a.tienda_id
          WHERE a.entregado IS NULL AND a.descartado IS NULL AND a.proximo <= NOW() AND a.intentos < $1 AND t.baja IS NULL`,
        [MAX_INTENTOS]
    );
    for (const row of r.rows) programarEntrega(row.tienda_id, 10);
}

/** Renueva cada Mercado Pago que vence en menos de CUEVAWEB_MP_RENOVAR_DIAS (30) días y le avisa a su tienda. */
export async function renovarMercadoPagoPorVencer() {
    if (!servicioListo('mp')) return 0;
    const r = await query(
        `SELECT c.* FROM cuevaweb_conexiones c JOIN cuevaweb_tiendas t ON t.id = c.tienda_id
          WHERE c.servicio = 'mp' AND c.estado = 'activa' AND t.baja IS NULL
            AND c.vence IS NOT NULL AND c.vence < NOW() + make_interval(days => $1)
            AND (c.error_en IS NULL OR c.error_en < NOW() - INTERVAL '6 hours')`,
        [conf().renovarDias]
    );
    let n = 0;
    for (const c of r.rows) {
        try {
            const f = await renovar(c, { forzar: true });
            await avisarTienda(c.tienda_id, 'cuevaweb', 'mp_token', 'mp', { vence: f.vence });
            n++;
            console.log(`[cuevaweb] Mercado Pago renovado (tienda ${c.tienda_id}, vence ${new Date(f.vence).toISOString().slice(0, 10)}).`);
        } catch (e) {
            console.warn(`[cuevaweb] no se pudo renovar Mercado Pago (tienda ${c.tienda_id}): ${e.message}`);
        }
    }
    return n;
}

async function limpiar() {
    await query(`DELETE FROM cuevaweb_estados WHERE creado < NOW() - INTERVAL '1 hour'`);
    await query(`DELETE FROM cuevaweb_conexiones WHERE estado = 'pendiente' AND conectada < NOW() - INTERVAL '2 hours'`);
    await descartarAvisos();
    await query(`DELETE FROM cuevaweb_avisos WHERE recibido < NOW() - INTERVAL '30 days'`);
}

// ─────────────────────────────────────────────────────────────── las páginas (sólo si no se puede volver a la tienda)

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
function paginaCw(titulo, texto) {
    return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><title>${esc(titulo)} · CuevaWeb</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">
<style>
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background: #f6f6f9; color: #18181b; margin: 0; padding: 24px 16px; line-height: 1.55; }
  .caja { max-width: 520px; margin: 12vh auto 0; background: #fff; border: 1px solid #e4e4e7; border-radius: 16px; padding: 28px 28px 24px; }
  .marca { font-weight: 700; color: #8b5cf6; letter-spacing: .01em; margin: 0 0 14px; }
  h1 { font-size: 20px; margin: 0 0 8px; }
  p { color: #52525b; margin: 6px 0; }
  @media (prefers-color-scheme: dark) { body { background: #0b0d12; color: #f4f4f5; } .caja { background: #15171d; border-color: #27272a; } p { color: #a1a1aa; } .marca { color: #b9a3ff; } }
</style></head><body><div class="caja"><p class="marca">CuevaWeb</p><h1>${esc(titulo)}</h1><p>${esc(texto)}</p></div></body></html>`;
}

// ─────────────────────────────────────────────────────────────── las rutas

const responder = (res, status, datos) => res.status(status).set('Cache-Control', 'no-store').json(datos);
const rutaDe = (req) => req.originalUrl.split('?')[0];
const uno = (v) => (Array.isArray(v) ? v[0] : v);

/** La tienda que pide: la de la huella, con su firma (su clave). */
async function autenticarTienda(req, res, next) {
    try {
        const t = await tiendaPorClaveId(req.get('x-cuevaweb-tienda'));
        const clave = t && openSecret(t.clave);
        if (!t || !clave || !pedidoValido(clave, req.get('x-cuevaweb-tiempo'), req.get('x-cuevaweb-firma'), req.method, rutaDe(req), req.rawBody || '')) {
            return responder(res, 401, { ok: false, error: 'no_autorizada', message: 'La tienda no está registrada en conectar o la firma no es válida.' });
        }
        req.tienda = t;
        return next();
    } catch (e) {
        console.error('[cuevaweb] autenticando una tienda:', e.message);
        return responder(res, 500, { ok: false, error: 'interno' });
    }
}

/** El panel de CuevaWeb (admin.cuevaweb.com.ar), con CUEVAWEB_CONECTAR_CLAVE. */
function autenticarPanel(req, res, next) {
    const clave = conf().claveDelPanel;
    if (clave.length < 32) return responder(res, 503, { ok: false, error: 'sin_clave', message: 'Falta CUEVAWEB_CONECTAR_CLAVE en conectar (32 letras o más, la misma que en el panel).' });
    if (!pedidoValido(clave, req.get('x-cuevaweb-tiempo'), req.get('x-cuevaweb-firma'), req.method, rutaDe(req), req.rawBody || '')) {
        return responder(res, 401, { ok: false, error: 'no_autorizado', message: 'La firma del panel no es válida (¿CUEVAWEB_CONECTAR_CLAVE es la misma en los dos?).' });
    }
    return next();
}

function urlValida(u) {
    try {
        const x = new URL(String(u || '').trim());
        if (x.protocol !== 'https:' && x.protocol !== 'http:') return null;
        return `${x.protocol}//${x.host}`;
    } catch (_) {
        return null;
    }
}

/** Para el panel: cómo está una tienda acá (sin secretos). */
async function estadoDeTienda(t) {
    const [conexiones, avisos, ultimo, error] = await Promise.all([
        query(`SELECT * FROM cuevaweb_conexiones WHERE tienda_id = $1 AND estado = 'activa'`, [t.id]),
        query(
            `SELECT COUNT(*) FILTER (WHERE entregado IS NULL AND descartado IS NULL)::int AS n,
                    COUNT(*) FILTER (WHERE descartado > NOW() - INTERVAL '7 days')::int AS descartados
               FROM cuevaweb_avisos WHERE tienda_id = $1`,
            [t.id]
        ),
        query(`SELECT MAX(entregado) AS en FROM cuevaweb_avisos WHERE tienda_id = $1`, [t.id]),
        query(`SELECT error, proximo, recibido FROM cuevaweb_avisos WHERE tienda_id = $1 AND entregado IS NULL AND descartado IS NULL AND error IS NOT NULL ORDER BY id DESC LIMIT 1`, [t.id]),
    ]);
    const de = (s) => {
        const c = conexiones.rows.find((x) => x.servicio === s);
        if (!c) return null;
        return {
            conectada: true, cuenta: c.nombre, usuario: c.usuario_id, sitio: c.sitio || null, produccion: c.servicio === 'mp' ? !!c.produccion : null,
            desde: c.confirmada || c.conectada, vence: c.vence, renovada: c.renovada, error: c.error, errorEn: c.error_en,
        };
    };
    return {
        registrada: !t.baja, url: t.url, nombre: t.nombre, actualizada: t.actualizada,
        ml: de('ml'), mp: de('mp'),
        avisos: {
            pendientes: avisos.rows[0].n, descartados: avisos.rows[0].descartados, ultimoEntregado: ultimo.rows[0].en,
            ultimoError: error.rows[0] ? { texto: error.rows[0].error, recibido: error.rows[0].recibido } : null,
        },
    };
}

/**
 * Monta las rutas del modo CuevaWeb y sus vueltas solas. Lo llama server.js SÓLO con CUEVAWEB_MODO=1, justo después de
 * la API v1 (antes de la portada de Forger, que acá se reemplaza por la de CuevaWeb).
 */
export function montarCuevaweb(app) {
    const limiteConectar = createRateLimiter({ bucket: 'cw-conectar', windowMs: 15 * 60_000, max: 40, label: '/cuevaweb/conectar + volver' });
    const limiteTienda = createRateLimiter({ bucket: 'cw-tienda', windowMs: 60_000, max: 300, label: '/cuevaweb/v1/*' });
    const limitePanel = createRateLimiter({ bucket: 'cw-panel', windowMs: 60_000, max: 300, label: '/cuevaweb/panel/*' });
    const limiteAvisosMp = createRateLimiter({ bucket: 'cw-avisos-mp', windowMs: 60_000, max: 600, label: '/cuevaweb/mp/avisos' });

    app.get('/', (req, res) => {
        res.type('html').send(paginaCw('Conectar', 'Acá se conectan las tiendas de CuevaWeb con Mercado Libre y Mercado Pago. Si llegaste por error, entrá al panel de tu tienda y conectá desde ahí.'));
    });

    // ── el botón de la tienda: «Conectar con …» ──────────────────────────────────────────────────────────────────
    app.get('/cuevaweb/conectar', limiteConectar, async (req, res) => {
        try {
            const t = await tiendaPorClaveId(uno(req.query.t));
            const clave = t && openSecret(t.clave);
            if (!t || !clave) {
                return res.status(400).type('html').send(paginaCw('Este link no es de una tienda de CuevaWeb', 'Volvé al panel de tu tienda y tocá el botón otra vez. Si sigue pasando, escribinos a hola@cuevaweb.com.ar.'));
            }
            const p = leerPaquete(clave, 'conectar', uno(req.query.d), uno(req.query.f));
            const servicio = p && (p.s === 'ml' || p.s === 'mp') ? p.s : null;
            if (!p || !servicio || typeof p.n !== 'string' || p.n.length < 16 || p.n.length > 200) {
                return res.status(400).type('html').send(paginaCw('El link no es válido', 'Volvé al panel de tu tienda y tocá el botón otra vez.'));
            }
            const vuelta = rutaSegura(p.v, VUELTA_DE_FABRICA[servicio]);
            const volver = (error) => aLaTienda(res, t, clave, { s: servicio, n: p.n, v: vuelta, ok: false, error });
            if (typeof p.e !== 'number' || p.e < Date.now() || p.e > Date.now() + 15 * 60_000) return volver('El link venció: tocá el botón otra vez.');
            if (!servicioListo(servicio)) return volver(`La conexión con ${NOMBRE[servicio]} todavía no está disponible. Escribinos y la hacemos.`);
            const nuevo = await query(
                `INSERT INTO request_nonces (nonce, purpose, created_at) VALUES ($1, 'cw_conectar', $2) ON CONFLICT (nonce, purpose) DO NOTHING RETURNING nonce`,
                [p.n, Math.floor(Date.now() / 1000)]
            );
            if (!nuevo.rowCount) return volver('Ese link ya se usó: tocá el botón otra vez.');
            const estado = crypto.randomBytes(32).toString('hex');
            await query('INSERT INTO cuevaweb_estados (estado, tienda_id, servicio, vuelta, nonce) VALUES ($1, $2, $3, $4, $5)', [estado, t.id, servicio, vuelta, p.n]);
            res.set('Referrer-Policy', 'no-referrer');
            return res.redirect(302, urlDeAutorizacion(servicio, estado));
        } catch (e) {
            console.error('[cuevaweb] conectar:', e.message);
            return res.status(500).type('html').send(paginaCw('No pudimos empezar la conexión', 'Probá de nuevo en un rato. Si sigue pasando, escribinos a hola@cuevaweb.com.ar.'));
        }
    });

    // ── la vuelta del OAuth (las «Redirect URI» de las apps de CuevaWeb) ─────────────────────────────────────────
    app.get('/cuevaweb/:servicio(ml|mp)/volver', limiteConectar, async (req, res) => {
        const servicio = req.params.servicio;
        const estado = String(uno(req.query.state) || '');
        let fila = null;
        try {
            if (/^[a-f0-9]{64}$/.test(estado)) {
                fila = (await query(
                    `UPDATE cuevaweb_estados SET usado = NOW()
                      WHERE estado = $1 AND servicio = $2 AND usado IS NULL AND creado > NOW() - INTERVAL '15 minutes'
                      RETURNING *`,
                    [estado, servicio]
                )).rows[0] || null;
            }
        } catch (e) {
            console.error('[cuevaweb] volver (estado):', e.message);
        }
        const t = fila && (await tiendaPorId(fila.tienda_id).catch(() => null));
        const clave = t && !t.baja && openSecret(t.clave);
        if (!fila || !t || !clave) {
            return res.status(400).type('html').send(paginaCw('La conexión venció', 'Volvé al panel de tu tienda y tocá el botón otra vez (desde que lo tocás tenés 15 minutos).'));
        }
        const volver = (datos) => aLaTienda(res, t, clave, { s: servicio, n: fila.nonce, v: fila.vuelta, ...datos });
        const error = String(uno(req.query.error) || '');
        if (error) {
            return volver({ ok: false, error: error === 'access_denied' ? `No autorizaste a CuevaWeb en ${NOMBRE[servicio]}. Cuando quieras, tocá el botón otra vez.` : `${NOMBRE[servicio]} no dejó conectar (${String(uno(req.query.error_description) || error).slice(0, 200)}).` });
        }
        const code = String(uno(req.query.code) || '');
        if (!code) return volver({ ok: false, error: `${NOMBRE[servicio]} no devolvió la autorización. Probá de nuevo.` });
        try {
            const x = await canjear(servicio, code);
            const otra = await otraTiendaCon(servicio, x.usuario, t.id);
            if (otra) {
                return volver({ ok: false, error: `Esa cuenta de ${NOMBRE[servicio]} (${x.nombre || x.usuario}) ya está conectada a otra tienda de CuevaWeb. Desconectala allá primero, o conectá otra cuenta.` });
            }
            const a = cifrar(x.access);
            const r = cifrar(x.refresh);
            await tx(async (cl) => {
                await cl.query(`DELETE FROM cuevaweb_conexiones WHERE tienda_id = $1 AND servicio = $2 AND estado = 'pendiente'`, [t.id, servicio]);
                await cl.query(
                    `INSERT INTO cuevaweb_conexiones
                        (tienda_id, servicio, estado, usuario_id, nombre, sitio, clave_publica, produccion,
                         access_enc, access_iv, refresh_enc, refresh_iv, vence, nonce)
                     VALUES ($1, $2, 'pendiente', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
                    [t.id, servicio, x.usuario, x.nombre, x.sitio, x.clavePublica, x.produccion, a.enc, a.iv, r.enc, r.iv, x.vence.toISOString(), fila.nonce]
                );
            });
            // `usuario`: la tienda revisa ANTES de confirmar si tiene guardado lo de otra cuenta (no se mezcla)
            return volver({ ok: true, cuenta: x.nombre || x.usuario, usuario: x.usuario });
        } catch (e) {
            if (!(e instanceof Problema)) console.error(`[cuevaweb] volver de ${servicio}:`, e.message);
            return volver({ ok: false, error: e instanceof Problema ? e.message : `No pudimos terminar la conexión con ${NOMBRE[servicio]}. Probá de nuevo en un rato.` });
        }
    });

    // ── los avisos de Mercado Pago ───────────────────────────────────────────────────────────────────────────────
    // (12/11/2026, la revisión) La MISMA regla que el aviso directo de la tienda (src/app/api/webhooks/mercadopago): sólo
    // los pagos, y sólo con la firma de la app de CuevaWeb VÁLIDA (sin MP_WEBHOOK_SECRET, o sin x-signature, o con una mala:
    // 401 y no se guarda nada). Se revisa ANTES de contestar. No se pierde ningún cobro: la tienda igual le pregunta a
    // Mercado Pago por los pedidos que esperan el pago (cada media hora) y por el de la vuelta de quien pagó.
    app.post('/cuevaweb/mp/avisos', limiteAvisosMp, (req, res) => {
        const b = req.body && typeof req.body === 'object' ? req.body : {};
        const q = req.query || {};
        const tipo = String(b.type || b.topic || uno(q.type) || uno(q.topic) || '');
        const idDeLaUrl = uno(q['data.id']);
        const dataId = String(idDeLaUrl || (b.data && typeof b.data === 'object' ? b.data.id : '') || uno(q.id) || '');
        if (tipo !== 'payment' || !/^[A-Za-z0-9_-]{1,64}$/.test(dataId)) return responder(res, 200, { ok: true, ignorado: true });
        const firma = firmaMp(req, idDeLaUrl ? String(idDeLaUrl) : dataId);
        if (firma !== 'valida') {
            console.warn(`[cuevaweb] aviso de Mercado Pago ${firma === 'sin_clave' ? 'sin MP_WEBHOOK_SECRET en conectar' : firma === 'sin_firma' ? 'sin firma' : 'con firma inválida'}: no se reenvía`);
            return responder(res, 401, { ok: false, error: firma === 'sin_clave' ? 'sin_clave' : 'firma_invalida' });
        }
        res.status(200).json({ ok: true }); // enseguida: Mercado Pago reintenta lo que tarda
        (async () => {
            let tienda = null;
            const porT = uno(q.t) ? await tiendaPorClaveId(uno(q.t)) : null;
            if (porT && (await conexionActiva(porT.id, 'mp'))) tienda = porT;
            const usuario = b.user_id != null && /^\d{1,20}$/.test(String(b.user_id)) ? String(b.user_id) : '';
            if (!tienda && usuario) {
                const r = await query(
                    `SELECT c.tienda_id FROM cuevaweb_conexiones c JOIN cuevaweb_tiendas t ON t.id = c.tienda_id
                      WHERE c.servicio = 'mp' AND c.estado = 'activa' AND c.usuario_id = $1 AND t.baja IS NULL LIMIT 1`,
                    [usuario]
                );
                if (r.rowCount) tienda = { id: r.rows[0].tienda_id };
            }
            if (!tienda) return;
            // sólo lo que hace falta, revisado (la tienda lee el pago de Mercado Pago con su token: no le cree al aviso)
            const accion = typeof b.action === 'string' && /^[a-z_.]{1,40}$/i.test(b.action) ? b.action : undefined;
            await avisarTienda(tienda.id, 'mp', tipo, dataId, {
                type: tipo, action: accion, data: { id: dataId },
                user_id: usuario || undefined, live_mode: typeof b.live_mode === 'boolean' ? b.live_mode : undefined,
            });
        })().catch((e) => console.error('[cuevaweb] aviso de Mercado Pago:', e.message));
    });

    // ── la API para las tiendas (firmada con la clave de cada una) ──────────────────────────────────────────────
    app.use('/cuevaweb/v1', limiteTienda);

    app.post('/cuevaweb/v1/confirmar', autenticarTienda, async (req, res) => {
        try {
            const servicio = req.body && (req.body.servicio === 'ml' || req.body.servicio === 'mp') ? req.body.servicio : null;
            const n = String((req.body && req.body.n) || '');
            if (!servicio || !n) return responder(res, 400, { ok: false, error: 'faltan_datos' });
            const p = (await query(`SELECT * FROM cuevaweb_conexiones WHERE tienda_id = $1 AND servicio = $2 AND estado = 'pendiente'`, [req.tienda.id, servicio])).rows[0];
            if (!p || !p.nonce || !iguales(p.nonce, n) || new Date(p.conectada).getTime() < Date.now() - 60 * 60_000) {
                return responder(res, 409, { ok: false, error: 'sin_pendiente', message: 'La conexión venció o se empezó en otro navegador: tocá el botón otra vez.' });
            }
            const otra = await otraTiendaCon(servicio, p.usuario_id, req.tienda.id);
            if (otra) return responder(res, 409, { ok: false, error: 'de_otra_tienda', message: `Esa cuenta de ${NOMBRE[servicio]} ya está conectada a otra tienda de CuevaWeb.` });
            const activa = await tx(async (cl) => {
                await cl.query(`DELETE FROM cuevaweb_conexiones WHERE tienda_id = $1 AND servicio = $2 AND estado = 'activa'`, [req.tienda.id, servicio]);
                return (await cl.query(`UPDATE cuevaweb_conexiones SET estado = 'activa', confirmada = NOW(), nonce = '' WHERE id = $1 RETURNING *`, [p.id])).rows[0];
            });
            return responder(res, 200, credenciales(activa, descifrar(activa.access_enc, activa.access_iv)));
        } catch (e) {
            console.error('[cuevaweb] confirmar:', e.message);
            return responder(res, 500, { ok: false, error: 'interno' });
        }
    });

    app.get('/cuevaweb/v1/estado', autenticarTienda, async (req, res) => {
        try {
            const e = await estadoDeTienda(req.tienda);
            return responder(res, 200, { ok: true, ml: e.ml, mp: e.mp, avisos: e.avisos, disponibles: { ml: servicioListo('ml'), mp: servicioListo('mp') } });
        } catch (e) {
            return responder(res, 500, { ok: false, error: 'interno' });
        }
    });

    app.get('/cuevaweb/v1/:servicio(ml|mp)/token', autenticarTienda, async (req, res) => {
        const servicio = req.params.servicio;
        try {
            const c = await conexionActiva(req.tienda.id, servicio);
            if (!c) return responder(res, 404, { ok: false, error: 'no_conectada', message: `${NOMBRE[servicio]} no está conectado a esta tienda.` });
            const actual = String(uno(req.query.actual) || '');
            const { fila, token } = await tokenVigente(c, String(uno(req.query.forzar) || '') === '1', /^[A-Za-z0-9_-]{8,64}$/.test(actual) ? actual : '');
            return responder(res, 200, credenciales(fila, token));
        } catch (e) {
            if (e instanceof Reconectar) return responder(res, 409, { ok: false, error: 'reconectar', message: e.message });
            console.error(`[cuevaweb] token de ${servicio}:`, e.message);
            return responder(res, 502, { ok: false, error: 'no_disponible', message: `No se pudo renovar el permiso de ${NOMBRE[servicio]} ahora. Probá de nuevo en un rato.` });
        }
    });

    app.post('/cuevaweb/v1/desconectar', autenticarTienda, async (req, res) => {
        const servicio = req.body && (req.body.servicio === 'ml' || req.body.servicio === 'mp') ? req.body.servicio : null;
        if (!servicio) return responder(res, 400, { ok: false, error: 'faltan_datos' });
        try {
            const r = await query('DELETE FROM cuevaweb_conexiones WHERE tienda_id = $1 AND servicio = $2', [req.tienda.id, servicio]);
            return responder(res, 200, { ok: true, borradas: r.rowCount });
        } catch (e) {
            return responder(res, 500, { ok: false, error: 'interno' });
        }
    });

    // (12/11/2026, la revisión) Los avisos sin entregar que la tienda viene a buscar. Primero los que nunca se llevó; cada
    // vez que se lleva uno y no lo confirma (no lo pudo hacer), vuelve recién después de una espera cada vez más larga
    // (1, 2, 5, 10, 30 minutos… hasta 6 horas) y, pasadas MAX_TRAIDAS veces, se descarta: uno que no se puede hacer nunca
    // no tapa a los nuevos ni hace que la tienda le pregunte lo mismo a Mercado Pago cada media hora durante un mes.
    app.get('/cuevaweb/v1/avisos', autenticarTienda, async (req, res) => {
        try {
            const limite = Math.min(100, Math.max(1, Number(uno(req.query.limite)) || 50));
            await descartarAvisos(req.tienda.id);
            const r = await query(
                `WITH elegidos AS (
                    SELECT id FROM cuevaweb_avisos
                     WHERE tienda_id = $1 AND entregado IS NULL AND descartado IS NULL
                       AND (traido IS NULL OR traido <= NOW() - make_interval(mins => (ARRAY[1,2,5,10,30,60,120,240,360])[LEAST(9, GREATEST(1, traidas))]))
                     ORDER BY traidas, id
                     LIMIT $2
                     FOR UPDATE SKIP LOCKED)
                 UPDATE cuevaweb_avisos a SET traidas = a.traidas + 1, traido = NOW()
                   FROM elegidos e WHERE a.id = e.id
                 RETURNING a.id, a.origen, a.tema, a.recurso, a.cuerpo, a.recibido`,
                [req.tienda.id, limite]
            );
            const avisos = r.rows.sort((x, y) => Number(x.id) - Number(y.id));
            return responder(res, 200, { ok: true, avisos: avisos.map((a) => ({ id: String(a.id), origen: a.origen, tema: a.tema, recurso: a.recurso, cuerpo: a.cuerpo, recibido: a.recibido })) });
        } catch (e) {
            console.error('[cuevaweb] los avisos de una tienda:', e.message);
            return responder(res, 500, { ok: false, error: 'interno' });
        }
    });

    app.post('/cuevaweb/v1/avisos/ack', autenticarTienda, async (req, res) => {
        const ids = Array.isArray(req.body && req.body.ids) ? req.body.ids.map(String).filter((x) => /^\d{1,18}$/.test(x)).slice(0, 500) : [];
        if (!ids.length) return responder(res, 200, { ok: true, marcados: 0 });
        try {
            const r = await query(
                'UPDATE cuevaweb_avisos SET entregado = NOW(), error = NULL WHERE tienda_id = $1 AND id = ANY($2::bigint[]) AND entregado IS NULL',
                [req.tienda.id, ids]
            );
            return responder(res, 200, { ok: true, marcados: r.rowCount });
        } catch (e) {
            return responder(res, 500, { ok: false, error: 'interno' });
        }
    });

    // ── la API para el panel de CuevaWeb (firmada con CUEVAWEB_CONECTAR_CLAVE) ──────────────────────────────────
    app.use('/cuevaweb/panel', limitePanel, autenticarPanel);

    app.get('/cuevaweb/panel/estado', async (req, res) => {
        try {
            const n = await query('SELECT COUNT(*)::int AS n FROM cuevaweb_tiendas WHERE baja IS NULL');
            return responder(res, 200, { ok: true, ml: servicioListo('ml'), mp: servicioListo('mp'), mpFirma: !!conf().mp.webhookSecret, tiendas: n.rows[0].n, base: conf().base });
        } catch (e) {
            return responder(res, 500, { ok: false, error: 'interno', message: 'La base de conectar no contesta.' });
        }
    });

    app.put('/cuevaweb/panel/tiendas/:panelId', async (req, res) => {
        const panelId = String(req.params.panelId || '');
        const b = req.body || {};
        const url = urlValida(b.url);
        const clave = typeof b.clave === 'string' ? b.clave.trim() : '';
        const nombre = typeof b.nombre === 'string' ? b.nombre.trim().slice(0, 120) : '';
        if (!/^[A-Za-z0-9_-]{1,64}$/.test(panelId) || !url || clave.length < 32) {
            return responder(res, 400, { ok: false, error: 'datos_invalidos', message: 'Falta la dirección (https://…) o la clave de la tienda (32 letras o más).' });
        }
        try {
            const claveId = idDeClave(clave);
            const otra = await query('SELECT panel_id FROM cuevaweb_tiendas WHERE clave_id = $1 AND panel_id <> $2', [claveId, panelId]);
            if (otra.rowCount) return responder(res, 409, { ok: false, error: 'clave_repetida', message: 'Esa clave ya es de otra tienda: cada tienda tiene la suya.' });
            const r = await query(
                `INSERT INTO cuevaweb_tiendas (panel_id, clave_id, clave, url, nombre)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (panel_id) DO UPDATE
                    SET clave_id = EXCLUDED.clave_id, clave = EXCLUDED.clave, url = EXCLUDED.url, nombre = EXCLUDED.nombre,
                        actualizada = NOW(), baja = NULL
                 RETURNING *`,
                [panelId, claveId, sealSecret(clave), url, nombre]
            );
            return responder(res, 200, { ok: true, tienda: await estadoDeTienda(r.rows[0]) });
        } catch (e) {
            console.error('[cuevaweb] registrar tienda:', e.message);
            return responder(res, 500, { ok: false, error: 'interno' });
        }
    });

    app.get('/cuevaweb/panel/tiendas/:panelId', async (req, res) => {
        try {
            const t = await tiendaPorPanelId(req.params.panelId);
            if (!t || t.baja) return responder(res, 404, { ok: false, error: 'no_registrada', message: 'Esta tienda no está registrada en conectar.' });
            return responder(res, 200, { ok: true, tienda: await estadoDeTienda(t) });
        } catch (e) {
            return responder(res, 500, { ok: false, error: 'interno' });
        }
    });

    app.delete('/cuevaweb/panel/tiendas/:panelId', async (req, res) => {
        try {
            const t = await tiendaPorPanelId(req.params.panelId);
            if (!t) return responder(res, 200, { ok: true, ya: true });
            await tx(async (cl) => {
                await cl.query('DELETE FROM cuevaweb_conexiones WHERE tienda_id = $1', [t.id]);
                await cl.query('UPDATE cuevaweb_tiendas SET baja = NOW() WHERE id = $1', [t.id]);
            });
            return responder(res, 200, { ok: true });
        } catch (e) {
            return responder(res, 500, { ok: false, error: 'interno' });
        }
    });

    app.post('/cuevaweb/panel/tiendas/:panelId/mp/renovar', async (req, res) => {
        try {
            const t = await tiendaPorPanelId(req.params.panelId);
            if (!t || t.baja) return responder(res, 404, { ok: false, error: 'no_registrada', message: 'Esta tienda no está registrada en conectar.' });
            const c = await conexionActiva(t.id, 'mp');
            if (!c) return responder(res, 409, { ok: false, error: 'no_conectada', message: 'Esta tienda no conectó Mercado Pago con el botón.' });
            try {
                const f = await renovar(c, { forzar: true });
                await avisarTienda(t.id, 'cuevaweb', 'mp_token', 'mp', { vence: f.vence });
            } catch (e) {
                return responder(res, e instanceof Reconectar ? 409 : 502, { ok: false, error: e instanceof Reconectar ? 'reconectar' : 'no_disponible', message: e.message, tienda: await estadoDeTienda(t) });
            }
            return responder(res, 200, { ok: true, tienda: await estadoDeTienda(t) });
        } catch (e) {
            console.error('[cuevaweb] renovar Mercado Pago (panel):', e.message);
            return responder(res, 500, { ok: false, error: 'interno' });
        }
    });

    // ── las vueltas solas: reintentar avisos, renovar Mercado Pago y limpiar ────────────────────────────────────────
    const c = conf();
    const cada = (ms, fn, nombre) => {
        const i = setInterval(() => fn().catch((e) => console.error(`[cuevaweb] ${nombre}:`, e.message)), ms);
        if (i.unref) i.unref();
    };
    cada(c.avisosCadaMs, reintentarEntregas, 'reintentar avisos');
    cada(c.renovarCadaMs, renovarMercadoPagoPorVencer, 'renovar Mercado Pago');
    cada(10 * 60_000, limpiar, 'limpiar');
    const primero = setTimeout(() => {
        reintentarEntregas().catch(() => {});
        renovarMercadoPagoPorVencer().catch(() => {});
        limpiar().catch(() => {});
    }, 5000);
    if (primero.unref) primero.unref();

    console.log(`[cuevaweb] modo CuevaWeb ACTIVO: Mercado Libre ${servicioListo('ml') ? 'listo' : 'sin configurar'}, Mercado Pago ${servicioListo('mp') ? 'listo' : 'sin configurar'}, panel ${c.claveDelPanel.length >= 32 ? 'con clave' : 'SIN CUEVAWEB_CONECTAR_CLAVE'}.`);
    if (servicioListo('mp') && !c.mp.webhookSecret) {
        console.warn('[cuevaweb] falta MP_WEBHOOK_SECRET: los avisos de pago de Mercado Pago se rechazan (las tiendas igual preguntan por sus pagos cada media hora).');
    }
}

/** Vuelve a la tienda (/api/conectar/vuelta) con lo que pasó, firmado con su clave. */
function aLaTienda(res, t, clave, datos) {
    const { d, f } = firmarPaquete(clave, 'conectar.vuelta', { ...datos, e: Date.now() + 10 * 60_000 });
    res.set('Referrer-Policy', 'no-referrer');
    return res.redirect(303, `${t.url}/api/conectar/vuelta?d=${encodeURIComponent(d)}&f=${encodeURIComponent(f)}`);
}

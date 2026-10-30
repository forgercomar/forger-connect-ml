/**
 * ml-api.js — Cliente de la API de MercadoLibre para el worker del central.
 *
 * Porta a Node la lógica que antes vivía en el plugin PHP (wf-ml-api.php):
 *   - Refresh del access_token usando el refresh_token.
 *   - Búsqueda de items del seller (paginado).
 *   - Multi-get de items (trae detalle de N items en un request).
 *
 * Los tokens se guardan encriptados en la tabla `accounts` (AES-256-GCM, ver
 * auth.js). Esta capa los desencripta, refresca cuando expiran, y re-encripta
 * el refresh_token nuevo (ML rota el refresh en cada uso).
 *
 * @module ml-api
 */

import { query } from './db.js';
import { encryptToken, decryptToken } from './auth.js';

const ML_API = 'https://api.mercadolibre.com';
const ML_CLIENT_ID     = process.env.ML_CLIENT_ID || '';
const ML_CLIENT_SECRET = process.env.ML_CLIENT_SECRET || '';

// Margen de seguridad: si el access_token expira en menos de esto, lo
// refrescamos preventivamente para no chocar un 401 a mitad de un batch.
const TOKEN_REFRESH_MARGIN_SEC = 120;

// ML multi-get: el endpoint /items?ids= acepta hasta 20 ids por request.
export const ML_BATCH_SIZE = 20;

// ----------------------------------------------------------------------------
// Tokens
// ----------------------------------------------------------------------------

/**
 * Devuelve un access_token válido para la cuenta. Si el cacheado sigue vigente
 * lo reusa; si está por expirar (o no hay), refresca contra ML.
 *
 * @param {object} account fila de la tabla accounts
 * @returns {Promise<string>} access_token
 * @throws si no se puede obtener un token (refresh falló, sin refresh_token, etc.)
 */
export async function getValidAccessToken(account) {
    const now = Date.now();
    // ¿Hay un access_token cacheado y todavía vigente?
    if (account.access_token_enc && account.access_expires_at) {
        const expMs = new Date(account.access_expires_at).getTime();
        if (expMs - now > TOKEN_REFRESH_MARGIN_SEC * 1000) {
            const cached = decryptToken(account.access_token_enc, account.access_token_iv);
            if (cached) return cached;
        }
    }
    // Refrescar.
    return await refreshAccessToken(account);
}

/**
 * Refresca el access_token usando el refresh_token de la cuenta. Persiste el
 * nuevo access_token (cacheado) y el nuevo refresh_token (ML lo rota).
 *
 * @param {object} account fila de accounts
 * @returns {Promise<string>} el access_token nuevo
 */
export async function refreshAccessToken(account) {
    if (!ML_CLIENT_ID || !ML_CLIENT_SECRET) {
        throw new Error('ML_CLIENT_ID / ML_CLIENT_SECRET no configurados');
    }
    const refreshToken = decryptToken(account.refresh_token_enc, account.refresh_token_iv);
    if (!refreshToken) {
        throw new Error(`account ${account.public_id}: sin refresh_token utilizable`);
    }

    const resp = await fetch(`${ML_API}/oauth/token`, {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            grant_type:    'refresh_token',
            client_id:     ML_CLIENT_ID,
            client_secret: ML_CLIENT_SECRET,
            refresh_token: refreshToken,
        }).toString(),
    });
    const raw = await resp.text();
    let data;
    try { data = JSON.parse(raw); } catch (_) { data = null; }
    if (!resp.ok || !data || !data.access_token) {
        const msg = (data && (data.message || data.error_description)) || `HTTP ${resp.status}`;
        throw new Error(`ML rechazó el refresh: ${msg}`);
    }

    const accessToken  = String(data.access_token);
    const newRefresh   = String(data.refresh_token || refreshToken); // ML rota; si no vino, mantener
    const expiresInSec = Number(data.expires_in || 21600); // ML default ~6h
    const expiresAt    = new Date(Date.now() + expiresInSec * 1000);

    // Persistir: access_token cacheado + refresh_token rotado.
    const accEnc = encryptToken(accessToken);
    const refEnc = encryptToken(newRefresh);
    await query(
        `UPDATE accounts SET
            access_token_enc  = $2,
            access_token_iv   = $3,
            access_expires_at = $4,
            refresh_token_enc = $5,
            refresh_token_iv  = $6,
            last_token_refresh_at = NOW()
         WHERE id = $1`,
        [account.id, accEnc.ciphertext, accEnc.iv, expiresAt.toISOString(),
         refEnc.ciphertext, refEnc.iv]
    );
    // Mutamos el objeto in-memory para que el caller use los valores frescos.
    account.access_token_enc  = accEnc.ciphertext;
    account.access_token_iv   = accEnc.iv;
    account.access_expires_at = expiresAt.toISOString();
    account.refresh_token_enc = refEnc.ciphertext;
    account.refresh_token_iv  = refEnc.iv;

    return accessToken;
}

// ----------------------------------------------------------------------------
// Llamadas a la API
// ----------------------------------------------------------------------------

/**
 * GET genérico a la API de ML con bearer token. Reintenta 1 vez si recibe 401
 * (refrescando el token). Devuelve { ok, status, data }.
 *
 * @param {object|null} extraHeaders headers adicionales (ej. { 'x-version': '2' }
 *   para billing_info) — se suman a los base sin pisarse el Authorization.
 */
export async function mlGet(account, path, accessToken, _isRetry = false, extraHeaders = null) {
    const url = path.startsWith('http') ? path : `${ML_API}${path}`;
    const headers = {
        'Accept': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
    };
    if (extraHeaders && typeof extraHeaders === 'object') Object.assign(headers, extraHeaders);
    const resp = await fetch(url, { headers });
    if (resp.status === 401 && !_isRetry) {
        // Token venció antes de tiempo — refrescar y reintentar una vez.
        const fresh = await refreshAccessToken(account);
        return mlGet(account, path, fresh, true, extraHeaders);
    }
    const raw = await resp.text();
    let data;
    try { data = JSON.parse(raw); } catch (_) { data = null; }
    return { ok: resp.ok, status: resp.status, data, raw };
}

/**
 * GET BINARIO a la API de ML (PDF/ZPL de etiquetas): mismo contrato que mlGet
 * pero devuelve el cuerpo como Buffer sin intentar JSON.parse. Reintenta 1 vez
 * ante 401 refrescando el token.
 *
 * @returns {Promise<{ ok: boolean, status: number, buf: Buffer, contentType: string }>}
 */
export async function mlGetRaw(account, path, accessToken, _isRetry = false, extraHeaders = null) {
    const url = path.startsWith('http') ? path : `${ML_API}${path}`;
    const headers = { 'Authorization': `Bearer ${accessToken}` };
    if (extraHeaders && typeof extraHeaders === 'object') Object.assign(headers, extraHeaders);
    const resp = await fetch(url, { headers });
    if (resp.status === 401 && !_isRetry) {
        const fresh = await refreshAccessToken(account);
        return mlGetRaw(account, path, fresh, true, extraHeaders);
    }
    const buf = Buffer.from(await resp.arrayBuffer());
    return { ok: resp.ok, status: resp.status, buf, contentType: String(resp.headers.get('content-type') || '') };
}

/**
 * Etiqueta de Mercado Envíos en PDF (Mercado Envíos, P2).
 *   GET /shipment_labels?shipment_ids={id}&response_type=pdf
 *
 * Solo existe para envíos que despacha el VENDEDOR (self_service/xd_drop_off)
 * y en estados imprimibles (ready_to_ship) — fuera de eso ML responde 4xx y
 * el caller debe traducirlo a "todavía no disponible".
 *
 * @returns {Promise<Buffer>} el PDF crudo
 */
export async function mlGetShipmentLabel(account, accessToken, shipmentId) {
    const r = await mlGetRaw(
        account,
        `/shipment_labels?shipment_ids=${encodeURIComponent(String(shipmentId))}&response_type=pdf`,
        accessToken
    );
    if (!r.ok || !r.buf || !r.buf.length) {
        throw new Error(`shipment_labels ${shipmentId}: HTTP ${r.status}`);
    }
    return r.buf;
}

/**
 * Lista los IDs de items del seller, paginado.
 *   GET /users/{uid}/items/search?offset=&limit=[&orders=]
 *
 * @param {string} [orders] criterio de orden de ML (ej. 'last_updated_desc').
 *   Vacío = orden por defecto. El sync incremental lo usa para paginar de más
 *   reciente a más viejo y cortar al cruzar el watermark.
 * @returns {Promise<{ ids: string[], total: number }>}
 */
export async function mlSearchItems(account, accessToken, offset, limit, orders = '') {
    const uid = Number(account.ml_user_id);
    let path = `/users/${uid}/items/search?offset=${offset}&limit=${limit}`;
    if (orders) path += `&orders=${encodeURIComponent(orders)}`;
    const r = await mlGet(account, path, accessToken);
    if (!r.ok || !r.data) {
        throw new Error(`items/search falló: HTTP ${r.status} ${(r.data && r.data.message) || ''}`);
    }
    return {
        ids:   Array.isArray(r.data.results) ? r.data.results : [],
        total: Number(r.data.paging && r.data.paging.total) || 0,
    };
}

/**
 * Lista los IDs de items del seller en modo SCAN (sellers grandes).
 *   GET /users/{uid}/items/search?search_type=scan&limit=[&scroll_id=]
 *
 * ML corta la paginación por offset en 1.000 items. Con search_type=scan la
 * primera respuesta trae un `scroll_id` que se reenvía tal cual en cada llamada
 * siguiente hasta que `results` viene vacío. Límite máximo por página: 100.
 * El scroll_id vence a los 5 minutos de inactividad (entre página y página
 * hacemos multi-get, lejos de ese tope).
 *
 * @param {string} [scrollId] vacío en la primera llamada; después, el devuelto.
 * @returns {Promise<{ ids: string[], total: number, scroll_id: string }>}
 */
export async function mlSearchItemsScan(account, accessToken, scrollId, limit) {
    const uid = Number(account.ml_user_id);
    const lim = Math.max(1, Math.min(100, Number(limit) || 100));
    let path = `/users/${uid}/items/search?search_type=scan&limit=${lim}`;
    if (scrollId) path += `&scroll_id=${encodeURIComponent(scrollId)}`;
    const r = await mlGet(account, path, accessToken);
    if (!r.ok || !r.data) {
        throw new Error(`items/search (scan) falló: HTTP ${r.status} ${(r.data && r.data.message) || ''}`);
    }
    return {
        ids:       Array.isArray(r.data.results) ? r.data.results : [],
        total:     Number(r.data.paging && r.data.paging.total) || 0,
        scroll_id: String(r.data.scroll_id || scrollId || ''),
    };
}

/**
 * Trae una orden completa de ML.
 *   GET /orders/{id}
 *
 * @returns {Promise<object>} la orden ML (status, order_items, etc.)
 */
export async function mlGetOrder(account, accessToken, orderId) {
    const r = await mlGet(account, `/orders/${encodeURIComponent(orderId)}`, accessToken);
    if (!r.ok || !r.data) {
        throw new Error(`orders/${orderId} falló: HTTP ${r.status}`);
    }
    return r.data;
}

/**
 * Datos fiscales del comprador de una orden (Ventas ML, F0).
 *   GET /orders/{id}/billing_info  (header x-version: 2 → shape enriquecido
 *   con nombre/razón social, doc_type/doc_number, taxes)
 *
 * DNI/CUIT del receptor: clave para facturar por ARCA desde el espejo. No
 * toda orden lo tiene (depende del sitio/comprador) — el caller debe tolerar
 * el throw y seguir sin billing.
 *
 * @returns {Promise<object>} el JSON crudo de billing_info
 */
export async function mlGetOrderBillingInfo(account, accessToken, orderId) {
    const r = await mlGet(
        account,
        `/orders/${encodeURIComponent(orderId)}/billing_info`,
        accessToken,
        false,
        { 'x-version': '2' }
    );
    if (!r.ok || !r.data) {
        throw new Error(`orders/${orderId}/billing_info falló: HTTP ${r.status}`);
    }
    return r.data;
}

/**
 * Estado del envío de una orden (Ventas ML, F0).
 *   GET /shipments/{id}  (header x-format-new: true → formato nuevo)
 *
 * La orden ML solo trae shipping.id; el estado real (preparando / en camino /
 * entregado) y el tracking viven acá.
 *
 * @returns {Promise<object>} el JSON crudo del shipment
 */
export async function mlGetShipment(account, accessToken, shipmentId) {
    const r = await mlGet(
        account,
        `/shipments/${encodeURIComponent(shipmentId)}`,
        accessToken,
        false,
        { 'x-format-new': 'true' }
    );
    if (!r.ok || !r.data) {
        throw new Error(`shipments/${shipmentId} falló: HTTP ${r.status}`);
    }
    return r.data;
}

/**
 * Búsqueda de órdenes del seller, paginada (backfill de Ventas ML).
 *   GET /orders/search?seller={uid}&order.date_created.from=&sort=date_desc...
 *
 * Los results vienen con la orden bastante completa (status, order_items,
 * payments, buyer, totales); billing_info y shipment siguen siendo llamadas
 * aparte por orden.
 *
 * @param {object} range { from?, to?, offset?, limit?, sort? } — fechas en el
 *   formato ISO de ML (ej. '2025-07-03T00:00:00.000-00:00').
 * @returns {Promise<{ results: object[], total: number }>}
 */
export async function mlSearchOrders(account, accessToken, range = {}) {
    const uid    = Number(account.ml_user_id);
    const offset = Math.max(0, Number(range.offset) || 0);
    const limit  = Math.min(50, Math.max(1, Number(range.limit) || 50));
    const sort   = String(range.sort || 'date_desc');
    let path = `/orders/search?seller=${uid}&offset=${offset}&limit=${limit}&sort=${encodeURIComponent(sort)}`;
    if (range.from) path += `&order.date_created.from=${encodeURIComponent(range.from)}`;
    if (range.to)   path += `&order.date_created.to=${encodeURIComponent(range.to)}`;
    const r = await mlGet(account, path, accessToken);
    if (!r.ok || !r.data) {
        throw new Error(`orders/search falló: HTTP ${r.status} ${(r.data && r.data.message) || ''}`);
    }
    return {
        results: Array.isArray(r.data.results) ? r.data.results : [],
        total:   Number(r.data.paging && r.data.paging.total) || 0,
    };
}

/**
 * PUT /items/{id} — actualiza un item de ML (precio, stock, o el array de
 * variations). El body lo arma el plugin; esta capa solo lo manda. Reintenta
 * 1 vez si recibe 401 (refrescando el token).
 *
 * @param {object} body  cuerpo del PUT (ej. { price, available_quantity } o
 *                        { variations: [...] }).
 * @returns {Promise<{ ok: boolean, status: number, data: object|null }>}
 */
export async function mlUpdateItem(account, accessToken, itemId, body, _isRetry = false) {
    const url = `${ML_API}/items/${encodeURIComponent(itemId)}`;
    const resp = await fetch(url, {
        method: 'PUT',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`,
        },
        body: JSON.stringify(body || {}),
    });
    if (resp.status === 401 && !_isRetry) {
        const fresh = await refreshAccessToken(account);
        return mlUpdateItem(account, fresh, itemId, body, true);
    }
    const raw = await resp.text();
    let data;
    try { data = JSON.parse(raw); } catch (_) { data = null; }
    return { ok: resp.ok, status: resp.status, data };
}

/**
 * Multi-get de items. ML acepta hasta 20 ids; el caller debe chunkear.
 *   GET /items/bulk?ids=A,B,C&attributes=body.…   primero (v2.10.2)
 *   GET /items?ids=A,B,C&attributes=...           la de siempre, de vuelta
 *
 * ML deprecó /items?ids= («Migrá tus integraciones antes del 25/10/2026. Durante
 * este período, los endpoints actuales y sus reemplazos convivirán»; no publicó la
 * fecha de corte). La respuesta nueva se acepta SÓLO con la forma esperada
 * (validarItemsBulk) y sale igual que la vieja: los body de los envoltorios con
 * code 200, en el mismo orden. Con la misma respuesta de ML, lo que el worker deja
 * en synced_items es idéntico por las dos lecturas.
 *   - La nueva falla (HTTP, forma, ningún pedido, campos que faltan) → la vieja, y
 *     el resto del job va directo a la vieja (no se duplica cada pedido).
 *   - La nueva viene a medias → la tanda ENTERA con la vieja (nada se mezcla).
 *   - La vieja contesta 404/410 (ya no existe) → el resto del job vuelve a la
 *     nueva, sin vuelta.
 *   - Las dos fallan → Error, como hoy (el job queda failed y el watermark no avanza).
 * La nueva no renueva el token ante un 401: cae a la vieja, que lo renueva como siempre.
 *
 * El memo es del objeto de la cuenta: el worker carga la fila de accounts en cada
 * job (processSyncJob), así que dura lo que dura el job. Interruptor sin cambiar
 * código: ML_ITEMS_LECTURA=ids (sólo la vieja).
 *
 * @returns {Promise<object[]>} array de items completos (los body de cada wrapper)
 */
export async function mlGetItems(account, accessToken, ids) {
    if (!ids.length) return [];
    const attrs = [
        'id', 'title', 'seller_custom_field', 'price', 'available_quantity',
        'sold_quantity', 'status', 'permalink', 'thumbnail', 'has_variations',
        'variations', 'listing_type_id', 'category_id', 'sale_terms',
        'installments', 'catalog_product_id', 'date_created', 'last_updated',
    ];
    const idsQ = ids.map(encodeURIComponent).join(',');
    const leerVieja = () => mlGet(account, `/items?ids=${idsQ}&attributes=${encodeURIComponent(attrs.join(','))}`, accessToken);

    if (itemsLecturaModo() === 'ids') {
        registrarLecturaItems(account, 'lectura /items?ids= (ML_ITEMS_LECTURA=ids)');
        return cuerposDeItems(await leerVieja());
    }

    const memo = memoLecturaItems(account);
    if (memo.estado === 'vieja') {
        const rv = await leerVieja();
        if (rv.ok || !VIEJA_NO_EXISTE.has(rv.status)) return cuerposDeItems(rv);
        // La vieja dejó de existir a mitad del job: esta tanda y las que siguen, con la nueva.
        memo.estado = 'sin_vieja';
        registrarLecturaItems(account, `/items?ids= http_${rv.status} → /items/bulk (la vieja ya no existe)`, true);
    }

    let rn;
    try {
        rn = await mlGet(account, `/items/bulk?ids=${idsQ}&attributes=${encodeURIComponent(attrs.map((a) => 'body.' + a).join(','))}`, accessToken, true);
    } catch (err) {
        rn = { ok: false, status: 0, data: null, excepcion: err };
    }
    const v = validarItemsBulk(ids, rn);
    if (v.estado === 'ok') {
        registrarLecturaItems(account, 'lectura /items/bulk');
        return cuerposDeItems(rn);
    }

    if (memo.estado === 'sin_vieja') {
        registrarLecturaItems(account, `/items/bulk ${v.motivo}, sin vuelta (la vieja ya no existe)`, true);
        if (v.estado === 'parcial') return v.validos.map((w) => w.body);
        if (rn.excepcion) throw rn.excepcion;
        throw new Error(`items multi-get falló: HTTP ${rn.status} (${v.motivo})`);
    }

    const rv = await leerVieja();
    const viejaNoExiste = !rv.ok && VIEJA_NO_EXISTE.has(rv.status);
    memo.estado = viejaNoExiste ? 'sin_vieja' : 'vieja';
    registrarLecturaItems(account, `/items/bulk ${v.motivo} → /items?ids= ${rv.ok ? 'ok' : 'http_' + rv.status}`, true);
    if (viejaNoExiste && v.estado === 'parcial') return v.validos.map((w) => w.body);
    return cuerposDeItems(rv);
}

// La vieja contestó que el endpoint ya no existe.
const VIEJA_NO_EXISTE = new Set([404, 410]);

// Campos que trae toda publicación real: sin ellos la respuesta no sirve (el
// incremental corta por last_updated).
const ITEMS_NUCLEO = ['id', 'title', 'status', 'price', 'available_quantity', 'variations', 'last_updated'];

/** 'bulk' (la nueva primero, por defecto) o 'ids' (sólo la vieja). Se lee en cada llamada. */
function itemsLecturaModo() {
    return String(process.env.ML_ITEMS_LECTURA || '').trim().toLowerCase() === 'ids' ? 'ids' : 'bulk';
}

// Memo de la lectura por objeto de cuenta (= por job). estado: '' (la nueva con
// vuelta) | 'vieja' (la nueva ya falló: directo a la vieja) | 'sin_vieja'.
const _lecturaItems = new WeakMap();
function memoLecturaItems(account) {
    if (!account || typeof account !== 'object') return { estado: '', registrado: '' };
    let m = _lecturaItems.get(account);
    if (!m) {
        m = { estado: '', registrado: '' };
        _lecturaItems.set(account, m);
    }
    return m;
}

/**
 * Registro corto de qué lectura respondió y, si la nueva falló, por qué. Una línea
 * por job y por cambio. Sin token, ids, títulos ni datos del vendedor: la cuenta va
 * por su public_id de la central.
 */
function registrarLecturaItems(account, msg, aviso = false) {
    const memo = memoLecturaItems(account);
    if (memo.registrado === msg) return;
    memo.registrado = msg;
    const linea = `[items] cuenta ${(account && account.public_id) || '?'}: ${msg}`;
    if (aviso) console.warn(linea);
    else console.log(linea);
}

/** Lo que devolvía siempre el multi-get: los body con code 200, o Error si la respuesta no sirve. */
function cuerposDeItems(r) {
    if (!r.ok || !Array.isArray(r.data)) {
        throw new Error(`items multi-get falló: HTTP ${r.status}`);
    }
    // El multi-get devuelve [{ code: 200, body: {...} }, ...].
    const out = [];
    for (const wrap of r.data) {
        if (wrap && wrap.code === 200 && wrap.body && wrap.body.id) {
            out.push(wrap.body);
        }
    }
    return out;
}

/**
 * ¿La respuesta de /items/bulk tiene la forma esperada?
 *   'ok'      → lista de envoltorios {code: 200, body} y cada pedido con su body
 *               (id pedido + campos núcleo).
 *   'parcial' → algunos sí y otros no (sin body, otro código, otro id, campos que
 *               faltan, pedidos que no vinieron).
 *   'falla'   → HTTP != 200, no es lista, todos sin body, ningún body.id pedido,
 *               campos que faltan en todos.
 *
 * @returns {{ estado: string, motivo: string, validos: object[] }}
 */
function validarItemsBulk(ids, r) {
    const falla = (motivo) => ({ estado: 'falla', motivo, validos: [] });
    if (!r || !r.ok || r.status !== 200) return falla(`http_${(r && r.status) || 0}`);
    const data = r.data;
    if (!Array.isArray(data)) return falla('forma_no_lista');
    if (!data.length) return falla('sin_pedidos');

    const pedidos = new Set(ids.map(String));
    const validos = [];
    const cubiertos = new Set();
    let sinBody = 0;
    let conId = 0;
    let otros = 0;
    for (const w of data) {
        if (!w || typeof w !== 'object' || !w.body || typeof w.body !== 'object') { sinBody++; continue; }
        const bid = w.body.id == null ? '' : String(w.body.id);
        if (w.code !== 200 || bid === '' || !pedidos.has(bid)) { otros++; continue; }
        conId++;
        if (!ITEMS_NUCLEO.every((k) => Object.prototype.hasOwnProperty.call(w.body, k))) { otros++; continue; }
        validos.push(w);
        cubiertos.add(bid);
    }
    if (sinBody === data.length) return falla('envoltorios_sin_body');
    if (conId === 0) return falla('sin_pedidos');
    if (!validos.length) return falla('sin_campos');
    if (sinBody || otros || cubiertos.size < pedidos.size) {
        return { estado: 'parcial', motivo: `parcial_${cubiertos.size}_de_${pedidos.size}`, validos };
    }
    return { estado: 'ok', motivo: '', validos };
}

// ----------------------------------------------------------------------------
// Mensajería post-venta + Preguntas pre-venta (M0, v2.9.0)
// ----------------------------------------------------------------------------

/**
 * POST genérico a la API de ML con bearer token. Reintenta 1 vez ante 401
 * (refrescando el token). Mismo contrato de retorno que mlUpdateItem.
 *
 * @returns {Promise<{ ok: boolean, status: number, data: object|null }>}
 */
export async function mlPost(account, path, accessToken, body, _isRetry = false) {
    const url = path.startsWith('http') ? path : `${ML_API}${path}`;
    const resp = await fetch(url, {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`,
        },
        body: JSON.stringify(body || {}),
    });
    if (resp.status === 401 && !_isRetry) {
        const fresh = await refreshAccessToken(account);
        return mlPost(account, path, fresh, body, true);
    }
    const raw = await resp.text();
    let data;
    try { data = JSON.parse(raw); } catch (_) { data = null; }
    return { ok: resp.ok, status: resp.status, data };
}

/**
 * Un MENSAJE puntual de la mensajería post-venta (el webhook `messages` trae
 * el resource /messages/{id}). Devuelve el mensaje crudo de ML — el shape trae
 * from/to, text, message_resources (pack/orden), message_date.
 */
export async function mlGetMessage(account, accessToken, messageId) {
    const r = await mlGet(account, `/messages/${encodeURIComponent(messageId)}?tag=post_sale`, accessToken);
    if (!r.ok || !r.data) {
        throw new Error(`messages/${messageId} falló: HTTP ${r.status}`);
    }
    return r.data;
}

/**
 * Hilo COMPLETO de mensajes de un pack (conversación comprador↔vendedor).
 *   GET /messages/packs/{pack_id}/sellers/{seller_id}?tag=post_sale
 * mark_as_read=false: leer el hilo desde el sistema NO lo marca leído en ML
 * (el estado de lectura del operador vive en el WP del cliente).
 */
export async function mlGetPackMessages(account, accessToken, packId, offset = 0, limit = 40) {
    const uid  = Number(account.ml_user_id);
    const path = `/messages/packs/${encodeURIComponent(String(packId))}/sellers/${uid}`
               + `?tag=post_sale&mark_as_read=false&offset=${offset}&limit=${limit}`;
    const r = await mlGet(account, path, accessToken);
    if (!r.ok || !r.data) {
        throw new Error(`messages/packs/${packId} falló: HTTP ${r.status}`);
    }
    return r.data; // { paging, messages: [...], conversation_status }
}

/**
 * RESPONDER al comprador en el hilo de un pack.
 *   POST /messages/packs/{pack_id}/sellers/{seller_id}?tag=post_sale
 * ML exige from (seller) y to (buyer) explícitos.
 */
export async function mlSendPackMessage(account, accessToken, packId, buyerUserId, text) {
    const uid  = Number(account.ml_user_id);
    const path = `/messages/packs/${encodeURIComponent(String(packId))}/sellers/${uid}?tag=post_sale`;
    return mlPost(account, path, accessToken, {
        from: { user_id: uid },
        to:   { user_id: Number(buyerUserId) },
        text: String(text || ''),
    });
}

/**
 * Preguntas del seller (pre-venta), paginado.
 *   GET /questions/search?seller_id=&status=&offset=&limit=&api_version=4
 * status típico: 'UNANSWERED' (para el backfill de abiertas) o vacío (todas).
 */
export async function mlSearchQuestions(account, accessToken, { status = '', offset = 0, limit = 50 } = {}) {
    const uid  = Number(account.ml_user_id);
    let path = `/questions/search?seller_id=${uid}&offset=${offset}&limit=${limit}&api_version=4&sort_fields=date_created&sort_types=DESC`;
    if (status) path += `&status=${encodeURIComponent(status)}`;
    const r = await mlGet(account, path, accessToken);
    if (!r.ok || !r.data) {
        throw new Error(`questions/search falló: HTTP ${r.status}`);
    }
    return {
        questions: Array.isArray(r.data.questions) ? r.data.questions : [],
        total:     Number(r.data.total) || 0,
    };
}

/** Una pregunta puntual (el webhook `questions` trae el resource /questions/{id}). */
export async function mlGetQuestion(account, accessToken, questionId) {
    const r = await mlGet(account, `/questions/${encodeURIComponent(String(questionId))}?api_version=4`, accessToken);
    if (!r.ok || !r.data) {
        throw new Error(`questions/${questionId} falló: HTTP ${r.status}`);
    }
    return r.data; // { id, text, status, item_id, from, answer, date_created }
}

/**
 * RESPONDER una pregunta.
 *   POST /answers  body { question_id, text }
 */
export async function mlAnswerQuestion(account, accessToken, questionId, text) {
    return mlPost(account, '/answers', accessToken, {
        question_id: Number(questionId),
        text: String(text || ''),
    });
}

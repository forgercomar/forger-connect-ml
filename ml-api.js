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
 */
export async function mlGet(account, path, accessToken, _isRetry = false) {
    const url = path.startsWith('http') ? path : `${ML_API}${path}`;
    const resp = await fetch(url, {
        headers: {
            'Accept': 'application/json',
            'Authorization': `Bearer ${accessToken}`,
        },
    });
    if (resp.status === 401 && !_isRetry) {
        // Token venció antes de tiempo — refrescar y reintentar una vez.
        const fresh = await refreshAccessToken(account);
        return mlGet(account, path, fresh, true);
    }
    const raw = await resp.text();
    let data;
    try { data = JSON.parse(raw); } catch (_) { data = null; }
    return { ok: resp.ok, status: resp.status, data, raw };
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
 *   GET /items?ids=A,B,C&attributes=...
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
    const path = `/items?ids=${ids.map(encodeURIComponent).join(',')}`
               + `&attributes=${encodeURIComponent(attrs.join(','))}`;
    const r = await mlGet(account, path, accessToken);
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

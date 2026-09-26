/**
 * worker.js — Worker del Central Orchestrator.
 *
 * Loop interno (setInterval) que procesa los jobs de sincronización:
 *
 *   1. Toma un job `pending` de tipo sync_* (lock con FOR UPDATE SKIP LOCKED).
 *   2. Resuelve la cuenta + un access_token válido de ML.
 *   3. Pagina /users/{uid}/items/search, trae los items con multi-get, arma
 *      el row para wf_ml_items y lo inserta en `synced_items`.
 *   4. Va actualizando jobs.steps_done para que el plugin vea el progreso.
 *   5. Marca el job `done` (o `failed` si algo explotó).
 *
 * El worker corre EN EL MISMO proceso que el server Express. Node es
 * single-thread pero todo el I/O (ML API, Postgres) es async, así que el
 * event loop no se bloquea. Para escalar a muchos clientes simultáneos se
 * puede mover a un proceso aparte — el lock SKIP LOCKED ya lo hace seguro.
 *
 * Son DOS loops independientes (v2.10.0): uno para los jobs de sync (sync_full /
 * sync_incremental) y otro para los `push` de stock/precio. Antes era un solo
 * loop FIFO: un full sync de miles de publicaciones frenaba los push de TODAS
 * las cuentas durante minutos (ventana de sobreventa). Los dos loops reclaman
 * con FOR UPDATE SKIP LOCKED, así que nunca toman el mismo job.
 *
 * Variables de entorno:
 *   WFML_WORKER_ENABLED   '0' para apagar el worker (default: encendido)
 *   WFML_WORKER_INTERVAL  ms entre ticks del loop de sync (default 5000)
 *   WFML_PUSH_INTERVAL    ms entre ticks del loop de push (default 2000)
 *   WFML_SYNC_CHUNK       items por página de ML por offset (default 50, max 50 = cap ML)
 *   WFML_SCAN_THRESHOLD   a partir de cuántas publicaciones el full usa search_type=scan (default 1000)
 *   WFML_SCAN_LIMIT       ids por página en modo scan (default 100, max 100 = cap ML)
 *   WFML_PUSH_PAUSE_MS    pausa entre PUT de un push masivo (default 0)
 *   WFML_PUSH_PROGRESS_EVERY  cada cuántos PUT se persiste el resultado parcial (default 25)
 *
 * @module worker
 */

import { query, tx } from './db.js';
import { accountLicenseVerdict } from './license-context.js';
import {
    getValidAccessToken,
    mlSearchItems,
    mlSearchItemsScan,
    mlGetItems,
    mlUpdateItem,
    ML_BATCH_SIZE,
} from './ml-api.js';

const WORKER_ENABLED  = process.env.WFML_WORKER_ENABLED !== '0';
const WORKER_INTERVAL = Math.max(2000, Number(process.env.WFML_WORKER_INTERVAL) || 5000);
const SYNC_CHUNK      = Math.max(1, Math.min(50, Number(process.env.WFML_SYNC_CHUNK) || 50));

// Sellers grandes: ML no pagina por offset más allá de ML_OFFSET_CAP items en
// /users/{uid}/items/search. A partir de SCAN_THRESHOLD publicaciones el full
// sync pagina con search_type=scan + scroll_id (hasta 100 por página, sin tope).
const ML_OFFSET_CAP   = 1000;
const SCAN_THRESHOLD  = Math.max(1, Number(process.env.WFML_SCAN_THRESHOLD) || ML_OFFSET_CAP);
const SCAN_LIMIT      = Math.max(1, Math.min(100, Number(process.env.WFML_SCAN_LIMIT) || 100));

// Loop de push aparte (ver encabezado): intervalo propio, pausa opcional entre
// PUT (para no martillar a ML en pushes de miles) y persistencia del resultado
// parcial cada N PUT (si el proceso muere a mitad, lo ya aplicado queda a la
// vista del plugin en jobs.result en vez de perderse).
const PUSH_INTERVAL       = Math.max(1000, Number(process.env.WFML_PUSH_INTERVAL) || 2000);
const PUSH_PAUSE_MS       = Math.max(0, Number(process.env.WFML_PUSH_PAUSE_MS) || 0);
const PUSH_PROGRESS_EVERY = Math.max(1, Number(process.env.WFML_PUSH_PROGRESS_EVERY) || 25);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Enforcement de licencia (Fase 6). Lo inyecta server.js vía startWorker(); si no,
// queda null → el worker no aplica ningún gate (comportamiento "off").
let _license = null; // { getContext, isEnforcing, isLicenseActive }

// Backoff en memoria para no re-claimear en loop un job de cuenta con licencia
// vencida: tras saltearlo lo devolvemos a 'pending' y anotamos un "no antes de".
// Sin esto, claimJob lo re-tomaría cada tick (~5s) y nunca avanzaría otros jobs.
const LICENSE_SKIP_BACKOFF_MS = 5 * 60_000; // 5 min entre reintentos de un job vencido
const _licenseSkipUntil = new Map(); // jobId → epoch ms hasta el que no re-procesar

// TTL de espera por licencia: un job NO puede esperar la renovación para siempre.
// Aplicar un push viejo al renovar días después pisaría precios/stock más nuevos.
// Al cancelarlo NO se pierde nada: el diff sigue figurando "Pendiente de push" en
// la grilla del cliente (verdad = build_payload vs espejo) y se re-pushea fresco.
const LICENSE_BLOCK_TTL_MS = Math.max(60 * 60_000, Number(process.env.WFML_LICENSE_BLOCK_TTL_MS) || 24 * 60 * 60_000);

// Anti-spam del log: "EN ESPERA — licencia vencida" se loguea 1 vez por hora por
// job (antes: una línea cada 5 min por job, para siempre).
const _licenseLogAt = new Map(); // jobId → epoch ms del último log

setInterval(() => {
    const now = Date.now();
    for (const [k, v] of _licenseSkipUntil.entries()) {
        if (v < now) _licenseSkipUntil.delete(k);
    }
    for (const [k, v] of _licenseLogAt.entries()) {
        if (now - v > 2 * 60 * 60_000) _licenseLogAt.delete(k);
    }
}, 10 * 60_000).unref();

/**
 * Gate de licencia para jobs del worker (CON gracia). Devuelve true si el job
 * NO debe procesarse ahora: licencia vencida (account.license_exp <= now) Y fuera
 * del período de gracia Y enforcement activo. La denylist (revoke explícito)
 * también bloquea aunque license_exp no haya vencido. En "observe"/"off" => false
 * (nunca bloquea). NO pierde el job: lo deja para más tarde (lo maneja el caller).
 *
 * @returns {{ blocked: boolean, reason?: string }}
 */
function licenseBlocksJob(account) {
    if (!_license || !_license.isLicenseActive() || !_license.isEnforcing()) {
        return { blocked: false };
    }
    // Regla ÚNICA compartida con GET /v1/jobs/:id (license-context.js) — así el
    // plugin recibe el MISMO veredicto que aplica el worker y puede mostrarlo.
    return accountLicenseVerdict(account);
}

/**
 * Devuelve un job bloqueado por licencia a 'pending' (sin perderlo) y anota un
 * backoff para no re-claimearlo en el próximo tick. El job correrá cuando la
 * licencia se renueve (o aplique gracia) y pase el backoff.
 */
async function deferJobForLicense(job, reason) {
    _licenseSkipUntil.set(String(job.id), Date.now() + LICENSE_SKIP_BACKOFF_MS);
    try {
        await query(
            `UPDATE jobs SET status = 'pending', started_at = NULL,
                             message = $2
             WHERE id = $1 AND status = 'running'`,
            [job.id, `En espera: licencia ${reason === 'revoked' ? 'revocada' : 'vencida'} (se reintenta al renovar).`]
        );
    } catch (e) {
        console.warn('[worker] deferJobForLicense update failed:', e.message);
    }
}

// Margen de seguridad del sync incremental: al watermark se le restan estos ms
// antes de comparar contra el `last_updated` de cada item. Sobre-traer items
// sin cambios es inofensivo (upsert idempotente del lado del plugin); perder
// uno por desfasaje de reloj o empate de orden, no — por eso el corte es generoso.
const INCREMENTAL_MARGIN_MS = 60 * 60 * 1000; // 1 hora

// Flags para evitar que dos ticks del MISMO loop se solapen si un job tarda más
// que el intervalo. Sync y push tienen cada uno el suyo: son loops independientes.
let _busySync = false;
let _busyPush = false;

// ----------------------------------------------------------------------------
// Construcción del row para wf_ml_items
// ----------------------------------------------------------------------------

/**
 * SKU de un item ML: lo busca en seller_custom_field o en attributes.
 */
function extractSku(node) {
    if (node.seller_custom_field) return String(node.seller_custom_field);
    if (Array.isArray(node.attributes)) {
        for (const a of node.attributes) {
            if (a && a.id === 'SELLER_SKU') return String(a.value_name || '');
        }
    }
    return '';
}

/**
 * Extrae info de cuotas del item ML. Porta wfml_sync_extract_installments
 * del plugin PHP:
 *   - Si viene item.installments con quantity → ese es el N real.
 *     rate=0 → sin interés.
 *   - Fallback por listing_type_id:
 *       gold_pro / gold_premium → no_interest=1, max=null  (badge "Sin interés")
 *       otros                   → max=0, no_interest=null  (badge "Clásica")
 *       sin listing_type        → ambos null               (badge "Definir")
 */
function extractInstallments(item) {
    if (item.installments && typeof item.installments === 'object') {
        const qty = Number(item.installments.quantity) || 0;
        if (qty > 0) {
            const rate = Number(item.installments.rate) || 0;
            return { installments_max: qty, installments_no_interest: rate === 0 ? 1 : 0 };
        }
    }
    const lt = String(item.listing_type_id || '').toLowerCase();
    if (lt === '') return { installments_max: null, installments_no_interest: null };
    if (lt === 'gold_pro' || lt === 'gold_premium') {
        return { installments_max: null, installments_no_interest: 1 };
    }
    return { installments_max: 0, installments_no_interest: null };
}

/**
 * Thumbnail de una variation (usa picture_ids) con fallback al del item.
 */
function variationThumb(variation, item) {
    if (variation.picture_ids && variation.picture_ids[0]) {
        return 'https://http2.mlstatic.com/D_NQ_NP_' + variation.picture_ids[0] + '-V.webp';
    }
    return String(item.thumbnail || '');
}

/**
 * Nombre legible de una variation: título del item + los atributos concretos
 * (color/talle/etc) que la distinguen, p.ej. "Remera Lisa — Negro / M".
 * ML no le da título propio a las variantes; lo componemos de
 * attribute_combinations. Sin atributos, cae al título del item.
 */
function variationLabel(item, variation) {
    const combos = Array.isArray(variation.attribute_combinations)
        ? variation.attribute_combinations : [];
    const parts = combos
        .map((c) => String((c && (c.value_name || c.value_id)) || '').trim())
        .filter(Boolean);
    const base = String(item.title || '');
    return parts.length ? (base + ' — ' + parts.join(' / ')) : base;
}

/**
 * Arma el row completo para wf_ml_items (sin account_id — lo pone el plugin
 * al aplicar, porque el id de cuenta local lo conoce solo él).
 *
 * @param {object} item       item ML completo
 * @param {object|null} variation  si != null, arma el row de esa variante
 * @param {boolean} hasVariations  si el item tiene variantes
 */
function buildItemRow(item, variation, hasVariations) {
    // Las cuotas son del item entero (ML no permite cuotas por variante);
    // las variantes heredan las del padre.
    const inst = extractInstallments(item);
    if (variation) {
        return {
            ml_item_id:               String(item.id),
            parent_item_id:           String(item.id),
            variation_id:             Number(variation.id),
            title:                    variationLabel(item, variation),
            sku:                      extractSku(variation),
            price:                    variation.price != null ? Number(variation.price) : 0,
            available_quantity:       variation.available_quantity != null ? Number(variation.available_quantity) : 0,
            sold_quantity:            item.sold_quantity != null ? Number(item.sold_quantity) : 0,
            status:                   String(item.status || ''),
            permalink:                String(item.permalink || ''),
            thumbnail:                variationThumb(variation, item),
            has_variations:           0,
            variations_json:          null,
            installments_max:         inst.installments_max,
            installments_no_interest: inst.installments_no_interest,
            category_id:              String(item.category_id || ''),
        };
    }
    return {
        ml_item_id:               String(item.id),
        parent_item_id:           null,
        variation_id:             null,
        title:                    String(item.title || ''),
        sku:                      extractSku(item),
        price:                    item.price != null ? Number(item.price) : 0,
        available_quantity:       item.available_quantity != null ? Number(item.available_quantity) : 0,
        sold_quantity:            item.sold_quantity != null ? Number(item.sold_quantity) : 0,
        status:                   String(item.status || ''),
        permalink:                String(item.permalink || ''),
        thumbnail:                String(item.thumbnail || ''),
        has_variations:           hasVariations ? 1 : 0,
        variations_json:          hasVariations && Array.isArray(item.variations)
                                    ? JSON.stringify(item.variations) : null,
        installments_max:         inst.installments_max,
        installments_no_interest: inst.installments_no_interest,
        category_id:              String(item.category_id || ''),
    };
}

// ----------------------------------------------------------------------------
// Persistencia de items en staging
// ----------------------------------------------------------------------------

/**
 * Inserta en synced_items un batch de rows ya armados.
 * Cada `row` = { ml_item_id, variation_id, item_data }.
 */
async function insertSyncedItems(accountId, jobId, rows) {
    if (!rows.length) return;
    const placeholders = [];
    const values = [];
    let p = 1;
    for (const r of rows) {
        placeholders.push(`($${p++}, $${p++}, $${p++}, $${p++}, $${p++})`);
        values.push(accountId, jobId, r.ml_item_id, r.variation_id, JSON.stringify(r.item_data));
    }
    await query(
        `INSERT INTO synced_items (account_id, job_id, ml_item_id, variation_id, item_data)
         VALUES ${placeholders.join(',')}`,
        values
    );
}

/**
 * Convierte una página de items ML en rows de synced_items (padres + variantes).
 */
function expandItemsToRows(items) {
    const rows = [];
    for (const item of items) {
        const variations = Array.isArray(item.variations) ? item.variations : [];
        const hasVars = variations.length > 0;
        // Padre / item simple.
        rows.push({
            ml_item_id:   String(item.id),
            variation_id: null,
            item_data:    buildItemRow(item, null, hasVars),
        });
        // Variantes.
        if (hasVars) {
            for (const v of variations) {
                if (!v || !v.id) continue;
                rows.push({
                    ml_item_id:   String(item.id),
                    variation_id: Number(v.id),
                    item_data:    buildItemRow(item, v, true),
                });
            }
        }
    }
    return rows;
}

// ----------------------------------------------------------------------------
// Procesamiento de un job de sync
// ----------------------------------------------------------------------------

/**
 * ¿El job sigue vivo? (no fue cancelado mientras procesábamos)
 */
async function jobIsActive(jobId) {
    const r = await query(`SELECT status FROM jobs WHERE id = $1`, [jobId]);
    return r.rowCount > 0 && r.rows[0].status === 'running';
}

/**
 * Procesa un job "targeted": una lista explícita de ml_item_ids (típicamente
 * originada por webhooks). En vez de paginar todo el catálogo del seller,
 * trae solo esos items con multi-get. Mucho más liviano y rápido.
 */
async function processTargetedSync(job, account, token, ids) {
    const unique = [...new Set(ids)];
    const stepsTotal = Math.max(1, Math.ceil(unique.length / ML_BATCH_SIZE));
    await query(
        `UPDATE jobs SET steps_total = $2, steps_done = 0, message = $3 WHERE id = $1`,
        [job.id, stepsTotal, `Actualizando ${unique.length} publicación(es) modificada(s)...`]
    );

    let processed = 0;
    let stepsDone = 0;
    for (let i = 0; i < unique.length; i += ML_BATCH_SIZE) {
        if (!(await jobIsActive(job.id))) {
            console.log(`[worker] job ${job.public_id} cancelado a mitad — corto.`);
            return;
        }
        const chunk = unique.slice(i, i + ML_BATCH_SIZE);
        // mlGetItems descarta los ids que ML no devuelve con code 200 (item
        // borrado, etc.) — esos simplemente no se actualizan.
        const items = await mlGetItems(account, token, chunk);
        const rows = expandItemsToRows(items);
        await insertSyncedItems(account.id, job.id, rows);
        processed += items.length;
        stepsDone++;
        await query(
            `UPDATE jobs SET steps_done = $2, message = $3, last_seen_at = NOW() WHERE id = $1`,
            [job.id, stepsDone, `Actualizadas ${processed} de ${unique.length}...`]
        );
    }

    await query(
        `UPDATE jobs SET status = 'done', finished_at = NOW(), result = $2, message = $3
         WHERE id = $1 AND status = 'running'`,
        [job.id,
         JSON.stringify({ items_synced: processed, total: unique.length, mode: 'targeted' }),
         `Actualización completa: ${processed} publicación(es).`]
    );
    console.log(`[worker] job ${job.public_id} done (targeted) — ${processed} items`);
}

/**
 * Procesa un job de tipo sync_full / sync_incremental.
 */
async function processSyncJob(job) {
    // 1) Cargar la cuenta.
    const accR = await query(`SELECT * FROM accounts WHERE id = $1`, [job.account_id]);
    if (!accR.rowCount) throw new Error('cuenta no encontrada');
    const account = accR.rows[0];
    if (account.revoked_at) throw new Error('cuenta revocada');

    // 2) Token de ML.
    const token = await getValidAccessToken(account);

    // 2b) Modo "targeted": si el job trae una lista explícita de items
    //     (ej. agrupados desde webhooks), sincronizamos solo esos.
    const input = (job.input && typeof job.input === 'object') ? job.input : {};
    const targetIds = Array.isArray(input.ml_item_ids)
        ? input.ml_item_ids.map(String).filter(Boolean)
        : [];
    if (targetIds.length > 0) {
        return await processTargetedSync(job, account, token, targetIds);
    }

    // 2c) Modo "incremental": si el job es sync_incremental y la cuenta ya
    //     tiene watermark, traemos solo lo modificado desde ahí. Sin watermark
    //     (primer sync de la cuenta) cae al full de abajo — que lo deja seteado.
    if (job.type === 'sync_incremental' && account.last_sync_at) {
        return await processIncrementalSync(job, account, token);
    }

    // 3) Primera búsqueda para conocer el total.
    const first = await mlSearchItems(account, token, 0, SYNC_CHUNK);
    const total = first.total;
    // Sellers grandes (v2.10.0): por encima de SCAN_THRESHOLD publicaciones ML
    // no deja paginar por offset (cap 1.000) → modo scan con scroll_id. Antes el
    // full de un seller de 5.000 publicaciones veía solo las primeras 1.000.
    const useScan   = total > SCAN_THRESHOLD;
    const pageSize  = useScan ? SCAN_LIMIT : SYNC_CHUNK;
    const stepsTotal = Math.max(1, Math.ceil(total / pageSize));
    await query(
        `UPDATE jobs SET steps_total = $2, steps_done = 0,
                         message = $3
         WHERE id = $1`,
        [job.id, stepsTotal, `Sincronizando ${total} publicaciones${useScan ? ' (modo scan)' : ''}...`]
    );

    // 4) Procesar página por página.
    let processed = 0;
    let stepsDone = 0;
    let truncated = false;

    async function handlePage(ids) {
        if (!ids.length) return;
        // Multi-get en chunks de ML_BATCH_SIZE.
        const allItems = [];
        for (let i = 0; i < ids.length; i += ML_BATCH_SIZE) {
            const chunk = ids.slice(i, i + ML_BATCH_SIZE);
            const items = await mlGetItems(account, token, chunk);
            allItems.push(...items);
        }
        const rows = expandItemsToRows(allItems);
        await insertSyncedItems(account.id, job.id, rows);
        processed += allItems.length;
        stepsDone++;
        await query(
            `UPDATE jobs SET steps_done = $2,
                             message = $3,
                             last_seen_at = NOW()
             WHERE id = $1`,
            [job.id, stepsDone, `Sincronizadas ${processed} de ${total}...`]
        );
    }

    if (useScan) {
        // Modo scan: arranca de cero (la página por offset de arriba solo sirvió
        // para conocer el total) y reenvía el scroll_id hasta que ML devuelve
        // una página vacía. `seen` descarta ids repetidos entre páginas para que
        // ningún item entre dos veces en staging; el tope de iteraciones evita
        // un loop sin fin si ML repitiera páginas.
        const seen = new Set();
        let scrollId = '';
        let iterations = 0;
        const maxIterations = Math.ceil(total / SCAN_LIMIT) + 10;
        for (;;) {
            if (!(await jobIsActive(job.id))) {
                console.log(`[worker] job ${job.public_id} cancelado a mitad — corto.`);
                return; // el status ya quedó en cancelled
            }
            if (++iterations > maxIterations) {
                console.warn(`[worker] job ${job.public_id}: scan pasó ${maxIterations} páginas para ${total} publicaciones — corto por seguridad.`);
                truncated = true;
                break;
            }
            const page = await mlSearchItemsScan(account, token, scrollId, SCAN_LIMIT);
            if (page.scroll_id) scrollId = page.scroll_id;
            if (!page.ids.length) break;
            const ids = page.ids.map(String).filter((id) => id && !seen.has(id));
            for (const id of ids) seen.add(id);
            await handlePage(ids);
        }
    } else {
        // 5) Modo offset (sellers chicos): la primera página ya la tenemos.
        await handlePage(first.ids);
        for (let offset = SYNC_CHUNK; offset < total; offset += SYNC_CHUNK) {
            if (!(await jobIsActive(job.id))) {
                console.log(`[worker] job ${job.public_id} cancelado a mitad — corto.`);
                return; // el status ya quedó en cancelled
            }
            const page = await mlSearchItems(account, token, offset, SYNC_CHUNK);
            await handlePage(page.ids);
        }
    }

    // 6) Done. Un sync full (o el primer incremental, que cae acá por no tener
    //    watermark) deja la cuenta con cobertura total → avanzamos la marca.
    await query(
        `UPDATE jobs SET status = 'done', finished_at = NOW(),
                         result = $2,
                         message = $3
         WHERE id = $1 AND status = 'running'`,
        [job.id,
         JSON.stringify({ items_synced: processed, total, mode: useScan ? 'full_scan' : 'full', truncated }),
         `Sync completo: ${processed} publicaciones.`]
    );
    await advanceWatermark(account.id, job.started_at);
    console.log(`[worker] job ${job.public_id} done (${useScan ? 'scan' : 'offset'}) — ${processed} items`);
}

/**
 * Avanza accounts.last_sync_at al `started_at` del job — el watermark desde el
 * cual el próximo sync_incremental considera un item "modificado". Se usa el
 * INICIO del job (no el fin) para no dejar afuera nada que haya cambiado
 * mientras el sync corría.
 */
async function advanceWatermark(accountId, startedAt) {
    if (!startedAt) return;
    await query(`UPDATE accounts SET last_sync_at = $2 WHERE id = $1`, [accountId, startedAt]);
}

/**
 * Procesa un job sync_incremental real: trae SOLO los items de ML modificados
 * desde el watermark de la cuenta (accounts.last_sync_at).
 *
 * ML no expone un filtro "items modificados desde X", pero su items/search sí
 * ordena por `last_updated`. Paginamos con orders=last_updated_desc (lo más
 * reciente primero), multi-get de cada página para conocer el `last_updated`
 * real de cada item, y CORTAMOS apenas una página trae un item por debajo del
 * umbral — de ahí en más todo es más viejo. Así solo se recorren las páginas
 * que tienen cambios.
 *
 * Al watermark se le resta INCREMENTAL_MARGIN_MS de margen. Sin cambios, el job
 * termina con 0 items (el plugin lo ve como "catálogo al día").
 */
async function processIncrementalSync(job, account, token) {
    const sinceMs = new Date(account.last_sync_at).getTime() - INCREMENTAL_MARGIN_MS;
    const luMs = (it) => (it && it.last_updated ? new Date(it.last_updated).getTime() : 0);

    await query(
        `UPDATE jobs SET steps_total = 0, steps_done = 0, message = $2 WHERE id = $1`,
        [job.id, 'Buscando publicaciones modificadas...']
    );

    let processed = 0;
    let pages = 0;
    let reachedCutoff = false;
    let capped = false;
    let total = 0;

    for (let offset = 0; ; offset += SYNC_CHUNK) {
        if (!(await jobIsActive(job.id))) {
            console.log(`[worker] job ${job.public_id} cancelado a mitad — corto.`);
            return;
        }
        // ML no pagina por offset más allá de 1.000 (y `orders=` no se combina
        // con scan). Si en una ventana cambiaron más de 1.000 publicaciones,
        // cortamos limpio y lo marcamos: antes el request fallaba y el job
        // entero quedaba en failed. El full periódico (con scan) cubre el resto.
        if (offset + SYNC_CHUNK > ML_OFFSET_CAP) { capped = true; break; }
        const page = await mlSearchItems(account, token, offset, SYNC_CHUNK, 'last_updated_desc');
        total = page.total;
        if (!page.ids.length) break;

        // Multi-get de la página para conocer el last_updated de cada item.
        const items = [];
        for (let i = 0; i < page.ids.length; i += ML_BATCH_SIZE) {
            const chunk = page.ids.slice(i, i + ML_BATCH_SIZE);
            items.push(...await mlGetItems(account, token, chunk));
        }

        // Items modificados después del watermark → a staging.
        const fresh = items.filter((it) => luMs(it) >= sinceMs);
        if (fresh.length) {
            await insertSyncedItems(account.id, job.id, expandItemsToRows(fresh));
            processed += fresh.length;
        }
        pages++;
        await query(
            `UPDATE jobs SET steps_done = $2, message = $3, last_seen_at = NOW() WHERE id = $1`,
            [job.id, pages, `Revisando cambios — ${processed} publicación(es) modificada(s)...`]
        );

        // La página viene ordenada last_updated_desc: si algún item ya cayó
        // bajo el umbral, todo lo que sigue es más viejo → no hay nada más.
        if (items.some((it) => luMs(it) < sinceMs)) { reachedCutoff = true; break; }
        if (offset + SYNC_CHUNK >= total) break;
    }

    await query(
        `UPDATE jobs SET status = 'done', finished_at = NOW(), result = $2, message = $3
         WHERE id = $1 AND status = 'running'`,
        [job.id,
         JSON.stringify({ items_synced: processed, mode: 'incremental', pages_scanned: pages, reached_cutoff: reachedCutoff, capped }),
         processed > 0
            ? `Sync incremental: ${processed} publicación(es) actualizada(s).${capped ? ' Se revisaron las 1.000 más recientes; el resto lo cubre el sync completo.' : ''}`
            : 'Sync incremental: catálogo al día, sin cambios.']
    );
    await advanceWatermark(account.id, job.started_at);
    console.log(`[worker] job ${job.public_id} done (incremental) — ${processed} items, ${pages} página(s)${capped ? ', tope de offset' : ''}`);
}

// ----------------------------------------------------------------------------
// Procesamiento de un job de push (push masivo Web → ML)
// ----------------------------------------------------------------------------

/**
 * Extrae un mensaje legible del cuerpo de error de ML.
 */
function mlErrorMessage(res) {
    const d = res && res.data;
    if (d) {
        if (Array.isArray(d.cause) && d.cause.length) {
            const msg = d.cause
                .map((c) => (c && (c.message || c.code)) || '')
                .filter(Boolean).join('; ');
            if (msg) return msg;
        }
        if (d.message) return String(d.message);
    }
    return `HTTP ${res ? res.status : '?'}`;
}

/**
 * Procesa un job `push`: ejecuta los PUT contra ML que el plugin ya dejó
 * armados. El plugin calculó cada body (precio/stock/variations) con sus datos
 * de WooCommerce — el central solo los manda y reporta cómo fue.
 *
 * input.pushes = [{ ml_item_id, body, apply?, variation_id? }]
 *   body  → cuerpo del PUT /items/{id}.
 *   apply → blob opaco que el plugin necesita para sincronizar su cache; el
 *           central no lo interpreta, solo lo devuelve tal cual en el result.
 *
 * El resultado por item queda en result.items; el plugin lo baja con
 * GET /v1/jobs/:id, aplica los OK a su cache y loguea los que fallaron.
 */
async function processPushJob(job) {
    const accR = await query(`SELECT * FROM accounts WHERE id = $1`, [job.account_id]);
    if (!accR.rowCount) throw new Error('cuenta no encontrada');
    const account = accR.rows[0];
    if (account.revoked_at) throw new Error('cuenta revocada');
    const token = await getValidAccessToken(account);

    const input  = (job.input && typeof job.input === 'object') ? job.input : {};
    const pushes = Array.isArray(input.pushes) ? input.pushes : [];
    const total  = pushes.length;

    await query(
        `UPDATE jobs SET steps_total = $2, steps_done = 0, message = $3 WHERE id = $1`,
        [job.id, total, `Pusheando ${total} publicación(es) a Mercado Libre...`]
    );

    const results = [];
    let pushed = 0, failed = 0, done = 0;

    for (const pu of pushes) {
        if (!(await jobIsActive(job.id))) {
            console.log(`[worker] job ${job.public_id} cancelado a mitad — corto.`);
            return;
        }
        // Pausa opcional entre PUT (pushes de miles: no martillar a ML).
        if (PUSH_PAUSE_MS > 0 && done > 0) await sleep(PUSH_PAUSE_MS);
        const mlItemId = String((pu && pu.ml_item_id) || '');
        const body     = (pu && pu.body && typeof pu.body === 'object') ? pu.body : null;
        let r;
        if (!mlItemId || !body) {
            r = { ml_item_id: mlItemId, ok: false, http_code: 0, error: 'push inválido (sin ml_item_id o body)' };
        } else {
            try {
                const res = await mlUpdateItem(account, token, mlItemId, body);
                r = {
                    ml_item_id: mlItemId,
                    ok: res.ok,
                    http_code: res.status,
                    error: res.ok ? null : mlErrorMessage(res),
                };
            } catch (err) {
                r = { ml_item_id: mlItemId, ok: false, http_code: 0, error: err.message };
            }
        }
        // Passthrough: el plugin necesita estos campos para sincronizar su cache.
        if (pu && pu.apply !== undefined) r.apply = pu.apply;
        if (pu && pu.variation_id !== undefined) r.variation_id = pu.variation_id;
        results.push(r);
        if (r.ok) pushed++; else failed++;
        done++;
        const progressMsg = `Pusheadas ${done}/${total} — ${pushed} OK, ${failed} con error...`;
        if (done % PUSH_PROGRESS_EVERY === 0 || done === total) {
            // Resultado PARCIAL persistido (v2.10.0): si el proceso muere a mitad de
            // un push de miles, el janitor marca el job failed pero lo ya aplicado
            // queda a la vista en jobs.result en vez de perderse. El plugin aplica
            // resultados SOLO con status 'done', así que no hay doble aplicación.
            await query(
                `UPDATE jobs SET steps_done = $2, message = $3, last_seen_at = NOW(), result = $4 WHERE id = $1`,
                [job.id, done, progressMsg,
                 JSON.stringify({ mode: 'push', partial: true, total, pushed, failed, items: results })]
            );
        } else {
            await query(
                `UPDATE jobs SET steps_done = $2, message = $3, last_seen_at = NOW() WHERE id = $1`,
                [job.id, done, progressMsg]
            );
        }
    }

    await query(
        `UPDATE jobs SET status = 'done', finished_at = NOW(), result = $2, message = $3
         WHERE id = $1 AND status = 'running'`,
        [job.id,
         JSON.stringify({ mode: 'push', total, pushed, failed, items: results }),
         `Push masivo: ${pushed} OK, ${failed} con error (de ${total}).`]
    );
    console.log(`[worker] job ${job.public_id} done (push) — ${pushed} OK, ${failed} fail`);
}

// ----------------------------------------------------------------------------
// Loop principal
// ----------------------------------------------------------------------------

const SYNC_TYPES = ['sync_full', 'sync_incremental'];
const PUSH_TYPES = ['push'];

/**
 * Toma un job pending procesable de los tipos pedidos. Lock atómico para no
 * doble-procesar (FOR UPDATE SKIP LOCKED): el loop de sync y el de push pueden
 * reclamar a la vez sin pisarse. auto_link lo maneja el plugin (modelo A).
 *
 * @param {string[]} types tipos de job que este loop procesa.
 */
async function claimJob(types) {
    // Excluir jobs en backoff por licencia vencida (devueltos a 'pending' tras un
    // skip). Sin esto se re-claimearían cada tick y bloquearían a los demás.
    const now = Date.now();
    const deferred = [];
    for (const [k, v] of _licenseSkipUntil.entries()) {
        if (v >= now) deferred.push(k);
    }
    const r = await query(
        `UPDATE jobs SET status = 'running', started_at = COALESCE(started_at, NOW())
         WHERE id = (
            SELECT id FROM jobs
            WHERE status = 'pending'
              AND type = ANY($2::text[])
              AND NOT (id = ANY($1::bigint[]))
            ORDER BY created_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
         )
         RETURNING id, public_id, account_id, type, input, started_at, created_at`,
        [deferred.length ? deferred.map((x) => Number(x)) : [0], types]
    );
    return r.rowCount ? r.rows[0] : null;
}

/**
 * Carga la cuenta del job y aplica el gate de licencia (CON gracia). Si la cuenta
 * tiene licencia vencida/revocada fuera de gracia y el enforcement está activo,
 * devuelve el job a 'pending' con backoff y retorna true (skip). NO pierde el job.
 */
async function jobBlockedByLicense(job) {
    if (!_license || !_license.isLicenseActive() || !_license.isEnforcing()) return false;
    let account;
    try {
        const accR = await query(
            `SELECT id, public_id, license_id, license_exp, last_valid_license_token_at, revoked_at
             FROM accounts WHERE id = $1`,
            [job.account_id]
        );
        account = accR.rows[0];
    } catch (e) {
        // Si no podemos leer la cuenta, NO bloqueamos (fail-open de infra): el
        // procesamiento normal ya revalida la cuenta y fallará limpio si no existe.
        console.warn('[worker] license gate: no se pudo leer la cuenta — se permite:', e.message);
        return false;
    }
    if (!account) return false; // processSyncJob/processPushJob lo manejan (cuenta no encontrada)

    const verdict = licenseBlocksJob(account);
    if (!verdict.blocked) {
        _licenseLogAt.delete(String(job.id));
        return false;
    }

    // TTL: pasado el plazo, el job se CANCELA con motivo claro en vez de esperar
    // para siempre (aplicar un push viejo tras renovar pisaría datos más nuevos;
    // el pendiente sigue visible en la grilla del cliente y se re-pushea fresco).
    const createdMs = job.created_at ? new Date(job.created_at).getTime() : 0;
    if (createdMs && (Date.now() - createdMs) > LICENSE_BLOCK_TTL_MS) {
        try {
            await query(
                `UPDATE jobs SET status = 'cancelled', finished_at = NOW(), message = $2
                 WHERE id = $1 AND status = 'running'`,
                [job.id, 'Cancelado: la licencia lleva vencida más de ' + Math.round(LICENSE_BLOCK_TTL_MS / 3600000) + 'h. Renovala y volvé a pushear — el cambio sigue como pendiente en la grilla.']
            );
        } catch (e) {
            console.warn('[worker] cancel por licencia falló:', e.message);
        }
        _licenseSkipUntil.delete(String(job.id));
        _licenseLogAt.delete(String(job.id));
        console.warn(`[worker] job ${job.public_id} CANCELADO — licencia ${verdict.reason} > TTL para cuenta ${account.public_id}.`);
        return true;
    }

    const lastLog = _licenseLogAt.get(String(job.id)) || 0;
    if (Date.now() - lastLog > 60 * 60_000) {
        _licenseLogAt.set(String(job.id), Date.now());
        console.warn(`[worker] job ${job.public_id} EN ESPERA — licencia ${verdict.reason} para cuenta ${account.public_id} (fuera de gracia). Se reintenta cada ${LICENSE_SKIP_BACKOFF_MS / 60000}min (este aviso se loguea 1 vez/hora).`);
    }
    await deferJobForLicense(job, verdict.reason);
    return true;
}

/**
 * Un tick: reclama UN job de los tipos dados y lo procesa entero. Compartido por
 * los dos loops; cada uno pasa sus tipos y su flag de ocupado.
 */
async function runOne(types, label) {
    const job = await claimJob(types);
    if (!job) return;
    // Gate de licencia (Fase 6): si la cuenta tiene licencia vencida/revocada
    // fuera de gracia y enforcement activo, devolvemos el job a 'pending' (sin
    // perderlo) y salimos del tick — el batch en curso de OTRO job no existe acá
    // (un tick = un job), así que no cortamos nada a mitad.
    if (await jobBlockedByLicense(job)) return;
    console.log(`[worker:${label}] tomando job ${job.public_id} (${job.type})`);
    try {
        await (job.type === 'push' ? processPushJob(job) : processSyncJob(job));
    } catch (err) {
        console.error(`[worker:${label}] job ${job.public_id} falló:`, err.message);
        await query(
            `UPDATE jobs SET status = 'failed', finished_at = NOW(),
                             message = $2
             WHERE id = $1 AND status = 'running'`,
            [job.id, 'Error: ' + err.message]
        );
    }
}

async function tickSync() {
    if (_busySync) return;
    _busySync = true;
    try {
        await runOne(SYNC_TYPES, 'sync');
    } catch (err) {
        console.error('[worker:sync] tick error:', err.message);
    } finally {
        _busySync = false;
    }
}

async function tickPush() {
    if (_busyPush) return;
    _busyPush = true;
    try {
        await runOne(PUSH_TYPES, 'push');
    } catch (err) {
        console.error('[worker:push] tick error:', err.message);
    } finally {
        _busyPush = false;
    }
}

/**
 * Arranca los dos loops del worker (sync y push). Llamado una vez desde server.js.
 */
export function startWorker(opts = {}) {
    // Enforcement de licencia (Fase 6): server.js inyecta el contexto compartido.
    if (opts.license) _license = opts.license;
    if (!WORKER_ENABLED) {
        console.log('[worker] deshabilitado (WFML_WORKER_ENABLED=0)');
        return;
    }
    console.log(`[worker] arrancando — sync cada ${WORKER_INTERVAL}ms (chunk ${SYNC_CHUNK}, scan desde ${SCAN_THRESHOLD}), push cada ${PUSH_INTERVAL}ms`);
    setInterval(() => { tickSync().catch((e) => console.error('[worker:sync] tick uncaught:', e)); }, WORKER_INTERVAL);
    setInterval(() => { tickPush().catch((e) => console.error('[worker:push] tick uncaught:', e)); }, PUSH_INTERVAL);
}

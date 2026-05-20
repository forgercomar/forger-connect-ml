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
 * Variables de entorno:
 *   WFML_WORKER_ENABLED   '0' para apagar el worker (default: encendido)
 *   WFML_WORKER_INTERVAL  ms entre ticks (default 5000)
 *   WFML_SYNC_CHUNK       items por página de ML (default 50, max 50 = cap ML)
 *
 * @module worker
 */

import { query, tx } from './db.js';
import {
    getValidAccessToken,
    mlSearchItems,
    mlGetItems,
    ML_BATCH_SIZE,
} from './ml-api.js';

const WORKER_ENABLED  = process.env.WFML_WORKER_ENABLED !== '0';
const WORKER_INTERVAL = Math.max(2000, Number(process.env.WFML_WORKER_INTERVAL) || 5000);
const SYNC_CHUNK      = Math.max(1, Math.min(50, Number(process.env.WFML_SYNC_CHUNK) || 50));

// Margen de seguridad del sync incremental: al watermark se le restan estos ms
// antes de comparar contra el `last_updated` de cada item. Sobre-traer items
// sin cambios es inofensivo (upsert idempotente del lado del plugin); perder
// uno por desfasaje de reloj o empate de orden, no — por eso el corte es generoso.
const INCREMENTAL_MARGIN_MS = 60 * 60 * 1000; // 1 hora

// Flag para evitar que dos ticks se solapen si un job tarda más que el intervalo.
let _busy = false;

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
    const stepsTotal = Math.max(1, Math.ceil(total / SYNC_CHUNK));
    await query(
        `UPDATE jobs SET steps_total = $2, steps_done = 0,
                         message = $3
         WHERE id = $1`,
        [job.id, stepsTotal, `Sincronizando ${total} publicaciones...`]
    );

    // 4) Procesar la primera página (ya la tenemos) y después el resto.
    let processed = 0;
    let stepsDone = 0;

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

    await handlePage(first.ids);

    // 5) Resto de las páginas.
    for (let offset = SYNC_CHUNK; offset < total; offset += SYNC_CHUNK) {
        if (!(await jobIsActive(job.id))) {
            console.log(`[worker] job ${job.public_id} cancelado a mitad — corto.`);
            return; // el status ya quedó en cancelled
        }
        const page = await mlSearchItems(account, token, offset, SYNC_CHUNK);
        await handlePage(page.ids);
    }

    // 6) Done. Un sync full (o el primer incremental, que cae acá por no tener
    //    watermark) deja la cuenta con cobertura total → avanzamos la marca.
    await query(
        `UPDATE jobs SET status = 'done', finished_at = NOW(),
                         result = $2,
                         message = $3
         WHERE id = $1 AND status = 'running'`,
        [job.id,
         JSON.stringify({ items_synced: processed, total }),
         `Sync completo: ${processed} publicaciones.`]
    );
    await advanceWatermark(account.id, job.started_at);
    console.log(`[worker] job ${job.public_id} done — ${processed} items`);
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
    let total = 0;

    for (let offset = 0; ; offset += SYNC_CHUNK) {
        if (!(await jobIsActive(job.id))) {
            console.log(`[worker] job ${job.public_id} cancelado a mitad — corto.`);
            return;
        }
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
         JSON.stringify({ items_synced: processed, mode: 'incremental', pages_scanned: pages, reached_cutoff: reachedCutoff }),
         processed > 0
            ? `Sync incremental: ${processed} publicación(es) actualizada(s).`
            : 'Sync incremental: catálogo al día, sin cambios.']
    );
    await advanceWatermark(account.id, job.started_at);
    console.log(`[worker] job ${job.public_id} done (incremental) — ${processed} items, ${pages} página(s)`);
}

// ----------------------------------------------------------------------------
// Loop principal
// ----------------------------------------------------------------------------

/**
 * Toma un job pending procesable. Lock atómico para no doble-procesar.
 * Solo tipos sync_* — push/auto_link los maneja el plugin (modelo A).
 */
async function claimJob() {
    const r = await query(
        `UPDATE jobs SET status = 'running', started_at = COALESCE(started_at, NOW())
         WHERE id = (
            SELECT id FROM jobs
            WHERE status = 'pending'
              AND type IN ('sync_full', 'sync_incremental')
            ORDER BY created_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
         )
         RETURNING id, public_id, account_id, type, input, started_at`
    );
    return r.rowCount ? r.rows[0] : null;
}

async function tick() {
    if (_busy) return;
    _busy = true;
    try {
        const job = await claimJob();
        if (!job) return;
        console.log(`[worker] tomando job ${job.public_id} (${job.type})`);
        try {
            await processSyncJob(job);
        } catch (err) {
            console.error(`[worker] job ${job.public_id} falló:`, err.message);
            await query(
                `UPDATE jobs SET status = 'failed', finished_at = NOW(),
                                 message = $2
                 WHERE id = $1 AND status = 'running'`,
                [job.id, 'Error: ' + err.message]
            );
        }
    } catch (err) {
        console.error('[worker] tick error:', err.message);
    } finally {
        _busy = false;
    }
}

/**
 * Arranca el loop del worker. Llamado una vez desde server.js.
 */
export function startWorker() {
    if (!WORKER_ENABLED) {
        console.log('[worker] deshabilitado (WFML_WORKER_ENABLED=0)');
        return;
    }
    console.log(`[worker] arrancando — intervalo ${WORKER_INTERVAL}ms, chunk ${SYNC_CHUNK}`);
    setInterval(() => { tick().catch((e) => console.error('[worker] tick uncaught:', e)); }, WORKER_INTERVAL);
}

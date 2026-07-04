/**
 * orders-snapshot.js — Snapshot completo de órdenes ML (Ventas ML, F0).
 *
 * Helpers compartidos por el procesador de órdenes en vivo y el backfill
 * histórico (ambos en scheduler.js): enriquecen una orden ML con los datos
 * que la orden a secas no trae (billing_info del comprador, estado del
 * envío) y la persisten en order_snapshots.
 *
 * Filosofía: se guarda el JSON CRUDO tal como lo devolvió la API de ML.
 * El que interpreta es el plugin al ingestar al espejo wf_orders — igual
 * que synced_items.item_data ("flexible ante cambios de schema").
 *
 * @module orders-snapshot
 */

import { query } from './db.js';
import { mlGetOrderBillingInfo, mlGetShipment } from './ml-api.js';

/**
 * Enriquecimiento TOLERANTE: si billing_info o el shipment fallan, la orden
 * sigue su curso — el snapshot guarda null en ese campo y un evento futuro
 * (o un re-backfill) lo completa. El pipeline de stock nunca queda rehén de
 * un dato accesorio.
 *
 * @param {object} account fila de accounts
 * @param {string} token   access_token vigente
 * @param {object} order   orden ML (de GET /orders/{id} o de orders/search)
 * @param {object} [opts]  { billing: false } / { shipment: false } para saltear
 * @returns {Promise<{billing: object|null, shipment: object|null}>}
 */
export async function enrichOrder(account, token, order, opts = {}) {
    const out = { billing: null, shipment: null };
    const mlOrderId = order && order.id != null ? String(order.id) : '';
    if (mlOrderId && opts.billing !== false) {
        try {
            out.billing = await mlGetOrderBillingInfo(account, token, mlOrderId);
        } catch (err) {
            console.warn(`[orders] billing_info ${mlOrderId} no disponible:`, err.message);
        }
    }
    const shipId = order && order.shipping && order.shipping.id;
    if (shipId && opts.shipment !== false) {
        try {
            out.shipment = await mlGetShipment(account, token, String(shipId));
        } catch (err) {
            console.warn(`[orders] shipment ${shipId} (orden ${mlOrderId}) no disponible:`, err.message);
        }
    }
    return out;
}

/**
 * Upsert del snapshot por (account_id, ml_order_id).
 *
 * order_json siempre se pisa con el más reciente (la orden cambia de estado);
 * billing/shipment solo se pisan si el fetch nuevo trajo algo — un fallo
 * transitorio no borra un dato que ya teníamos (COALESCE con la fila vieja).
 *
 * @param {number} accountId
 * @param {object} order   orden ML completa (debe tener .id)
 * @param {object} [enrich] { billing, shipment } de enrichOrder()
 */
export async function upsertOrderSnapshot(accountId, order, enrich = {}) {
    const mlOrderId = String(order.id);
    const dc = order.date_created ? new Date(order.date_created) : null;
    await query(
        `INSERT INTO order_snapshots
             (account_id, ml_order_id, order_json, billing_json, shipment_json, ml_date_created)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (account_id, ml_order_id) DO UPDATE SET
             order_json      = EXCLUDED.order_json,
             billing_json    = COALESCE(EXCLUDED.billing_json,  order_snapshots.billing_json),
             shipment_json   = COALESCE(EXCLUDED.shipment_json, order_snapshots.shipment_json),
             ml_date_created = COALESCE(EXCLUDED.ml_date_created, order_snapshots.ml_date_created),
             updated_at      = NOW()`,
        [accountId, mlOrderId,
         JSON.stringify(order),
         enrich.billing != null ? JSON.stringify(enrich.billing) : null,
         enrich.shipment != null ? JSON.stringify(enrich.shipment) : null,
         dc && !Number.isNaN(dc.getTime()) ? dc.toISOString() : null]
    );
}

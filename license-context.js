/**
 * license-context.js — Estado compartido del enforcement de licencia (Fase 6).
 *
 * Un único source-of-truth en memoria para:
 *   - La pública Ed25519 del license-api (createPublicKey de LICENSE_API_PUBLIC_KEY).
 *   - El modo de enforcement (off | observe | enforce).
 *   - El período de gracia (segundos).
 *   - El Set de license_id revocados (denylist), refrescado periódicamente desde
 *     la tabla license_denylist.
 *   - El secret HMAC del endpoint interno de revoke.
 *
 * Lo consumen server.js (boot + refresh loop + endpoint revoke), routes-v1.js
 * (handshake + jobs + authAccount) y worker.js (skip de jobs vencidos). Se inicializa
 * UNA vez desde server.js con initLicenseContext() y después se lee con getLicenseContext().
 *
 * REGLAS DURAS:
 *   - LICENSE_ENFORCE default "observe": verifica + loguea pero NUNCA bloquea salvo
 *     que sea exactamente "enforce".
 *   - fail-safe de infra: si NO hay LICENSE_API_PUBLIC_KEY, se trata como "off"
 *     (no rompemos el servicio si falta config), con warning al boot.
 */

import { createPublicKey } from 'node:crypto';

const GRACE_DEFAULT_SEC = 259200; // 72h

// Estado del módulo (singleton).
const ctx = {
    publicKey: null,          // KeyObject | null
    mode: 'off',              // 'off' | 'observe' | 'enforce' (efectivo)
    modeRequested: 'observe', // lo que pidió la env, antes del fail-safe de pubkey
    gracePeriodSec: GRACE_DEFAULT_SEC,
    skewSec: 30,              // margen de reloj para exp (LICENSE_SKEW_SEC)
    revokeSecret: '',
    denylist: new Set(),      // Set<string> de license_id revocados
    initialized: false,
};

/**
 * Inicializa el contexto desde las env vars. Llamar una vez al boot, ANTES de
 * arrancar el refresh loop. NO lanza: ante config faltante/ inválida, degrada a
 * modo "off" con warning (fail-safe de infra).
 *
 * @param {object} env  típicamente process.env
 */
export function initLicenseContext(env = process.env) {
    const requested = String(env.LICENSE_ENFORCE || 'observe').trim().toLowerCase();
    ctx.modeRequested = ['off', 'observe', 'enforce'].includes(requested) ? requested : 'observe';

    const graceRaw = Number(env.GRACE_PERIOD_SEC);
    ctx.gracePeriodSec = Number.isFinite(graceRaw) && graceRaw > 0 ? Math.floor(graceRaw) : GRACE_DEFAULT_SEC;

    const skewRaw = Number(env.LICENSE_SKEW_SEC);
    ctx.skewSec = Number.isFinite(skewRaw) && skewRaw >= 0 ? Math.floor(skewRaw) : 30;

    ctx.revokeSecret = String(env.LICENSE_REVOKE_SECRET || '');

    const pubRaw = String(env.LICENSE_API_PUBLIC_KEY || '').trim();
    if (!pubRaw) {
        // Fail-safe de infra: sin pública no podemos verificar → comportarse como
        // enforce=off (no romper). Mode requested se ignora.
        ctx.publicKey = null;
        ctx.mode = 'off';
        console.warn('[license] LICENSE_API_PUBLIC_KEY no seteada — enforcement DESHABILITADO (modo off). ' +
            `(LICENSE_ENFORCE solicitado: "${ctx.modeRequested}", se ignora hasta que haya pública.)`);
    } else {
        try {
            // Robusto contra cómo los paneles de envs guardan el PEM multilínea:
            // comillas envolventes + '\n'/'\r\n' literales escapados + CR reales.
            let pem = pubRaw;
            if ((pem.startsWith('"') && pem.endsWith('"')) || (pem.startsWith("'") && pem.endsWith("'"))) {
                pem = pem.slice(1, -1);
            }
            pem = pem.replace(/\\r\\n/g, '\n').replace(/\\n/g, '\n').replace(/\\r/g, '').replace(/\r/g, '');
            ctx.publicKey = createPublicKey(pem);
            ctx.mode = ctx.modeRequested;
            console.log(`[license] enforcement habilitado — modo "${ctx.mode}", gracia ${ctx.gracePeriodSec}s ` +
                `(${(ctx.gracePeriodSec / 3600).toFixed(0)}h).`);
            if (ctx.mode === 'enforce' && !ctx.revokeSecret) {
                console.warn('[license] modo "enforce" SIN LICENSE_REVOKE_SECRET — el endpoint /internal/license-revoked quedará deshabilitado.');
            }
        } catch (e) {
            // Pública inválida = config rota → fail-safe a off para no tumbar el servicio.
            ctx.publicKey = null;
            ctx.mode = 'off';
            console.warn('[license] LICENSE_API_PUBLIC_KEY inválida (' + e.message + ') — enforcement DESHABILITADO (modo off).');
        }
    }

    ctx.initialized = true;
    return ctx;
}

/** Devuelve el contexto vivo (mismo objeto, denylist mutable). */
export function getLicenseContext() {
    return ctx;
}

/** ¿El enforcement bloquea de verdad? Solo en modo "enforce". */
export function isEnforcing() {
    return ctx.mode === 'enforce';
}

/** ¿Está habilitada (no "off") la verificación de tokens? */
export function isLicenseActive() {
    return ctx.mode !== 'off' && !!ctx.publicKey;
}

/**
 * Reemplaza el contenido del Set de denylist con los license_id dados.
 * Mutamos el MISMO Set para que las referencias que ya capturaron `ctx.denylist`
 * (verifyCapabilityToken recibe el Set) vean los cambios sin re-wiring.
 */
export function replaceDenylist(licenseIds) {
    ctx.denylist.clear();
    for (const id of licenseIds) {
        if (id) ctx.denylist.add(String(id));
    }
    return ctx.denylist.size;
}

/** Agrega un license_id a la denylist viva (usado por el endpoint de revoke). */
export function addToDenylist(licenseId) {
    if (licenseId) ctx.denylist.add(String(licenseId));
}

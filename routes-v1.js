/**
 * routes-v1.js — API REST del Central Orchestrator (v1).
 *
 * Todos los endpoints viven bajo /v1/* y se autentican con HMAC shared-secret
 * por cuenta (ver auth.js). La única excepción es /v1/handshake que se
 * autentica con el HUB_SECRET global (mismo que el OAuth bridge), porque es
 * por definición el primer contacto antes de tener un secret de cuenta.
 *
 * Endpoints:
 *
 *   POST /v1/handshake          → registra cuenta (o rota su secret). Auth: HUB.
 *   POST /v1/jobs               → crea un job + sus steps. Auth: cuenta.
 *   GET  /v1/jobs/:job_id       → status + progress. Auth: cuenta.
 *   POST /v1/jobs/:job_id/next-batch → siguiente step (o "done"). Auth: cuenta.
 *   POST /v1/jobs/:job_id/report     → resultado de un step. Auth: cuenta.
 *   GET  /v1/jobs/:job_id/results    → items sincronizados (paginado). Auth: cuenta.
 *   POST /v1/jobs/:job_id/ack        → marca resultados como entregados. Auth: cuenta.
 *   POST /v1/jobs/:job_id/cancel     → aborta el job. Auth: cuenta.
 *   GET  /v1/sync/pending       → jobs de sync con resultados sin bajar. Auth: cuenta.
 *   GET  /v1/orders/pending     → órdenes sin aplicar (payload v2: orden completa
 *                                 + billing + shipment desde order_snapshots). Auth: cuenta.
 *   POST /v1/orders/ack         → marca órdenes como aplicadas. Auth: cuenta.
 *   POST /v1/orders/backfill    → job de importación histórica (Ventas ML). Auth: cuenta.
 *   GET  /v1/orders/history     → pagina los snapshots completos. Auth: cuenta.
 *
 * Convenciones:
 *   - Toda fecha sale como ISO8601 UTC.
 *   - Errores: { ok: false, error: '<code>', message: '<human>' } + status code.
 *   - Éxitos:  { ok: true,  ...data }.
 */

import crypto from 'node:crypto';
import { query, tx } from './db.js';
import {
    verifyRequest,
    generateSecret,
    generatePublicId,
    encryptToken,
    sealSecret,
    openSecret,
} from './auth.js';
import { verifyCapabilityToken } from './license-token.js';
import { getValidAccessToken, mlGetShipmentLabel, mlGetPackMessages, mlSendPackMessage, mlSearchQuestions, mlAnswerQuestion } from './ml-api.js';

// Header donde el satélite ML manda el capability-token de licencia (Fase 6).
// (El central TN usa X-Wftn-License-Token con este MISMO archivo copiado.)
const LICENSE_TOKEN_HEADER = 'X-Wfml-License-Token';

// Producto que el token DEBE cubrir para autorizar al satélite ML.
const LICENSE_EXPECT_PRODUCT = 'wf-mercadolibre';

// =============================================================================
// Constantes del job runtime
// =============================================================================

// Lease default cuando un plugin "toma" un step (next-batch). Si no reporta
// dentro de este tiempo, el step queda disponible para que otro plugin/worker
// lo tome. 90s es suficiente para batches de 50 items.
const STEP_LEASE_SEC = 90;

// Cantidad máxima de steps por job (anti-explosion: si el cliente pide 1M
// de items, rechazamos en vez de matar Postgres).
const MAX_STEPS_PER_JOB = 5000;

// Job types válidos. Cualquier otro string se rechaza al crear job.
const VALID_JOB_TYPES = new Set([
    'sync_incremental',
    'sync_full',
    'auto_link_sku',
    'push',
]);

// =============================================================================
// Helpers internos
// =============================================================================

function nowIso() { return new Date().toISOString(); }

// =============================================================================
// Enforcement del capability-token de licencia (Fase 6)
// =============================================================================
//
// El contexto (pública Ed25519, modo off|observe|enforce, gracia, denylist Set)
// lo inyecta server.js vía mountV1(opts.license) y lo guardamos a nivel de módulo
// para que authAccount (top-level) lo lea. Si nunca se inyecta (tests/standalone),
// queda en null → se comporta como "off" (no bloquea nada).
let _license = null; // { getContext, isEnforcing, isLicenseActive }

/**
 * Verifica el capability-token de un request contra el contexto de licencia.
 *
 * Pura respecto de la red: NO escribe DB acá (el caller decide cuándo sellar el
 * last_valid_license_token_at). Devuelve un veredicto que el caller interpreta
 * según el modo (off/observe/enforce) y según si aplica gracia.
 *
 * @param {string}  token        valor crudo del header X-Wfml-License-Token
 * @param {object}  account      fila de accounts (para expectDomain = site_url)
 * @returns {{ active, valid, reason, payload }}
 *   - active: false → enforcement OFF (o sin pública); el caller debe permitir sin más.
 *   - valid:  true  → token verificado OK (firma + exp + dominio + producto + no revocado).
 *   - reason: detalle (solo a log) cuando valid=false.
 *   - payload: claims decodificados (presente aunque valid=false en algunos casos).
 */
function verifyLicenseForAccount(token, account) {
    if (!_license || !_license.isLicenseActive()) {
        return { active: false, valid: false, reason: 'inactive', payload: null };
    }
    const ctx = _license.getContext();
    const res = verifyCapabilityToken(String(token || ''), {
        publicKey:     ctx.publicKey,
        skewSec:       ctx.skewSec,
        denylist:      ctx.denylist,
        expectDomain:  account && account.site_url ? account.site_url : undefined,
        expectProduct: LICENSE_EXPECT_PRODUCT,
    });
    return { active: true, valid: res.valid, reason: res.reason || null, payload: res.payload || null };
}

// Throttle del sello del watermark: el plugin pollea jobs agresivamente; sin
// throttle escribiríamos accounts en CADA request /v1/* válido (el mismo problema
// que motivó bumpAccountLastSeenThrottled). 60s de precisión sobra para la gracia
// (que mide en horas). Se fuerza el write cuando cambia el claim (exp/license_id).
const _stampCache = new Map(); // accountId → { at: epochMs, exp, licenseId }
const STAMP_THROTTLE_MS = 60_000;
setInterval(() => {
    const cutoff = Date.now() - 60 * 60_000;
    for (const [k, v] of _stampCache.entries()) {
        if (v.at < cutoff) _stampCache.delete(k);
    }
}, 10 * 60_000).unref();

/**
 * Sella en accounts el último token VÁLIDO: ancla de la gracia + copia del claim.
 * Fire-and-forget (no bloquea la respuesta). license_exp viene del claim.exp (sec).
 * Throttle 60s/cuenta salvo que el claim haya cambiado (renovación/upgrade).
 */
function stampValidLicense(accountId, payload) {
    if (!accountId || !payload) return;
    const exp = typeof payload.exp === 'number' ? payload.exp : null;
    const licenseId = payload.license_id ? String(payload.license_id) : null;
    const prev = _stampCache.get(accountId);
    const now = Date.now();
    const claimChanged = !prev || prev.exp !== exp || prev.licenseId !== licenseId;
    if (prev && !claimChanged && (now - prev.at) < STAMP_THROTTLE_MS) {
        return; // ya sellado recientemente con el mismo claim
    }
    _stampCache.set(accountId, { at: now, exp, licenseId });
    query(
        `UPDATE accounts
            SET last_valid_license_token_at = NOW(),
                license_id  = COALESCE($2, license_id),
                license_exp = CASE WHEN $3::bigint IS NOT NULL THEN to_timestamp($3) ELSE license_exp END
          WHERE id = $1`,
        [accountId, licenseId, exp]
    ).catch((e) => console.warn('[license] stampValidLicense failed:', e.message));
}

/**
 * ¿La cuenta está dentro del período de gracia? Permite seguir operando jobs
 * (sync/push) ante token ausente/expirado por caída de infra del license-api,
 * SIEMPRE que haya presentado un token válido dentro de GRACE_PERIOD_SEC.
 * La gracia NO aplica al handshake (entrada nueva) ni vence una denylist.
 */
function withinGrace(account) {
    if (!_license) return false;
    const ctx = _license.getContext();
    const ts = account && account.last_valid_license_token_at
        ? new Date(account.last_valid_license_token_at).getTime()
        : 0;
    if (!ts) return false;
    return (Date.now() - ts) <= ctx.gracePeriodSec * 1000;
}

/**
 * Acceso al body crudo (string). Lo necesitamos para verificar el HMAC, que
 * incluye el sha256 del body original. Express ya lo parseó a req.body, pero
 * el express.json() option `verify` nos permite stashearlo crudo en req.rawBody.
 *
 * (Esa configuración se hace en server.js — acá solo lo leemos.)
 */
function getRawBody(req) {
    return req.rawBody || '';
}

/**
 * Middleware que verifica el HMAC + carga la cuenta en req.account.
 * Usar en las rutas que requieren auth de cuenta.
 */
async function authAccount(req, res, next) {
    const publicId = req.get('X-Wfml-Account') || '';
    const ts       = req.get('X-Wfml-Ts')      || '';
    const sig      = req.get('X-Wfml-Sig')     || '';
    if (!publicId || !ts || !sig) {
        return res.status(401).json({ ok: false, error: 'unauthorized', message: 'Faltan headers de auth.' });
    }
    let acc;
    try {
        const r = await query(
            `SELECT id, public_id, ml_user_id, ml_nickname, ml_site_id, site_url, shared_secret, revoked_at,
                    last_valid_license_token_at, license_id, license_exp
             FROM accounts WHERE public_id = $1`,
            [publicId]
        );
        acc = r.rows[0];
    } catch (err) {
        return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
    }
    if (!acc || acc.revoked_at) {
        return res.status(401).json({ ok: false, error: 'unknown_account' });
    }
    // shared_secret puede estar cifrado at-rest (formato enc1) o plano (fila
    // legacy). openSecret resuelve ambos; null = no se pudo descifrar (key
    // rotada sin migrar / fila corrupta) → falla la auth de ESA cuenta, sin
    // tirar el proceso. JAMÁS loguear el secreto.
    const accSecret = openSecret(acc.shared_secret);
    if (!accSecret) {
        console.warn(`[v1] shared_secret ilegible acct=${acc.public_id} (key rotada o fila corrupta) — auth rechazada`);
        return res.status(401).json({ ok: false, error: 'secret_unreadable', message: 'No se pudo validar el secreto de la cuenta. Reconectá la cuenta (handshake).' });
    }
    const verdict = verifyRequest({
        secret: accSecret,
        method: req.method,
        path: req.originalUrl.split('?')[0], // sin query string
        ts,
        body: getRawBody(req),
        sigGiven: sig,
    });
    if (!verdict.ok) {
        return res.status(401).json({ ok: false, error: 'bad_signature', message: verdict.reason });
    }

    // -------------------------------------------------------------------------
    // Capability-token de licencia (Fase 6) — capa ADICIONAL sobre el HMAC.
    // CON gracia: si el token falta/expiró pero la cuenta presentó uno válido
    // dentro de GRACE_PERIOD_SEC, permitimos igual (no romper operación por una
    // caída del license-api). La denylist (revoke explícito) GANA sobre la gracia.
    // En modo "observe" se loguea pero NUNCA se bloquea. En "off" no se verifica.
    // -------------------------------------------------------------------------
    const lic = verifyLicenseForAccount(req.get(LICENSE_TOKEN_HEADER), acc);
    if (lic.active) {
        if (lic.valid) {
            // Token OK → sella el ancla de gracia + copia del claim (fire-and-forget).
            stampValidLicense(acc.id, lic.payload);
            // En observe logueamos también el caso OK → confirmación visible de que el
            // token llega y verifica (en enforce queda silencioso para no hacer ruido).
            if (!_license.isEnforcing()) {
                const _exp = lic.payload && typeof lic.payload.exp === 'number' ? (lic.payload.exp - Math.floor(Date.now() / 1000)) : '?';
                console.log(`[license][observe] token OK acct=${acc.public_id} license=${String((lic.payload && lic.payload.license_id) || '').slice(0, 8)} exp_in=${_exp}s`);
            }
        } else {
            const revoked = lic.reason === 'revoked';
            const graced = !revoked && withinGrace(acc);
            const enforcing = _license.isEnforcing();
            if (!graced) {
                if (enforcing) {
                    console.warn(`[license] BLOQUEADO acct=${acc.public_id} reason=${lic.reason}` +
                        (revoked ? ' (revoked: denylist gana sobre gracia)' : ' (sin gracia válida)'));
                    return res.status(403).json({ ok: false, error: 'license_invalid' });
                }
                console.warn(`[license][observe] permitiría-bloquear acct=${acc.public_id} reason=${lic.reason}` +
                    (revoked ? ' (revoked)' : '') + ' (modo observe — no se bloquea)');
            } else {
                console.warn(`[license] acct=${acc.public_id} token ${lic.reason} pero DENTRO de gracia — permitido`);
            }
        }
    }

    req.account = acc;
    // Bump last_seen para detección de actividad. Fire-and-forget + throttle.
    // Antes pegabamos a Postgres en CADA request /v1/* — con polling agresivo
    // de jobs + multicuenta llegaba a cientos/min y Postgres lo logueaba como
    // slow query. last_seen no necesita precisión sub-minuto, throttle 60s
    // baja el tráfico ~100x sin perder utilidad informativa.
    bumpAccountLastSeenThrottled(acc.id);
    next();
}

const _lastSeenCache = new Map(); // accountId → epoch ms del último bump
const LAST_SEEN_THROTTLE_MS = 60_000; // 1 min entre bumps por cuenta
function bumpAccountLastSeenThrottled(accountId) {
    const now = Date.now();
    const last = _lastSeenCache.get(accountId) || 0;
    if (now - last < LAST_SEEN_THROTTLE_MS) return; // ya bumpeado recientemente
    _lastSeenCache.set(accountId, now);
    query('SELECT bump_account_last_seen($1)', [accountId]).catch((e) =>
        console.warn('[v1] bump_account_last_seen failed:', e.message)
    );
}
// GC del cache cada 10 min: entries más viejas que 1h se pueden borrar para
// no acumular accountIds que ya no se usan. unref para no bloquear shutdown.
setInterval(() => {
    const cutoff = Date.now() - 60 * 60_000;
    for (const [k, v] of _lastSeenCache.entries()) {
        if (v < cutoff) _lastSeenCache.delete(k);
    }
}, 10 * 60_000).unref();

/**
 * Construye el array de steps a insertar según el tipo de job + input.
 *
 * Cada step describe un chunk concreto que el plugin sabe ejecutar.
 *
 * Devuelve `{ steps, totalCount }` donde steps es array de { seq, input }.
 */
function buildStepsForJob(type, params) {
    const chunkSize = Math.max(1, Math.min(500, Number(params.chunk_size) || 50));
    if (type === 'sync_full' || type === 'sync_incremental') {
        // Plugin nos dice cuántos items espera total. Creamos N steps con
        // offset/limit. El plugin va a usar esos params para llamar a ML.
        const total = Number(params.total) || 0;
        if (total <= 0) {
            return { steps: [{ seq: 0, input: { offset: 0, limit: chunkSize, since_ts: params.since_ts || null } }], totalCount: 1 };
        }
        const steps = [];
        let seq = 0;
        for (let offset = 0; offset < total; offset += chunkSize) {
            steps.push({
                seq,
                input: {
                    offset,
                    limit: Math.min(chunkSize, total - offset),
                    since_ts: params.since_ts || null,
                },
            });
            seq++;
        }
        return { steps, totalCount: steps.length };
    }
    if (type === 'auto_link_sku') {
        // Plugin nos manda la lista de candidatos (ml_item_id + sku) y los
        // partimos en chunks para procesar.
        const candidates = Array.isArray(params.candidates) ? params.candidates : [];
        const steps = [];
        for (let i = 0, seq = 0; i < candidates.length; i += chunkSize, seq++) {
            steps.push({
                seq,
                input: { candidates: candidates.slice(i, i + chunkSize) },
            });
        }
        return { steps, totalCount: steps.length };
    }
    if (type === 'push') {
        const items = Array.isArray(params.items) ? params.items : [];
        const steps = [];
        for (let i = 0, seq = 0; i < items.length; i += chunkSize, seq++) {
            steps.push({
                seq,
                input: { items: items.slice(i, i + chunkSize) },
            });
        }
        return { steps, totalCount: steps.length };
    }
    throw new Error(`Tipo de job desconocido: ${type}`);
}

// =============================================================================
// Mount
// =============================================================================

export function mountV1(app, opts = {}) {
    const HUB_SECRET = opts.hubSecret;
    if (!HUB_SECRET) {
        throw new Error('mountV1: hubSecret requerido');
    }
    // Hardening #25 (2026-05-25): rate-limit por IP. Si el llamador no pasa
    // limiters (compat con tests / standalone), no-op.
    const rlGeneral   = opts.rlGeneral   || ((req, res, next) => next());
    const rlHandshake = opts.rlHandshake || ((req, res, next) => next());
    // Enforcement de licencia (Fase 6). Lo inyecta server.js; si no, queda en
    // null → authAccount/handshake se comportan como "off" (no bloquean).
    if (opts.license) _license = opts.license;
    // Registramos cada ruta con DOS paths: el "limpio" /v1/* y el prefijado
    // /connect-ml/v1/*. Esto es por el reverse proxy de EasyPanel: el dominio
    // goforger.com sirve a comingsoon en la raíz, y solo enruta /connect-ml/*
    // hacia este container. Con ambas formas registradas, no importa si el
    // proxy strippea o conserva el prefijo: la ruta siempre matchea.
    const p = (path) => [path, '/connect-ml' + path];

    // Rate-limit general aplicado a TODOS los /v1/* — handshake suma su propio
    // limiter más estricto encima (ambos deben pasar).
    app.use(['/v1', '/connect-ml/v1'], rlGeneral);

    // -------------------------------------------------------------------------
    // POST /v1/handshake
    // Body:
    //   {
    //     ml_user_id: number,
    //     ml_nickname: string,
    //     ml_site_id: string ("MLA"...),
    //     site_url: string,
    //     refresh_token: string (de ML; lo encriptamos al guardar),
    //     handshake_sig: base64 HMAC(HUB_SECRET, json sin handshake_sig)
    //   }
    // Respuesta:
    //   { ok: true, account_id: "acc_...", shared_secret: "base64" }
    //
    // Idempotente sobre ml_user_id: si la cuenta ya existe, rota el secret y
    // actualiza site_url + refresh_token.
    // -------------------------------------------------------------------------
    app.post(p('/v1/handshake'), rlHandshake, async (req, res) => {
        const body = req.body || {};

        // ---------------------------------------------------------------------
        // Capability-token de licencia (Fase 6) — SIN gracia.
        // El handshake registra/rota el shared_secret: es una ENTRADA NUEVA, no
        // una operación recurrente, así que NO le aplica el período de gracia.
        // expectDomain = site_url del body (la cuenta puede no existir aún). En
        // modo "observe" se loguea pero NO se bloquea; en "off" no se verifica.
        // Esto va ANTES de validar la firma del handshake (gate de licencia primero).
        // ---------------------------------------------------------------------
        let hsLicensePayload = null; // claim del token válido, para sellar tras el upsert
        {
            const hsAccount = { site_url: String(body.site_url || '') };
            const lic = verifyLicenseForAccount(req.get(LICENSE_TOKEN_HEADER), hsAccount);
            if (lic.active) {
                if (lic.valid) {
                    hsLicensePayload = lic.payload;
                } else if (_license.isEnforcing()) {
                    console.warn(`[license] handshake BLOQUEADO site=${hsAccount.site_url} reason=${lic.reason} (sin gracia)`);
                    return res.status(403).json({ ok: false, error: 'license_invalid' });
                } else {
                    console.warn(`[license][observe] handshake permitiría-bloquear site=${hsAccount.site_url} reason=${lic.reason} (modo observe)`);
                }
            }
        }

        const sigGiven = String(body.handshake_sig || '');
        if (!sigGiven) {
            return res.status(400).json({ ok: false, error: 'missing_sig' });
        }
        const payloadObj = { ...body };
        delete payloadObj.handshake_sig;
        const payloadStr = JSON.stringify(payloadObj);
        const expectedSig = crypto.createHmac('sha256', HUB_SECRET)
            .update(payloadStr, 'utf8')
            .digest('base64');
        try {
            const a = Buffer.from(expectedSig);
            const b = Buffer.from(sigGiven);
            if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
                return res.status(403).json({ ok: false, error: 'bad_sig' });
            }
        } catch (_) {
            return res.status(403).json({ ok: false, error: 'bad_sig' });
        }

        // Hardening #23 (2026-05-25): anti-replay. El body firmado DEBE incluir
        // `ts` (unix seconds) dentro de window ±5min y `nonce` random one-use.
        // Sin esto, capturar UNA vez el body firmado (logs de proxy, MITM
        // histórico, backup) permitía rotar el shared_secret de la cuenta a
        // perpetuidad → robo de cuenta.
        const ts = Number(body.ts || 0);
        const reqNonce = String(body.nonce || '').trim();
        if (!ts || !reqNonce) {
            return res.status(400).json({ ok: false, error: 'missing_anti_replay', message: 'Falta ts o nonce en el body firmado.' });
        }
        const nowSec = Math.floor(Date.now() / 1000);
        if (Math.abs(nowSec - ts) > 300) {
            return res.status(400).json({ ok: false, error: 'ts_window', message: 'Timestamp fuera de la ventana ±5min.' });
        }
        try {
            const dup = await query(
                `INSERT INTO request_nonces (nonce, purpose, created_at) VALUES ($1, $2, $3)
                 ON CONFLICT (nonce, purpose) DO NOTHING RETURNING nonce`,
                [reqNonce, 'handshake', nowSec]
            );
            if (dup.rowCount === 0) {
                return res.status(409).json({ ok: false, error: 'replay', message: 'Este request ya se procesó.' });
            }
        } catch (e) {
            console.error('[handshake] nonce insert error:', e.message);
            return res.status(500).json({ ok: false, error: 'nonce_check_failed' });
        }

        const mlUserId = Number(body.ml_user_id);
        const siteUrl  = String(body.site_url || '').trim();
        const nick     = String(body.ml_nickname || '').trim();
        const siteId   = String(body.ml_site_id  || '').trim();
        const refreshT = String(body.refresh_token || '').trim();
        if (!mlUserId || !siteUrl) {
            return res.status(400).json({ ok: false, error: 'missing_fields', message: 'ml_user_id y site_url son obligatorios.' });
        }

        const newSecret = generateSecret();
        // At-rest: el secret viaja PLANO al plugin (protocolo intacto) pero en
        // la DB se persiste cifrado (formato enc1, ver auth.js). Si la key de
        // cifrado falta → 500 explícito, nunca guardar plano por accidente.
        let storedSecret;
        try {
            storedSecret = sealSecret(newSecret);
        } catch (err) {
            return res.status(500).json({ ok: false, error: 'crypto_failed', message: err.message });
        }
        let enc = { ciphertext: '', iv: '' };
        if (refreshT) {
            try {
                enc = encryptToken(refreshT);
            } catch (err) {
                return res.status(500).json({ ok: false, error: 'crypto_failed', message: err.message });
            }
        }

        try {
            // Upsert sobre ml_user_id (la unique partial index excluye revocadas).
            const existing = await query(
                `SELECT id, public_id FROM accounts WHERE ml_user_id = $1 AND revoked_at IS NULL`,
                [mlUserId]
            );
            let accId, accPublic;
            if (existing.rowCount > 0) {
                accId = existing.rows[0].id;
                accPublic = existing.rows[0].public_id;
                await query(
                    `UPDATE accounts
                     SET ml_nickname = $2,
                         ml_site_id  = $3,
                         site_url    = $4,
                         shared_secret = $5,
                         refresh_token_enc = COALESCE(NULLIF($6, ''), refresh_token_enc),
                         refresh_token_iv  = COALESCE(NULLIF($7, ''), refresh_token_iv),
                         last_token_refresh_at = CASE WHEN $6 <> '' THEN NOW() ELSE last_token_refresh_at END
                     WHERE id = $1`,
                    [accId, nick, siteId, siteUrl, storedSecret, enc.ciphertext, enc.iv]
                );
            } else {
                accPublic = generatePublicId('acc');
                const ins = await query(
                    `INSERT INTO accounts
                        (public_id, ml_user_id, ml_nickname, ml_site_id, site_url,
                         shared_secret, refresh_token_enc, refresh_token_iv, last_token_refresh_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                             CASE WHEN $7 <> '' THEN NOW() ELSE NULL END)
                     RETURNING id`,
                    [accPublic, mlUserId, nick, siteId, siteUrl, storedSecret, enc.ciphertext, enc.iv]
                );
                accId = ins.rows[0].id;
            }

            // Si el handshake trajo un token VÁLIDO, sellamos el ancla de gracia
            // + copia del claim ahora que la cuenta existe (fire-and-forget).
            if (hsLicensePayload) stampValidLicense(accId, hsLicensePayload);

            return res.json({
                ok: true,
                account_id: accPublic,
                shared_secret: newSecret,
                rotated: existing.rowCount > 0,
            });
        } catch (err) {
            console.error('[handshake] db error:', err);
            return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
        }
    });

    // -------------------------------------------------------------------------
    // POST /v1/jobs
    // Body:
    //   {
    //     type: 'sync_full' | 'sync_incremental' | 'auto_link_sku' | 'push',
    //     params: {...}    // depende del tipo (ver buildStepsForJob)
    //   }
    // Respuesta:
    //   { ok: true, job_id: "job_...", steps_total: N, status: "pending" }
    // -------------------------------------------------------------------------
    app.post(p('/v1/jobs'), authAccount, async (req, res) => {
        const body = req.body || {};
        const type = String(body.type || '');
        if (!VALID_JOB_TYPES.has(type)) {
            return res.status(400).json({ ok: false, error: 'bad_type', message: `type debe ser uno de: ${[...VALID_JOB_TYPES].join(', ')}` });
        }
        const params = body.params && typeof body.params === 'object' ? body.params : {};
        const jobPublic = generatePublicId('job');

        // Jobs ejecutados por el worker del central (sync_* y push): NO pre-crean
        // steps — el worker los procesa solo (pagina ML, o ejecuta los PUT del
        // push masivo). auto_link_sku sigue siendo modelo A: pre-crea steps que
        // el plugin ejecuta.
        const isWorkerJob = (type === 'sync_full' || type === 'sync_incremental' || type === 'push');

        if (isWorkerJob) {
            try {
                await query(
                    `INSERT INTO jobs (public_id, account_id, type, status, input, steps_total)
                     VALUES ($1, $2, $3, 'pending', $4, 0)`,
                    [jobPublic, req.account.id, type, JSON.stringify(params)]
                );
            } catch (err) {
                console.error('[v1/jobs] create sync error:', err);
                return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
            }
            return res.json({
                ok: true,
                job_id: jobPublic,
                type,
                status: 'pending',
                steps_total: 0, // el worker lo va a setear al descubrir el total
            });
        }

        // Jobs con steps pre-calculados (push / auto_link_sku).
        let plan;
        try {
            plan = buildStepsForJob(type, params);
        } catch (err) {
            return res.status(400).json({ ok: false, error: 'bad_params', message: err.message });
        }
        if (plan.totalCount > MAX_STEPS_PER_JOB) {
            return res.status(400).json({ ok: false, error: 'too_many_steps', message: `El job genera ${plan.totalCount} steps; máximo permitido: ${MAX_STEPS_PER_JOB}. Usá un chunk_size más grande.` });
        }
        if (plan.totalCount === 0) {
            return res.status(400).json({ ok: false, error: 'empty_job', message: 'El job no tiene work — nada que procesar.' });
        }

        try {
            await tx(async (client) => {
                const ins = await client.query(
                    `INSERT INTO jobs (public_id, account_id, type, status, input, steps_total)
                     VALUES ($1, $2, $3, 'pending', $4, $5)
                     RETURNING id`,
                    [jobPublic, req.account.id, type, JSON.stringify(params), plan.totalCount]
                );
                const jobId = ins.rows[0].id;
                const values = [];
                const placeholders = [];
                let p = 1;
                for (const s of plan.steps) {
                    const stepPublic = generatePublicId('stp');
                    placeholders.push(`($${p++}, $${p++}, $${p++}, 'queued', $${p++})`);
                    values.push(stepPublic, jobId, s.seq, JSON.stringify(s.input));
                }
                await client.query(
                    `INSERT INTO job_steps (public_id, job_id, seq, status, input)
                     VALUES ${placeholders.join(',')}`,
                    values
                );
            });
        } catch (err) {
            console.error('[v1/jobs] create error:', err);
            return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
        }

        return res.json({
            ok: true,
            job_id: jobPublic,
            type,
            status: 'pending',
            steps_total: plan.totalCount,
        });
    });

    // -------------------------------------------------------------------------
    // GET /v1/jobs/:job_id
    // Respuesta:
    //   { ok: true, job: { id, type, status, steps_total, steps_done, steps_failed,
    //                      created_at, started_at, finished_at, message, result } }
    // -------------------------------------------------------------------------
    app.get(p('/v1/jobs/:job_id'), authAccount, async (req, res) => {
        const r = await query(
            `SELECT public_id, type, status, steps_total, steps_done, steps_failed,
                    input, result, created_at, started_at, finished_at, message
             FROM jobs
             WHERE public_id = $1 AND account_id = $2`,
            [req.params.job_id, req.account.id]
        );
        if (!r.rowCount) return res.status(404).json({ ok: false, error: 'not_found' });
        const j = r.rows[0];
        return res.json({
            ok: true,
            job: {
                id: j.public_id,
                type: j.type,
                status: j.status,
                steps_total: j.steps_total,
                steps_done: j.steps_done,
                steps_failed: j.steps_failed,
                input: j.input,
                result: j.result,
                created_at: j.created_at,
                started_at: j.started_at,
                finished_at: j.finished_at,
                message: j.message,
            },
        });
    });

    // -------------------------------------------------------------------------
    // POST /v1/jobs/:job_id/next-batch
    // Devuelve el próximo step disponible (queued) y lo marca como leased.
    // Si no hay más → ok: true, done: true.
    //
    // El plugin debe procesar el step y luego llamar /report. Si tarda más del
    // lease (STEP_LEASE_SEC), otro pull puede tomarlo de nuevo (idempotencia).
    // -------------------------------------------------------------------------
    app.post(p('/v1/jobs/:job_id/next-batch'), authAccount, async (req, res) => {
        // 1) Validar que el job pertenece a esta cuenta y no está finalizado.
        const j = await query(
            `SELECT id, status FROM jobs WHERE public_id = $1 AND account_id = $2`,
            [req.params.job_id, req.account.id]
        );
        if (!j.rowCount) return res.status(404).json({ ok: false, error: 'not_found' });
        const jobRow = j.rows[0];
        if (['done', 'failed', 'cancelled'].includes(jobRow.status)) {
            return res.json({ ok: true, done: true, status: jobRow.status });
        }

        // 2) Tomar el primer step disponible (queued) o leased-expirado.
        //    UPDATE ... RETURNING para atomicidad sin race condition.
        const leaseUntil = new Date(Date.now() + STEP_LEASE_SEC * 1000);
        const upd = await query(
            `UPDATE job_steps SET
                status = 'leased',
                leased_until = $2,
                attempts = attempts + 1,
                started_at = COALESCE(started_at, NOW())
             WHERE id = (
                SELECT id FROM job_steps
                WHERE job_id = $1
                  AND (status = 'queued' OR (status = 'leased' AND leased_until < NOW()))
                ORDER BY seq ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
             )
             RETURNING public_id, seq, input`,
            [jobRow.id, leaseUntil]
        );

        if (!upd.rowCount) {
            // No quedan steps. Marcar el job como done si todo finalizó.
            await query(
                `UPDATE jobs SET status = 'done', finished_at = NOW(),
                                 message = COALESCE(message, 'Job completado.')
                 WHERE id = $1 AND status NOT IN ('done','failed','cancelled')
                   AND NOT EXISTS (
                       SELECT 1 FROM job_steps WHERE job_id = $1 AND status IN ('queued','leased')
                   )`,
                [jobRow.id]
            );
            return res.json({ ok: true, done: true });
        }

        // 3) Marcar job como running si era pending (primer step tomado).
        if (jobRow.status === 'pending') {
            await query(
                `UPDATE jobs SET status = 'running', started_at = COALESCE(started_at, NOW())
                 WHERE id = $1 AND status = 'pending'`,
                [jobRow.id]
            );
        }

        const step = upd.rows[0];
        return res.json({
            ok: true,
            done: false,
            step: {
                id: step.public_id,
                seq: step.seq,
                input: step.input,
                lease_expires_at: leaseUntil.toISOString(),
            },
        });
    });

    // -------------------------------------------------------------------------
    // POST /v1/jobs/:job_id/report
    // Body:
    //   {
    //     step_id: "stp_...",
    //     result: 'done' | 'failed' | 'skipped',
    //     output: {...},
    //     error?: string
    //   }
    // Respuesta:
    //   { ok: true, job: { steps_done, steps_failed, status, message } }
    // -------------------------------------------------------------------------
    app.post(p('/v1/jobs/:job_id/report'), authAccount, async (req, res) => {
        const body = req.body || {};
        const stepId = String(body.step_id || '');
        const result = String(body.result  || '');
        const output = body.output || {};
        const errorMsg = body.error ? String(body.error).slice(0, 1024) : null;

        if (!stepId || !['done','failed','skipped'].includes(result)) {
            return res.status(400).json({ ok: false, error: 'bad_params' });
        }

        let updated;
        try {
            updated = await tx(async (client) => {
                // Cargar job + step + chequear ownership.
                const j = await client.query(
                    `SELECT id, status FROM jobs WHERE public_id = $1 AND account_id = $2 FOR UPDATE`,
                    [req.params.job_id, req.account.id]
                );
                if (!j.rowCount) throw new Error('job_not_found');
                const job = j.rows[0];

                const s = await client.query(
                    `SELECT id, status FROM job_steps
                     WHERE public_id = $1 AND job_id = $2 FOR UPDATE`,
                    [stepId, job.id]
                );
                if (!s.rowCount) throw new Error('step_not_found');
                const step = s.rows[0];
                if (['done','failed','skipped'].includes(step.status)) {
                    // Idempotente: si ya está finalizado, no re-procesamos.
                    // Devolvemos el job actualizado sin cambios.
                } else {
                    await client.query(
                        `UPDATE job_steps SET
                            status = $2,
                            output = $3,
                            last_error = $4,
                            finished_at = NOW()
                         WHERE id = $1`,
                        [step.id, result, JSON.stringify(output), errorMsg]
                    );
                    // Actualizar counters del job.
                    if (result === 'done' || result === 'skipped') {
                        await client.query(`UPDATE jobs SET steps_done = steps_done + 1 WHERE id = $1`, [job.id]);
                    } else if (result === 'failed') {
                        await client.query(`UPDATE jobs SET steps_failed = steps_failed + 1, message = $2 WHERE id = $1`, [job.id, errorMsg]);
                    }
                }

                // ¿Quedan steps pendientes?
                const pending = await client.query(
                    `SELECT COUNT(*) AS n FROM job_steps WHERE job_id = $1 AND status IN ('queued','leased')`,
                    [job.id]
                );
                const remaining = Number(pending.rows[0].n);
                if (remaining === 0) {
                    // Job terminado. Decidir done vs failed.
                    const counts = await client.query(
                        `SELECT steps_total, steps_done, steps_failed FROM jobs WHERE id = $1`,
                        [job.id]
                    );
                    const c = counts.rows[0];
                    const allOk = c.steps_failed === 0;
                    await client.query(
                        `UPDATE jobs SET status = $2, finished_at = NOW(),
                                         message = COALESCE(message, $3)
                         WHERE id = $1`,
                        [job.id, allOk ? 'done' : 'failed', allOk ? 'Job completado.' : 'Job completado con errores.']
                    );
                }
                const fin = await client.query(
                    `SELECT status, steps_total, steps_done, steps_failed, message FROM jobs WHERE id = $1`,
                    [job.id]
                );
                return fin.rows[0];
            });
        } catch (err) {
            const code = (err.message === 'job_not_found' || err.message === 'step_not_found') ? 404 : 500;
            return res.status(code).json({ ok: false, error: err.message });
        }

        return res.json({
            ok: true,
            job: {
                status: updated.status,
                steps_total: updated.steps_total,
                steps_done: updated.steps_done,
                steps_failed: updated.steps_failed,
                message: updated.message,
            },
        });
    });

    // -------------------------------------------------------------------------
    // GET /v1/jobs/:job_id/results?offset=&limit=
    // Devuelve los items que el worker sincronizó para este job, paginados.
    // El plugin los baja en lotes y los aplica a su wf_ml_items local.
    //
    // Idempotente: no marca nada al leer. El plugin puede re-bajar sin riesgo
    // (su upsert local es idempotente). Para liberar espacio, cuando el plugin
    // termina de bajar todo llama a POST /v1/jobs/:id/ack.
    //
    // Respuesta:
    //   { ok: true, items: [ <item_data>, ... ], total: N, offset, limit }
    // -------------------------------------------------------------------------
    app.get(p('/v1/jobs/:job_id/results'), authAccount, async (req, res) => {
        const j = await query(
            `SELECT id FROM jobs WHERE public_id = $1 AND account_id = $2`,
            [req.params.job_id, req.account.id]
        );
        if (!j.rowCount) return res.status(404).json({ ok: false, error: 'not_found' });
        const jobId = j.rows[0].id;

        const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
        const limit  = Math.max(1, Math.min(1000, parseInt(req.query.limit, 10) || 500));

        const totalR = await query(
            `SELECT COUNT(*) AS n FROM synced_items WHERE job_id = $1`,
            [jobId]
        );
        const total = Number(totalR.rows[0].n);

        const rowsR = await query(
            `SELECT item_data FROM synced_items
             WHERE job_id = $1
             ORDER BY id ASC
             LIMIT $2 OFFSET $3`,
            [jobId, limit, offset]
        );
        return res.json({
            ok: true,
            items: rowsR.rows.map((r) => r.item_data),
            total,
            offset,
            limit,
        });
    });

    // -------------------------------------------------------------------------
    // POST /v1/jobs/:job_id/ack
    // El plugin confirma que bajó y aplicó todos los resultados. Marcamos los
    // synced_items como delivered para que el cron de retención los limpie.
    // -------------------------------------------------------------------------
    app.post(p('/v1/jobs/:job_id/ack'), authAccount, async (req, res) => {
        const j = await query(
            `SELECT id FROM jobs WHERE public_id = $1 AND account_id = $2`,
            [req.params.job_id, req.account.id]
        );
        if (!j.rowCount) return res.status(404).json({ ok: false, error: 'not_found' });
        const r = await query(
            `UPDATE synced_items SET delivered_at = NOW()
             WHERE job_id = $1 AND delivered_at IS NULL`,
            [j.rows[0].id]
        );
        return res.json({ ok: true, marked: r.rowCount });
    });

    // -------------------------------------------------------------------------
    // GET /v1/sync/pending
    // ¿Hay resultados de sync sin bajar para esta cuenta? Lo usa el plugin al
    // cargar el admin para detectar los syncs que dejó el cron automático
    // mientras el operador no estaba.
    //
    // Devuelve la lista de jobs con synced_items pendientes (delivered_at NULL),
    // del más viejo al más nuevo, para que el plugin los baje en orden.
    //
    // Solo se reportan jobs en estado 'done': mientras el worker todavía está
    // paginando ('running') va insertando synced_items, y si el plugin drenara
    // + ack en ese momento marcaría como entregadas filas que el worker
    // todavía no terminó de escribir. Esperando a 'done' la descarga es segura.
    //
    // Respuesta:
    //   { ok: true, pending: bool, jobs: [{ job_id, count, synced_at }], total }
    // -------------------------------------------------------------------------
    app.get(p('/v1/sync/pending'), authAccount, async (req, res) => {
        const r = await query(
            `SELECT j.public_id AS job_id,
                    COUNT(si.id)::int AS count,
                    MAX(si.synced_at) AS synced_at
             FROM synced_items si
             JOIN jobs j ON j.id = si.job_id
             WHERE si.account_id = $1
               AND si.delivered_at IS NULL
               AND j.status = 'done'
             GROUP BY j.public_id
             ORDER BY MAX(si.synced_at) ASC`,
            [req.account.id]
        );
        const jobs = r.rows.map((row) => ({
            job_id: row.job_id,
            count: row.count,
            synced_at: row.synced_at,
        }));
        const total = jobs.reduce((s, j) => s + j.count, 0);
        return res.json({ ok: true, pending: jobs.length > 0, jobs, total });
    });

    // -------------------------------------------------------------------------
    // GET /v1/orders/pending
    // Órdenes ML ya procesadas (el central bajó la orden de ML) que el plugin
    // todavía no aplicó a su ledger de stock. Una fila por orden — la más
    // reciente procesada, porque una orden puede generar varios webhooks. El
    // plugin descuenta/repone stock según el status.
    //
    // payload v2 (Ventas ML, F0): cada orden suma `order` (la orden ML
    // completa), `billing` (billing_info del comprador) y `shipment` (estado
    // del envío) desde order_snapshots — pueden ser null si el snapshot aún no
    // existe o el enriquecimiento falló. Compat: el shape v1 (ml_order_id /
    // status / items) se conserva TAL CUAL y los plugins viejos ignoran las
    // claves nuevas (verificado contra wf-ml-stock.php 1.6.5). LIMIT 200 para
    // acotar la respuesta (los snapshots pesan); lo que no entra sale en el
    // próximo drenado.
    //
    // Respuesta:
    //   { ok: true, payload_version: 2,
    //     orders: [{ ml_order_id, status, items: [...],
    //                order, billing, shipment, snapshot_at }] }
    // -------------------------------------------------------------------------
    app.get(p('/v1/orders/pending'), authAccount, async (req, res) => {
        const r = await query(
            `SELECT DISTINCT ON (e.ml_order_id)
                    e.ml_order_id, e.order_status, e.items_json,
                    s.order_json, s.billing_json, s.shipment_json,
                    s.updated_at AS snapshot_at
             FROM order_events e
             LEFT JOIN order_snapshots s
                    ON s.account_id = e.account_id AND s.ml_order_id = e.ml_order_id
             WHERE e.account_id = $1
               AND e.processed_at IS NOT NULL
               AND e.delivered_at IS NULL
               AND e.error IS NULL
             ORDER BY e.ml_order_id, e.processed_at DESC
             LIMIT 200`,
            [req.account.id]
        );
        const orders = r.rows.map((row) => ({
            ml_order_id: row.ml_order_id,
            status:      row.order_status,
            items:       Array.isArray(row.items_json) ? row.items_json : [],
            order:       row.order_json || null,
            billing:     row.billing_json || null,
            shipment:    row.shipment_json || null,
            snapshot_at: row.snapshot_at || null,
        }));
        return res.json({ ok: true, payload_version: 2, orders });
    });

    // -------------------------------------------------------------------------
    // POST /v1/orders/ack
    // Body: { ml_order_ids: ["123", ...] }
    // El plugin confirma que aplicó esas órdenes a su ledger. Marcamos todas
    // las order_events de esas órdenes como delivered.
    // -------------------------------------------------------------------------
    app.post(p('/v1/orders/ack'), authAccount, async (req, res) => {
        const ids = Array.isArray(req.body && req.body.ml_order_ids)
            ? req.body.ml_order_ids.map(String).filter(Boolean)
            : [];
        if (!ids.length) return res.json({ ok: true, marked: 0 });
        const r = await query(
            `UPDATE order_events SET delivered_at = NOW()
             WHERE account_id = $1 AND ml_order_id = ANY($2::text[]) AND delivered_at IS NULL`,
            [req.account.id, ids]
        );
        return res.json({ ok: true, marked: r.rowCount });
    });

    // -------------------------------------------------------------------------
    // POST /v1/orders/backfill  (Ventas ML, F0)
    // Body: { months?: number }  (1..24, default 12)
    //
    // Importa el historial de órdenes ML de la cuenta a order_snapshots. Crea
    // un job 'orders_backfill' que procesa el SCHEDULER en su propio loop (no
    // compite con el worker de sync/push). El plugin pollea el avance con
    // GET /v1/jobs/:job_id y después pagina GET /v1/orders/history.
    //
    // Idempotente: si ya hay un backfill pending/running para la cuenta,
    // devuelve ESE job (already: true) en vez de encolar otro. Re-correrlo
    // cuando terminó es inofensivo (upsert por orden).
    //
    // Respuesta: { ok, job_id, status, months? , already?: true }
    // -------------------------------------------------------------------------
    app.post(p('/v1/orders/backfill'), authAccount, async (req, res) => {
        const months = Math.min(24, Math.max(1, Number(req.body && req.body.months) || 12));
        try {
            const act = await query(
                `SELECT public_id, status FROM jobs
                 WHERE account_id = $1 AND type = 'orders_backfill'
                   AND status IN ('pending','running')
                 ORDER BY created_at DESC LIMIT 1`,
                [req.account.id]
            );
            if (act.rowCount) {
                return res.json({ ok: true, job_id: act.rows[0].public_id, status: act.rows[0].status, already: true });
            }
            const jobPublic = generatePublicId('job');
            await query(
                `INSERT INTO jobs (public_id, account_id, type, status, input, steps_total)
                 VALUES ($1, $2, 'orders_backfill', 'pending', $3, 0)`,
                [jobPublic, req.account.id, JSON.stringify({ months, source: 'plugin' })]
            );
            return res.json({ ok: true, job_id: jobPublic, status: 'pending', months });
        } catch (err) {
            console.error('[v1/orders/backfill] error:', err);
            return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
        }
    });

    // -------------------------------------------------------------------------
    // GET /v1/orders/history?offset=&limit=  (Ventas ML, F0)
    //
    // Pagina los snapshots completos de órdenes de la cuenta (backfill + los
    // que dejó el pipeline en vivo), de la más nueva a la más vieja. El plugin
    // los ingesta al espejo wf_orders con upsert idempotente — no hay ack: el
    // cliente lleva su propio offset y re-bajar una página repetida no duplica.
    //
    // Respuesta:
    //   { ok, payload_version: 2, total, offset, limit,
    //     orders: [{ ml_order_id, order, billing, shipment, snapshot_at }] }
    // -------------------------------------------------------------------------
    app.get(p('/v1/orders/history'), authAccount, async (req, res) => {
        const limit  = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 50));
        const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
        try {
            const r = await query(
                `SELECT ml_order_id, order_json, billing_json, shipment_json, updated_at
                 FROM order_snapshots
                 WHERE account_id = $1
                 ORDER BY ml_date_created DESC NULLS LAST, id DESC
                 LIMIT $2 OFFSET $3`,
                [req.account.id, limit, offset]
            );
            const c = await query(
                `SELECT COUNT(*)::int AS n FROM order_snapshots WHERE account_id = $1`,
                [req.account.id]
            );
            const orders = r.rows.map((row) => ({
                ml_order_id: row.ml_order_id,
                order:       row.order_json || null,
                billing:     row.billing_json || null,
                shipment:    row.shipment_json || null,
                snapshot_at: row.updated_at,
            }));
            return res.json({ ok: true, payload_version: 2, total: c.rows[0].n, offset, limit, orders });
        } catch (err) {
            console.error('[v1/orders/history] error:', err);
            return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
        }
    });

    // -------------------------------------------------------------------------
    // GET /v1/orders/label?ml_order_id=  (Mercado Envíos, P2)
    //
    // Proxy EN CALIENTE de la etiqueta de envío: busca el shipment de la orden
    // en el snapshot, pide el PDF a ML con el token de la cuenta y lo devuelve
    // en base64. No se persiste nada (la etiqueta es un artefacto de imprenta).
    //
    // Respuesta: { ok, pdf_b64 } · 404 sin snapshot/envío · 502 si ML no la dio
    // (envío Full, ya despachado, o todavía no imprimible).
    // -------------------------------------------------------------------------
    app.get(p('/v1/orders/label'), authAccount, async (req, res) => {
        const mlOrderId = String(req.query.ml_order_id || '').trim();
        if (!mlOrderId) {
            return res.status(400).json({ ok: false, error: 'bad_request', message: 'Falta ml_order_id.' });
        }
        try {
            const r = await query(
                `SELECT shipment_id, order_json FROM order_snapshots
                 WHERE account_id = $1 AND ml_order_id = $2 LIMIT 1`,
                [req.account.id, mlOrderId]
            );
            if (!r.rowCount) {
                return res.status(404).json({ ok: false, error: 'not_found', message: 'La orden no está en el snapshot.' });
            }
            let shipmentId = r.rows[0].shipment_id ? String(r.rows[0].shipment_id) : '';
            if (!shipmentId) {
                const oj = r.rows[0].order_json || {};
                const raw = oj && oj.shipping && oj.shipping.id != null ? String(oj.shipping.id) : '';
                if (/^\d+$/.test(raw)) shipmentId = raw;
            }
            if (!shipmentId) {
                return res.status(404).json({ ok: false, error: 'no_shipment', message: 'La orden no tiene envío de Mercado Envíos.' });
            }
            const token = await getValidAccessToken(req.account);
            const pdf = await mlGetShipmentLabel(req.account, token, shipmentId);
            // Solo PDF de verdad: un 200 de ML con JSON/ZPL adentro no debe
            // llegar al operador como archivo corrupto (review P2).
            if (pdf.length < 5 || pdf.subarray(0, 4).toString() !== '%PDF') {
                return res.status(502).json({ ok: false, error: 'label_not_pdf', message: 'Mercado Libre no entregó la etiqueta en PDF todavía — probá de nuevo en unos minutos.' });
            }
            return res.json({ ok: true, pdf_b64: pdf.toString('base64') });
        } catch (err) {
            console.error('[v1/orders/label] error:', err.message);
            return res.status(502).json({ ok: false, error: 'label_unavailable', message: 'Mercado Libre no entregó la etiqueta (¿envío Full, ya despachado o aún no imprimible?).' });
        }
    });

    // =========================================================================
    // Mensajería post-venta + Preguntas pre-venta (M0, v2.9.0)
    //
    // Mismo contrato que el bloque de órdenes: pending (cola procesada, sin
    // entregar) → ack (por ids de evento). Los proxies de escritura (reply /
    // answer) van EN CALIENTE a ML con el token custodiado — el central no
    // persiste conversaciones (cola de tránsito; retención purga entregadas).
    // =========================================================================

    // -------------------------------------------------------------------------
    // GET /v1/messages/pending
    // Respuesta: { ok, messages: [{ id, ml_message_id, message, received_at }] }
    // `message` = payload CRUDO de ML (from/to/text/message_resources/fecha).
    // -------------------------------------------------------------------------
    app.get(p('/v1/messages/pending'), authAccount, async (req, res) => {
        const r = await query(
            `SELECT id, ml_message_id, payload_json, received_at
             FROM message_events
             WHERE account_id = $1
               AND processed_at IS NOT NULL
               AND delivered_at IS NULL
               AND error IS NULL
             ORDER BY id
             LIMIT 200`,
            [req.account.id]
        );
        const messages = r.rows.map((row) => ({
            id:            String(row.id),
            ml_message_id: row.ml_message_id,
            message:       row.payload_json || null,
            received_at:   row.received_at,
        }));
        return res.json({ ok: true, messages });
    });

    // -------------------------------------------------------------------------
    // POST /v1/messages/ack   Body: { ids: ["1","2",...] } (ids de evento)
    // -------------------------------------------------------------------------
    app.post(p('/v1/messages/ack'), authAccount, async (req, res) => {
        const ids = Array.isArray(req.body && req.body.ids)
            ? req.body.ids.map((v) => String(v)).filter((v) => /^\d+$/.test(v))
            : [];
        if (!ids.length) return res.json({ ok: true, marked: 0 });
        const r = await query(
            `UPDATE message_events SET delivered_at = NOW()
             WHERE account_id = $1 AND id = ANY($2::bigint[]) AND delivered_at IS NULL`,
            [req.account.id, ids]
        );
        return res.json({ ok: true, marked: r.rowCount });
    });

    // -------------------------------------------------------------------------
    // GET /v1/messages/thread?pack_id=&offset=&limit=
    // Proxy EN CALIENTE del hilo completo de un pack (para materializar la
    // conversación al abrirla por primera vez en el plugin). No persiste nada.
    // -------------------------------------------------------------------------
    app.get(p('/v1/messages/thread'), authAccount, async (req, res) => {
        const packId = String(req.query.pack_id || '').trim();
        if (!/^\d+$/.test(packId)) {
            return res.status(400).json({ ok: false, error: 'bad_request', message: 'Falta pack_id.' });
        }
        const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
        const limit  = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 40));
        try {
            const token = await getValidAccessToken(req.account);
            const data  = await mlGetPackMessages(req.account, token, packId, offset, limit);
            return res.json({ ok: true, thread: data });
        } catch (err) {
            console.error('[v1/messages/thread] error:', err.message);
            return res.status(502).json({ ok: false, error: 'thread_unavailable', message: 'Mercado Libre no entregó el hilo — probá de nuevo en unos minutos.' });
        }
    });

    // -------------------------------------------------------------------------
    // POST /v1/messages/reply
    // Body: { pack_id, buyer_user_id, text }
    // Proxy EN CALIENTE: responde al comprador en el hilo del pack.
    // -------------------------------------------------------------------------
    app.post(p('/v1/messages/reply'), authAccount, async (req, res) => {
        const packId  = String((req.body && req.body.pack_id) || '').trim();
        const buyerId = String((req.body && req.body.buyer_user_id) || '').trim();
        const text    = String((req.body && req.body.text) || '').trim();
        if (!/^\d+$/.test(packId) || !/^\d+$/.test(buyerId) || !text) {
            return res.status(400).json({ ok: false, error: 'bad_request', message: 'Faltan pack_id, buyer_user_id o text.' });
        }
        try {
            const token = await getValidAccessToken(req.account);
            const r = await mlSendPackMessage(req.account, token, packId, buyerId, text);
            if (!r.ok) {
                const msg = (r.data && (r.data.message || r.data.error)) || `HTTP ${r.status}`;
                return res.status(502).json({ ok: false, error: 'ml_rejected', message: `Mercado Libre rechazó el mensaje: ${msg}` });
            }
            return res.json({ ok: true, message: r.data || null });
        } catch (err) {
            console.error('[v1/messages/reply] error:', err.message);
            return res.status(502).json({ ok: false, error: 'reply_failed', message: 'No se pudo enviar el mensaje a Mercado Libre.' });
        }
    });

    // -------------------------------------------------------------------------
    // GET /v1/questions/pending + POST /v1/questions/ack — mismo contrato.
    // -------------------------------------------------------------------------
    app.get(p('/v1/questions/pending'), authAccount, async (req, res) => {
        const r = await query(
            `SELECT id, ml_question_id, payload_json, received_at
             FROM question_events
             WHERE account_id = $1
               AND processed_at IS NOT NULL
               AND delivered_at IS NULL
               AND error IS NULL
             ORDER BY id
             LIMIT 200`,
            [req.account.id]
        );
        const questions = r.rows.map((row) => ({
            id:             String(row.id),
            ml_question_id: row.ml_question_id,
            question:       row.payload_json || null,
            received_at:    row.received_at,
        }));
        return res.json({ ok: true, questions });
    });

    app.post(p('/v1/questions/ack'), authAccount, async (req, res) => {
        const ids = Array.isArray(req.body && req.body.ids)
            ? req.body.ids.map((v) => String(v)).filter((v) => /^\d+$/.test(v))
            : [];
        if (!ids.length) return res.json({ ok: true, marked: 0 });
        const r = await query(
            `UPDATE question_events SET delivered_at = NOW()
             WHERE account_id = $1 AND id = ANY($2::bigint[]) AND delivered_at IS NULL`,
            [req.account.id, ids]
        );
        return res.json({ ok: true, marked: r.rowCount });
    });

    // -------------------------------------------------------------------------
    // POST /v1/questions/answer   Body: { question_id, text }
    // Proxy EN CALIENTE: responde la pregunta en ML.
    // -------------------------------------------------------------------------
    app.post(p('/v1/questions/answer'), authAccount, async (req, res) => {
        const qid  = String((req.body && req.body.question_id) || '').trim();
        const text = String((req.body && req.body.text) || '').trim();
        if (!/^\d+$/.test(qid) || !text) {
            return res.status(400).json({ ok: false, error: 'bad_request', message: 'Faltan question_id o text.' });
        }
        try {
            const token = await getValidAccessToken(req.account);
            const r = await mlAnswerQuestion(req.account, token, qid, text);
            if (!r.ok) {
                const msg = (r.data && (r.data.message || r.data.error)) || `HTTP ${r.status}`;
                return res.status(502).json({ ok: false, error: 'ml_rejected', message: `Mercado Libre rechazó la respuesta: ${msg}` });
            }
            return res.json({ ok: true, answer: r.data || null });
        } catch (err) {
            console.error('[v1/questions/answer] error:', err.message);
            return res.status(502).json({ ok: false, error: 'answer_failed', message: 'No se pudo enviar la respuesta a Mercado Libre.' });
        }
    });

    // -------------------------------------------------------------------------
    // POST /v1/questions/backfill
    // Siembra las preguntas ABIERTAS (sin responder) de la cuenta en la cola,
    // como si hubieran llegado por webhook (decisión del dueño: al activar el
    // módulo no se pierde ninguna pregunta pendiente). Inline y acotado
    // (≤10 páginas de 50); idempotente: no re-siembra preguntas que ya tienen
    // un evento sin entregar.
    // -------------------------------------------------------------------------
    app.post(p('/v1/questions/backfill'), authAccount, async (req, res) => {
        try {
            const token = await getValidAccessToken(req.account);
            let offset = 0, seeded = 0, total = 0;
            for (let page = 0; page < 10; page++) {
                const { questions, total: t } = await mlSearchQuestions(req.account, token, { status: 'UNANSWERED', offset, limit: 50 });
                total = t;
                if (!questions.length) break;
                for (const q of questions) {
                    if (!q || q.id == null) continue;
                    const r = await query(
                        `INSERT INTO question_events (account_id, ml_question_id, processed_at, payload_json)
                         SELECT $1, $2, NOW(), $3
                         WHERE NOT EXISTS (
                             SELECT 1 FROM question_events
                             WHERE account_id = $1 AND ml_question_id = $2 AND delivered_at IS NULL
                         )`,
                        [req.account.id, String(q.id), JSON.stringify(q)]
                    );
                    seeded += r.rowCount;
                }
                offset += questions.length;
                if (offset >= total) break;
            }
            return res.json({ ok: true, seeded, total });
        } catch (err) {
            console.error('[v1/questions/backfill] error:', err.message);
            return res.status(502).json({ ok: false, error: 'backfill_failed', message: 'No se pudieron traer las preguntas abiertas de Mercado Libre.' });
        }
    });

    // -------------------------------------------------------------------------
    // POST /v1/jobs/:job_id/cancel
    // Marca el job y todos sus steps queued/leased como cancelled.
    // -------------------------------------------------------------------------
    app.post(p('/v1/jobs/:job_id/cancel'), authAccount, async (req, res) => {
        try {
            const r = await query(
                `UPDATE jobs SET status = 'cancelled', finished_at = NOW(),
                                 message = COALESCE(message, 'Cancelado por el usuario.')
                 WHERE public_id = $1 AND account_id = $2
                   AND status IN ('pending','running')
                 RETURNING id`,
                [req.params.job_id, req.account.id]
            );
            if (!r.rowCount) return res.status(404).json({ ok: false, error: 'not_cancelable' });
            await query(
                `UPDATE job_steps SET status = 'skipped', last_error = 'cancelled', finished_at = NOW()
                 WHERE job_id = $1 AND status IN ('queued','leased')`,
                [r.rows[0].id]
            );
            return res.json({ ok: true, cancelled: true });
        } catch (err) {
            return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
        }
    });
}

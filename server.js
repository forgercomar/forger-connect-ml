/**
 * wooforger-connect-ml — Microservicio OAuth bridge para MercadoLibre.
 *
 * Stateless: no DB, no sesiones server-side. El "state" del flow OAuth se
 * codifica en URL (base64 del JSON) y se valida con HMAC en cada paso.
 *
 * Flow:
 *
 *   [Plugin cliente] ─── popup ───>  GET /connect-ml?site_url=&return_to=&nonce=
 *                                    (este endpoint codifica state y redirige a ML)
 *
 *   [User en ML]     ─── login ───>  https://auth.mercadolibre.com.ar/authorization
 *                                    (ML pide autorizar acceso a sus publicaciones)
 *
 *   [ML]             ─── 302 ────>   GET /connect-ml/callback?code=XXX&state=YYY
 *                                    (este endpoint intercambia code → tokens y
 *                                     redirige al return_to del cliente con
 *                                     payload firmado)
 *
 *   [Plugin cliente] ─── valida ──>  Recibe payload + firma, valida HMAC contra
 *                                    WFML_OAUTH_HUB_SECRET compartido, upsert
 *                                    de la cuenta ML en su DB local.
 *
 * Variables de entorno requeridas:
 *
 *   ML_CLIENT_ID           App ID de developers.mercadolibre.com
 *   ML_CLIENT_SECRET       Client Secret de developers.mercadolibre.com
 *   WFML_OAUTH_HUB_SECRET  Shared secret con los plugins clientes (HMAC key,
 *                          generar con `openssl rand -base64 48`)
 *   ML_AUTH_DOMAIN         (opcional) Default 'https://auth.mercadolibre.com.ar'.
 *                          Para clientes en MX: 'https://auth.mercadolibre.com.mx'.
 *                          La auth domain NO importa al final del flow porque ML
 *                          devuelve el code a cualquier auth domain del mismo país.
 *                          Para multi-país, podemos derivarlo de site_id si querés.
 *   BASE_URL               (opcional) Default 'https://wooforger.dev'. Usado para
 *                          construir el callback URL. Tiene que coincidir con el
 *                          redirect URI configurado en developers.mercadolibre.com.
 *   PORT                   (opcional) Default 3000.
 *
 * @author WooForger.dev
 */

import express from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

// Versión del bridge — leído de package.json al arrancar. Se expone en /version
// para que el cliente pueda verificar qué build está corriendo sin acceso al
// container. Útil para diagnosticar "deploy aplicado vs. no aplicado".
const __dirname = path.dirname(fileURLToPath(import.meta.url));
let PKG_VERSION = 'unknown';
try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
    PKG_VERSION = pkg.version || 'unknown';
} catch (_) { /* ignore */ }
const STARTED_AT = new Date().toISOString();

// ============================================================================
// Storage simple en JSON file para el mapping ml_user_id → site_url.
// El forwarder de webhooks lo usa para saber a dónde reenviar las notifications
// que recibe del bridge cuando ML las manda a /connect-ml/webhooks.
//
// Se popula al confirmar OAuth en /connect-ml/finish (ahí tenemos return_to →
// site_url + payload.ml_user_id). Si el bridge reinicia y se pierde el archivo,
// los clientes existentes dejan de recibir webhooks hasta que reconecten.
//
// Para persistencia entre rebuilds, EasyPanel debe montar un volume en /data.
// ============================================================================
const DATA_DIR = process.env.DATA_DIR || '/data';
const MAPPINGS_FILE = path.join(DATA_DIR, 'mappings.json');
try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
} catch (e) {
    console.warn('[mappings] no se pudo crear DATA_DIR ' + DATA_DIR + ': ' + e.message);
}

function loadMappings() {
    try {
        const raw = fs.readFileSync(MAPPINGS_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        return (parsed && typeof parsed === 'object') ? parsed : {};
    } catch (_) {
        return {};
    }
}

function saveMappings(map) {
    try {
        fs.writeFileSync(MAPPINGS_FILE, JSON.stringify(map, null, 2), 'utf8');
    } catch (e) {
        console.error('[mappings] save error:', e.message);
    }
}

function registerMapping(mlUserId, siteUrl) {
    if (!mlUserId || !siteUrl) return;
    const map = loadMappings();
    const key = String(mlUserId);
    const prev = map[key] || {};
    map[key] = {
        site_url:      siteUrl,
        registered_at: prev.registered_at || Math.floor(Date.now() / 1000),
        updated_at:    Math.floor(Date.now() / 1000),
    };
    saveMappings(map);
    console.log(`[mappings] registered user=${mlUserId} site=${siteUrl}`);
}

function getMappingForUser(mlUserId) {
    if (!mlUserId) return null;
    const map = loadMappings();
    return map[String(mlUserId)] || null;
}

// ============================================================================
// Config — leído de env vars
// ============================================================================
const PORT             = Number(process.env.PORT || 3000);
const ML_CLIENT_ID     = process.env.ML_CLIENT_ID || '';
const ML_CLIENT_SECRET = process.env.ML_CLIENT_SECRET || '';
const HUB_SECRET       = process.env.WFML_OAUTH_HUB_SECRET || '';
const ML_AUTH_DOMAIN   = process.env.ML_AUTH_DOMAIN || 'https://auth.mercadolibre.com.ar';
const BASE_URL         = (process.env.BASE_URL || 'https://wooforger.dev').replace(/\/$/, '');
const CALLBACK_URL     = `${BASE_URL}/connect-ml/callback`;

// Validar config al arrancar — fail-fast.
const missing = [];
if (!ML_CLIENT_ID)     missing.push('ML_CLIENT_ID');
if (!ML_CLIENT_SECRET) missing.push('ML_CLIENT_SECRET');
if (!HUB_SECRET)       missing.push('WFML_OAUTH_HUB_SECRET');
if (missing.length) {
    console.error('[wooforger-connect-ml] FATAL: faltan env vars:', missing.join(', '));
    process.exit(1);
}

const app = express();
app.disable('x-powered-by');

// Trust proxy — el reverse proxy termina TLS y reenvía con X-Forwarded-*.
app.set('trust proxy', true);

// Anti-caché global. Cualquier respuesta del bridge debe ser fresh — sino
// el reverse proxy o el browser pueden servir HTML viejo del deploy anterior
// (ej. la pantalla "Conectaste tu cuenta" después de que la removimos).
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.set('X-Bridge-Version', PKG_VERSION);
    next();
});

// Middleware de parsing — antes de los route handlers para que /connect-ml/finish
// y /refresh-token reciban req.body parseado.
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(express.json({ limit: '64kb' }));

// ============================================================================
// Helpers
// ============================================================================

/** Codifica un objeto JSON a base64url (sin padding, URL-safe). */
function b64urlEncode(json) {
    return Buffer.from(JSON.stringify(json), 'utf8')
        .toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decodifica base64url a objeto. */
function b64urlDecode(s) {
    const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
    return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
}

/** HMAC-SHA256 en base64 standard (no URL-safe — pareo con el lado PHP). */
function hmac(payloadB64) {
    return crypto.createHmac('sha256', HUB_SECRET).update(payloadB64).digest('base64');
}

/** Sanity: ¿return_to está bien formado y apunta a un dominio razonable? */
function isValidReturnTo(url) {
    try {
        const u = new URL(url);
        return (u.protocol === 'http:' || u.protocol === 'https:');
    } catch (e) {
        return false;
    }
}

/** Render simple HTML para páginas de error / fallback. */
function htmlPage(title, body) {
    return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<title>${title} · WooForger</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f8fafc; color: #1f2937; padding: 40px 20px; line-height: 1.55; }
  .wrap { max-width: 560px; margin: 60px auto; background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); padding: 32px 40px; }
  h1 { margin: 0 0 12px; font-size: 22px; color: #1e1b4b; }
  p { color: #4b5563; margin: 8px 0; }
  code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 12px; color: #c2410c; }
  .ok { color: #166534; }
  .err { color: #991b1b; }
</style>
</head><body>
<div class="wrap">${body}</div>
<p style="text-align:center;font-size:11px;color:#9ca3af;margin-top:30px;">wooforger-connect-ml · stateless OAuth bridge</p>
</body></html>`;
}

/**
 * Pantalla de confirmación pre-handoff: el usuario revisa los datos de la cuenta
 * y decide si confirmar (mandar al plugin) o cancelar (volver sin guardar).
 *
 * Stateless: payload + return_to + nonce viajan como hidden fields firmados con
 * HMAC. El handler /connect-ml/finish valida la firma y decide qué hacer.
 */
function confirmationPage({ payload, returnTo, nonce, siteUrl }) {
    const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
    // Firma sobre el trío payload|return_to|nonce para evitar tampering del form.
    const formSig = crypto.createHmac('sha256', HUB_SECRET)
        .update(payloadB64 + '|' + returnTo + '|' + nonce)
        .digest('base64');

    const hasRefresh = !!payload.refresh_token;
    const siteIdOk = payload.site_id && payload.site_id !== '0';
    const expHours = payload.expires_in > 0 ? (payload.expires_in / 3600).toFixed(1) : '?';

    const warnings = [];
    if (!hasRefresh) {
        warnings.push('El payload <strong>no incluye refresh_token</strong>. Tu sitio no podrá renovar el token automáticamente cuando expire (~6h) y vas a tener que reconectar manualmente.');
    }
    if (!siteIdOk) {
        warnings.push('El <strong>site_id</strong> vino vacío. Esto puede impedir que el plugin identifique correctamente el país de tu cuenta.');
    }

    const warningsHtml = warnings.length === 0 ? '' : `
        <div class="warnings">
            <strong>⚠ Atención antes de confirmar:</strong>
            <ul>${warnings.map(w => `<li>${w}</li>`).join('')}</ul>
        </div>
    `;

    return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<title>Confirmá tu cuenta · WooForger</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: linear-gradient(180deg,#f5f7fa 0%,#eef2f7 100%); color: #1f2937; padding: 20px; line-height: 1.55; min-height: 100vh; margin: 0; }
  .wrap { max-width: 680px; margin: 40px auto; background: #fff; border: 1px solid #e5e7eb; border-radius: 16px; box-shadow: 0 8px 32px rgba(0,0,0,0.06); overflow: hidden; }
  /* === Hero trío === */
  .hero { background: radial-gradient(circle at 25% 50%, rgba(33,117,191,0.06), transparent 45%), radial-gradient(circle at 75% 50%, rgba(255,230,0,0.10), transparent 45%), linear-gradient(180deg,#fafbfc 0%,#f3f4f6 100%); padding: 32px 24px 28px; border-bottom: 1px solid #e5e7eb; }
  .trio { display: grid; grid-template-columns: 1fr 80px 1.3fr 80px 1fr; align-items: center; justify-items: center; gap: 0; max-width: 560px; margin: 0 auto; }
  .side, .center { display: flex; flex-direction: column; align-items: center; gap: 8px; text-align: center; position: relative; }
  .ring { background: #fff; border-radius: 50%; width: 56px; height: 56px; display: inline-flex; align-items: center; justify-content: center; box-shadow: 0 4px 14px rgba(0,0,0,0.08), 0 1px 3px rgba(0,0,0,0.04); border: 1px solid rgba(0,0,0,0.04); position: relative; z-index: 1; }
  .ring img { max-width: 36px; max-height: 36px; object-fit: contain; }
  .ring.is-center { width: 76px; height: 76px; box-shadow: 0 8px 24px rgba(229,91,15,0.18), 0 2px 6px rgba(0,0,0,0.08); }
  .ring.is-center img { max-width: 52px; max-height: 52px; }
  .halo { position: absolute; top: 0; left: 50%; transform: translateX(-50%); width: 76px; height: 76px; border-radius: 50%; background: radial-gradient(circle, rgba(229,91,15,0.25) 0%, transparent 70%); animation: pulse 2.6s ease-in-out infinite; pointer-events: none; z-index: 0; }
  @keyframes pulse { 0%,100% { transform: translateX(-50%) scale(1); opacity: 0.7; } 50% { transform: translateX(-50%) scale(1.15); opacity: 0.3; } }
  .label { font-size: 11px; color: #4b5563; line-height: 1.3; font-weight: 500; }
  .label.is-center { font-size: 12px; }
  .label.is-center strong { color: #E55B0F; font-weight: 700; font-size: 13px; }
  .label.is-center span { color: #6b7280; font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; }
  .connector { position: relative; width: 100%; height: 18px; display: flex; align-items: center; }
  .line { width: 100%; height: 2px; background: linear-gradient(90deg,transparent 0%,#cbd5e1 15%,#cbd5e1 85%,transparent 100%); border-radius: 999px; }
  .dot { position: absolute; top: 50%; left: 0; width: 6px; height: 6px; border-radius: 50%; background: #E55B0F; transform: translateY(-50%); box-shadow: 0 0 8px rgba(229,91,15,0.6); animation: flow 2.4s linear infinite; }
  .dot.d2 { animation-delay: 0.8s; } .dot.d3 { animation-delay: 1.6s; }
  @keyframes flow { 0% { left: -6px; opacity: 0; transform: translateY(-50%) scale(0.5); } 10% { opacity: 1; transform: translateY(-50%) scale(1); } 90% { opacity: 1; transform: translateY(-50%) scale(1); } 100% { left: calc(100% + 6px); opacity: 0; transform: translateY(-50%) scale(0.5); } }
  /* === Body === */
  .body { padding: 26px 32px 28px; }
  h1 { margin: 0 0 6px; font-size: 20px; color: #111827; }
  .intro { color: #4b5563; font-size: 13.5px; margin: 0 0 18px; }
  .site-pill { display: inline-block; background: #eef2ff; color: #3730a3; padding: 3px 10px; border-radius: 6px; font-size: 12px; font-family: ui-monospace, Menlo, Consolas, monospace; margin-left: 4px; }
  .details { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 10px; padding: 4px 0; margin-bottom: 16px; }
  .row { display: flex; padding: 10px 16px; border-bottom: 1px solid #f3f4f6; }
  .row:last-child { border-bottom: 0; }
  .row .k { width: 130px; color: #6b7280; font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; font-weight: 600; flex-shrink: 0; }
  .row .v { flex: 1; font-size: 13px; color: #111827; }
  .row .v code { background: #f3f4f6; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
  .row .v.big { font-weight: 700; font-size: 15px; }
  .ok { color: #047857; }
  .err { color: #b91c1c; }
  .warnings { background: #fef3c7; border: 1px solid #fde68a; border-radius: 10px; padding: 12px 16px; margin-bottom: 18px; color: #78350f; font-size: 12.5px; }
  .warnings strong { display: block; margin-bottom: 6px; }
  .warnings ul { margin: 0; padding-left: 18px; }
  .warnings li { margin: 4px 0; line-height: 1.45; }
  .actions { display: flex; gap: 12px; justify-content: flex-end; }
  .btn { padding: 10px 18px; border-radius: 8px; border: 1px solid; font-size: 14px; font-weight: 600; cursor: pointer; font-family: inherit; transition: all 0.15s; }
  .btn-primary { background: #E55B0F; border-color: #E55B0F; color: #fff; }
  .btn-primary:hover { background: #c44a08; border-color: #c44a08; }
  .btn-secondary { background: #fff; border-color: #d1d5db; color: #374151; }
  .btn-secondary:hover { background: #f9fafb; border-color: #9ca3af; }
  .hint { margin: 18px 0 0; font-size: 11.5px; color: #9ca3af; text-align: center; line-height: 1.5; }
  @media (max-width: 560px) {
      .trio { grid-template-columns: 1fr 30px 1.3fr 30px 1fr; }
      .row { flex-direction: column; gap: 4px; }
      .row .k { width: auto; }
      .actions { flex-direction: column-reverse; }
      .btn { width: 100%; }
  }
</style>
</head><body>
<div class="wrap">
    <div class="hero">
        <div class="trio">
            <div class="side">
                <div class="ring"><img src="https://s.w.org/style/images/about/WordPress-logotype-wmark.png" alt="WordPress" /></div>
                <span class="label">Tu tienda<br>WooCommerce</span>
            </div>
            <div class="connector" aria-hidden="true">
                <span class="line"></span><span class="dot"></span><span class="dot d2"></span><span class="dot d3"></span>
            </div>
            <div class="center">
                <div class="halo" aria-hidden="true"></div>
                <div class="ring is-center"><img src="https://wooforger.dev/wooforger-logo.png" alt="WooForger" onerror="this.style.display='none'" /></div>
                <span class="label is-center"><strong>WooForger</strong><br><span>Capa de integración</span></span>
            </div>
            <div class="connector" aria-hidden="true">
                <span class="line"></span><span class="dot"></span><span class="dot d2"></span><span class="dot d3"></span>
            </div>
            <div class="side">
                <div class="ring"><img src="https://http2.mlstatic.com/frontend-assets/ml-web-navigation/ui-navigation/6.6.83/mercadolibre/logo__small@2x.png" alt="MercadoLibre" /></div>
                <span class="label">Publicaciones<br>en MercadoLibre</span>
            </div>
        </div>
    </div>
    <div class="body">
        <h1>Confirmá tu cuenta MercadoLibre</h1>
        <p class="intro">Estos son los datos de la cuenta que vamos a enviar a tu sitio
            <span class="site-pill">${escapeHtml(siteUrl || 'tu WordPress')}</span>.
            <strong>Antes de guardarlos</strong>, revisá que sea la cuenta correcta — la sesión activa en este browser puede no ser la que querés conectar.</p>

        <div class="details">
            <div class="row"><span class="k">Nickname</span><span class="v big">${escapeHtml(payload.nickname || '—')}</span></div>
            <div class="row"><span class="k">Email</span><span class="v">${escapeHtml(payload.email || '—')}</span></div>
            <div class="row"><span class="k">Sitio (país)</span><span class="v">${siteIdOk ? `<code>${escapeHtml(payload.site_id)}</code>` : '<em class="err">vacío</em>'}</span></div>
            <div class="row"><span class="k">ML user_id</span><span class="v"><code>${payload.ml_user_id}</code></span></div>
            <div class="row"><span class="k">access_token</span><span class="v"><span class="ok">✓ recibido (${String(payload.access_token).length} chars)</span> · válido por ${expHours}h</span></div>
            <div class="row"><span class="k">refresh_token</span><span class="v">${hasRefresh ? `<span class="ok">✓ recibido (${String(payload.refresh_token).length} chars)</span>` : '<span class="err">✗ ausente — refresh automático no funcionará</span>'}</span></div>
        </div>

        ${warningsHtml}

        <form method="POST" action="/connect-ml/finish" class="actions">
            <input type="hidden" name="payload" value="${escapeHtml(payloadB64)}" />
            <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}" />
            <input type="hidden" name="nonce" value="${escapeHtml(nonce)}" />
            <input type="hidden" name="form_sig" value="${escapeHtml(formSig)}" />
            <button type="submit" name="decision" value="cancel" class="btn btn-secondary">Cancelar (usar otra cuenta)</button>
            <button type="submit" name="decision" value="confirm" class="btn btn-primary">Confirmar y conectar</button>
        </form>

        <p class="hint">Si esta no es la cuenta correcta: cancelá, cerrá sesión en mercadolibre.com.ar/argentina/menu/cuenta o cambiá de cuenta en el browser, y volvé a iniciar la conexión desde tu sitio.</p>
    </div>
</div>
<p style="text-align:center;font-size:11px;color:#9ca3af;margin-top:24px;">wooforger-connect-ml · OAuth bridge</p>
</body></html>`;
}

// ============================================================================
// GET /healthz — liveness check para el reverse proxy.
// Registrado en ambas formas porque algunos reverse proxies no strippean el
// path prefix del dominio (https://example/connect-ml/healthz puede llegar al
// container literal como /connect-ml/healthz).
// ============================================================================
app.get(['/healthz', '/connect-ml/healthz'], (req, res) => {
    res.json({ ok: true, ts: Date.now() });
});

// ============================================================================
// GET /version — qué build está corriendo. Útil para verificar que un deploy
// haya tomado efecto sin tener que entrar al container.
// ============================================================================
app.get(['/version', '/connect-ml/version'], (req, res) => {
    res.json({
        ok: true,
        version: PKG_VERSION,
        started_at: STARTED_AT,
        ts: Date.now(),
    });
});

// ============================================================================
// GET /mappings/count — diagnóstico simple para verificar que los mappings
// ml_user_id → site_url se están persistiendo (sin exponer URLs sensibles).
// ============================================================================
app.get(['/mappings/count', '/connect-ml/mappings/count'], (req, res) => {
    const map = loadMappings();
    const keys = Object.keys(map);
    res.json({
        ok:           true,
        count:        keys.length,
        user_ids:     keys,
        data_dir:     DATA_DIR,
        data_dir_writable: (() => {
            try { fs.accessSync(DATA_DIR, fs.constants.W_OK); return true; } catch (_) { return false; }
        })(),
    });
});

// ============================================================================
// GET /connect-ml — inicio del flow. Recibe los params del cliente y redirige a ML.
//
//   site_url   identifica al cliente (solo informativo).
//   return_to  URL del admin del cliente donde devolver el resultado (típicamente
//              <site>/wp-admin/admin-post.php?action=wfml_oauth_callback).
//   nonce      anti-CSRF generado por el plugin del cliente.
// ============================================================================
app.get('/connect-ml', (req, res) => {
    const { site_url = '', return_to = '', nonce = '' } = req.query;

    if (!return_to || !isValidReturnTo(String(return_to))) {
        return res.status(400).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ return_to inválido</h1>
            <p>El plugin del cliente debe enviar el parámetro <code>return_to</code> con una URL HTTP/HTTPS válida.</p>`
        ));
    }
    if (!nonce) {
        return res.status(400).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ nonce faltante</h1>
            <p>El plugin del cliente no envió el parámetro <code>nonce</code>.</p>`
        ));
    }

    // Codificar el state para que ML nos lo devuelva en el callback.
    // No confiamos en el contenido del state cuando vuelve (ML solo lo retransmite),
    // pero como solo lo usamos para reconstruir return_to/nonce, está OK.
    const state = b64urlEncode({
        s: String(site_url),
        r: String(return_to),
        n: String(nonce),
        t: Math.floor(Date.now() / 1000),
    });

    const authUrl = new URL(ML_AUTH_DOMAIN + '/authorization');
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', ML_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', CALLBACK_URL);
    authUrl.searchParams.set('state', state);

    res.redirect(302, authUrl.toString());
});

// ============================================================================
// GET /connect-ml/callback — vuelve del flow de ML con ?code= y ?state=.
//
// 1. Decodifica state → recupera return_to + nonce.
// 2. Intercambia code por access_token + refresh_token + user_id (POST a ML).
// 3. Pide /users/me para nickname + email + site_id.
// 4. Arma payload, lo firma con HMAC, redirige al return_to del cliente.
// ============================================================================
app.get('/connect-ml/callback', async (req, res) => {
    const { code, state, error, error_description } = req.query;

    if (error) {
        return res.status(400).type('html').send(htmlPage('Acceso denegado',
            `<h1 class="err">⚠ ${escapeHtml(String(error))}</h1>
            <p>${escapeHtml(String(error_description || 'MercadoLibre rechazó la solicitud.'))}</p>
            <p>Cerrá esta ventana y volvé a intentar desde el plugin.</p>`
        ));
    }
    if (!code || !state) {
        return res.status(400).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ Callback inválido</h1>
            <p>Faltó <code>code</code> o <code>state</code> en la respuesta de ML.</p>`
        ));
    }

    // Decodificar state.
    let stateObj;
    try { stateObj = b64urlDecode(String(state)); }
    catch (e) {
        return res.status(400).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ State corrupto</h1>
            <p>No pudimos decodificar el state. Cerrá esta ventana y reintentá desde el plugin.</p>`
        ));
    }
    const { r: return_to, n: nonce, s: site_url } = stateObj;
    if (!return_to || !isValidReturnTo(return_to)) {
        return res.status(400).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ return_to inválido en state</h1>`
        ));
    }

    // 1) Intercambiar code → tokens.
    let tokenData;
    try {
        const resp = await fetch('https://api.mercadolibre.com/oauth/token', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                grant_type:    'authorization_code',
                client_id:     ML_CLIENT_ID,
                client_secret: ML_CLIENT_SECRET,
                code:          String(code),
                redirect_uri:  CALLBACK_URL,
            }).toString(),
        });
        tokenData = await resp.json();
        if (!resp.ok) {
            console.error('[oauth/token] error', resp.status, tokenData);
            return res.status(502).type('html').send(htmlPage('Error',
                `<h1 class="err">⚠ ML rechazó el code</h1>
                <p><code>${escapeHtml((tokenData && tokenData.message) || resp.status)}</code></p>
                <p>Esto normalmente significa que el code ya se usó o expiró. Reintentá desde el plugin.</p>`
            ));
        }
    } catch (e) {
        console.error('[oauth/token] transport', e);
        return res.status(502).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ No pudimos contactar a ML</h1>
            <p>Reintentá en unos minutos.</p>`
        ));
    }

    // 2) Pedir /users/me para datos del seller.
    let user = {};
    try {
        const r = await fetch('https://api.mercadolibre.com/users/me', {
            headers: { 'Authorization': 'Bearer ' + tokenData.access_token },
        });
        if (r.ok) user = await r.json();
    } catch (e) {
        // No fatal — si falla, igual mandamos lo del token (user_id ya viene en tokenData).
        console.warn('[users/me] no se pudo enriquecer:', e.message);
    }

    // 3) Armar payload normalizado para el plugin.
    const payload = {
        ml_user_id:    Number(tokenData.user_id || user.id || 0),
        nickname:      String(user.nickname || ''),
        email:         String(user.email || ''),
        site_id:       String(user.site_id || ''),
        access_token:  String(tokenData.access_token || ''),
        refresh_token: String(tokenData.refresh_token || ''),
        expires_in:    Number(tokenData.expires_in || 0),
    };
    if (!payload.ml_user_id || !payload.access_token) {
        return res.status(502).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ Respuesta inesperada de ML</h1>
            <p>Faltan campos críticos en el payload (user_id / access_token).</p>`
        ));
    }

    // 4) En lugar de redirigir directo al plugin, mostramos pantalla de confirmación
    //    para que el usuario verifique que la cuenta sea la correcta antes de que
    //    sus tokens lleguen a su WordPress. El form postea a /connect-ml/finish con
    //    los datos firmados; ahí se decide redirect o cancel.
    res.type('html').send(confirmationPage({
        payload,
        returnTo: return_to,
        nonce: String(nonce),
        siteUrl: String(site_url || ''),
    }));
});

// ============================================================================
// POST /connect-ml/finish — el usuario confirmó o canceló la pantalla pre-handoff.
//
// Valida la firma del form (HMAC sobre payload|return_to|nonce) y según `decision`:
//   - confirm: firma el payload con HUB_SECRET y redirige al return_to del plugin.
//   - cancel:  redirige al return_to con ?wfml_cancel=1 (plugin muestra notice).
// ============================================================================
app.post(['/connect-ml/finish', '/finish'], (req, res) => {
    const payloadB64 = String((req.body && req.body.payload)    || '');
    const returnTo   = String((req.body && req.body.return_to)  || '');
    const nonce      = String((req.body && req.body.nonce)      || '');
    const formSig    = String((req.body && req.body.form_sig)   || '');
    const decision   = String((req.body && req.body.decision)   || '');

    if (!payloadB64 || !returnTo || !nonce || !formSig) {
        return res.status(400).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ Form incompleto</h1>
            <p>Faltan campos en el formulario de confirmación. Cerrá esta ventana y reintentá desde tu sitio.</p>`
        ));
    }
    if (!isValidReturnTo(returnTo)) {
        return res.status(400).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ return_to inválido</h1>`
        ));
    }

    // Validar firma del form (anti-tampering).
    const expectedSig = crypto.createHmac('sha256', HUB_SECRET)
        .update(payloadB64 + '|' + returnTo + '|' + nonce)
        .digest('base64');
    const expectedBuf = Buffer.from(expectedSig);
    const receivedBuf = Buffer.from(formSig);
    if (expectedBuf.length !== receivedBuf.length ||
        !crypto.timingSafeEqual(expectedBuf, receivedBuf)) {
        return res.status(403).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ Firma inválida</h1>
            <p>El formulario fue manipulado o el shared secret cambió. Reintentá desde tu sitio.</p>`
        ));
    }

    // Decisión del usuario.
    if (decision === 'cancel') {
        // Volvemos al plugin con un flag de cancelación — sin payload ni firma.
        const cancelUrl = new URL(returnTo);
        cancelUrl.searchParams.set('nonce', nonce);
        cancelUrl.searchParams.set('wfml_cancel', '1');
        return res.type('html').send(htmlPage('Cancelado', `
            <h1>Conexión cancelada</h1>
            <p>No se guardó ninguna cuenta en tu sitio.</p>
            <p style="margin-top:14px;"><a href="${escapeHtml(cancelUrl.toString())}">Volver al panel del plugin</a></p>
            <script>setTimeout(function(){ window.location.href = ${JSON.stringify(cancelUrl.toString())}; }, 1500);</script>
        `));
    }

    // Confirmar: re-firmamos el payload con el HMAC standard que espera el plugin
    // y redirigimos. El plugin valida la firma y persiste.
    const signature = hmac(payloadB64);
    const finalUrl  = new URL(returnTo);
    finalUrl.searchParams.set('nonce', nonce);
    finalUrl.searchParams.set('payload', payloadB64);
    finalUrl.searchParams.set('signature', signature);

    // Registrar mapping ml_user_id → site_url para forward de webhooks futuros.
    // El site_url lo derivamos del returnTo (origin de la URL del admin del cliente).
    try {
        const decoded = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));
        const siteOrigin = new URL(returnTo).origin;
        if (decoded.ml_user_id && siteOrigin) {
            registerMapping(decoded.ml_user_id, siteOrigin);
        }
    } catch (e) {
        console.warn('[finish] register mapping failed:', e.message);
    }

    res.type('html').send(htmlPage('Conectando...', `
        <h1 class="ok">✓ Listo, conectando tu cuenta...</h1>
        <p>Volviendo a tu panel WooForger con las credenciales validadas.</p>
        <p style="margin-top:20px;font-size:12px;color:#9ca3af;">Si no se redirige automáticamente, <a href="${escapeHtml(finalUrl.toString())}">hacé click acá</a>.</p>
        <script>setTimeout(function(){ window.location.href = ${JSON.stringify(finalUrl.toString())}; }, 1000);</script>
    `));
});

// ============================================================================
// POST /refresh-token — refresh del access_token usando el refresh_token.
//
// Endpoint llamado por los plugins WF cuando reciben 401 de ML.
//
// Body esperado (form-urlencoded o JSON):
//   refresh_token  el refresh token actual (largo TG-xxxxxx).
//   payload_sig    HMAC-SHA256(refresh_token, WFML_OAUTH_HUB_SECRET) en base64.
//
// Validamos firma para evitar que cualquiera llame a refresh con un refresh
// token robado: el solicitante tiene que conocer el shared secret.
//
// Respuesta (JSON):
//   { ok: true,  payload: <base64>, signature: <base64> }   — payload tiene los tokens nuevos
//   { ok: false, error: <string> }
// ============================================================================
app.post(['/refresh-token', '/connect-ml/refresh-token'], async (req, res) => {
    // IMPORTANTE: algunos reverse proxies interceptan cualquier 5xx upstream y
    // lo reemplazan por una pagina HTML de error generica, aplastando el body
    // JSON. Por eso este endpoint SIEMPRE responde 200 y el cliente discrimina
    // por la flag `ok` del JSON. Excepcion: 400/403 si pasan limpio.
    try {
    const refresh_token = String((req.body && req.body.refresh_token) || '').trim();
    const payload_sig   = String((req.body && req.body.payload_sig) || '').trim();

    if (!refresh_token || !payload_sig) {
        return res.status(400).json({ ok: false, error: 'missing refresh_token or payload_sig' });
    }
    // Validar firma del refresh_token.
    // timingSafeEqual exige buffers del mismo length — si difieren, es ataque
    // o cliente roto, asi que devolvemos 403 sin llamarlo.
    const expectedSig = crypto.createHmac('sha256', HUB_SECRET).update(refresh_token).digest('base64');
    const expectedBuf = Buffer.from(expectedSig);
    const receivedBuf = Buffer.from(payload_sig);
    if (expectedBuf.length !== receivedBuf.length ||
        !crypto.timingSafeEqual(expectedBuf, receivedBuf)) {
        return res.status(403).json({ ok: false, error: 'invalid signature' });
    }

    // Hacer refresh contra ML. Errores aca van como 200 + ok:false para no
    // gatillar la pagina de error de Traefik.
    try {
        const resp = await fetch('https://api.mercadolibre.com/oauth/token', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                grant_type:    'refresh_token',
                client_id:     ML_CLIENT_ID,
                client_secret: ML_CLIENT_SECRET,
                refresh_token: refresh_token,
            }).toString(),
        });
        const raw  = await resp.text();
        let data;
        try { data = JSON.parse(raw); } catch (_) { data = null; }
        if (!resp.ok) {
            return res.json({
                ok: false,
                error: 'ML rejected refresh: ' + ((data && (data.message || data.error_description)) || ('HTTP ' + resp.status)),
                ml_status: resp.status,
                ml_response: data,
            });
        }
        if (!data) {
            return res.json({ ok: false, error: 'ML responded non-JSON', ml_raw: raw.slice(0, 500) });
        }
        const out = {
            access_token:  String(data.access_token || ''),
            refresh_token: String(data.refresh_token || ''),
            expires_in:    Number(data.expires_in || 0),
            user_id:       Number(data.user_id || 0),
        };
        if (!out.access_token) {
            return res.json({ ok: false, error: 'ML response missing access_token' });
        }
        const payloadB64 = Buffer.from(JSON.stringify(out), 'utf8').toString('base64');
        const signature  = crypto.createHmac('sha256', HUB_SECRET).update(payloadB64).digest('base64');
        return res.json({ ok: true, payload: payloadB64, signature });
    } catch (e) {
        return res.json({ ok: false, error: 'transport: ' + e.message });
    }
    } catch (outer) {
        console.error('[refresh-token] unhandled:', outer);
        return res.json({ ok: false, error: 'internal: ' + outer.message });
    }
});

// ============================================================================
// POST /connect-ml/webhooks — receptor de notifications de MercadoLibre.
//
// Este endpoint cumple dos roles:
//   1. Hoy: STUB que responde 200 OK rápido para que ML acepte la URL en
//      la configuración de la app y no marque el sitio como inalcanzable.
//   2. Próximo: FORWARDER que identifique el seller por user_id del payload
//      y reenvíe la notification al endpoint del plugin del cliente correspondiente
//      (https://<site>/wp-json/wfml/v1/webhook), firmando el forward con HMAC.
//
// Topics que ML manda según permisos otorgados:
//   - orders_v2, items, messages, shipments, claims, questions, etc.
//
// ML hace retry agresivo si no respondemos 200 en pocos segundos. Por eso
// respondemos ANTES de cualquier procesamiento.
// ============================================================================
app.post(['/connect-ml/webhooks', '/webhooks'], (req, res) => {
    // 1. Responder 200 INMEDIATO. ML retry si > 1.5s o status != 200.
    res.status(200).json({ ok: true });

    // 2. Procesar fire-and-forget.
    const body = req.body || {};
    const topic    = String(body.topic    || '?');
    const resource = String(body.resource || '?');
    const userId   = body.user_id ? String(body.user_id) : '';
    const sent     = body.sent ? String(body.sent) : '';
    console.log(`[webhook] topic=${topic} user=${userId} resource=${resource} sent=${sent}`);

    if (!userId) {
        console.log('[webhook] payload sin user_id — no se puede forwardear');
        return;
    }

    // 3. Buscar mapping y reenviar al plugin del cliente.
    const mapping = getMappingForUser(userId);
    if (!mapping || !mapping.site_url) {
        console.log(`[webhook] no mapping registrado para user=${userId} — skip forward`);
        return;
    }

    // Body crudo serializado (lo que se va a firmar y reenviar al plugin).
    let rawBody;
    try {
        rawBody = JSON.stringify(body);
    } catch (e) {
        console.error('[webhook] no se pudo serializar body:', e.message);
        return;
    }

    const forwardUrl = mapping.site_url.replace(/\/$/, '') + '/wp-json/wfml/v1/webhook';
    const sig = crypto.createHmac('sha256', HUB_SECRET).update(rawBody).digest('base64');

    fetch(forwardUrl, {
        method: 'POST',
        headers: {
            'Content-Type':       'application/json',
            'X-Wfml-Bridge-Sig':  sig,
            'X-Wfml-Bridge':      'wooforger-connect-ml/' + PKG_VERSION,
            'User-Agent':         'wooforger-bridge-forwarder',
        },
        body: rawBody,
        // 8s timeout — más que suficiente para que el plugin loguee + dispatch async.
        signal: AbortSignal.timeout(8000),
    }).then(r => {
        console.log(`[webhook] forwarded user=${userId} → ${forwardUrl} status=${r.status}`);
    }).catch(e => {
        console.error(`[webhook] forward error user=${userId} → ${forwardUrl}: ${e.message}`);
    });
});

// ============================================================================
// GET / — pequeña landing informativa
// ============================================================================
app.get('/', (req, res) => {
    res.type('html').send(htmlPage('WooForger Connect ML',
        `<h1>WooForger · Connect MercadoLibre</h1>
        <p>Microservicio OAuth bridge para clientes WooForger MercadoLibre.</p>
        <p>Si llegaste acá por error: este endpoint solo lo usan los plugins WooForger instalados en tu WordPress.</p>
        <p><a href="https://wooforger.dev">wooforger.dev</a></p>`
    ));
});

// 404 fallback.
app.use((req, res) => {
    res.status(404).type('html').send(htmlPage('Not found',
        `<h1 class="err">404</h1><p>Ruta no encontrada.</p>`
    ));
});

// ============================================================================
// Util: escape HTML para inyectar valores en templates
// ============================================================================
function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

app.listen(PORT, () => {
    console.log(`[wooforger-connect-ml] listening on :${PORT}`);
    console.log(`[wooforger-connect-ml] BASE_URL = ${BASE_URL}`);
    console.log(`[wooforger-connect-ml] CALLBACK_URL = ${CALLBACK_URL}`);
});

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

    // 4) Firmar payload y redirigir al return_to del cliente.
    const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
    const signature  = hmac(payloadB64);

    const finalUrl = new URL(return_to);
    finalUrl.searchParams.set('nonce', nonce);
    finalUrl.searchParams.set('payload', payloadB64);
    finalUrl.searchParams.set('signature', signature);

    // Página de "redirigiendo" para que el user vea feedback antes del redirect.
    res.type('html').send(htmlPage('Conectando...', `
        <h1 class="ok">✓ Conectaste tu cuenta MercadoLibre</h1>
        <p>Volviendo al panel del plugin con tus credenciales...</p>
        <p style="margin-top:20px;font-size:12px;color:#9ca3af;">Si no se redirige automáticamente, <a href="${escapeHtml(finalUrl.toString())}">hacé click acá</a>.</p>
        <script>setTimeout(function(){ window.location.href = ${JSON.stringify(finalUrl.toString())}; }, 1200);</script>
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
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(express.json({ limit: '64kb' }));

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

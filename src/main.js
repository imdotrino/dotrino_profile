/**
 * dotrino-profile-app — perfil + calificación + validación de firma (web-of-trust).
 *
 * Modos según el #fragment (nunca llega al server, no indexable):
 *   #<pubkey>            → calificar al sujeto del link (mode="edit").
 *   #p=<pk>&name=&since= → idem, con datos extra.
 *   #v=<payload>         → VALIDAR: verifica la firma del contenido (ECDSA P-256)
 *                          y, en el mismo paso, muestra el perfil + reputación
 *                          del remitente (reviews) con opción de calificarlo.
 *   (sin hash)           → tu propio perfil (mode="self").
 *
 * Reutiliza @dotrino/identity + @dotrino/profile + @dotrino/reputation. La
 * verificación es client-side (solo necesita la clave PÚBLICA, que va en el link).
 */
import { Identity } from '@dotrino/identity'
import { avatarDataUri } from '@dotrino/identity/capabilities'
import { createVaultReputation, canonicalStringify } from '@dotrino/reputation'
import { createVaultProfileProvider } from '@dotrino/profile'
import '@dotrino/profile' // registra el custom element <dotrino-profile>
import '@dotrino/topbar'  // barra superior estándar (marca+volver+idioma+perfil+support)
import jsQR from 'jsqr' // lector de QR client-side (misma lib que dotrino-qrreader)
import { qrSvg } from './qr.js' // generador de QR como SVG (emparejamiento self-vault)
import { makeDeviceKey, signWithDevice } from '@dotrino/identity/capabilities'
import { keyLabel } from '@dotrino/identity/keyid'
import { verifySession, cleanSessionScopes } from '@dotrino/identity/session'
import { openSession, grantSession, denySession, closeSession, parseInvite, sessionCode } from '@dotrino/identity/session-flow'
import { WebSocketProxyClient, makeEncKeypair } from '@dotrino/proxy-client'

const mount = document.getElementById('app')
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
const showState = (title, html = '') =>
  (mount.innerHTML = `<div class="state">${title ? `<h1>${esc(title)}</h1>` : ''}${html}</div>`)

function b64urlDecode(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  try {
    return decodeURIComponent(atob(s).split('').map((c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join(''))
  } catch { return atob(s) }
}
// base64url del JSON: para el CÓDIGO COPIABLE (oculta iss/token/sn en texto plano,
// más corto). El QR usa el JSON crudo. El agente (CLI) acepta ambos formatos.
function b64urlEncode(str) {
  const b64 = btoa(String.fromCharCode(...new TextEncoder().encode(str)))
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/* ── verificación de firma — MISMO esquema que el vault (ECDSA P-256 + SHA-256
   sobre canonicalStringify, firma = base64 de r||s crudos). Solo clave pública. */
const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' }
const SIGN = { name: 'ECDSA', hash: { name: 'SHA-256' } }
const b64ToBuf = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer
async function verifySig(pubkeyStr, data, sigB64) {
  if (!pubkeyStr || !sigB64) return false
  try {
    const pub = await crypto.subtle.importKey('jwk', JSON.parse(pubkeyStr), ECDSA, true, ['verify'])
    return await crypto.subtle.verify(SIGN, pub, b64ToBuf(sigB64), new TextEncoder().encode(canonicalStringify(data)))
  } catch { return false }
}

// Enrutado: las VISTAS van por PATH — `/` (tu perfil), `/myvault` (tu bóveda),
// `/vault` (conectar a la bóveda del PC). El `#fragment` queda SOLO para datos que
// NO deben llegar al servidor (privacidad de Dotrino): `#v=` (validar firma),
// `#<pubkey>` (calificar) y `#vault=<token>` (token de emparejamiento, un secreto).
// Los enlaces legacy de vista (`#myvault`, `#vault`) se siguen aceptando y se migran
// a su path en `main()`. GitHub Pages sirve `404.html` (copia del index) para las
// rutas sin archivo, y la SPA enruta por `location.pathname`.
//
// `appBase()` = prefijo bajo el que se sirve la app (`/` en profile.dotrino.com, o
// `/<repo>/` en el mirror github.io) para que los enlaces funcionen en ambos.
function appBase () {
  let p = location.pathname.replace(/index\.html$/i, '').replace(/(myvault|vault|sessions)\/?$/i, '')
  if (!p.endsWith('/')) p += '/'
  return p
}
function viewUrl (view) { return appBase() + view } // view: '' | 'myvault' | 'vault' | 'sessions'

function parseRoute() {
  const h = location.hash.replace(/^#/, '').trim()
  // 1) DATOS en el #fragment (viajan sin tocar el servidor) — PRIORIDAD.
  if (h.startsWith('v=')) {
    try { return { mode: 'validate', payload: JSON.parse(b64urlDecode(h.slice(2))) } } catch { return { mode: 'invalid' } }
  }
  if (h.startsWith('vault=')) {
    try { return { mode: 'vault', qr: JSON.parse(b64urlDecode(h.slice(6))), token: true } } catch { return { mode: 'vault', token: true } }
  }
  // 2) VISTAS por PATH (o hash legacy #myvault/#vault → se migra al path en main()).
  const seg = location.pathname.replace(/\/+$/, '').split('/').pop().toLowerCase()
  if (seg === 'myvault' || h === 'myvault') return { mode: 'selfvault', legacy: h === 'myvault' }
  if (seg === 'vault' || h === 'vault') return { mode: 'vault', legacy: h === 'vault' }
  if (seg === 'create') return { mode: 'create' }
  if (seg === 'sessions' || h === 'sessions') return { mode: 'sessions', legacy: h === 'sessions' }
  // 3) CALIFICAR (#<pubkey> o #p=…) — dato público, se queda como hash.
  if (h) {
    if (h.includes('=')) {
      const q = new URLSearchParams(h)
      const p = q.get('p') || q.get('pubkey')
      if (!p) return { mode: 'invalid' }
      return { mode: 'rate', pubkey: b64urlDecode(p), name: q.get('name') ? b64urlDecode(q.get('name')) : '', since: q.get('since') || '' }
    }
    return { mode: 'rate', pubkey: b64urlDecode(h), name: '', since: '' }
  }
  // 4) Nada → tu perfil.
  return { mode: 'self' }
}

async function connectProvider() {
  const id = await Identity.connect()
  let reputation = null
  try { reputation = createVaultReputation(id) } catch { /* sin reputación: el perfil igual abre */ }
  return { id, provider: createVaultProfileProvider({ identity: id, reputation }) }
}

function makeProfile({ pubkey, name, since, mode, modal, manage }) {
  const el = document.createElement('dotrino-profile')
  if (modal) el.setAttribute('modal', '')
  if (manage) el.setAttribute('manage', '') // crear perfil habilitado SOLO aquí (profile.dotrino.com)
  el.setAttribute('mode', mode)
  el.setAttribute('lang', 'auto')
  el.setAttribute('pubkey', pubkey)
  if (name) el.setAttribute('name', name)
  if (since) el.setAttribute('since', since)
  el.addEventListener('cc-profile-close', () => { window.location.href = 'https://dotrino.com' })
  return el
}

/* ── Conectar este dispositivo a la bóveda del usuario (dotrino-vault) — #vault ── */
function injectVaultStyles () {
  if (document.getElementById('vault-css')) return
  const s = document.createElement('style'); s.id = 'vault-css'
  s.textContent = `
    .vault-wrap { max-width: 560px; margin: 0 auto; text-align: left; }
    .vault-wrap textarea { width: 100%; box-sizing: border-box; font-family: ui-monospace, monospace; font-size: 13px; padding: 10px; border: 1px solid #ccc; border-radius: 8px; resize: vertical; }
    .vault-wrap .btn { display: inline-block; margin-top: 12px; padding: 10px 18px; border: 0; border-radius: 999px; background: #1a73e8; color: #fff; font-size: 15px; cursor: pointer; }
    .vault-wrap .btn[disabled] { opacity: .5; cursor: default; }
    .vault-wrap .btn.danger { background: #d93025; }
    .vault-wrap .banner { margin: 14px 0; padding: 10px 14px; border-radius: 8px; background: #eef2ff; }
    .vault-wrap .banner.ok { background: #e6f4ea; color: #137333; }
    .vault-wrap .banner.bad { background: #fce8e6; color: #c5221f; }
    .vault-wrap .sas-box { margin: 16px 0; padding: 16px; border: 2px solid #1a73e8; border-radius: 12px; text-align: center; }
    .vault-wrap .sas-box .sas { font-size: 40px; letter-spacing: 8px; font-weight: 700; font-family: ui-monospace, monospace; margin: 8px 0; }
    .vault-wrap .muted { color: #777; font-size: 13px; }
    .vault-wrap .vault-info { list-style: none; padding: 0; }
    .vault-wrap .vault-info li { padding: 4px 0; }
    .vault-wrap .btn.ghost { background: #eef2ff; color: #1a73e8; }
    .vault-wrap .scanrow { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .vault-wrap .scanbox video { width: 100%; max-width: 360px; border-radius: 10px; background: #000; display: block; margin: 8px 0; }
    .vault-wrap details > summary { cursor: pointer; margin-top: 10px; color: #777; }
    /* Barra superior estándar del ecosistema: <dotrino-topbar> (@dotrino/topbar),
       tematizada en CLARO para esta página. La marca a medida va por slot. */
    #app:has(.vault-page) { padding: 0; align-items: stretch; }
    .vault-page { width: 100%; min-height: 100vh; display: flex; flex-direction: column; }
    .vault-topbar {
      position: sticky; top: 0; z-index: 50;
      --dotrino-topbar-bg: #fff; --dotrino-topbar-border: #e3e9ed;
      --dotrino-topbar-text: #181c1e; --dotrino-topbar-muted: #4a5560;
      --dotrino-topbar-accent: #00658c;
    }
    .vault-page .brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
    .vault-page .brand-logo { width: 36px; height: 36px; border-radius: 9px; }
    .vault-page .brand-text { display: flex; flex-direction: column; line-height: 1.1; min-width: 0; }
    .vault-page .brand-name { font-weight: 700; font-size: 1.15rem; color: #181c1e; }
    .vault-page .brand-tag { font-size: .72rem; color: #4a5560; }
    .vault-page .vault-main { flex: 1; display: flex; align-items: flex-start; justify-content: center; padding: 1.2rem 1rem; }
    .vault-page .vault-card { max-width: 560px; width: 100%; text-align: left; }
    .vault-page .vault-card h1 { font-size: 1.3rem; color: #181c1e; margin: 0 0 1rem; }
    /* Sección de PIN (inline en la página, no popup) */
    .pin-box { margin-top: 1.2rem; padding: 1rem 1.1rem; border: 1px solid #e3e9ed; border-radius: 14px; background: #fff; }
    .pin-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
    .pin-title { font-weight: 700; color: #181c1e; }
    .pin-box .btn { display: inline-flex; align-items: center; padding: 9px 14px; border: 0; border-radius: 999px; background: #1a73e8; color: #fff; font-size: 14px; cursor: pointer; }
    .pin-box .btn.ghost { background: #eef2ff; color: #1a73e8; }
    .pin-box .btn.danger { background: #d93025; color: #fff; }
    .pin-box .btn[disabled] { opacity: .5; cursor: default; }
    .pf-nameform, .pf-confirm { display: flex; gap: 8px; align-items: center; margin-top: 12px; flex-wrap: wrap; }
    .pf-nameform input { flex: 1 1 auto; padding: 9px 11px; border: 1px solid #cfd8de; border-radius: 8px; font-size: 14px; }
    .pf-confirm span { flex: 1 1 100%; font-size: .85rem; color: #b3261e; }
    /* ── /create: crear un perfil ── */
    .cp-field { display: flex; flex-direction: column; gap: 4px; margin: 14px 0; }
    .cp-field span { font-weight: 600; font-size: 14px; }
    .cp-field input { padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border, #d4c4a8); background: var(--bg-1, #fff); color: inherit; font: inherit; }
    .cp-field small { font-size: 12px; }
    .cp-more { margin: 18px 0; }
    .cp-more summary { cursor: pointer; font-weight: 600; }
    .cp-more > p { margin: 8px 0 4px; font-size: 13px; }

    /* ── Self-vault (#myvault): este dispositivo ES la bóveda ── */
    .sv-status { display: inline-block; margin: 4px 0 12px; font-size: .82rem; color: #137333; }
    .sv-status.bad { color: #b3261e; }
    .sv-block { margin: 14px 0; }
    .sv-setup { background: #f4f7f9; border: 1px solid #e3e9ed; border-radius: 12px; padding: 14px; }
    .sv-setup pre, .sv-qr-code pre { background: #0e1116; color: #7dd3fc; padding: 10px; border-radius: 8px; overflow-x: auto; font-size: .78rem; word-break: break-all; margin: 8px 0; }
    .sv-qr-wrap { background: #fff; padding: 10px; border-radius: 10px; display: inline-block; margin: 8px 0; border: 1px solid #e3e9ed; }
    .sv-qr-wrap svg { width: 200px; height: 200px; display: block; }
    .sv-pending { margin-top: 12px; padding-top: 12px; border-top: 1px dashed #cfd8de; }
    .sv-pair-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .sv-code-input { flex: 1 1 120px; background: #fff; color: #181c1e; border: 1px solid #cfd8de; border-radius: 10px; padding: 10px 12px; font-size: 1.1rem; letter-spacing: 2px; }
    .sv-machine-list { display: flex; flex-direction: column; gap: 8px; margin-top: 8px; }
    .sv-machine-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; background: #f4f7f9; border: 1px solid #e3e9ed; border-radius: 10px; padding: 10px 14px; }
    .sv-machine-name { word-break: break-all; display: inline-flex; align-items: center; gap: 8px; }
    .sv-mdot { width: 9px; height: 9px; border-radius: 50%; background: #cfd8de; display: inline-block; flex: none; }
    .sv-mdot.on { background: #34a853; } .sv-mdot.off { background: #ea4335; }
    .sv-link-row { margin-top: 14px; }
    .sv-link-row a { color: #00658c; font-weight: 600; text-decoration: none; }
    .sv-toggle-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin: 10px 0; padding: 12px 14px; border: 1px solid #e3e9ed; border-radius: 12px; background: #fff; }`
  document.head.appendChild(s)
}

async function vaultFingerprint (jwkStr) {
  try {
    const jwk = JSON.parse(jwkStr)
    const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalStringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })))
    return [...new Uint8Array(h)].slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('')
  } catch { return '????????' }
}

// Extrae el objeto de emparejamiento de un texto: URL profile.dotrino.com/#vault=… o JSON crudo.
function extractPayload (text) {
  if (!text) return null
  text = String(text).trim()
  const i = text.indexOf('#vault=')
  if (i >= 0) { try { return JSON.parse(b64urlDecode(text.slice(i + 7))) } catch { return null } }
  try { const o = JSON.parse(text); return (o && o.iss && o.token) ? o : null } catch { return null }
}

// Decodifica un QR desde una imagen (archivo). Devuelve el texto o null.
function decodeQrFromImage (file) {
  return new Promise((resolve) => {
    const img = new Image()
    img.onload = () => {
      const c = document.createElement('canvas'); c.width = img.naturalWidth; c.height = img.naturalHeight
      try { const ctx = c.getContext('2d'); ctx.drawImage(img, 0, 0); const d = ctx.getImageData(0, 0, c.width, c.height); resolve(jsQR(d.data, d.width, d.height)?.data || null) }
      catch { resolve(null) }
      URL.revokeObjectURL(img.src)
    }
    img.onerror = () => resolve(null)
    img.src = URL.createObjectURL(file)
  })
}

// Escáner con cámara: muestra el video en `host`, devuelve el texto del QR (o null si cancelan/falla).
function scanWithCamera (host) {
  return new Promise((resolve) => {
    let stream = null, raf = null, done = false
    const stop = (val) => { if (done) return; done = true; if (raf) cancelAnimationFrame(raf); if (stream) stream.getTracks().forEach(t => t.stop()); host.innerHTML = ''; resolve(val) }
    host.innerHTML = `<div class="scanbox"><video playsinline muted></video><div><button id="scancancel" class="btn ghost">${esc(svt('cancel'))}</button></div></div>`
    const video = host.querySelector('video')
    host.querySelector('#scancancel').onclick = () => stop(null)
    const c = document.createElement('canvas'); const ctx = c.getContext('2d')
    const tick = () => {
      if (done) return
      if (video.readyState >= 2 && video.videoWidth) {
        c.width = video.videoWidth; c.height = video.videoHeight; ctx.drawImage(video, 0, 0, c.width, c.height)
        try { const d = ctx.getImageData(0, 0, c.width, c.height); const r = jsQR(d.data, d.width, d.height); if (r?.data) return stop(r.data) } catch {}
      }
      raf = requestAnimationFrame(tick)
    }
    navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
      .then((s) => { stream = s; video.srcObject = s; return video.play().catch(() => {}) })
      .then(() => { raf = requestAnimationFrame(tick) })
      .catch(() => { host.innerHTML = `<div class="banner bad">${esc(svt('cam_err'))}</div>`; resolve(null) })
  })
}

function vaultShell (title, inner, tag = svt('tag_identity')) {
  mount.innerHTML = `<div class="vault-page">
    <dotrino-topbar class="vault-topbar" brand-href="https://dotrino.com/"
      support-repo="imdotrino/dotrino-profile-app" support-discord="https://discord.gg/D648uq7cth" profile>
      <div slot="brand" class="brand"><img class="brand-logo" src="/images/imagoWBG.png" alt="" /><div class="brand-text"><span class="brand-name">Dotrino</span><span class="brand-tag">${esc(tag)}</span></div></div>
    </dotrino-topbar>
    <main class="vault-main"><div class="vault-card">${title ? `<h1>${esc(title)}</h1>` : ''}${inner}</div></main>
  </div>`
  decorateProfileButton()
}

/**
 * El botón de perfil del topbar (§6.1) se comporta IGUAL que en el resto del ecosistema:
 * abre el modal «Mi perfil», y al pasar el ratón ofrece el cambio rápido de perfil.
 *
 * Antes, aquí y solo aquí, navegaba a `/` con el argumento de que esta app es el hub de
 * identidad y el modal sería redundante. Era un error: el mismo botón, en el mismo sitio,
 * haciendo algo distinto según la página es justo lo que hace que una interfaz no se pueda
 * aprender. Que sobre información en esta página no justifica cambiarle el gesto.
 */
async function decorateProfileButton () {
  const tb = mount.querySelector('dotrino-topbar'); if (!tb) return
  try {
    const id = await Identity.connect()
    // Con identity + reputation, el topbar es dueño del modal y lo abre él mismo.
    tb.identity = id
    tb.reputation = createVaultReputation(id)
  } catch (_) { /* sin identidad, el botón queda con el ícono genérico */ }
}

// Sección de PIN INLINE en la página (NO en popup). El PIN protege el perfil
// activo SOLO en este dispositivo. Cambiar/crear/renombrar perfil lo hace el
// componente <dotrino-profile mode="self" manage> (switcher integrado); aquí solo
// va lo que es exclusivo de esta página: el candado por PIN.
async function renderPinSection (host) {
  let id
  try { id = await Identity.connect() } catch { return }
  const lock = await id.profileLockStatus?.().catch(() => null) || { protected: false }
  host.innerHTML = `
    <div class="pin-box">
      <div class="pin-row">
        <span class="pin-title">${svt('pin_title')}</span>
        <button class="btn ghost" id="pin-toggle">${lock.protected ? svt('pin_remove') : svt('pin_protect')}</button>
      </div>
      <p class="muted" style="font-size:12.5px;margin:6px 0 0">${svt('pin_desc')}</p>
      <div id="pf-form"></div>
    </div>`
  host.querySelector('#pin-toggle').onclick = () => {
    if (lock.protected) {
      confirmDelete(host, null, async () => { await id.removeProfilePassword(); location.reload() },
        svt('pin_remove_q'), svt('pin_remove'))
    } else {
      pinForm(host, async (pin) => { await id.setProfilePassword(pin); location.reload() })
    }
  }
}

// Formulario inline de PIN (candado local): pide el PIN dos veces.
function pinForm (overlay, onSubmit) {
  const host = overlay.querySelector('#pf-form')
  host.innerHTML = `<div class="pf-nameform" style="flex-wrap:wrap">
    <input id="pf-pin1" type="password" inputmode="numeric" maxlength="64" placeholder="${esc(svt('pin_ph1'))}" />
    <input id="pf-pin2" type="password" inputmode="numeric" maxlength="64" placeholder="${esc(svt('pin_ph2'))}" />
    <button class="btn" id="pf-pingo">${svt('pin_go')}</button>
    <span class="muted" id="pf-pinerr" style="flex-basis:100%"></span></div>`
  const p1 = host.querySelector('#pf-pin1'); const p2 = host.querySelector('#pf-pin2')
  const err = host.querySelector('#pf-pinerr'); p1.focus()
  const go = async () => {
    err.textContent = ''
    if (p1.value.length < 4) { err.textContent = svt('pin_min'); return }
    if (p1.value !== p2.value) { err.textContent = svt('pin_mismatch'); return }
    host.querySelector('#pf-pingo').disabled = true
    try { await onSubmit(p1.value) } catch (e) { err.textContent = e.message; host.querySelector('#pf-pingo').disabled = false }
  }
  host.querySelector('#pf-pingo').onclick = go
  p2.onkeydown = (e) => { if (e.key === 'Enter') go() }
}

// Confirmación inline de borrado (sin confirm() del navegador).
function confirmDelete (overlay, btn, onYes, msg = svt('del_msg'), yes = svt('del_yes')) {
  const host = overlay.querySelector('#pf-form')
  host.innerHTML = `<div class="pf-confirm"><span>${esc(msg)}</span><button class="btn danger" id="pf-yes">${esc(yes)}</button><button class="btn ghost" id="pf-no">${esc(svt('cancel'))}</button></div>`
  host.querySelector('#pf-no').onclick = () => { host.innerHTML = '' }
  host.querySelector('#pf-yes').onclick = async () => { host.querySelector('#pf-yes').disabled = true; await onYes() }
}

async function vaultMode (prefillQr) {
  injectVaultStyles()
  let id
  try { id = await Identity.connect() } catch {
    showState(svt('v_title'), `<p>${svt('v_connect_err')}</p>`); return
  }
  // Si venimos de elegir/crear un perfil para esta bóveda (se cambió de perfil y la página
  // recargó), retomamos el emparejamiento con el perfil ya activo, sin volver a preguntar.
  let intentQr = null
  try { const r = sessionStorage.getItem('cc-pair-intent'); if (r) { sessionStorage.removeItem('cc-pair-intent'); intentQr = JSON.parse(r) } } catch (_) {}
  const status = intentQr ? { paired: false } : await id.vaultStatus().catch(() => ({ paired: false }))
  // Cert de dispositivo VENCIDO = ya no estás conectado (el vault rechaza todo con
  // "unauthorized"): tratarlo como no emparejado, con aviso, y ofrecer re-conectar.
  const expired = status.paired && status.exp && status.exp <= Date.now()

  if (status.paired && !expired) {
    const fp = await vaultFingerprint(status.master)
    vaultShell(svt('v_title'), `<div class="vault-wrap">
      <div class="banner ok">${svt('v_connected_ok')}</div>
      <ul class="vault-info">
        <li>${svt('v_device')}: <code>${esc(status.deviceId)}</code></li>
        <li>${svt('v_vault_fp')}: <code>${esc(fp)}</code></li>
        <li>${svt('v_scope')}: <code>${esc((status.scope || []).join(', '))}</code></li>
        ${status.exp ? `<li>${svt('v_valid_until')}: <code>${esc(new Date(status.exp).toLocaleString())}</code></li>` : ''}
      </ul>
      <h2 style="font-size:16px;margin:18px 0 6px">${svt('v_your_devices')}</h2>
      <div id="devlist" class="muted">${svt('loading')}</div>
    </div>`)
    wireLangReload()
    // Lista (solo lectura) de dispositivos enrolados; desconectar/revocar es desde el PC.
    id.listVaultDevices().then(({ devices }) => {
      const box = document.getElementById('devlist'); if (!box) return
      if (!devices?.length) { box.textContent = '—'; return }
      box.innerHTML = '<ul class="vault-info">' + devices.map((d) => {
        const me = d.deviceId === status.deviceId ? ` <strong>${svt('v_this')}</strong>` : ''
        const exp = d.exp ? ' · ' + svt('v_expires') + ' ' + new Date(d.exp).toLocaleDateString() : ''
        return `<li>· <code>${esc(d.deviceId || '????')}</code>${me} ${esc(d.label || '')}<span class="muted">${esc(exp)}</span></li>`
      }).join('') + '</ul>'
    }).catch((e) => {
      const box = document.getElementById('devlist'); if (!box) return
      // Distinguir "unauthorized" (cert rechazado/revocado) de "vault apagado". El texto
      // es el que manda la bóveda —el daemon del PC y el iframe dicen el mismo desde
      // @dotrino/vault 0.24.0—, así que si algún día vuelve a cambiar, esto va detrás.
      box.textContent = /unauthorized/i.test(e?.message || '')
        ? svt('v_dev_rejected', e.message)
        : svt('v_dev_load_err')
    })
    return
  }

  vaultShell(svt('v_connect_title'), `<div class="vault-wrap">
    ${expired ? `<div class="banner bad">${svt('v_expired', esc(new Date(status.exp).toLocaleDateString()))}</div>` : ''}
    <p>${svt('v_intro')}</p>
    <div class="scanrow">
      <button id="scan" class="btn">${svt('v_scan')}</button>
      <button id="openfile" class="btn ghost">${svt('v_openfile')}</button>
    </div>
    <input id="fileinput" type="file" accept="image/*,.dpair,.json,text/plain" style="display:none">
    <div id="scanarea"></div>
    <details><summary>${svt('v_paste_toggle')}</summary>
      <textarea id="qr" rows="3" placeholder='{"v":2,"iss":"…","proxy":"…","token":"…","sn":"…"}'></textarea>
      <div><button id="connect" class="btn ghost">${svt('v_connect_pasted')}</button></div>
    </details>
    <div id="vmsg"></div>
  </div>`)
  wireLangReload()

  const msg = () => document.getElementById('vmsg')
  async function doConnect (qr, skip) {
    if (!qr || !qr.iss || !qr.token) { msg().innerHTML = `<div class="banner bad">${svt('v_bad_code')}</div>`; return }
    if (!qr.sn || (qr.v && qr.v < 2)) { msg().innerHTML = `<div class="banner bad">${svt('v_old_code')}</div>`; return }
    // Ya no se elige «con qué perfil conectar esta bóveda»: esa pregunta era del modelo
    // viejo, en el que enganchar la bóveda a una cuenta existente la reemplazaba por la
    // suya. Hoy hay un solo camino disponible (§3 de `vinculacion-de-cuentas.md`): la
    // cuenta de la bóveda entra aquí como una cuenta MÁS, con llave nueva, y la que
    // estabas usando no se toca. Se avisa antes, no después.
    if (!skip) {
      msg().innerHTML = `<div class="sas-box" style="text-align:left">
        <p><strong>${svt('v_new_account_q')}</strong></p>
        <p class="muted">${svt('v_new_account_d')}</p>
        <button class="btn" id="pick-go">${svt('v_new_account_go')}</button>
      </div>`
      msg().querySelector('#pick-go').onclick = () => doConnect(qr, true)
      return
    }
    msg().innerHTML = `<div class="banner">${svt('v_connecting')}</div>`
    const off = id.onVault((e) => {
      if (e.phase === 'challenge') {
        msg().innerHTML = `<div class="sas-box">
          <p>${svt('v_challenge_q')}</p>
          <div class="sas">${esc(e.code)}</div>
          <p class="muted">${svt('v_challenge_d')}</p>
          <p><code>dotrino-vault approve ${esc(e.code)}</code></p>
          <p class="muted">${svt('v_challenge_wait')}</p></div>`
      }
    })
    try {
      // Camino B: la cuenta de la bóveda entra aquí como una cuenta MÁS (llave nueva).
      // La que estabas usando no se toca. Ver `vinculacion-de-cuentas.md` §3.
      await id.enrollDevice(qr, { join: 'new' }); off()
      msg().innerHTML = `<div class="banner ok">${svt('v_connected_done')}</div>
        <div class="banner"><strong>${svt('v_two_title')}</strong><p>${svt('v_two_body')}</p></div>`
      setTimeout(() => vaultMode(), 1600)
    } catch (e) {
      off()
      // Esa bóveda ya vive en OTRA cuenta de este aparato: no se duplica, se te lleva a
      // ella. Por `code` y no por el texto del error (que se traduce y cambia).
      if (e?.code === 'ALREADY_PAIRED') {
        const otra = e.detail?.profile
        msg().innerHTML = `<div class="banner">${svt('v_already_paired', esc(e.detail?.name || ''))}</div>
          <div><button class="btn" id="go-other">${svt('v_already_paired_go')}</button></div>`
        msg().querySelector('#go-other').onclick = async () => {
          // Cambiar de cuenta no es reactivo (por diseño): se recarga para entrar con ella.
          try { await id.switchProfile(otra); location.reload() }
          catch (err) { msg().innerHTML = `<div class="banner bad">${svt('v_connect_fail', esc(err.message))}</div>` }
        }
        return
      }
      msg().innerHTML = `<div class="banner bad">${svt('v_connect_fail', esc(e.message))}</div>`
    }
  }

  document.getElementById('connect').onclick = () => {
    try { doConnect(JSON.parse(document.getElementById('qr').value.trim())) }
    catch { msg().innerHTML = `<div class="banner bad">${svt('v_pasted_invalid')}</div>` }
  }
  document.getElementById('scan').onclick = async () => {
    const text = await scanWithCamera(document.getElementById('scanarea'))
    if (text) doConnect(extractPayload(text))
  }
  document.getElementById('openfile').onclick = () => document.getElementById('fileinput').click()
  document.getElementById('fileinput').onchange = async (ev) => {
    const f = ev.target.files?.[0]; if (!f) return
    let text
    if (/^image\//.test(f.type)) { text = await decodeQrFromImage(f); if (!text) { msg().innerHTML = `<div class="banner bad">${svt('v_no_qr_img')}</div>`; return } }
    else { text = await f.text() }
    doConnect(extractPayload(text))
  }

  // Retomar tras elegir perfil (intent) → emparejar directo. Si el QR vino en la URL, mostrar el selector.
  if (intentQr) doConnect(intentQr, true)
  else if (prefillQr) doConnect(prefillQr)
}

/* ── #myvault: ESTE dispositivo actúa como su propia bóveda (modo self) ──
   El daemon device-vault vive dentro del iframe de identidad (no requiere el
   binario del PC). Aquí lo activas, generas códigos de emparejamiento para
   enlazar agentes (ia, terminal), apruebas con SAS y listas/revocas máquinas —
   todo por RPC al iframe vía @dotrino/identity. */
let _svPresenceTimer = null
const svEl = (h) => { const tp = document.createElement('template'); tp.innerHTML = h.trim(); return tp.content.firstElementChild }

// i18n de TODA la app (es/en). El toggle del topbar emite 'dotrino-lang'; al cambiar,
// persistimos en 'dotrino.lang' (clave estándar del ecosistema, la misma que usa el
// topbar y el resto de apps) y recargamos para servir toda la página en el idioma elegido.
let svLang = (() => { try { const s = localStorage.getItem('dotrino.lang'); if (s === 'en' || s === 'es') return s } catch {} return ((navigator.language || '').slice(0, 2) === 'en') ? 'en' : 'es' })()
try { document.documentElement.lang = svLang } catch {}
const SV_I18N = {
  es: {
    h: 'Mi bóveda', loading: 'Cargando…',
    need_id: 'Necesitas una identidad primero. Créala en la sección', need_id_link: 'Tu perfil',
    back: (h) => `← Volver a ${h}`,
    intro_off: 'Activa este dispositivo como tu bóveda para enlazar agentes (ia, terminal) que firmen en tu nombre sin exponer tu llave maestra. La llave nunca sale de este navegador.',
    state_off: 'Estado: desactivado', enable: 'Activar como bóveda',
    running: 'Bóveda activa en este dispositivo', not_running: 'Bóveda activa (dormida en esta pestaña — ábrela a la vista para que responda)',
    disable: 'Desactivar', pair_new: 'Generar código de emparejamiento',
    pair_step1: 'Pega este código en el agente (ia/terminal) que quieres enlazar:',
    pair_step2: 'El agente pedirá aprobación con un código que TIPEAS aquí.',
    pair_wait: '⏳ Esperando a que pida acceso…', copy: 'Copiar código', copied: 'Copiado', cancel: 'Cancelar',
    pending: (d) => `La máquina ${d} pide acceso. Tipea el código que muestra:`,
    code_ph: 'código', approve: 'Aprobar', reject: 'Rechazar',
    machines_title: 'Máquinas enlazadas', machines_none: 'Aún no hay máquinas enlazadas.',
    checking: 'comprobando…', online: 'en línea', offline: 'desconectado', revoke: 'Revocar',
    self_link_desc: 'Convierte este dispositivo en tu bóveda para enlazar agentes (ia, terminal) que firmen en tu nombre.',
    self_link: 'Mi bóveda →',
    // --- Conectar a la bóveda del PC (#vault) ---
    v_title: 'Tu bóveda',
    v_connect_err: 'No se pudo conectar tu identidad. Recarga e inténtalo de nuevo.',
    v_connected_ok: '✓ Este dispositivo está conectado a tu bóveda.',
    v_device: 'Dispositivo',
    v_vault_fp: 'Bóveda (identificador corto)',
    v_scope: 'Permisos',
    v_valid_until: 'Conexión válida hasta',
    v_your_devices: 'Tus dispositivos',
    v_this: '(este)',
    v_expires: 'expira',
    v_dev_rejected: (m) => 'El vault rechazó este dispositivo (' + m + '). Vuelve a conectarlo con `dotrino-vault pair`.',
    v_dev_load_err: 'No se pudo cargar (¿el vault está encendido?).',
    v_connect_title: 'Conectar a tu bóveda',
    v_expired: (d) => `Tu conexión con la bóveda <strong>venció</strong> (${d}). Vuelve a conectar este dispositivo.`,
    v_intro: 'Conecta este navegador a tu <strong>bóveda</strong> (el programa <code>dotrino-vault</code> en tu PC), para que tu información viva en tu propio servidor. En tu PC ejecuta <code>dotrino-vault pair</code> y <strong>escanea el QR</strong>, abre su imagen/archivo, o pega el código:',
    v_scan: '📷 Escanear QR',
    v_openfile: '📁 Abrir imagen/archivo',
    v_paste_toggle: '…o pegar el código a mano',
    v_connect_pasted: 'Conectar con el código pegado',
    v_bad_code: 'No reconocí un código de emparejamiento válido. Vuelve a generar el QR con <code>dotrino-vault pair</code>.',
    v_old_code: 'Este código es de una <strong>versión vieja</strong> del vault. Actualiza a la última y reinicia el servicio (<code>systemctl --user restart dotrino-vault</code>), confirma con <code>dotrino-vault status</code>, y genera un código nuevo con <code>dotrino-vault pair</code>.',
    v_new_account_q: 'Se creará aquí una cuenta nueva: la de tu bóveda.',
    v_new_account_d: 'La cuenta que estás usando ahora no se toca. Al terminar tendrás dos en este aparato y podrás cambiar entre ellas desde el botón de tu foto.',
    v_new_account_go: 'Entendido, conectar',
    v_two_title: 'Ahora tienes dos cuentas en este aparato',
    v_two_body: 'La que ya usabas sigue intacta. Si no quieres conservarla, ábrela en «Tus perfiles» (aquí abajo) y pulsa Borrar: se va con todo lo suyo y no se puede deshacer.',
    v_connecting: 'Conectando…',
    v_challenge_q: 'Tu <strong>código de emparejamiento</strong>:',
    v_challenge_d: 'Ingrésalo en tu PC para conectar este dispositivo (el vault no lo conoce hasta que tú se lo des):',
    v_challenge_wait: 'Esperando que lo apruebes en el PC…',
    v_connected_done: '✓ ¡Conectado! Este dispositivo ahora usa tu bóveda.',
    v_connect_fail: (m) => `No se pudo conectar: ${m}`,
    v_already_paired: (n) => `Esa bóveda ya está en este dispositivo, en la cuenta <strong>${n || 'sin nombre'}</strong>. No hace falta conectarla otra vez: entra con esa cuenta.`,
    v_already_paired_go: 'Entrar con esa cuenta',
    v_pasted_invalid: 'Ese código pegado no es válido.',
    v_no_qr_img: 'No encontré un QR en esa imagen.',
    // --- Cámara / escáner ---
    cam_err: 'No se pudo abrir la cámara. Prueba «Abrir imagen/archivo» o pega el código.',
    // --- Validar firma (#v=) ---
    val_ok: '✓ Firma válida',
    val_ok_by: (n) => ` — firmado por <strong>${n}</strong>`,
    val_bad: '✗ Firma inválida o no verificable',
    // --- Estados de error ---
    err_invalid_title: 'Link inválido',
    err_invalid_body: 'Este enlace no es válido.',
    err_noid_title: 'No se pudo conectar tu identidad',
    err_noid_body: 'Esto requiere tu identidad de Dotrino. Recarga e inténtalo de nuevo.',
    // --- Perfil propio + PIN ---
    tag_identity: 'Tu identidad',
    tag_profiles: 'Perfiles',
    prof_title: 'Tu perfil',
    pin_title: '🔒 Protección con PIN',
    pin_remove: 'Quitar el PIN',
    pin_protect: 'Proteger con PIN',
    pin_desc: 'Protege el perfil activo <strong>solo en este dispositivo</strong> (no se comparte ni se sincroniza). Se pide una vez por pestaña; refrescar no lo vuelve a pedir.',
    pin_remove_q: '¿Quitar el PIN de este perfil en este dispositivo?',
    pin_ph1: 'PIN (mín. 4)',
    pin_ph2: 'Repite el PIN',
    pin_go: 'Proteger',
    pin_min: 'Mínimo 4 caracteres.',
    pin_mismatch: 'No coinciden.',
    del_msg: '¿Borrar este perfil y todos sus datos? No se puede deshacer.',
    del_yes: 'Borrar',
    // --- Entrar en otro navegador (sesiones) ---
    tag_sessions: 'Entrar',
    ses_title: 'Entrar en otro navegador',
    ses_desc: 'Para usar tus aplicaciones en un equipo prestado sin dejarlo enlazado: ese equipo te enseña un código, tú lo lees aquí, y entra por un rato. Cuando vence, se acabó — y si quitas este dispositivo, se van todas las que diste.',
    ses_open: 'Entrar en ESTE navegador',
    ses_open_desc: 'Genera un código para que lo leas desde el teléfono donde ya tienes tu cuenta.',
    ses_grant: 'Dar acceso a otro equipo',
    ses_grant_desc: 'Lee el código que muestra el otro equipo y déjalo entrar.',
    ses_waiting: 'Esperando a que alguien lo apruebe…',
    ses_code: 'Código',
    ses_code_hint: 'Comprueba que el otro equipo muestra este mismo código antes de aprobar.',
    ses_in: (n) => `Entraste como <strong>${n}</strong>`,
    ses_until: (d) => `Hasta ${d}`,
    ses_paste: 'O pega aquí el código del otro equipo',
    ses_read: 'Leer',
    ses_asks: (o) => `<strong>${o}</strong> quiere entrar`,
    ses_scopes: 'Podrá',
    ses_scope_whoami: 'saber quién eres',
    ses_scope_store: 'leer y escribir tus datos',
    ses_allow: 'Permitir',
    ses_deny: 'No',
    ses_given: 'Sesiones que diste',
    ses_none: 'Ninguna.',
    ses_close: 'Cerrar',
    ses_closed: 'Cerrada.',
    ses_denied: 'No se concedió.',
    ses_timeout: 'Nadie la aprobó a tiempo.',
    ses_err: 'No se pudo abrir la sesión.',
    ses_mine: 'Tu sesión en este navegador',
    ses_leave: 'Salir',
    ses_copy: 'Sin cámara: copia este texto y pégalo en el otro equipo',
    ses_desc_short: 'Usa tus aplicaciones en un equipo prestado, por un rato y sin dejarlo enlazado.',
    gr_title: 'Lo que ven tus aplicaciones',
    gr_desc: 'Saber quién eres no hace falta permitirlo. Tus datos, sí — y aquí se retiran.',
    gr_none: 'Ninguna aplicación tiene tus datos.',
    gr_revoke: 'Retirar',
    gr_revoked: 'Retirado.',
    gr_name: 'tu nombre', gr_avatar: 'tu foto', gr_email: 'tu correo', gr_links: 'tus enlaces',
    gr_via: 'a través de',
    gr_last: (d) => `Última vez: ${d}`,
  },
  en: {
    h: 'My vault', loading: 'Loading…',
    need_id: 'You need an identity first. Create one at', need_id_link: 'Your profile',
    back: (h) => `← Back to ${h}`,
    intro_off: 'Enable this device as your vault to link agents (ia, terminal) that sign on your behalf without exposing your master key. The key never leaves this browser.',
    state_off: 'Status: off', enable: 'Enable as vault',
    running: 'Vault active on this device', not_running: 'Vault active (asleep in this tab — bring it into view so it can answer)',
    disable: 'Disable', pair_new: 'Generate pairing code',
    pair_step1: 'Paste this code in the agent (ia/terminal) you want to link:',
    pair_step2: 'The agent will ask for approval with a code you TYPE here.',
    pair_wait: '⏳ Waiting for it to request access…', copy: 'Copy code', copied: 'Copied', cancel: 'Cancel',
    pending: (d) => `Machine ${d} requests access. Type the code it shows:`,
    code_ph: 'code', approve: 'Approve', reject: 'Reject',
    machines_title: 'Linked machines', machines_none: 'No machines linked yet.',
    checking: 'checking…', online: 'online', offline: 'offline', revoke: 'Revoke',
    self_link_desc: 'Turn this device into your vault to link agents (ia, terminal) that sign on your behalf.',
    self_link: 'My vault →',
    // --- Connect to the PC vault (#vault) ---
    v_title: 'Your vault',
    v_connect_err: 'Could not connect your identity. Reload and try again.',
    v_connected_ok: '✓ This device is connected to your vault.',
    v_device: 'Device',
    v_vault_fp: 'Vault (short ID)',
    v_scope: 'Permissions',
    v_valid_until: 'Connection valid until',
    v_your_devices: 'Your devices',
    v_this: '(this one)',
    v_expires: 'expires',
    v_dev_rejected: (m) => 'The vault rejected this device (' + m + '). Reconnect it with `dotrino-vault pair`.',
    v_dev_load_err: 'Could not load (is the vault on?).',
    v_connect_title: 'Connect to your vault',
    v_expired: (d) => `Your vault connection <strong>expired</strong> (${d}). Connect this device again.`,
    v_intro: 'Connect this browser to your <strong>vault</strong> (the <code>dotrino-vault</code> program on your PC), so your information lives on your own server. On your PC run <code>dotrino-vault pair</code> and <strong>scan the QR</strong>, open its image/file, or paste the code:',
    v_scan: '📷 Scan QR',
    v_openfile: '📁 Open image/file',
    v_paste_toggle: '…or paste the code by hand',
    v_connect_pasted: 'Connect with the pasted code',
    v_bad_code: 'I did not recognize a valid pairing code. Generate the QR again with <code>dotrino-vault pair</code>.',
    v_old_code: 'This code is from an <strong>old version</strong> of the vault. Update to the latest and restart the service (<code>systemctl --user restart dotrino-vault</code>), confirm with <code>dotrino-vault status</code>, and generate a new code with <code>dotrino-vault pair</code>.',
    v_new_account_q: 'A new account will be created here: your vault\'s.',
    v_new_account_d: 'The account you are using now is left untouched. When it is done you will have two on this device and can switch between them from your photo button.',
    v_new_account_go: 'Got it, connect',
    v_two_title: 'You now have two accounts on this device',
    v_two_body: 'The one you were using is untouched. If you do not want to keep it, open it under “Your profiles” (below) and press Delete: it goes with everything in it and cannot be undone.',
    v_connecting: 'Connecting…',
    v_challenge_q: 'Your <strong>pairing code</strong>:',
    v_challenge_d: 'Enter it on your PC to connect this device (the vault does not know it until you give it to it):',
    v_challenge_wait: 'Waiting for you to approve it on the PC…',
    v_connected_done: '✓ Connected! This device now uses your vault.',
    v_connect_fail: (m) => `Could not connect: ${m}`,
    v_already_paired: (n) => `That vault is already on this device, under the account <strong>${n || 'unnamed'}</strong>. There is no need to connect it again: open that account.`,
    v_already_paired_go: 'Open that account',
    v_pasted_invalid: 'That pasted code is not valid.',
    v_no_qr_img: 'I could not find a QR in that image.',
    // --- Camera / scanner ---
    cam_err: 'Could not open the camera. Try «Open image/file» or paste the code.',
    // --- Signature validation (#v=) ---
    val_ok: '✓ Valid signature',
    val_ok_by: (n) => ` — signed by <strong>${n}</strong>`,
    val_bad: '✗ Invalid or unverifiable signature',
    // --- Error states ---
    err_invalid_title: 'Invalid link',
    err_invalid_body: 'This link is not valid.',
    err_noid_title: 'Could not connect your identity',
    err_noid_body: 'This requires your Dotrino identity. Reload and try again.',
    // --- Own profile + PIN ---
    tag_identity: 'Your identity',
    tag_profiles: 'Profiles',
    prof_title: 'Your profile',
    pin_title: '🔒 PIN protection',
    pin_remove: 'Remove PIN',
    pin_protect: 'Protect with PIN',
    pin_desc: 'Protects the active profile <strong>on this device only</strong> (not shared or synced). Asked once per tab; refreshing does not ask again.',
    pin_remove_q: 'Remove the PIN of this profile on this device?',
    pin_ph1: 'PIN (min. 4)',
    pin_ph2: 'Repeat the PIN',
    pin_go: 'Protect',
    pin_min: 'Minimum 4 characters.',
    pin_mismatch: 'They do not match.',
    del_msg: 'Delete this profile and all its data? This cannot be undone.',
    del_yes: 'Delete',
    // --- Signing in on another browser (sessions) ---
    tag_sessions: 'Sign in',
    ses_title: 'Sign in on another browser',
    ses_desc: 'To use your apps on a borrowed computer without leaving it linked: that computer shows you a code, you read it here, and it gets in for a while. When it expires, that is that — and if you remove this device, every session you gave goes with it.',
    ses_open: 'Sign in on THIS browser',
    ses_open_desc: 'Creates a code for you to read from the phone where you already have your account.',
    ses_grant: 'Let another computer in',
    ses_grant_desc: 'Read the code the other computer is showing and let it in.',
    ses_waiting: 'Waiting for someone to approve it…',
    ses_code: 'Code',
    ses_code_hint: 'Check that the other computer shows this same code before approving.',
    ses_in: (n) => `You are in as <strong>${n}</strong>`,
    ses_until: (d) => `Until ${d}`,
    ses_paste: 'Or paste the other computer\'s code here',
    ses_read: 'Read',
    ses_asks: (o) => `<strong>${o}</strong> wants to get in`,
    ses_scopes: 'It will be able to',
    ses_scope_whoami: 'know who you are',
    ses_scope_store: 'read and write your data',
    ses_allow: 'Allow',
    ses_deny: 'No',
    ses_given: 'Sessions you gave',
    ses_none: 'None.',
    ses_close: 'Close',
    ses_closed: 'Closed.',
    ses_denied: 'Not granted.',
    ses_timeout: 'Nobody approved it in time.',
    ses_err: 'Could not open the session.',
    ses_mine: 'Your session on this browser',
    ses_leave: 'Leave',
    ses_copy: 'No camera? Copy this text and paste it on the other device',
    ses_desc_short: 'Use your apps on a borrowed computer, for a while and without leaving it linked.',
    gr_title: 'What your apps can see',
    gr_desc: 'Knowing who you are needs no permission. Your data does — and here is where you take it back.',
    gr_none: 'No app has your data.',
    gr_revoke: 'Take back',
    gr_revoked: 'Taken back.',
    gr_name: 'your name', gr_avatar: 'your picture', gr_email: 'your email', gr_links: 'your links',
    gr_via: 'through',
    gr_last: (d) => `Last used: ${d}`,
  }
}
function svt (k, ...a) { const v = SV_I18N[svLang]?.[k]; return String(typeof v === 'function' ? v(...a) : (v ?? k)) }
// Conecta el toggle de idioma del <dotrino-topbar>: persiste y recarga para servir todo en el idioma elegido.
function wireLangReload () {
  const tb = mount.querySelector('dotrino-topbar'); if (!tb) return
  tb.setAttribute('lang', svLang)
  tb.addEventListener('dotrino-lang', (e) => {
    const l = e.detail?.lang === 'en' ? 'en' : 'es'
    try { localStorage.setItem('dotrino.lang', l) } catch {}
    document.documentElement.lang = l
    window.location.reload()
  })
}

/**
 * ENTRAR EN OTRO NAVEGADOR — las sesiones (`@dotrino/identity/session`).
 *
 * Enlazar un aparato y entrar en uno no son lo mismo: enlazar mete una llave en el acta,
 * y para eso hace falta la selladora y el perfil abierto. Esta pantalla es la otra puerta.
 *
 * Tiene las DOS puntas porque el mismo aparato hace las dos cosas en momentos distintos:
 * hoy quieres entrar desde un equipo prestado, mañana eres tú quien deja entrar a otro.
 */

const SES_LS = 'dotrino.session.mine'      // el papel de ESTA sesión, si entramos aquí
const SES_GIVEN = 'dotrino.session.given'  // las que ha concedido este aparato

const sesLoad = (k) => { try { return JSON.parse(localStorage.getItem(k) || 'null') } catch (_) { return null } }
const sesSave = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)) } catch (_) {} }

/**
 * Aquí SÍ va `localStorage` y no el store del ecosistema, y no es un descuido: el
 * navegador que entra todavía NO tiene identidad —eso es lo que viene a conseguir—, así
 * que no hay store al que escribir. Y lo que se guarda vence solo.
 */
function sesFecha (ms) {
  try { return new Date(ms).toLocaleString(svLang === 'en' ? 'en-US' : 'es-ES', { dateStyle: 'short', timeStyle: 'short' }) }
  catch (_) { return String(ms) }
}

const sesScopeTexto = (sc) => sc.map((x) => x === 'vault:store' ? svt('ses_scope_store') : svt('ses_scope_whoami'))
/** Los alcances del PERMISO (datos del perfil), en palabras. */
const sesScopeNombres = (sc) => (sc || []).map((x) => ({
  'profile:name': svt('gr_name'), 'profile:avatar': svt('gr_avatar'),
  'profile:email': svt('gr_email'), 'profile:social': svt('gr_links'), 'id:whoami': svt('ses_scope_whoami')
})[x] || x)

/**
 * Un transporte identificado con la identidad de ESTE aparato (la del perfil activo).
 *
 * Es lo que usa el lado que RESPALDA. Se identificaba con la llave de sesión local, y eso
 * está mal por partida doble: se anuncia como si fuera una sesión, y —cuando las dos
 * puntas están en el mismo navegador— acaba compartiendo pubkey con quien espera, así que
 * el papel nunca llegaba a su destino.
 */
async function sesTransporteIdentidad (id) {
  const client = new WebSocketProxyClient({ url: 'wss://proxy.dotrino.com', autoReconnect: true })
  await client.connect()
  const pub = (await id.currentProfile?.().catch(() => null))?.pubkey || id.me.publickey
  await client.identifyAs({ publickey: pub, sign: (d) => id.signData(d) })
  return client
}

/**
 * Un transporte identificado bajo la llave que se le pase (el lado que ENTRA).
 *
 * `encPrivateKey` NO es opcional en la práctica: la respuesta viene SELLADA (el proxio no
 * cifra, CONVENCIONES §4.1) y sin la privada aquí el cliente del pilar no puede abrir el
 * sobre y lo descarta en silencio — la pantalla se queda esperando algo que ya llegó.
 */
async function sesTransporte (llave, encPrivateKey = null) {
  const client = new WebSocketProxyClient({ url: 'wss://proxy.dotrino.com', autoReconnect: true, myEncPrivateKey: encPrivateKey })
  await client.connect()
  await client.identifyAs({
    publickey: llave.publickey,
    sign: (d) => signWithDevice({ privateJwk: llave.privateJwk, data: d })
  })
  return client
}

async function sessionsMode () {
  injectVaultStyles()
  // `vaultShell` PINTA (no devuelve): asignar su resultado dejaba «undefined» en la página.
  vaultShell(svt('ses_title'), `<p class="muted">${esc(svt('ses_desc'))}</p>
    <div id="ses-mine"></div>
    <div class="card"><h3>${esc(svt('ses_open'))}</h3><p class="muted">${esc(svt('ses_open_desc'))}</p>
      <div id="ses-open-box"><button class="btn" id="ses-open" data-testid="ses-open">${esc(svt('ses_open'))}</button></div></div>
    <div class="card"><h3>${esc(svt('ses_grant'))}</h3><p class="muted">${esc(svt('ses_grant_desc'))}</p>
      <div id="ses-grant-box">
        <button class="btn ghost" id="ses-scan" data-testid="ses-scan">📷</button>
        <div style="margin-top:8px"><input id="ses-paste" data-testid="ses-paste" placeholder="${esc(svt('ses_paste'))}" style="width:100%">
        <button class="btn ghost" id="ses-read" data-testid="ses-read" style="margin-top:6px">${esc(svt('ses_read'))}</button></div>
      </div></div>
    <div class="card"><h3>${esc(svt('ses_given'))}</h3><div id="ses-given"></div></div>
    <div class="card"><h3>${esc(svt('gr_title'))}</h3><p class="muted">${esc(svt('gr_desc'))}</p><div id="ses-grants"></div></div>`, svt('tag_sessions'))
  wireLangReload()   // el botón de perfil ya lo decora `vaultShell`

  pintaMia()
  pintaDadas()
  pintaPermisos()

  document.getElementById('ses-open')?.addEventListener('click', entrar)
  document.getElementById('ses-read')?.addEventListener('click', () => {
    const t = /** @type {HTMLInputElement} */ (document.getElementById('ses-paste'))?.value || ''
    const inv = parseInvite(extractPayload(t) || t)
    if (!inv) return alerta('ses-grant-box', svt('v_pasted_invalid'), 'bad')
    pedirPermiso(inv)
  })
  document.getElementById('ses-scan')?.addEventListener('click', async () => {
    const box = document.getElementById('ses-grant-box')
    const leido = await scanWithCamera(box)
    if (!leido) return pintaGrantBox()
    const inv = parseInvite(extractPayload(leido) || leido)
    pintaGrantBox()
    if (!inv) return alerta('ses-grant-box', svt('v_pasted_invalid'), 'bad')
    pedirPermiso(inv)
  })

  function alerta (donde, texto, tipo = 'ok') {
    const host = document.getElementById(donde); if (!host) return
    const b = document.createElement('div'); b.className = 'banner ' + tipo; b.textContent = texto
    host.appendChild(b); setTimeout(() => b.remove(), 4000)
  }

  function pintaGrantBox () {
    const box = document.getElementById('ses-grant-box'); if (!box) return
    box.innerHTML = `<button class="btn ghost" id="ses-scan" data-testid="ses-scan">📷</button>
      <div style="margin-top:8px"><input id="ses-paste" data-testid="ses-paste" placeholder="${esc(svt('ses_paste'))}" style="width:100%">
      <button class="btn ghost" id="ses-read" data-testid="ses-read" style="margin-top:6px">${esc(svt('ses_read'))}</button></div>`
    document.getElementById('ses-read')?.addEventListener('click', () => {
      const t = /** @type {HTMLInputElement} */ (document.getElementById('ses-paste'))?.value || ''
      const inv = parseInvite(extractPayload(t) || t)
      if (!inv) return alerta('ses-grant-box', svt('v_pasted_invalid'), 'bad')
      pedirPermiso(inv)
    })
    document.getElementById('ses-scan')?.addEventListener('click', async () => {
      const leido = await scanWithCamera(document.getElementById('ses-grant-box'))
      pintaGrantBox()
      if (leido) { const inv = parseInvite(extractPayload(leido) || leido); if (inv) pedirPermiso(inv) }
    })
  }

  /** La sesión de ESTE navegador, si entramos aquí. */
  function pintaMia () {
    const host = document.getElementById('ses-mine'); if (!host) return
    const mia = sesLoad(SES_LS)
    if (!mia?.paper || mia.paper.exp <= Date.now()) { host.innerHTML = ''; return }
    host.innerHTML = `<div class="banner ok">${svt('ses_in', esc(mia.name || mia.paper.sid.slice(0, 8)))} · ${esc(svt('ses_until', sesFecha(mia.paper.exp)))}
      <button class="btn ghost" id="ses-leave" data-testid="ses-leave" style="margin-left:8px">${esc(svt('ses_leave'))}</button></div>`
    document.getElementById('ses-leave')?.addEventListener('click', () => {
      try { localStorage.removeItem(SES_LS) } catch (_) {}
      pintaMia()
    })
  }

  /** Las que este aparato concedió: se ven y se cierran. */
  function pintaDadas () {
    const host = document.getElementById('ses-given'); if (!host) return
    const dadas = (sesLoad(SES_GIVEN) || []).filter((x) => x.exp > Date.now())
    sesSave(SES_GIVEN, dadas)
    if (!dadas.length) { host.innerHTML = `<p class="muted">${esc(svt('ses_none'))}</p>`; return }
    host.innerHTML = dadas.map((d) => `<div class="row" data-sid="${esc(d.sid)}">
      <div><strong>${esc(d.origin)}</strong><br><span class="muted">${esc(svt('ses_until', sesFecha(d.exp)))}</span></div>
      <button class="btn ghost ses-close" data-sid="${esc(d.sid)}">${esc(svt('ses_close'))}</button></div>`).join('')
    host.querySelectorAll('.ses-close').forEach((b) => b.addEventListener('click', async () => {
      const sid = b.getAttribute('data-sid')
      const d = (sesLoad(SES_GIVEN) || []).find((x) => x.sid === sid)
      sesSave(SES_GIVEN, (sesLoad(SES_GIVEN) || []).filter((x) => x.sid !== sid))
      pintaDadas(); alerta('ses-given', svt('ses_closed'))
      // Avisar es cortesía: lo que la corta de verdad es que el papel vence y nadie lo
      // renueva. Si el aviso no llega, la sesión muere igual.
      try {
        if (d?.s) {
          const { id } = await connectProvider()
          const t = await sesTransporteIdentidad(id)
          await closeSession({ transport: t, sessionPubkey: d.s, encPub: d.encPub, sid }); t.close?.()
        }
      } catch (_) {}
    }))
  }

  /**
   * QUÉ LE HAS CONCEDIDO A CADA APLICACIÓN. Va aquí, al lado de las sesiones, y no en otra
   * pantalla: las dos responden a la misma pregunta —quién está usando tu identidad— y
   * separarlas obligaría al usuario a saber la diferencia entre un permiso y una sesión.
   */
  async function pintaPermisos () {
    const host = document.getElementById('ses-grants'); if (!host) return
    let lista = []
    try { const { id } = await connectProvider(); lista = await id.listGrants?.() || [] } catch (_) { }
    if (!lista.length) { host.innerHTML = `<p class="muted">${esc(svt('gr_none'))}</p>`; return }
    const nombre = (o) => { try { const h = new URL(o).hostname; const m = /^([a-z0-9-]+)\.dotrino\.com$/.exec(h); return m ? m[1][0].toUpperCase() + m[1].slice(1) : h } catch (_) { return o } }
    // QUIÉN pide arriba y CUÁNDO fue la última vez debajo: sin la fecha, la lista dice qué
    // concediste pero no si sigue usándose, que es lo que decide si retirarlo.
    // Lo que el origen dice pedir por otro va SUBORDINADO a él, nunca en su lugar.
    host.innerHTML = lista.map((g) => `<div class="row">
      <div><strong>${esc(g.onBehalfOf || nombre(g.origin))}</strong><br><span class="muted">${g.onBehalfOf ? esc(svt('gr_via')) + ' ' : ''}${esc(g.origin.replace(/^https?:\/\//, ''))}${g.scopes.length ? ' · ' + esc(sesScopeNombres(g.scopes).join(', ')) : ''}<br>${esc(svt('gr_last', sesFecha(g.lastUsed || g.at)))}</span></div>
      <button class="btn ghost gr-revoke" data-origin="${esc(g.origin)}">${esc(svt('gr_revoke'))}</button></div>`).join('')
    host.querySelectorAll('.gr-revoke').forEach((b) => b.addEventListener('click', async () => {
      try { const { id } = await connectProvider(); await id.revokeGrant(b.getAttribute('data-origin')) } catch (_) {}
      pintaPermisos(); alerta('ses-grants', svt('gr_revoked'))
    }))
  }

  /** Llave de sesión de este navegador (se guarda: reconectar no debe cambiar de identidad). */
  async function sesLlaveLocal () {
    let k = sesLoad('dotrino.session.key')
    if (!k?.privateJwk) { k = await makeDeviceKey({ label: 'sesión' }); sesSave('dotrino.session.key', k) }
    return k
  }

  /** LADO DEL QUE ENTRA: enseña el código y espera. */
  async function entrar () {
    const box = document.getElementById('ses-open-box'); if (!box) return
    const llave = await sesLlaveLocal()
    const enc = await makeEncKeypair()
    let client
    try { client = await sesTransporte(llave, enc.privateKey) } catch (_) { return alerta('ses-open-box', svt('ses_err'), 'bad') }
    try {
      const s = await openSession({
        transport: client, sessionPubkey: llave.publickey, encPub: enc.encPub,
        origin: location.origin, scopes: ['id:whoami', 'vault:store'],
        onInvite: ({ qr, code }) => {
          box.innerHTML = `<div class="qr">${qrSvg(qr)}</div>
            <p><strong>${esc(svt('ses_code'))}: ${esc(code)}</strong></p>
            <p class="muted">${esc(svt('ses_code_hint'))}</p>
            <p class="muted" data-testid="ses-waiting">${esc(svt('ses_waiting'))}</p>
            <details><summary class="muted">${esc(svt('ses_copy'))}</summary>
              <textarea readonly data-testid="ses-invite" style="width:100%;height:72px">${esc(qr)}</textarea></details>`
        }
      })
      // La HUELLA legible (AB12-CD34), no el JWK crudo: al usuario hay que enseñarle en qué
      // cuenta entró, no una llave.
      const huella = await keyLabel(s.profileId).catch(() => null)
      sesSave(SES_LS, { paper: s.paper, chain: s.chain, name: huella, privateJwk: llave.privateJwk })
      box.innerHTML = `<button class="btn" id="ses-open" data-testid="ses-open">${esc(svt('ses_open'))}</button>`
      document.getElementById('ses-open')?.addEventListener('click', entrar)
      pintaMia()
    } catch (e) {
      const cual = e?.code === 'session-denied' ? 'ses_denied' : e?.code === 'session-timeout' ? 'ses_timeout' : 'ses_err'
      box.innerHTML = `<button class="btn" id="ses-open" data-testid="ses-open">${esc(svt('ses_open'))}</button>`
      document.getElementById('ses-open')?.addEventListener('click', entrar)
      alerta('ses-open-box', svt(cual), 'bad')
    } finally { try { client.close?.() } catch (_) {} }
  }

  /** LADO DEL QUE RESPALDA: qué pide, y decidir. Nada se concede sin que el dueño pulse. */
  function pedirPermiso (inv) {
    const box = document.getElementById('ses-grant-box'); if (!box) return
    const scopes = cleanSessionScopes(inv.scopes)
    box.innerHTML = `<div class="banner">${svt('ses_asks', esc(inv.origin))}
      <p class="muted">${esc(svt('ses_scopes'))}: ${esc(sesScopeTexto(scopes).join(', '))}</p>
      <p><strong>${esc(svt('ses_code'))}: ${esc(sessionCode(inv.sid))}</strong></p>
      <p class="muted">${esc(svt('ses_code_hint'))}</p>
      <button class="btn" id="ses-allow" data-testid="ses-allow">${esc(svt('ses_allow'))}</button>
      <button class="btn ghost" id="ses-deny" data-testid="ses-deny">${esc(svt('ses_deny'))}</button></div>`
    document.getElementById('ses-deny')?.addEventListener('click', async () => {
      pintaGrantBox()
      try {
        const { id } = await connectProvider()
        const t = await sesTransporteIdentidad(id); await denySession({ transport: t, invite: inv }); t.close?.()
      } catch (_) {}
    })
    document.getElementById('ses-allow')?.addEventListener('click', async () => {
      let id
      try { ({ id } = await connectProvider()) } catch { return alerta('ses-grant-box', svt('err_noid_body'), 'bad') }
      try {
        const chain = await id.sealerChain()
        const by = (await id.currentProfile?.().catch(() => null))?.pubkey || id.me.publickey
        const t = await sesTransporteIdentidad(id)
        const paper = await grantSession({
          transport: t, invite: inv, by, chain, scopes,
          sign: (body) => id.signData(body)
        })
        t.close?.()
        const dadas = sesLoad(SES_GIVEN) || []
        dadas.push({ sid: paper.sid, s: paper.s, encPub: inv.encPub, origin: paper.origin, exp: paper.exp })
        sesSave(SES_GIVEN, dadas)
        pintaGrantBox(); pintaDadas()
      } catch (e) {
        pintaGrantBox(); alerta('ses-grant-box', svt('ses_err'), 'bad')
      }
    })
  }
}

async function selfVaultMode () {
  injectVaultStyles()
  // ?back= la app que nos llamó (sólo http/https, para evitar open-redirect)
  let backHref = null, backHost = null
  try {
    const b = new URLSearchParams(location.search).get('back')
    if (b) { const u = new URL(b); if (u.protocol === 'http:' || u.protocol === 'https:') { backHref = u.origin + u.pathname; backHost = u.hostname } }
  } catch {}
  const backBtn = backHost ? `<p style="margin-top:14px"><button class="btn ghost" id="svBack" data-testid="sv-back">${esc(svt('back', backHost))}</button></p>` : ''

  // Pintar el shell de carga ANTES de conectar la identidad (que puede tardar o,
  // intermitentemente, colgarse cargando el iframe id.dotrino.com): así la página
  // NUNCA queda en BLANCO mientras conecta. Al resolver, se rellena #sv-root.
  vaultShell(svt('h'), `<div class="vault-wrap"><div id="sv-root"><span class="status">${esc(svt('loading'))}</span></div>${backBtn}</div>`, svt('h'))
  wireLangReload()
  document.getElementById('svBack')?.addEventListener('click', () => { location.href = backHref })
  const root = document.getElementById('sv-root')

  let id
  try { id = await Identity.connect() } catch {}
  if (!id?.me?.publickey) {
    root.innerHTML = `<p class="status">${esc(svt('need_id'))} <a href="${viewUrl('')}" style="color:#00658c">${esc(svt('need_id_link'))}</a>.</p>`
    return
  }

  let pairBox, machinesBox
  // Eventos del daemon del iframe: { pending? running? error? }
  id.onSelfVault((p) => {
    if (!p) return
    if (Array.isArray(p.pending)) renderPending(p.pending)
    if (typeof p.running === 'boolean') {
      const badge = root.querySelector('#svStatus')
      if (badge) badge.textContent = p.running ? svt('running') : svt('not_running')
    }
  })

  async function render () {
    if (_svPresenceTimer) { clearInterval(_svPresenceTimer); _svPresenceTimer = null }
    let status
    try { status = await id.selfVaultStatus() } catch { status = { enabled: false, running: false } }

    if (!status.enabled) {
      root.innerHTML = `<p class="status">${esc(svt('intro_off'))}</p>
        <div class="sv-toggle-row"><span class="status">${esc(svt('state_off'))}</span></div>
        <button class="btn" id="svEnable" data-testid="sv-enable">${esc(svt('enable'))}</button>`
      document.getElementById('svEnable').addEventListener('click', async () => { await id.setSelfVault(true); render() })
      return
    }

    root.innerHTML = `<span class="sv-status" id="svStatus">${esc(status.running ? svt('running') : svt('not_running'))}</span>
      <button class="btn ghost" id="svDisable" data-testid="sv-disable" style="margin-left:8px">${esc(svt('disable'))}</button>
      <div class="sv-block" id="svPair"></div>
      <div class="sv-block" id="svMachines"><span class="status">${esc(svt('machines_none'))}</span></div>`
    document.getElementById('svDisable').addEventListener('click', async () => { await id.setSelfVault(false); render() })

    pairBox = document.getElementById('svPair')
    machinesBox = document.getElementById('svMachines')

    function renderPairIdle () {
      pairBox.innerHTML = `<div class="sv-setup"><button class="btn" id="svStartPair" data-testid="sv-start-pair">${esc(svt('pair_new'))}</button></div>`
      document.getElementById('svStartPair').addEventListener('click', startPairing)
    }
    async function startPairing () {
      let qr
      try { ({ qr } = await id.selfVaultPairing()) } catch { return }
      // El QR usa el JSON crudo (más corto → QR más chico); el código COPIABLE va en
      // base64url (oculta iss/token/sn en texto plano). El agente (CLI) acepta ambos.
      const json = JSON.stringify(qr)
      const code = b64urlEncode(json)
      pairBox.innerHTML = `<div class="sv-setup">
        <p class="status">${esc(svt('pair_step1'))}</p>
        <div class="sv-qr-wrap" title="QR">${qrSvg(json)}</div>
        <div class="sv-qr-code"><pre><code>${esc(code)}</code></pre></div>
        <button class="btn ghost" id="svCopy">${esc(svt('copy'))}</button>
        <span class="status" id="svCopyMsg"></span>
        <p class="status">${esc(svt('pair_step2'))}</p>
        <p class="status">${esc(svt('pair_wait'))}</p>
        <button class="btn ghost" id="svCancel">${esc(svt('cancel'))}</button>
      </div>`
      document.getElementById('svCopy').addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(code); document.getElementById('svCopyMsg').textContent = svt('copied') } catch {}
      })
      document.getElementById('svCancel').addEventListener('click', renderPairIdle)
    }

    function renderPending (list) {
      if (!pairBox) return
      if (!list || !list.length) { if (pairBox.querySelector('.sv-pending')) renderPairIdle(); return }
      const rows = list.map((x) => `
        <div class="sv-pending" data-device="${esc(x.deviceId)}">
          <p class="status">${esc(svt('pending', x.deviceId))}</p>
          <div class="sv-pair-actions">
            <input class="sv-code-input" data-code="${esc(x.deviceId)}" type="text" inputmode="numeric" autocomplete="off" maxlength="8" placeholder="${esc(svt('code_ph'))}" aria-label="${esc(svt('code_ph'))}" data-testid="sv-code" />
            <button class="btn" data-approve="${esc(x.deviceId)}" data-testid="sv-approve">${esc(svt('approve'))}</button>
            <button class="btn ghost" data-reject="${esc(x.deviceId)}">${esc(svt('reject'))}</button>
          </div>
        </div>`).join('')
      pairBox.innerHTML = `<div class="sv-setup">${rows}</div>`
      const approveWith = async (b) => {
        const dev = b.dataset.approve
        const input = pairBox.querySelector(`input[data-code="${CSS.escape(dev)}"]`)
        const code = (input?.value || '').trim()
        if (!code) { input?.focus(); return }
        b.disabled = true
        try { await id.selfVaultApprove(dev, code); refreshMachines() } catch { b.disabled = false }
      }
      pairBox.querySelectorAll('[data-approve]').forEach((b) => {
        b.addEventListener('click', () => approveWith(b))
        const input = pairBox.querySelector(`input[data-code="${CSS.escape(b.dataset.approve)}"]`)
        input?.addEventListener('keydown', (e) => { if (e.key === 'Enter') approveWith(b) })
      })
      pairBox.querySelectorAll('[data-reject]').forEach((b) => b.addEventListener('click', () => id.selfVaultReject(b.dataset.reject)))
    }

    try { renderPending(await id.selfVaultPending()) } catch {}
    renderPairIdle()

    async function updatePresence (subs) {
      if (!subs.length) return
      let online = new Set()
      try { const r = await id.selfVaultProbe(subs); online = new Set(r.online || []) } catch {}
      for (const row of machinesBox.querySelectorAll('.sv-machine-row')) {
        const dot = row.querySelector('.sv-mdot'); if (!dot) continue
        const on = online.has(row.dataset.sub)
        dot.className = 'sv-mdot ' + (on ? 'on' : 'off')
        dot.title = on ? svt('online') : svt('offline')
      }
    }
    async function refreshMachines () {
      try {
        const list = await id.selfVaultMachines()
        if (!list.length) {
          machinesBox.innerHTML = `<span class="status">${esc(svt('machines_none'))}</span>`
          return
        }
        machinesBox.innerHTML = `<b>${esc(svt('machines_title'))}</b><div class="sv-machine-list"></div>`
        const holder = machinesBox.querySelector('.sv-machine-list')
        for (const d of list) {
          const name = d.label ? `${d.label} · ${d.deviceId}` : d.deviceId
          holder.appendChild(svEl(`<div class="sv-machine-row" data-sub="${esc(d.sub)}">
            <span class="sv-machine-name"><span class="sv-mdot" title="${esc(svt('checking'))}"></span>🖥 ${esc(name)}</span>
            <button class="btn ghost" data-revoke="${esc(d.nonce)}">${esc(svt('revoke'))}</button>
          </div>`))
        }
        machinesBox.querySelectorAll('[data-revoke]').forEach((b) => b.addEventListener('click', async () => { await id.selfVaultRevoke(b.dataset.revoke); refreshMachines() }))
        updatePresence(list.map((d) => d.sub))
      } catch { machinesBox.innerHTML = `<span class="status">${esc(svt('machines_none'))}</span>` }
    }
    refreshMachines()
    _svPresenceTimer = setInterval(() => {
      const subs = [...machinesBox.querySelectorAll('.sv-machine-row')].map((r) => r.dataset.sub)
      if (subs.length) updatePresence(subs)
    }, 30000)
  }

  render()
}

/* La gestión de dispositivos y bóvedas se MUDÓ a vault.dotrino.com — una sola consola
   para todo el ecosistema, en vez de repartirla entre apps (ver
   dotrino-vault/docs/acta-de-perfil.md §3). Aquí solo queda el reenvío, para que los
   códigos de emparejamiento y los enlaces viejos sigan funcionando. El token viaja en
   el `#fragment`, que nunca llega a ningún servidor: se traslada tal cual. */
const CONSOLE_URL = 'https://vault.dotrino.com/dispositivos'
function redirectToConsole (data) {
  const b64 = (location.hash.match(/#vault=([^&]+)/) || [])[1]
  location.replace(b64 ? `${CONSOLE_URL}#vault=${b64}` : CONSOLE_URL)
}

/* ── /create: crear un perfil, con nombre y (si quieres) algún dato más ──
   Que sea una PÁGINA y no un botón escondido es a propósito: crear un perfil es un acto
   del dueño, no un efecto colateral de pulsar algo en un modal. Hasta que no le das a
   guardar aquí, no existe nada — antes el modal creaba un «Perfil sin nombre» al vuelo.
   Y solo el NOMBRE es público: lo demás nace oculto y tú decides si lo enseñas. */
const CREATE_I18N = {
  es: {
    title: 'Crear un perfil',
    lead: 'Un perfil es una identidad tuya en este dispositivo: su propia llave, sus propios datos. Puedes tener varios (personal, trabajo) y cambiar entre ellos cuando quieras.',
    nick: 'Nombre', nickPh: '¿Cómo quieres que te llamen?',
    nickHelp: 'Es lo único que se comparte. Puedes cambiarlo después.',
    more: 'Añadir algún dato más (opcional)',
    moreHelp: 'Nada de esto se comparte: nace oculto y tú decides después si lo enseñas y a quién.',
    f: { nombres: 'Nombres', apellidos: 'Apellidos', email: 'Correo', telefono: 'Teléfono', direccion: 'Dirección' },
    save: 'Crear el perfil', saving: 'Creando…', cancel: 'Cancelar',
    needNick: 'Ponle un nombre para poder crearlo.',
    done: 'Listo. Este es tu perfil nuevo.',
    fail: 'No se pudo crear: '
  },
  en: {
    title: 'Create a profile',
    lead: 'A profile is one of your identities on this device: its own key, its own data. You can have several (personal, work) and switch whenever you want.',
    nick: 'Name', nickPh: 'What should we call you?',
    nickHelp: 'It is the only thing that gets shared. You can change it later.',
    more: 'Add something else (optional)',
    moreHelp: 'None of this is shared: it starts hidden and you decide later whether to show it, and to whom.',
    f: { nombres: 'First name', apellidos: 'Last name', email: 'Email', telefono: 'Phone', direccion: 'Address' },
    save: 'Create the profile', saving: 'Creating…', cancel: 'Cancel',
    needNick: 'Give it a name to create it.',
    done: 'Done. This is your new profile.',
    fail: 'Could not create it: '
  }
}

async function createProfileMode () {
  injectVaultStyles()
  const t = CREATE_I18N[svLang] || CREATE_I18N.es
  const returnUrl = new URLSearchParams(location.search).get('return') || ''

  vaultShell(t.title, `<div class="vault-wrap">
    <p>${esc(t.lead)}</p>
    <label class="cp-field">
      <span>${esc(t.nick)}</span>
      <input id="cp-nick" type="text" maxlength="40" placeholder="${esc(t.nickPh)}" autocomplete="nickname" data-testid="nick" />
      <small class="muted">${esc(t.nickHelp)}</small>
    </label>
    <details class="cp-more">
      <summary>${esc(t.more)}</summary>
      <p class="muted">${esc(t.moreHelp)}</p>
      ${['nombres', 'apellidos', 'email', 'telefono', 'direccion'].map((k) => `
        <label class="cp-field"><span>${esc(t.f[k])}</span>
          <input id="cp-${k}" type="${k === 'email' ? 'email' : k === 'telefono' ? 'tel' : 'text'}" maxlength="200" /></label>`).join('')}
    </details>
    <div class="scanrow">
      <button id="cp-save" class="btn" data-testid="crear">${esc(t.save)}</button>
      <button id="cp-cancel" class="btn ghost">${esc(t.cancel)}</button>
    </div>
    <div id="cp-msg"></div>
  </div>`)
  wireLangReload()

  const msg = () => document.getElementById('cp-msg')
  document.getElementById('cp-cancel').onclick = () => { location.href = returnUrl || appBase() }
  document.getElementById('cp-nick').focus()

  document.getElementById('cp-save').onclick = async () => {
    const nick = document.getElementById('cp-nick').value.trim()
    if (!nick) { msg().innerHTML = `<div class="banner bad">${esc(t.needNick)}</div>`; return }
    const btn = document.getElementById('cp-save')
    btn.disabled = true; btn.textContent = t.saving
    try {
      const id = await Identity.connect()
      await id.createProfile(nick)
      // Los datos extra nacen OCULTOS: solo el nombre es público por defecto.
      const patch = {}
      for (const k of ['nombres', 'apellidos', 'email', 'telefono', 'direccion']) {
        const v = document.getElementById('cp-' + k).value.trim()
        if (v) { patch[k] = v; patch[k + 'Visible'] = false }
      }
      if (Object.keys(patch).length) await id.updateMe(patch)
      msg().innerHTML = `<div class="banner ok">${esc(t.done)}</div>`
      setTimeout(() => { location.href = returnUrl || appBase() }, 900)
    } catch (e) {
      btn.disabled = false; btn.textContent = t.save
      msg().innerHTML = `<div class="banner bad">${esc(t.fail + (e?.message || e))}</div>`
    }
  }
}

async function main() {
  const data = parseRoute()

  if (data.mode === 'create') return createProfileMode()
  if (data.mode === 'vault' || data.mode === 'selfvault' || data.token) return redirectToConsole(data)

  let pendingPair = false
  try { pendingPair = !!sessionStorage.getItem('cc-pair-intent') } catch (_) {}

  // El `#fragment` se limpia SOLO cuando lleva el TOKEN de emparejamiento
  // (`#vault=<token>`, secreto de ~5 min): se migra a la vista `/vault` (sin token)
  // para que no quede en la barra ni en el historial. Los enlaces legacy de VISTA
  // (`#myvault`, `#vault`) se reescriben a su PATH para que un refresco mantenga la
  // vista (antes se borraba SIEMPRE y al refrescar `#myvault` caías en "Tu perfil" o
  // la página quedaba en blanco). Los modos con DATOS (`#v=`, `#<pubkey>`) conservan
  // su `#fragment` (privacidad). `replaceState` no dispara 'hashchange'. El reingreso
  // al emparejamiento tras cambiar de perfil usa sessionStorage 'cc-pair-intent'.
  try {
    if (data.token) history.replaceState(null, '', viewUrl('vault') + location.search)
    else if (data.legacy) history.replaceState(null, '', viewUrl(data.mode === 'selfvault' ? 'myvault' : 'vault') + location.search)
  } catch (_) {}

  if (data.mode === 'vault' || pendingPair) return vaultMode(data.qr)
  if (data.mode === 'selfvault') return selfVaultMode()
  if (data.mode === 'sessions') return sessionsMode()

  // ── VALIDAR: firma del contenido + reputación del remitente, en un paso ──
  if (data.mode === 'validate') {
    const p = data.payload || {}
    const signed = { op: p.op || 'app-request', text: p.text, ts: p.ts }
    const ok = await verifySig(p.pubkey, signed, p.signature)
    const banner = ok
      ? `<div class="banner ok">${svt('val_ok')}${p.nickname ? svt('val_ok_by', esc(p.nickname)) : ''}</div>`
      : `<div class="banner bad">${svt('val_bad')}</div>`
    const content = p.text ? `<div class="content">${esc(p.text)}</div>` : ''
    mount.innerHTML = `<div class="validate-wrap">${banner}${content}<div id="prof"></div></div>`
    if (p.pubkey) {
      const el = makeProfile({ pubkey: p.pubkey, name: p.nickname, mode: 'edit', modal: false })
      document.getElementById('prof').appendChild(el)
      try { const { provider } = await connectProvider(); el.provider = provider } catch { /* reputación opcional */ }
    }
    return
  }

  if (data.mode === 'invalid') {
    showState(svt('err_invalid_title'), `<p>${svt('err_invalid_body')}</p>`)
    return
  }

  // ── RATE (#pubkey) o SELF (sin hash): perfil modal, requiere identidad ──
  let id, provider
  try { ({ id, provider } = await connectProvider()) } catch {
    showState(svt('err_noid_title'), `<p>${svt('err_noid_body')}</p>`)
    return
  }

  let pubkey, name, since, mode
  if (data.mode === 'rate') {
    pubkey = data.pubkey; name = data.name; since = data.since; mode = 'edit'
  } else {
    // Siempre hay identidad (el vault crea un perfil al cargar). Usamos el PERFIL ACTIVO.
    const cur = id.currentProfile ? await id.currentProfile().catch(() => null) : null
    pubkey = cur?.pubkey || (id && id.me && id.me.publickey); name = cur?.name || (id && id.me && id.me.nickname); mode = 'self'
  }

  // SELF (tu perfil): topbar + el componente inline, que YA trae el switcher de
  // perfiles (cambiar) y —AQUÍ, con `manage`— crear perfil. Debajo, la sección de
  // PIN, exclusiva de ESTA página (no aparece en el popup de las otras apps).
  if (mode === 'self') {
    injectVaultStyles()
    vaultShell(svt('prof_title'), `<div class="vault-wrap"><div id="self-prof"></div><div id="pin-section"></div><div class="sv-link-row"><p class="status">${esc(svt('self_link_desc'))}</p><a href="${viewUrl('myvault')}" data-testid="goto-myvault">${esc(svt('self_link'))}</a></div><div class="sv-link-row"><p class="status">${esc(svt('ses_desc_short'))}</p><a href="${viewUrl('sessions')}" data-testid="goto-sessions">${esc(svt('ses_title'))}</a></div></div>`, svt('tag_profiles'))
    wireLangReload()
    const el = makeProfile({ pubkey, name, since, mode, modal: false, manage: true })
    el.provider = provider
    document.getElementById('self-prof')?.appendChild(el)
    renderPinSection(document.getElementById('pin-section'))
    return
  }

  const el = makeProfile({ pubkey, name, since, mode, modal: true })
  el.provider = provider
  mount.innerHTML = ''
  mount.appendChild(el)
}

window.addEventListener('hashchange', () => window.location.reload())
main()

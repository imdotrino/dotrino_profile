/**
 * dotrino_profile — perfil + calificación + validación de firma (web-of-trust).
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
import { createVaultReputation, canonicalStringify } from '@dotrino/reputation'
import { createVaultProfileProvider } from '@dotrino/profile'
import '@dotrino/profile' // registra el custom element <dotrino-profile>

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

function parseHash() {
  const h = location.hash.replace(/^#/, '').trim()
  if (!h) return { mode: 'self' }
  if (h === 'vault') return { mode: 'vault' }
  if (h.startsWith('v=')) {
    try { return { mode: 'validate', payload: JSON.parse(b64urlDecode(h.slice(2))) } } catch { return { mode: 'invalid' } }
  }
  if (h.includes('=')) {
    const q = new URLSearchParams(h)
    const p = q.get('p') || q.get('pubkey')
    if (!p) return { mode: 'invalid' }
    return { mode: 'rate', pubkey: b64urlDecode(p), name: q.get('name') ? b64urlDecode(q.get('name')) : '', since: q.get('since') || '' }
  }
  return { mode: 'rate', pubkey: b64urlDecode(h), name: '', since: '' }
}

async function connectProvider() {
  const id = await Identity.connect()
  let reputation = null
  try { reputation = createVaultReputation(id) } catch { /* sin reputación: el perfil igual abre */ }
  return { id, provider: createVaultProfileProvider({ identity: id, reputation }) }
}

function makeProfile({ pubkey, name, since, mode, modal }) {
  const el = document.createElement('dotrino-profile')
  if (modal) el.setAttribute('modal', '')
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
    .vault-wrap .vault-info li { padding: 4px 0; }`
  document.head.appendChild(s)
}

async function vaultFingerprint (jwkStr) {
  try {
    const jwk = JSON.parse(jwkStr)
    const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalStringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })))
    return [...new Uint8Array(h)].slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('')
  } catch { return '????????' }
}

async function vaultMode () {
  injectVaultStyles()
  let id
  try { id = await Identity.connect() } catch {
    showState('Tu bóveda', '<p>No se pudo conectar tu identidad. Recarga e inténtalo de nuevo.</p>'); return
  }
  const status = await id.vaultStatus().catch(() => ({ paired: false }))

  if (status.paired) {
    const fp = await vaultFingerprint(status.master)
    showState('Tu bóveda', `<div class="vault-wrap">
      <div class="banner ok">✓ Este dispositivo está conectado a tu bóveda.</div>
      <ul class="vault-info">
        <li>Dispositivo: <code>${esc(status.deviceId)}</code></li>
        <li>Bóveda (huella): <code>${esc(fp)}</code></li>
        <li>Permisos: <code>${esc((status.scope || []).join(', '))}</code></li>
      </ul>
      <h2 style="font-size:16px;margin:18px 0 6px">Tus dispositivos</h2>
      <div id="devlist" class="muted">Cargando…</div>
      <button id="unpair" class="btn danger" style="margin-top:18px">Desconectar este dispositivo</button>
    </div>`)
    document.getElementById('unpair').onclick = async () => {
      if (!confirm('¿Desconectar este dispositivo de tu bóveda? Tendrás que volver a emparejarlo.')) return
      await id.unpairDevice(); vaultMode()
    }
    // Lista (solo lectura) de dispositivos enrolados; revocar es desde el PC.
    id.listVaultDevices().then(({ devices }) => {
      const box = document.getElementById('devlist'); if (!box) return
      if (!devices?.length) { box.textContent = '—'; return }
      box.innerHTML = '<ul class="vault-info">' + devices.map((d) => {
        const me = d.deviceId === status.deviceId ? ' <strong>(este)</strong>' : ''
        const exp = d.exp ? ' · expira ' + new Date(d.exp).toLocaleDateString() : ''
        return `<li>· <code>${esc(d.deviceId || '????')}</code>${me} ${esc(d.label || '')}<span class="muted">${esc(exp)}</span></li>`
      }).join('') + '</ul><p class="muted">Para revocar un dispositivo, usa <code>dotrino-vault revoke</code> en tu PC.</p>'
    }).catch(() => { const box = document.getElementById('devlist'); if (box) box.textContent = 'No se pudo cargar (¿el vault está encendido?).' })
    return
  }

  showState('Conectar a tu bóveda', `<div class="vault-wrap">
    <p>Conecta este navegador a tu <strong>bóveda</strong> (el programa <code>dotrino-vault</code> en tu PC),
       para que tu información viva en tu propio servidor. En tu PC ejecuta <code>dotrino-vault pair</code>
       y pega aquí el código que muestra:</p>
    <textarea id="qr" rows="4" placeholder='{"v":2,"iss":"…","proxy":"…","token":"…","sn":"…"}'></textarea>
    <div><button id="connect" class="btn">Conectar</button></div>
    <div id="vmsg"></div>
  </div>`)
  document.getElementById('connect').onclick = async () => {
    const msg = document.getElementById('vmsg')
    let qr
    try { qr = JSON.parse(document.getElementById('qr').value.trim()) }
    catch { msg.innerHTML = '<div class="banner bad">Ese código no es válido. Copia el objeto completo que muestra <code>dotrino-vault pair</code>.</div>'; return }
    document.getElementById('connect').disabled = true
    msg.innerHTML = '<div class="banner">Conectando…</div>'
    const off = id.onVault((e) => {
      if (e.phase === 'challenge') {
        msg.innerHTML = `<div class="sas-box">
          <p>Verifica que este código sea <strong>idéntico</strong> al que muestra tu PC, y apruébalo ahí:</p>
          <div class="sas">${esc(e.sas)}</div>
          <p class="muted">En tu PC: <code>dotrino-vault approve ${esc(e.deviceId)}</code></p>
          <p class="muted">Esperando tu aprobación en el PC…</p>
        </div>`
      }
    })
    try {
      await id.enrollDevice(qr); off()
      msg.innerHTML = '<div class="banner ok">✓ ¡Conectado! Este dispositivo ahora usa tu bóveda.</div>'
      setTimeout(() => vaultMode(), 1600)
    } catch (e) {
      off(); document.getElementById('connect').disabled = false
      msg.innerHTML = `<div class="banner bad">No se pudo conectar: ${esc(e.message)}</div>`
    }
  }
}

async function main() {
  const data = parseHash()

  if (data.mode === 'vault') return vaultMode()

  // ── VALIDAR: firma del contenido + reputación del remitente, en un paso ──
  if (data.mode === 'validate') {
    const p = data.payload || {}
    const signed = { op: p.op || 'app-request', text: p.text, ts: p.ts }
    const ok = await verifySig(p.pubkey, signed, p.signature)
    const banner = ok
      ? `<div class="banner ok">✓ Firma válida${p.nickname ? ` — firmado por <strong>${esc(p.nickname)}</strong>` : ''}</div>`
      : `<div class="banner bad">✗ Firma inválida o no verificable</div>`
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
    showState('Link inválido', '<p>Este enlace no es válido.</p>')
    return
  }

  // ── RATE (#pubkey) o SELF (sin hash): perfil modal, requiere identidad ──
  let id, provider
  try { ({ id, provider } = await connectProvider()) } catch {
    showState('No se pudo conectar tu identidad', '<p>Esto requiere tu identidad de Dotrino. Recarga e inténtalo de nuevo.</p>')
    return
  }

  let pubkey, name, since, mode
  if (data.mode === 'rate') {
    pubkey = data.pubkey; name = data.name; since = data.since; mode = 'edit'
  } else {
    pubkey = id && id.me && id.me.publickey; name = id && id.me && id.me.nickname; mode = 'self'
    if (!pubkey) { showState('Sin identidad', '<p>No se encontró tu perfil. Crea tu identidad de Dotrino e inténtalo de nuevo.</p>'); return }
  }

  const el = makeProfile({ pubkey, name, since, mode, modal: true })
  el.provider = provider
  mount.innerHTML = ''
  mount.appendChild(el)
}

window.addEventListener('hashchange', () => window.location.reload())
main()

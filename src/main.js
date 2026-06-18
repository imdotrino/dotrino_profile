/**
 * dotrino_profile — página pública de perfil + calificación (web-of-trust).
 *
 * Flujo:
 *   1. Lee el pubkey del SUJETO desde el #fragment (nunca llega al server, no
 *      indexable; igual que #room=/#rm= de las otras apps). El link del mail es
 *      https://profile.dotrino.com/#<pubkey-base64url>  (o #p=<pk>&name=<nombre>).
 *   2. Conecta el vault del VISITANTE (@dotrino/identity) — el que califica firma
 *      el rating con su clave; si no tiene identidad, el vault lo onboarda.
 *   3. Monta <dotrino-profile mode="edit"> con el provider (identity + reputation):
 *      el visitante ve el perfil del remitente y lo califica (confianza/afinidad).
 *
 * NO reimplementa nada: reutiliza @dotrino/profile (UI), @dotrino/identity
 * (firma/ratings) y @dotrino/reputation (registro) — las herramientas del ecosistema.
 */
import { Identity } from '@dotrino/identity'
import { createVaultReputation } from '@dotrino/reputation'
import { createVaultProfileProvider } from '@dotrino/profile'
import '@dotrino/profile' // registra el custom element <dotrino-profile>

const mount = document.getElementById('app')

const showState = (title, html = '') => {
  mount.innerHTML = `<div class="state">${title ? `<h1>${title}</h1>` : ''}${html}</div>`
}

// base64url → texto (UTF-8 seguro)
function b64urlDecode(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  try {
    return decodeURIComponent(
      atob(s).split('').map((c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join(''),
    )
  } catch {
    return atob(s)
  }
}

// Soporta "#<b64pubkey>" o "#p=<b64pubkey>&name=<b64name>&since=<ms>"
function parseHash() {
  const h = location.hash.replace(/^#/, '').trim()
  if (!h) return null
  if (h.includes('=')) {
    const q = new URLSearchParams(h)
    const p = q.get('p') || q.get('pubkey')
    if (!p) return null
    return {
      pubkey: b64urlDecode(p),
      name: q.get('name') ? b64urlDecode(q.get('name')) : '',
      since: q.get('since') || '',
    }
  }
  return { pubkey: b64urlDecode(h), name: '', since: '' }
}

async function main() {
  const data = parseHash()

  // La identidad del visitante hace falta en ambos modos: para FIRMAR un rating
  // (modo edit) o para mostrar TU propio perfil (modo self, sin hash).
  let id, reputation = null
  try {
    id = await Identity.connect()
    try { reputation = createVaultReputation(id) } catch { /* sin reputación: el perfil igual abre */ }
  } catch (err) {
    showState('No se pudo conectar tu identidad', '<p>Esto requiere tu identidad de Dotrino. Recarga e inténtalo de nuevo.</p>')
    return
  }

  const el = document.createElement('dotrino-profile')
  el.setAttribute('modal', '')
  el.setAttribute('lang', 'auto')
  el.addEventListener('cc-profile-close', () => { window.location.href = 'https://dotrino.com' })

  if (data && data.pubkey) {
    // CON hash → calificar al sujeto del link.
    el.setAttribute('mode', 'edit')
    el.setAttribute('pubkey', data.pubkey)
    if (data.name) el.setAttribute('name', data.name)
    if (data.since) el.setAttribute('since', data.since)
  } else {
    // SIN hash → mi propio perfil (nombre editable, sin auto-calificarme).
    const myPk = id && id.me && id.me.publickey
    if (!myPk) {
      showState('Sin identidad', '<p>No se encontró tu perfil. Crea tu identidad de Dotrino e inténtalo de nuevo.</p>')
      return
    }
    el.setAttribute('mode', 'self')
    el.setAttribute('pubkey', myPk)
    if (id.me.nickname) el.setAttribute('name', id.me.nickname)
  }

  el.provider = createVaultProfileProvider({ identity: id, reputation })
  mount.innerHTML = ''
  mount.appendChild(el)
}

window.addEventListener('hashchange', () => { window.location.reload() })
main()

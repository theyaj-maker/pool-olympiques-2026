// =====================================================
// 1) IMPORTS (toujours au tout début du module)
// =====================================================
import { State } from './state.js';
import { CSV }   from './csv.js';
import { Adapters } from './adapters.js';

// --- SafeStorage: localStorage -> sessionStorage -> in-memory ---
const SafeStorage = (function(){
  var mem = {};
  function hasLocal(){
    try { var k='__t'; localStorage.setItem(k,'1'); localStorage.removeItem(k); return true; } catch(e){ return false; }
  }
  function hasSession(){
    try { var k='__t'; sessionStorage.setItem(k,'1'); sessionStorage.removeItem(k); return true; } catch(e){ return false; }
  }
  var backend = hasLocal() ? localStorage : (hasSession() ? sessionStorage : null);
  return {
    getItem: function(k){ try { return backend ? backend.getItem(k) : (mem.hasOwnProperty(k)? mem[k] : null); } catch(e){ return mem.hasOwnProperty(k)? mem[k] : null; } },
    setItem: function(k,v){ try { if (backend) backend.setItem(k,v); else mem[k]=v; } catch(e){ mem[k]=v; } },
    removeItem: function(k){ try { if (backend) backend.removeItem(k); else delete mem[k]; } catch(e){ delete mem[k]; } },
    type: backend === localStorage ? 'localStorage' : (backend === sessionStorage ? 'sessionStorage' : 'memory')
  };
})();

// Petit utilitaire DOM facultatif (si tu veux)
const qs = (sel) => document.querySelector(sel);

// =====================================================
// 2) INITIALISATION CENTRALE DU STATE (une seule fois)
//    -> accessible partout via "state" et via window.state
// =====================================================
const __existing = window.__POOL_STATE__;
export const state = __existing || State.load();
if (!__existing) {
  window.__POOL_STATE__ = state;
  window.state = state; // pratique pour le debug dans la console
}

/*** =========================================================
 * ACCÈS PAR JETON SIGNÉ — ZÉRO SECRET DANS LE REPO
 * ECDSA P‑256 (clé privée conservée par toi), SHA‑256
 * Token compact = base64url(JSON payload) + "." + base64url(signature)
 * Payload conseillé : { role:"viewer"|"manager", exp:"ISO", aud:"https://<user>.github.io/<repo>", sub?:... }
 *========================================================= ***/

// 3) CLÉ PUBLIQUE JWK (non secrète) — COLLER ICI LA TIENNE
const PUBLIC_JWK = {
  "crv": "P-256",
  "ext": true,
  "key_ops": ["verify"],
  "kty": "EC",
  "x": "yhuI022ZqJOwpoB1o8NvywoDWBNEqRaIP7gwdCi8j6M",
  "y": "34j5Ghey2nwlSnhIi23nXhY8jcnDdgwu5OJ9k592w-0"
};

// 4) Helpers base64url
const b64urlToBytes = (s) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
  s += '='.repeat(pad);
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
};
const bytesToB64url = (buf) => {
  const b = Array.from(new Uint8Array(buf)).map(ch => String.fromCharCode(ch)).join('');
  return btoa(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

// 5) Import clé publique WebCrypto (ECDSA P‑256)
async function importPublicKey(jwk) {
  return crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, ['verify']
  );
}

// 6) Vérifier un token (signature + exp/nbf/aud + rôle)
async function verifyToken(token) {
  try {
    if (!token) return { ok:false, msg:'Token manquant' };

    const dot = token.indexOf('.');
    if (dot <= 0) return { ok:false, msg:'Format token invalide' };

    const pB64 = token.slice(0, dot);
    const sB64 = token.slice(dot + 1);

    const payloadJSON = new TextDecoder().decode(b64urlToBytes(pB64));
    const payload = JSON.parse(payloadJSON);

    // dates / audience
    const now = new Date();
    if (payload.nbf && now < new Date(payload.nbf)) return { ok:false, msg:'Token non actif (nbf)' };
    if (payload.exp && now > new Date(payload.exp)) return { ok:false, msg:'Token expiré' };
    if (payload.aud) {
      const expectedOrigin  = location.origin;                                  // ex: https://theyaj-maker.github.io
      const repoBase        = location.pathname.split('/').slice(0,2).join('/'); // ex: /pool-olympiques-2026
      const expectedWithRepo= expectedOrigin + repoBase;                         // ex: https://theyaj-maker.github.io/pool-olympiques-2026
      if (payload.aud !== expectedOrigin && payload.aud !== expectedWithRepo) {
        return { ok:false, msg:'Audience invalide' };
      }
    }

    // rôle
    if (payload.role !== 'viewer' && payload.role !== 'manager') {
      return { ok:false, msg:'Rôle invalide' };
    }

    // signature
    const pubKey = await importPublicKey(PUBLIC_JWK);
    const ok = await crypto.subtle.verify(
      { name:'ECDSA', hash:'SHA-256' },
      pubKey,
      b64urlToBytes(sB64),
      new TextEncoder().encode(pB64)
    );
    if (!ok) return { ok:false, msg:'Signature invalide' };

    return { ok:true, payload };
  } catch (e) {
    console.error('verifyToken error:', e);
    return { ok:false, msg:'Erreur interne' };
  }
}

// 7) Stockage local (non sensible) du statut d’accès
function setAuth(role, payload, token) {
  SafeStorage.setItem('pool-auth', JSON.stringify({ role, payload, token }));
}
function getAuth() {
  try { return JSON.parse(SafeStorage.getItem('pool-auth')); } catch { return null; }
}
function clearAuth() {
  SafeStorage.removeItem('pool-auth');
}

// 8) Appliquer l’accès (affiche/masque portail et blocs admin)
function applyAccessControls() {
  const auth = getAuth();
  const role = auth?.role || 'viewer';
  document.body.setAttribute('data-role', role);

  const app  = document.getElementById('app-root');
  const gate = document.getElementById('access-gate');

  if (auth) { gate.hidden = true;  app.hidden = false; }
  else      { gate.hidden = false; app.hidden = true;  }

  // Blocs manager-only
  document.querySelectorAll('[data-role="manager-only"]').forEach(el => {
    el.style.display = (role === 'manager') ? '' : 'none';
  });

  // Barre client & badge visibles après auth
  const badge = document.getElementById('status-badge');
  const bar   = document.getElementById('client-toolbar');
  if (badge) badge.hidden = !auth;
  if (bar)   bar.hidden   = !auth;
  // Active la réserve en haut quand le badge est visible
(function ensureBadgePadding(){
  const badge = document.getElementById('status-badge');
  if (!badge) return;
  // Badge visible => ajoute une classe au body (mobile détectera via CSS)
  badge.hidden ? document.body.classList.remove('has-status-badge')
               : document.body.classList.add('has-status-badge');
})();

}

// 9) Essayer ?token=... ou #token=...
async function tryTokenFromURL() {
  const url   = new URL(location.href);
  const raw   = url.searchParams.get('token') ||
                (location.hash.startsWith('#token=') ? location.hash.slice(7) : null);
  if (!raw) return false;

  // nettoyage léger (au cas où un espace/retour ligne s’est glissé)
  const token = raw.trim().replace(/\s+/g, '');

  const res = await verifyToken(token);
  const msg = document.getElementById('gate-msg');

  if (res.ok) {
    setAuth(res.payload.role, res.payload, token);
    applyAccessControls();
    return true;
  } else {
    if (msg) msg.textContent = `Token invalide : ${res.msg}`;
    return false;
  }
}

// 10) Collage manuel dans le portail
function bindGateUI() {
  const btn = document.getElementById('btn-try-token');
  const ta  = document.getElementById('paste-token');
  const msg = document.getElementById('gate-msg');

  if (btn && ta) {
    btn.onclick = async () => {
      const token = (ta.value || '').trim().replace(/\s+/g, '');
      const res = await verifyToken(token);
      if (res.ok) {
        setAuth(res.payload.role, res.payload, token);
        applyAccessControls();
      } else {
        msg.textContent = `Token invalide : ${res.msg}`;
      }
    };
  }
}
function setStatus(level='ok', text=''){
  const badge = document.getElementById('status-badge');
  if (!badge) return;
  badge.hidden = false;
  badge.classList.remove('ok','warn','err');
  badge.classList.add(level);
  badge.innerHTML = `<span class="dot" aria-hidden="true"></span><span>${text || ' '}</span>`;
  document.body.classList.add('has-status-badge');  // <= important
}
function setStatusOK(summary='Synchro OK'){
  const ts = new Date().toLocaleTimeString();
  setStatus('ok', `${summary} · ${ts}`);
}
function setStatusWarn(msg='Synchronisation en cours…'){
  setStatus('warn', msg);
}
function setStatusErr(msg='Erreur de synchronisation'){
  setStatus('err', msg);
}

// ---------- Helpers numériques sûrs ----------
function safeNum(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}
function safeFixed(v, d = 1) {
  const n = Number(v);
  return Number.isFinite(n) ? n.toFixed(d) : (0).toFixed(d);
}

// Flag sécurité : mets false si tu dois rollback instantanément
var SAFE_MOBILE_CARDS = true;

// Détecte “mobile”
function isMobile() {
  var w = (typeof window !== 'undefined' && window.innerWidth) ? window.innerWidth : 1024;
  var dw = (document.documentElement && document.documentElement.clientWidth) ? document.documentElement.clientWidth : w;
  return ((w || dw) <= 768);
}

function renderLeaderboardCardsMobile() {
  try {
    // Conditions pour afficher les cartes
    if (!SAFE_MOBILE_CARDS || !isMobile()) { showLeaderboardMode('table'); return; }

    var host    = document.getElementById('leaderboard-cards');
    var tblHost = document.getElementById('leaderboard');
    if (!host || !tblHost) return;

    host.innerHTML = '';

    // Recalcule les scores (total + today + yest)
    var totals = [];
    try { totals = computeScoresWithDaily() || []; } catch(e){ console.warn(e); totals = []; }

    // Rendu minimal si aucun pooler
    if (!totals.length) {
      host.innerHTML = '<div class="lb-card"><em>Aucun pooler à afficher</em></div>';
    } else {
      for (var i=0; i<totals.length; i++) {
        var r = totals[i];
        var card = document.createElement('div');
        card.className = 'lb-card';
        card.innerHTML =
          '<div class="lb-head">' +
            '<div class="lb-rank">'+ (i+1) +'</div>' +
            '<div class="lb-name"><button class="link-btn" data-open-pooler="' + r.pooler + '">' + r.pooler + '</button></div>' +
            '<div class="lb-total">🥇 ' + Number(r.points||0).toFixed(1) + '</div>' +
          '</div>' +
          '<div class="lb-sub">' +
            '<div class="lb-badge today"><span class="dot"></span> Aujourd’hui&nbsp;' + Number(r.today||0).toFixed(1) + '</div>' +
            '<div class="lb-badge yest"><span class="dot"></span> Hier&nbsp;' + Number(r.yest||0).toFixed(1) + '</div>' +
          '</div>';
        host.appendChild(card);
      }
    }

    // Si on a bien quelque chose dans host, bascule en “cartes”, sinon garde “table”
    if (host.children.length > 0) showLeaderboardMode('cards');
    else                          showLeaderboardMode('table');

    // Clic -> modale
    var btns = host.querySelectorAll('[data-open-pooler]');
    for (var j=0; j<btns.length; j++) {
      (function(b){
        b.onclick = function(){ openPoolerModal(b.getAttribute('data-open-pooler')); };
      })(btns[j]);
    }
  } catch (e) {
    console.warn('renderLeaderboardCardsMobile error:', e);
    showLeaderboardMode('table');
  }
}

function showLeaderboardMode(mode){
  var wrap  = document.getElementById('leaderboard-wrap');
  var tbl   = document.getElementById('leaderboard');
  var cards = document.getElementById('leaderboard-cards');
  if (!wrap || !tbl || !cards) return;

  if (mode === 'cards') {
    // On bascule par la classe sur le WRAPPER (surpasse le !important global)
    if (wrap.className.indexOf('cards-on') === -1) wrap.className += (wrap.className ? ' ' : '') + 'cards-on';
  } else {
    // Retire 'cards-on'
    wrap.className = (wrap.className || '').replace(/\bcards-on\b/g, '').trim();
  }
}

function showModalListsMode(mode){
  var pt = document.getElementById('pooler-players-table');
  var pc = document.getElementById('pooler-players-cards');
  var dt = document.getElementById('pooler-daily-table');
  var dc = document.getElementById('pooler-daily-cards');
  if (pt && pc) { pt.style.display = (mode==='cards'?'none':''); pc.style.display = (mode==='cards'?'block':'none'); }
  if (dt && dc) { dt.style.display = (mode==='cards'?'none':''); dc.style.display = (mode==='cards'?'block':'none'); }
}

// ---------- Compte les "matchs joués" (1 ligne de stats = 1 match) ----------
function countMatches(playerName, fromStr, toStr){
  const days = state.stats?.[playerName] || {};
  const from = fromStr ? new Date(fromStr + 'T00:00:00') : null;
  const toEff = toStr || new Date().toISOString().slice(0,10);
  const to = new Date(toEff + 'T23:59:59');

  let mj = 0;
  Object.entries(days).forEach(([d,v]) => {
    const dt = new Date(d + 'T12:00:00');
    if (from && dt < from) return;
    if (to   && dt > to)   return;
    mj += Number(v?.played || 0);
  });
  return mj;
}

/***** =========================================
 * SOURCES DISTANTES (CSV publiés - Google Sheets)
 *  - Poolers : pooler,skaters,goalies
 *  - Rosters : pooler,player[,position,team,box]
 *  - Stats   : (déjà géré par stats-url existant)
 *=========================================== ***/

const REFRESH_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

// On stocke les URLs dans localStorage (clé dédiée)
const REMOTE_KEY = 'pool-remote-sources';


function getRemoteSources(){
  try { var raw = SafeStorage.getItem('pool-remote-sources'); if (raw) return JSON.parse(raw); } catch(_){}
  return { playersUrl:'', poolersUrl:'', statsUrl:'' };
}
function setRemoteSources(s){
  SafeStorage.setItem('pool-remote-sources', JSON.stringify(s));
}

function takeRemoteFromURL(){
  var raw = location.href.replaceAll('&amp;', '&'); // normalise
  var u = new URL(raw);
  var src = getRemoteSources();
  var changed = false;

  function pick(key){
    var std = u.searchParams.get(key) || '';
    if (std && (std.includes('gid=') || std.includes('tqx=out:csv'))) return std;
    // fallback brut si non-encodé
    var i = raw.indexOf(key + '=');
    if (i < 0) return std;
    var start = i + key.length + 1;
    var stops = ['&players=','&poolers=','&stats=','&token=','#'];
    var end = raw.length;
    for (var s of stops){ var j = raw.indexOf(s, start); if (j >= 0 && j < end) end = j; }
    var slice = raw.slice(start, end);
    try { return decodeURIComponent(slice); } catch { return slice; }
  }

  var P = pick('players');
  var L = pick('poolers');
  var S = pick('stats');

  if (P && src.playersUrl !== P) { src.playersUrl = P; changed = true; }
  if (L && src.poolersUrl !== L) { src.poolersUrl = L; changed = true; }
  if (S && src.statsUrl   !== S) { src.statsUrl   = S; changed = true; }

  if (changed) setRemoteSources(src);
}


async function fetchTextNoCache(url){
  if (!url) return '';
  const r = await fetch(url, { cache: 'no-store' });
  if (!r.ok) throw new Error(`HTTP ${r.status} on ${url}`);
  return await r.text();
}

async function loadPlayersFromCSV(url){
  if (!url) return;
  const txt = await fetch(url, { cache:'no-store' }).then(r=>r.text());
  const rows = CSV.parse(txt);
  if (!rows.length) throw new Error('Joueurs CSV vide');

  const norm = s => String(s||'').toLowerCase().trim().replace(/\s+|_/g,'');
  const headerRaw = rows.shift();
  const header = headerRaw.map(norm);
  const find = (...alts) => { for (const a of alts){ const i=header.indexOf(a); if(i>=0) return i; } return -1; };

  const idx = {
    name:     find('name','nom','player','joueur'),
    position: find('position','pos'),
    team:     find('team','equipe','country','nation'),
    box:      find('box','boite','case')
  };
  if (idx.name < 0) {
    console.warn('[Joueurs] En-têtes reçus =', headerRaw, '→ normalisés =', header);
    throw new Error('Joueurs CSV: colonne "name" (ou alias) introuvable');
  }

  const players = [];
  rows.forEach(r=>{
    const name = (r[idx.name]||'').toString().trim();
    if (!name) return;
    const posRaw = (idx.position>=0 ? (r[idx.position]||'') : '').toString().trim().toUpperCase();
    const position = posRaw.startsWith('G') ? 'G' : (posRaw.startsWith('D') ? 'D' : (posRaw ? 'F' : 'F'));
    const team = (idx.team>=0 ? (r[idx.team]||'') : '').toString().trim().toUpperCase();
    const bxRaw = (idx.box >=0 ? (r[idx.box] ||'') : '').toString().trim().toUpperCase();
    const box = /^(B([1-9]|10)|G1|G2|BONUS)$/.test(bxRaw) ? bxRaw : '';
    players.push({ name, position, team, box });
  });

  state.players = players;
  State.save(state);
  refreshPlayersDatalist?.();
  renderPlayers?.('');
}
// Rosters CSV: pooler,player[,position,team,box] — position/team/box facultatifs
async function loadRostersFromCSV(url){
  if (!url) return;
  const txt = await fetch(url, { cache:'no-store' }).then(r=>r.text());
  const rows = CSV.parse(txt);
  if (!rows.length) throw new Error('Poolers CSV vide');

  const norm = s => String(s||'').toLowerCase().trim().replace(/\s+|_/g,'');
  const headerRaw = rows.shift();
  const header = headerRaw.map(norm);
  const find = (...alts) => { for (const a of alts){ const i=header.indexOf(a); if(i>=0) return i; } return -1; };

  const idx = {
    pooler:   find('pooler','equipe','owner','nom'),
    player:   find('player','joueur','name'),
    position: find('position','pos'),
    team:     find('team','equipe','country','nation'),
    box:      find('box','boite','case')
  };
  if (idx.pooler<0 || idx.player<0) {
    console.warn('[Poolers] En-têtes reçus =', headerRaw, '→ normalisés =', header);
    throw new Error('Poolers CSV: colonnes requises (pooler,player) introuvables');
  }

  // Indexe / enrichit la liste maîtresse
  const master = new Map((state.players||[]).map(p => [p.name.toLowerCase(), p]));

  // Map temporaire solide (pas de trous) : pooler -> objet complet
  const map = new Map();

  rows.forEach(r=>{
    const poolerName = (r[idx.pooler]||'').toString().trim();
    const playerName = (r[idx.player]||'').toString().trim();
    if (!poolerName) return;

    if (!map.has(poolerName)) {
      map.set(poolerName, { name: poolerName, roster:{ skaters:15, goalies:2 }, players: [] });
    }
    if (!playerName) return;

    const pl = map.get(poolerName);
    if (!pl.players.includes(playerName)) pl.players.push(playerName);

    // Enrichit la liste maîtresse si info fournie
    const posRaw = (idx.position>=0 ? (r[idx.position]||'') : '').toString().trim().toUpperCase();
    const position = posRaw.startsWith('G') ? 'G' : (posRaw.startsWith('D') ? 'D' : (posRaw ? 'F' : ''));
    const team = (idx.team>=0 ? (r[idx.team]||'') : '').toString().trim().toUpperCase();
    const bxRaw = (idx.box >=0 ? (r[idx.box] ||'') : '').toString().trim().toUpperCase();
    const box = /^(B([1-9]|10)|G1|G2|BONUS)$/.test(bxRaw) ? bxRaw : '';

    const ex = master.get(playerName.toLowerCase());
    if (!ex) {
      const np = { name: playerName, position: position || 'F', team, box };
      state.players.push(np);
      master.set(playerName.toLowerCase(), np);
    } else {
      if (!ex.position && position) ex.position = position;
      if (!ex.team && team) ex.team = team;
      if (!ex.box && box) ex.box = box;
    }
  });

  // Écrit un tableau compact sans trous
  state.poolers = Array.from(map.values());
  State.save(state);

  // Rendu
  renderPoolers?.();
  refreshDraftPooler?.();
  renderRosterView?.();
  renderPoolersCardsMobile();
  computeAndRender?.();
}
// Poolers CSV attendu : pooler,skaters,goalies
async function loadPoolersFromCSV(url){
  if (!url) return;
  const text = await fetchTextNoCache(url);
  const rows = CSV.parse(text);
  if (!rows.length) throw new Error('Poolers CSV vide');

  const header = rows.shift().map(h => h.toLowerCase().trim());
  const idx = {
    pooler:  header.indexOf('pooler'),
    skaters: header.indexOf('skaters'),
    goalies: header.indexOf('goalies')
  };
  if (idx.pooler < 0 || idx.skaters < 0 || idx.goalies < 0) {
    throw new Error('Poolers CSV: en-têtes requis = pooler,skaters,goalies');
  }

  const byName = Object.create(null);
  (state.poolers || []).forEach(p => byName[p.name.toLowerCase()] = p);

  const list = [];
  rows.forEach(r => {
    const name = (r[idx.pooler] || '').toString().trim();
    if (!name) return;
    const sk = parseInt(r[idx.skaters] || '15', 10) || 15;
    const go = parseInt(r[idx.goalies] || '2', 10) || 2;
    const ex = byName[name.toLowerCase()];
    list.push({ name, roster:{skaters:sk, goalies:go}, players: ex ? (ex.players || []) : [] });
  });

  state.poolers = list;
  State.save(state);
  renderPoolers();
  refreshDraftPooler();
  renderRosterView();
  computeAndRender();
}

async function refreshAllRemote(){
  const src = getRemoteSources();

  if (src.playersUrl) {
    try { await loadPlayersFromCSV(src.playersUrl); }
    catch(e){ console.warn('Joueurs CSV:', e.message||e); }
  }
  if (src.poolersUrl) {
    try { await loadRostersFromCSV(src.poolersUrl); }
    catch(e){ console.warn('Poolers CSV:', e.message||e); }
  }
  const elS = document.getElementById('stats-url');
  const statsUrl = (elS && elS.value) ? elS.value.trim() : (src.statsUrl || '');
  if (statsUrl) {
    try {
      const txt = await fetch(statsUrl, { cache:'no-store' }).then(r=>r.text());
      await ingestStatsFromCSVText(txt);
    } catch(e){
      console.warn('Stats CSV:', e.message||e);
    }
  }
  computeAndRender?.();
}
// 🔓 expose pour tests console (modules ES ne mettent pas les fonctions en global)
window.refreshAllRemote = refreshAllRemote;


// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
//  Fonction demandée : bindRemoteSourcesUI()
// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
function bindRemoteSourcesUI(){
  const src = getRemoteSources();

  const elPlayers = document.getElementById('players-url');
  const elPoolers = document.getElementById('poolers-url');
  const elStats   = document.getElementById('stats-url');

  if (elPlayers && src.playersUrl) elPlayers.value = src.playersUrl;
  if (elPoolers && src.poolersUrl) elPoolers.value = src.poolersUrl;
  if (elStats   && src.statsUrl)   elStats.value   = src.statsUrl;

  const btnSave = document.getElementById('save-remote-sources');
  if (btnSave) {
    btnSave.onclick = () => {
      const cur = getRemoteSources();
      if (elPlayers) cur.playersUrl = (elPlayers.value || '').trim();
      if (elPoolers) cur.poolersUrl = (elPoolers.value || '').trim();
      if (elStats)   cur.statsUrl   = (elStats.value   || '').trim();
      setRemoteSources(cur);
      alert('Sources sauvées.');
    };
  }

  const btnRef = document.getElementById('refresh-remote');
  if (btnRef) btnRef.onclick = () => refreshAllRemote();

  // Si on a déjà des URLs mémorisées, charger automatiquement
  if (src.playersUrl || src.poolersUrl || src.statsUrl) {
    refreshAllRemote().catch(console.warn);
  }
}
/***** =======================================================
 *  SÉLECTION PAR BOÎTES (B1..B10, G1, G2, BONUS x5)
 *========================================================= ***/

// Définition des boîtes et des quotas (cohérent avec BOX_RULES existants)
const BOX_LAYOUT = [
  { key:'B1',    label:'Boîte B1',   picks:1 },
  { key:'B2',    label:'Boîte B2',   picks:1 },
  { key:'B3',    label:'Boîte B3',   picks:1 },
  { key:'B4',    label:'Boîte B4',   picks:1 },
  { key:'B5',    label:'Boîte B5',   picks:1 },
  { key:'B6',    label:'Boîte B6',   picks:1 },
  { key:'B7',    label:'Boîte B7',   picks:1 },
  { key:'B8',    label:'Boîte B8',   picks:1 },
  { key:'B9',    label:'Boîte B9',   picks:1 },
  { key:'B10',   label:'Boîte B10',  picks:1 },
  { key:'G1',    label:'Gardiens G1',picks:1 },
  { key:'G2',    label:'Gardiens G2',picks:1 },
  { key:'BONUS', label:'BONUS',      picks:5 },
];

// Retourne la liste des joueurs pour une boîte donnée (triés)
function getPlayersByBox(boxKey){
  return state.players
    .filter(p => (p.box||'').toUpperCase() === boxKey.toUpperCase())
    .sort((a,b)=> a.name.localeCompare(b.name));
}

// Construit une <option> lisible
function optionLabel(p){
  // Ex: "Connor McDavid — F-CAN  [B3]"
  return `${p.name} — ${p.position||''}-${p.team||''}  [${p.box||''}]`;
}

// Rend la grille des <select> par boîtes
function renderBoxDraftUI(){
  const grid = document.getElementById('box-draft-grid');
  if(!grid) return;
  grid.innerHTML = '';

  const poolerSel = document.getElementById('draft-pooler');
  const poolerName = poolerSel ? poolerSel.value : null;
  const pooler = state.poolers.find(x=>x.name===poolerName);

  // On va désactiver les joueurs déjà pris par ce pooler
  const already = new Set((pooler?.players||[]));

  BOX_LAYOUT.forEach(box=>{
    const card = document.createElement('div');
    card.className = 'box-card';

    // Titre
    const h = document.createElement('h4');
    h.textContent = `${box.label} ${box.picks>1 ? `(${box.picks} choix)` : ''}`;
    card.appendChild(h);

    // Génère N <select> pour cette boîte
    for(let i=1; i<=box.picks; i++){
      const sel = document.createElement('select');
      sel.id = (box.key==='BONUS' ? `box-${box.key}-${i}` : `box-${box.key}`);
      const placeholder = document.createElement('option');
      placeholder.value = '';
      placeholder.textContent = '— choisir —';
      sel.appendChild(placeholder);

      // Options = joueurs de cette boîte
      getPlayersByBox(box.key).forEach(p=>{
        const opt = document.createElement('option');
        opt.value = p.name;
        opt.textContent = optionLabel(p);
        // Si déjà au roster, on grise
        if(already.has(p.name)) opt.disabled = true;
        sel.appendChild(opt);
      });

      // Marges
      sel.style.marginBottom = '6px';
      card.appendChild(sel);
    }

    grid.appendChild(card);
  });
}

// Efface les sélections en cours
function clearBoxDraftSelections(){
  const grid = document.getElementById('box-draft-grid');
  if(!grid) return;
  grid.querySelectorAll('select').forEach(sel => sel.value = '');
}

// Ajoute un joueur au roster avec validations (réutilise tes règles)
function addOneToRoster(pooler, player){
  // déjà pris ?
  pooler.players = pooler.players || [];
  if(pooler.players.includes(player.name)) return { ok:false, msg:`${player.name} est déjà dans le roster` };

  // limites roster
  const counts = countRoster(pooler);
  if(player.position==='G' && counts.go >= pooler.roster.goalies){
    return { ok:false, msg:`Limite de gardiens atteinte (${pooler.roster.goalies})` };
  }
  if(player.position!=='G' && counts.sk >= pooler.roster.skaters){
    return { ok:false, msg:`Limite de skaters atteinte (${pooler.roster.skaters})` };
  }

  // règles de boîtes
  if(state.boxRulesEnabled && player.box){
    const boxCounts = getBoxCounts(pooler);
    const BOX_RULES = { B1:1,B2:1,B3:1,B4:1,B5:1,B6:1,B7:1,B8:1,B9:1,B10:1, G1:1, G2:1, BONUS:5 };
    const limit = BOX_RULES[player.box] || Infinity;
    const cur = boxCounts[player.box] || 0;
    if(cur >= limit){
      return { ok:false, msg:`Limite atteinte pour la boîte ${player.box}` };
    }
  }

  // OK
  pooler.players.push(player.name);
  return { ok:true };
}

// Collecte toutes les sélections et ajoute au roster
function applyBoxDraft(){
  const poolerSel = document.getElementById('draft-pooler');
  if(!poolerSel || !poolerSel.value) { alert('Sélectionne un pooler.'); return; }
  const pooler = state.poolers.find(x=>x.name===poolerSel.value);
  if(!pooler){ alert('Pooler introuvable.'); return; }

  // Récupère tous les selects remplis
  const grid = document.getElementById('box-draft-grid');
  const chosenNames = [];
  grid.querySelectorAll('select').forEach(sel=>{
    const v = sel.value.trim();
    if(v) chosenNames.push(v);
  });

  if(chosenNames.length===0){ alert('Aucun joueur sélectionné.'); return; }

  // Ajoute un par un avec validations
  const errors = [];
  chosenNames.forEach(name=>{
    const p = state.players.find(x=>x.name===name);
    if(!p){ errors.push(`${name}: introuvable`); return; }
    const res = addOneToRoster(pooler, p);
    if(!res.ok) errors.push(`${name}: ${res.msg}`);
  });

  // Sauvegarde & rafraîchit
  State.save(state);
  renderPoolers();
  renderRosterView();
  renderBoxDraftUI(); // regénère les menus (désactive ce qui vient d’être pris)
  computeAndRender();

  if(errors.length){
    alert(`Certaines sélections n'ont pas pu être ajoutées:\n- ${errors.join('\n- ')}`);
  }else{
    alert('Sélection ajoutée.');
  }
}

// Bind des boutons
function bindBoxDraft(){
  const applyBtn = document.getElementById('box-draft-apply');
  const clearBtn = document.getElementById('box-draft-clear');
  if(applyBtn) applyBtn.onclick = applyBoxDraft;
  if(clearBtn) clearBtn.onclick = clearBoxDraftSelections;

  // Re-rendre la grille quand on change de pooler
  const poolerSel = document.getElementById('draft-pooler');
  if(poolerSel) poolerSel.addEventListener('change', renderBoxDraftUI);
}

function exportPoolersCSV(){
  const rows = [];
  rows.push("pooler,player,position,team,box");

  (state.poolers || []).forEach(pl => {
    (pl.players || []).forEach(name => {
      const p = state.players.find(x => x.name === name);
      if(!p) return;
      rows.push(
        [
          CSV.escape(pl.name),
          CSV.escape(p.name),
          p.position || "",
          p.team || "",
          p.box || ""
        ].join(",")
      );
    });
  });

  const blob = new Blob([rows.join("\n")], {type: "text/csv;charset=utf-8;"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "poolers_export.csv";
  a.click();
}

// --- Scoring ---
function renderScoring(){
  qs('#pts-goal').value = state.scoring.goal;
  qs('#pts-assist').value = state.scoring.assist;
  qs('#pts-win').value = state.scoring.goalie_win;
  qs('#pts-otl').value = state.scoring.goalie_otl;
  qs('#pts-so').value = state.scoring.shutout;
}
function bindScoring(){
  qs('#save-scoring').onclick = () => {
    state.scoring.goal = parseFloat(qs('#pts-goal').value)||0;
    state.scoring.assist = parseFloat(qs('#pts-assist').value)||0;
    state.scoring.goalie_win = parseFloat(qs('#pts-win').value)||0;
    state.scoring.goalie_otl = parseFloat(qs('#pts-otl').value)||0;
    state.scoring.shutout = parseFloat(qs('#pts-so').value)||0;
    State.save(state);
    alert('Paramètres enregistrés');
    computeAndRender();
  };
  qs('#reset-scoring').onclick = () => { State.resetScoring(state); renderScoring(); State.save(state); computeAndRender(); };
}

// --- Players master ---
function renderPlayers(filter = '') {
  const cont = document.getElementById('players-list');
  if (!cont) return;

  // Pas de zébrage sur cette zone si tu veux
  cont.classList.add('no-zebra');

  const players = (state.players || [])
    .filter(p => `${p.name} ${p.team} ${p.position} ${p.box || ''}`.toLowerCase().includes((filter || '').toLowerCase()))
    .sort((a, b) => a.name.localeCompare(b.name));

  const table = document.createElement('table');
  table.classList.add('table');
  table.innerHTML = `
    <thead>
      <tr>
        <th>Nom</th><th>Pos</th><th>Équipe</th><th>Boîte</th><th class="only-manager"></th>
      </tr>
    </thead>`;

  const tbody = document.createElement('tbody');

  players.forEach(p => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${p.name}</td>
      <td>${p.position}</td>
      <td>${p.team || ''}</td>
      <td>${p.box || ''}</td>`;

    const td = document.createElement('td');
    const del = document.createElement('button');
    
del.className = 'secondary only-manager';
del.setAttribute('data-role','manager-only')

    del.textContent = 'Supprimer';
    del.onclick = () => {
      state.players = state.players.filter(x => x !== p);
      State.save(state);
      renderPlayers(filter);
      refreshPlayersDatalist?.();
      renderBoxDraftUI?.();
    };
    td.appendChild(del);
    tr.appendChild(td);
    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  cont.innerHTML = '';
  cont.appendChild(table);
}
function refreshPlayersDatalist(){
  const dl = qs('#players-datalist');
  dl.innerHTML = state.players.sort((a,b)=>a.name.localeCompare(b.name)).map(p=>`<option value="${p.name}">${p.name} (${p.position}-${p.team||''}) [${p.box||'-'}]</option>`).join('');
}
function bindPlayers() {
  // Récupère toutes les références d’éléments (peuvent être null si la section n’existe pas)
  const addBtn        = document.getElementById('add-player');
  const search        = document.getElementById('player-search');
  const importUrlBtn  = document.getElementById('import-players-url');
  const importFileBtn = document.getElementById('import-players-file');
  const fileInput     = document.getElementById('players-file');
  const exportBtn     = document.getElementById('export-players');

  // Si aucun des contrôles n'est présent, on sort : la section "Joueurs" n'est probablement pas dans l'HTML.
  if (!addBtn && !search && !importUrlBtn && !importFileBtn && !fileInput && !exportBtn) {
    return;
  }

  // Helper normalisation + push d’un joueur (utilisé par les imports)
  const normalizePush = (header, idx, r) => {
    const name = r[idx.name];
    if (!name) return;

    // Pas de doublon par nom (case-insensitive)
    if (state.players.find(p => p.name.toLowerCase() === String(name).toLowerCase())) return;

    // Position normalisée
    const posRaw = ((r[idx.position] || 'F').toString().trim().toUpperCase());
    const posN   = posRaw.startsWith('G') ? 'G' : (posRaw.startsWith('D') ? 'D' : 'F');

    // Équipe en MAJ
    const team   = ((r[idx.team] || '').toString().trim().toUpperCase());

    // Boîte normalisée (B1..B10 | G1 | G2 | BONUS)
    const rawBox = (idx.box >= 0 ? (r[idx.box] || '') : '').toString().trim().toUpperCase();
    const box    = /^(B([1-9]|10)|G1|G2|BONUS)$/.test(rawBox) ? rawBox : '';

    state.players.push({ name, position: posN, team, box });
  };

  // Ajout manuel
  if (addBtn) {
    addBtn.onclick = () => {
      const nameEl = document.getElementById('player-name');
      const posEl  = document.getElementById('player-position');
      const teamEl = document.getElementById('player-team');
      if (!nameEl || !posEl || !teamEl) return;

      const name     = nameEl.value.trim();
      const position = posEl.value; // 'F' | 'D' | 'G'
      const team     = teamEl.value.trim().toUpperCase();

      if (!name) return alert('Nom requis');
      if (state.players.find(p => p.name.toLowerCase() === name.toLowerCase())) {
        return alert('Déjà présent');
      }

      state.players.push({ name, position, team, box: '' });
      State.save(state);

      nameEl.value = '';
      teamEl.value = '';

      renderPlayers('');
      refreshPlayersDatalist();
      renderBoxDraftUI();
      computeAndRender();
    };
  }

  // Recherche live
  if (search) {
    search.oninput = (e) => renderPlayers(e.target.value);
  }

  // Import via URL CSV (Google Sheets publié)
  if (importUrlBtn) {
    importUrlBtn.onclick = async () => {
      const urlEl = document.getElementById('players-import-url');
      if (!urlEl) return;

      const url = (urlEl.value || '').trim();
      if (!url) return;

      const text  = await fetch(url, { cache: 'no-store' }).then(r => r.text());
      const rows  = CSV.parse(text);
      if (!rows.length) return;

      const header = rows.shift().map(h => h.toLowerCase());
      const idx    = {
        name:     header.indexOf('name'),
        position: header.indexOf('position'),
        team:     header.indexOf('team'),
        box:      header.indexOf('box'),
      };

      rows.forEach(r => normalizePush(header, idx, r));

      State.save(state);
      renderPlayers('');
      refreshPlayersDatalist();
      renderBoxDraftUI();
      computeAndRender();
    };
  }

  // Import via fichier CSV
  if (importFileBtn) {
    importFileBtn.onclick = () => { if (fileInput) fileInput.click(); };
  }

  if (fileInput) {
    fileInput.onchange = async (e) => {
      const file = e.target.files?.[0];
      if (!file) return;

      const text  = await file.text();
      const rows  = CSV.parse(text);
      if (!rows.length) return;

      const header = rows.shift().map(h => h.toLowerCase());
      const idx    = {
        name:     header.indexOf('name'),
        position: header.indexOf('position'),
        team:     header.indexOf('team'),
        box:      header.indexOf('box'),
      };

      rows.forEach(r => normalizePush(header, idx, r));

      State.save(state);
      renderPlayers('');
      refreshPlayersDatalist();
      renderBoxDraftUI();
    };
  }

  // Export CSV
  if (exportBtn) {
    exportBtn.onclick = () => {
      const header = 'name,position,team,box\n';
      const body = (state.players || [])
        .map(p => `${CSV.escape(p.name)},${p.position},${p.team || ''},${p.box || ''}`)
        .join('\n');

      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([header + body], { type: 'text/csv;charset=utf-8;' }));
      a.download = 'players.csv';
      a.click();
    };
  }
}


function importPlayersFromCSV(text){
  const rows = CSV.parse(text);
  if(!rows.length) return;
  const header = rows.shift().map(h=>h.toLowerCase());
  const idx = { name: header.indexOf('name'), position: header.indexOf('position'), team: header.indexOf('team'), box: header.indexOf('box') };
  rows.forEach(r=>{
    const name = r[idx.name]; if(!name) return;
    if(!state.players.find(p=>p.name.toLowerCase()===name.toLowerCase())){
      state.players.push({name, position: r[idx.position]||'F', team: (r[idx.team]||'').toUpperCase(), box: idx.box>=0 ? (r[idx.box]||'') : ''});
    }
  });
  State.save(state); renderPlayers(); refreshPlayersDatalist();computeAndRender();
  renderBoxDraftUI();
}

// --- Poolers & draft ---
function renderPoolers(){
  const cont = document.getElementById('poolers-list');
  if (!cont) return;

  // option : pas de zébrage dans cette zone
  cont.classList.add('no-zebra');

  const table = document.createElement('table');
  table.classList.add('table');
  table.innerHTML = `
    <thead>
      <tr><th>Pooler</th><th>Skaters</th><th>Gardiens</th><th>Roster</th><th class="only-manager" data-role="manager-only"></th></tr>
    </thead>`;
  const tbody = document.createElement('tbody');

  (state.poolers || []).forEach(pl => {
    const counts = countRoster(pl); // déjà existant chez toi
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${pl.name}</td>
      <td>${counts.sk}/${pl.roster.skaters}</td>
      <td>${counts.go}/${pl.roster.goalies}</td>
      <td>${(pl.players||[]).join(', ')}</td>
    `;

    // Colonne "actions" visible uniquement côté manager (si tu gardes ce bouton)
    const td = document.createElement('td');
    const del = document.createElement('button');
    del.className = 'secondary only-manager';
    del.setAttribute('data-role','manager-only');          // <= double filet de sécurité
    del.textContent = 'Supprimer';
    del.onclick = () => {
      state.poolers = (state.poolers||[]).filter(x => x !== pl);
      State.save(state);
      renderPoolers();
      refreshDraftPooler?.();
      renderRosterView?.();
      computeAndRender?.();
    };
    td.appendChild(del);
    tr.appendChild(td);

    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  cont.innerHTML = '';
  cont.appendChild(table);
  renderPoolersCardsMobile();
}

function renderPoolersCardsMobile(){
  const cont = document.getElementById('poolers-cards');
  if (!cont) return;

  // Nettoie
  cont.innerHTML = '';

  // Seulement en mobile : si on n'est pas en mobile, sort (la CSS masque déjà)
  const isMobile = window.matchMedia && window.matchMedia('(max-width: 768px)').matches;
  if (!isMobile) return;

  const poolers = (state.poolers || []).filter(Boolean);
  poolers.forEach(pl => {
    // Comptage slots
    const skMax = Number(pl?.roster?.skaters || 0);
    const goMax = Number(pl?.roster?.goalies || 0);
    const roster = Array.isArray(pl.players) ? pl.players : [];

    let skCount = 0, goCount = 0;
    const chips = roster.map(name => {
      const meta = (state.players || []).find(p => p.name === name) || {};
      const pos = (meta.position || 'F').toUpperCase();
      if (pos === 'G') goCount++; else skCount++;
      const cls = ['tag', pos].join(' ');
      return `<span class="${cls}">${name}</span>`;
    });

    const card = document.createElement('div');
    card.className = 'pooler-card';
    card.innerHTML = `
      <div class="pooler-head">
        <div class="pooler-name">${pl.name}</div>
        <div class="pooler-slots">
          Skaters&nbsp;${skCount}/${skMax} · Gardiens&nbsp;${goCount}/${goMax}
        </div>
      </div>
      <div class="roster-list-wrap">
        <div class="roster-list">${chips.join(' ') || '<em>Aucun joueur</em>'}</div>
      </div>
    `;
    cont.appendChild(card);
  });
}

function bindPoolers(){
  qs('#add-pooler').onclick = ()=>{
    const name = qs('#pooler-name').value.trim(); if(!name) return alert('Nom requis');
    const sk = parseInt(qs('#roster-skaters').value)||0; const go = parseInt(qs('#roster-goalies').value)||0;
    if(state.poolers.find(p=>p.name.toLowerCase()===name.toLowerCase())) return alert('Pooler déjà existant');
    state.poolers.push({name, roster:{skaters: sk, goalies: go}, players: []});
    State.save(state); qs('#pooler-name').value=''; renderPoolers(); refreshDraftPooler(); computeAndRender();
  };
}
function refreshDraftPooler(){
  const sel = qs('#draft-pooler'); sel.innerHTML = state.poolers.map(p=>`<option value="${p.name}">${p.name}</option>`).join('');
}
function countRoster(pl){
  const picked = (pl.players||[]).map(n=>state.players.find(p=>p.name===n)).filter(Boolean);
  return {
    sk: picked.filter(p=>p.position!=='G').length,
    go: picked.filter(p=>p.position==='G').length,
  };
}
const BOX_RULES = { B1:1,B2:1,B3:1,B4:1,B5:1,B6:1,B7:1,B8:1,B9:1,B10:1, G1:1, G2:1, BONUS:5 };
function getBoxCounts(pl){
  const counts = {};
  (pl.players||[]).forEach(n=>{ const p = state.players.find(x=>x.name===n); if(!p||!p.box) return; counts[p.box] = (counts[p.box]||0)+1; });
  return counts;
}
function bindDraft(){
  qs('#draft-add').onclick = ()=>{
    const poolerName = qs('#draft-pooler').value; if(!poolerName) return alert('Sélectionnez un pooler');
    const playerName = qs('#draft-player').value.trim(); if(!playerName) return alert('Choisissez un joueur');
    const player = state.players.find(p=>p.name.toLowerCase()===playerName.toLowerCase()); if(!player) return alert('Joueur introuvable dans la liste maîtresse');
    const pl = state.poolers.find(p=>p.name===poolerName);
    pl.players = pl.players || [];
    if(pl.players.includes(player.name)) return alert('Déjà au roster');
    const counts = countRoster(pl);
    if(player.position==='G' && counts.go >= pl.roster.goalies) return alert('Limite de gardiens atteinte');
    if(player.position!=='G' && counts.sk >= pl.roster.skaters) return alert('Limite de skaters atteinte');
    if(state.boxRulesEnabled && player.box){
      const boxCounts = getBoxCounts(pl);
      const limit = BOX_RULES[player.box] || Infinity;
      const cur = boxCounts[player.box]||0;
      if(cur >= limit){ return alert(`Limite atteinte pour la boîte ${player.box}`); }
    }
    pl.players.push(player.name);
    State.save(state);
    qs('#draft-player').value='';
    renderPoolers(); renderRosterView(); computeAndRender();
  };
}
function renderRosterView() {
  const cont = document.getElementById('roster-view');
  if (!cont) return;

  const poolerSelEl = document.getElementById('draft-pooler'); // peut être masqué côté viewer
  const poolerName = poolerSelEl ? poolerSelEl.value : null;
  const pl = (state.poolers || []).find(p => p.name === poolerName);

  cont.innerHTML = '';
  if (!pl) return;

  const role = (getAuth()?.role) || 'viewer';
  const canEdit = (role === 'manager');

  const picked = (pl.players || [])
    .map(n => state.players.find(p => p.name === n))
    .filter(Boolean);

  const table = document.createElement('table');
  table.innerHTML = `
    <thead>
      <tr>
        <th>Nom</th><th>Pos</th><th>Équipe</th><th>Boîte</th>${canEdit ? '<th></th>' : ''}
      </tr>
    </thead>`;
  const tbody = document.createElement('tbody');

  picked.sort((a,b) =>
    (a.box||'').localeCompare(b.box||'') ||
    a.position.localeCompare(b.position) ||
    a.name.localeCompare(b.name)
  ).forEach(p => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${p.name}</td>
      <td>${p.position}</td>
      <td>${p.team || ''}</td>
      <td>${p.box || ''}</td>
    `;
   
if (canEdit) {
  const td = document.createElement('td');
  const rm = document.createElement('button');
  
rm.className = 'secondary only-manager';
rm.setAttribute('data-role','manager-only');

  rm.textContent = 'Retirer';
  rm.onclick = () => {
    pl.players = (pl.players || []).filter(n => n !== p.name);
    State.save(state);
    renderPoolers();
    renderRosterView();
    renderPoolersCardsMobile();
    computeAndRender();
  };
  td.appendChild(rm);
  tr.appendChild(td);
}

    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  cont.appendChild(table);
}

// --- Stats ingest ---
let autoTimer = null;
async function ingestStatsFromCSVText(text){
  const rows = CSV.parse(text);
  if (!rows.length) return;

  const norm = s => String(s||'').toLowerCase().replace(/\s+|_/g,'');
  const header = rows.shift().map(norm);

  const idx = {
    date:    header.indexOf('date'),
    player:  header.indexOf('player'),
    goals:   header.indexOf('goals')   >= 0 ? header.indexOf('goals')   : header.indexOf('but'),
    assists: header.indexOf('assists') >= 0 ? header.indexOf('assists') : header.indexOf('passes'),
    win:     ['goaliewin','win','w','victoiregardien','victoire'].map(k=>header.indexOf(k)).find(i=>i>=0) ?? -1,
    otl:     ['goalieotl','otl','otloss','defaiteot','defaiteprolongation'].map(k=>header.indexOf(k)).find(i=>i>=0) ?? -1,
    so:      ['shutout','so','blanchissage'].map(k=>header.indexOf(k)).find(i=>i>=0) ?? -1,
    played:  ['played','games','gp','matchs','mj'].map(k=>header.indexOf(k)).find(i=>i>=0) ?? -1
  };

  if (idx.date < 0 || idx.player < 0 || idx.goals < 0 || idx.assists < 0) {
    console.warn('[Stats] En-têtes indispensables manquants. Reçus =', header);
    return;
  }

  rows.forEach(r => {
    const name = (r[idx.player] || '').toString().trim();
    if (!name) return;

    const key = (r[idx.date] || '').toString().slice(0,10); // YYYY-MM-DD
    const goals   = Number(r[idx.goals]   || 0) || 0;
    const assists = Number(r[idx.assists] || 0) || 0;
    const win     = idx.win   >= 0 ? (Number(r[idx.win]  || 0) || 0) : 0;
    const otl     = idx.otl   >= 0 ? (Number(r[idx.otl]  || 0) || 0) : 0;
    const so      = idx.so    >= 0 ? (Number(r[idx.so]   || 0) || 0) : 0;
    const played  = idx.played>= 0 ? (Number(r[idx.played]|| 0) || 0) : 1; // fallback: 1 entrée = 1 match

    state.stats[name] = state.stats[name] || {};
    state.stats[name][key] = { goals, assists, win, otl, so, played };
  });

  state.lastUpdate = new Date().toISOString();
  State.save(state);

  // "Dernière mise à jour" (manager-only) : garde-fou
  const lu = document.getElementById('last-update');
  if (lu) lu.textContent = 'Dernière mise à jour : ' + new Date(state.lastUpdate).toLocaleString();

  computeAndRender();
}
function bindStats() {
  // Bouton "Mettre à jour maintenant"
  const fetchBtn = document.getElementById('fetch-stats');
  if (fetchBtn) {
    fetchBtn.onclick = async () => {
      const urlEl = document.getElementById('stats-url');
      const url = (urlEl && urlEl.value || '').trim();
      if (!url) return alert('Entrer URL CSV des Stats (publié)');
      const txt = await fetch(url, { cache: 'no-store' }).then(r => r.text());
      await ingestStatsFromCSVText(txt);
    };
  }

  // Case "Rafraîchir toutes les 5 min" (présente seulement côté manager)
  const auto = document.getElementById('auto-refresh');
  if (auto) {
    auto.onchange = (e) => {
      if (e.target.checked) {
        setInterval(() => {
          // Rafraîchit Poolers + Rosters + Stats
          refreshAllRemote().catch(console.warn);
        }, REFRESH_INTERVAL_MS);
      }
    };
  }
}

// =====================================================
// CLASSEMENT – calcul des points par pooler
// =====================================================

// Renvoie la date locale sous forme 'YYYY-MM-DD' (en tenant compte du fuseau du navigateur)

function localISODate(d) {
  var t = new Date(d.getTime() - d.getTimezoneOffset() * 60000);
  return t.toISOString().slice(0,10);
}
function getTodayAndYesterday() {
  var now = new Date();
  var todayStr = localISODate(now);
  var y = new Date(now); y.setDate(now.getDate() - 1);
  var yesterdayStr = localISODate(y);
  return { todayStr: todayStr, yesterdayStr: yesterdayStr };
}

function computeScoresWithDaily() {
  var s = (state && state.scoring) ? state.scoring : { goal:1, assist:1, goalie_win:2, goalie_otl:1, shutout:3 };
  var poolers = (state && state.poolers && state.poolers.length) ? state.poolers : [];
  var statsByPlayer = (state && state.stats) ? state.stats : {};
  var d = getTodayAndYesterday();
  var out = [];

  for (var i = 0; i < poolers.length; i++) {
    var pl = poolers[i]; if (!pl || !pl.name) continue;
    var roster = Array.isArray(pl.players) ? pl.players : [];
    var total = 0, todayPts = 0, yestPts = 0;

    for (var j = 0; j < roster.length; j++) {
      var name = roster[j];
      var days = statsByPlayer[name] || {};
      var keys = Object.keys(days);

      for (var k = 0; k < keys.length; k++) {
        var v = days[keys[k]] || {};
        var gg = Number(v.goals||0), aa = Number(v.assists||0), ww = Number(v.win||0), oo = Number(v.otl||0), ss = Number(v.so||0);
        total += gg*s.goal + aa*s.assist + ww*s.goalie_win + oo*s.goalie_otl + ss*s.shutout;
      }
      if (days[d.todayStr]) {
        var vt = days[d.todayStr];
        todayPts += Number(vt.goals||0)*s.goal + Number(vt.assists||0)*s.assist + Number(vt.win||0)*s.goalie_win + Number(vt.otl||0)*s.goalie_otl + Number(vt.so||0)*s.shutout;
      }
      if (days[d.yesterdayStr]) {
        var vy = days[d.yesterdayStr];
        yestPts += Number(vy.goals||0)*s.goal + Number(vy.assists||0)*s.assist + Number(vy.win||0)*s.goalie_win + Number(vy.otl||0)*s.goalie_otl + Number(vy.so||0)*s.shutout;
      }
    }

    out.push({ pooler: pl.name, points: total, today: todayPts, yest: yestPts, rosterCount: roster.length });
  }

  out.sort(function(a,b){ return (b.points - a.points) || a.pooler.localeCompare(b.pooler); });
  return out;
}


function computeScores() {
  const s = state && state.scoring
    ? state.scoring
    : { goal: 1, assist: 1, goalie_win: 2, goalie_otl: 1, shutout: 3 };

  const out = [];
  const poolers = Array.isArray(state?.poolers) ? state.poolers : [];
  const statsByPlayer = state?.stats || {};

  poolers
    .filter(pl => pl && pl.name)
    .forEach(pl => {
      const roster = Array.isArray(pl.players) ? pl.players.filter(Boolean) : [];
      let sum = 0;

      roster.forEach(name => {
        const days = statsByPlayer[name] || {};
        Object.values(days).forEach(v => {
          const goals = Number(v?.goals || 0);
          const assists = Number(v?.assists || 0);
          const win = Number(v?.win || 0);
          const otl = Number(v?.otl || 0);
          const so = Number(v?.so || 0);
          sum += goals * s.goal
              + assists * s.assist
              + win * s.goalie_win
              + otl * s.goalie_otl
              + so * s.shutout;
        });
      });

      out.push({ pooler: pl.name, points: Number.isFinite(sum) ? sum : 0, rosterCount: roster.length });
    });

  out.sort((a, b) => (b.points - a.points) || a.pooler.localeCompare(b.pooler));

  try {
    console.log(
      '[computeScores] poolers=',
      out.map(t => `${t.pooler}(${t.rosterCount})`).join(', '),
      'statsPlayers=',
      Object.keys(statsByPlayer).length
    );
  } catch (_) {}

  return out;
}
// Exposer pour debug en console (facultatif mais pratique)
window.computeScores = computeScores;
function renderLeaderboard() {
  var cont = document.getElementById('leaderboard');
  if (!cont) return;

  var totals = [];
  try { totals = computeScoresWithDaily() || []; } catch(e){ console.error('[Leaderboard] compute error:', e); totals = []; }

  var html = [];
  html.push('<table class="table leaderboard-table">');
  html.push('<thead><tr>');
  html.push('<th>#</th>');
  html.push('<th>Pooler</th>');
  html.push('<th>🥇 Points total</th>');
  html.push('<th>Points hier</th>');
  html.push('<th>Points aujourd’hui</th>');
  html.push('</tr></thead>');
  html.push('<tbody>');

  if (!totals.length) {
    html.push('<tr><td colspan="5"><em>Aucun pooler à afficher</em></td></tr>');
  } else {
    for (var i=0; i<totals.length; i++) {
      var r = totals[i];
      html.push('<tr>');
      html.push('<td>' + (i+1) + '</td>');
      html.push('<td><button class="link-btn" data-open-pooler="' + r.pooler + '">' + r.pooler + '</button></td>');
      html.push('<td><strong>' + Number(r.points||0).toFixed(1) + '</strong></td>');
      html.push('<td>' + Number(r.yest||0).toFixed(1) + '</td>');
      html.push('<td>' + Number(r.today||0).toFixed(1) + '</td>');
      html.push('</tr>');
    }
  }

  html.push('</tbody></table>');
  cont.innerHTML = html.join('');
  renderLeaderboardCardsMobile();  // active les cartes si mobile et rend OK

  // clic sur nom -> modale
  var btns = cont.querySelectorAll('[data-open-pooler]');
  for (var j=0; j<btns.length; j++) {
    (function(b){
      b.onclick = function(){ openPoolerModal(b.getAttribute('data-open-pooler')); };
    })(btns[j]);
  }
}
function compactLeaderboardHeadersIfSmall(){
  const isVerySmall = window.matchMedia && window.matchMedia('(max-width: 420px)').matches;
  const tbl = document.querySelector('.leaderboard-table thead tr');
  if (!tbl) return;
  const ths = tbl.querySelectorAll('th');
  if (ths.length < 5) return;

  // th[2] = Points total, th[3] = Points hier, th[4] = Points aujourd’hui
  if (isVerySmall) {
    ths[2].innerHTML = 'Pts total';
    ths[3].textContent = 'Pts hier';
    ths[4].textContent = 'Pts ajd';     // “aujourd’hui” abrégé
  } else {
    ths[2].innerHTML = 'Points total';
    ths[3].textContent = 'Points hier';
    ths[4].textContent = 'Points aujourd’hui';
  }
}

// =====================================================
// CLASSEMENT – total + points "aujourd'hui" + "hier"
// =====================================================

// Exposer en console si utile
window.computeScoresWithDaily = computeScoresWithDaily;

function bindLeagueIO(){
  qs('#export-league').onclick = ()=>{
    const blob = new Blob([JSON.stringify(state,null,2)], {type:'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'pool-olympiques-2026.json'; a.click();
  };
  qs('#import-league').onclick = ()=> qs('#import-league-file').click();
  qs('#import-league-file').onchange = async (e)=>{
    const file = e.target.files[0]; if(!file) return; const text = await file.text(); const data = JSON.parse(text);
    State.save(data); location.reload();
  };
}

function computeAndRender(){
  
renderLeaderboard();
}
window.computeAndRender = computeAndRender; // debug console


// Calcule les totaux par joueur pour un pooler, sur un intervalle
function aggregatePoolerStats(poolerName, fromStr, toStr) {
  const pooler = (state.poolers || []).find(p => p.name === poolerName);
  if (!pooler) return [];

  const roster = pooler.players || [];
  const from = fromStr ? new Date(fromStr + 'T00:00:00') : null;
  const toEff = toStr || new Date().toISOString().slice(0, 10);
  const to = new Date(toEff + 'T23:59:59');

  const s = state.scoring || { goal:1, assist:1, goalie_win:2, goalie_otl:1, shutout:3 };
  const rows = [];

  roster.forEach(name => {
    const days = state.stats?.[name] || {};
    let g = 0, a = 0, win = 0, otl = 0, so = 0, pts = 0;

    Object.entries(days).forEach(([d, v]) => {
      const dt = new Date(d + 'T12:00:00');
      if (from && dt < from) return;
      if (to && dt > to) return;

      const G = safeNum(v.goals), A = safeNum(v.assists);
      const W = safeNum(v.win),   O = safeNum(v.otl),    S = safeNum(v.so);

      g += G; a += A; win += W; otl += O; so += S;
      pts += G*s.goal + A*s.assist + W*s.goalie_win + O*s.goalie_otl + S*s.shutout;
    });

    // métadonnées du joueur (position/team) — valeurs par défaut si absent
    const meta = (state.players || []).find(p => p.name === name) || {};
    rows.push({
      name,
      position: meta.position || '',
      team: meta.team || '',
      goals: safeNum(g),
      assists: safeNum(a),
      win: safeNum(win),
      otl: safeNum(otl),
      so: safeNum(so),
      points: safeNum(pts)
    });
  });

  rows.sort((x, y) => y.points - x.points || x.name.localeCompare(y.name));
  return rows;
}


function renderPoolerPlayersTable(poolerName, fromStr, toStr) {
  const cont = document.getElementById('pooler-players-table');
  if (!cont) return;

  // zébrage OFF dans ce bloc
  cont.classList.add('no-zebra');

  let rows = [];
  try {
    rows = (aggregatePoolerStats(poolerName, fromStr, toStr) || []).map(r => ({
      ...r,
     
mj: countMatches(r.name, fromStr, toStr),  // <= utilise "played"
    points: Number(r.points || 0)

    }));
  } catch (e) {
    console.warn('aggregatePoolerStats error:', e);
    rows = [];
  }

  const table = document.createElement('table');
  table.classList.add('table');

  table.innerHTML = `
    <thead>
      <tr>
        <th>Joueur</th><th>Pos</th><th>Équipe</th>
        <th>MJ</th>
        <th>Buts</th><th>Passes</th><th>Win</th><th>OTL</th><th>SO</th>
        <th>Points</th><th>Détail</th>
      </tr>
    </thead>`;

  const tbody = document.createElement('tbody');

  if (!rows.length) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td colspan="11"><em>Aucune donnée pour cette période.</em></td>`;
    tbody.appendChild(tr);
  } else {
    rows.forEach(r => {
      // garde‑fous si jamais r est mal formé
      const name = r?.name || '';
      const pos  = r?.position || '';
      const team = r?.team || '';
      const mj   = safeNum(r?.mj);
      const g    = safeNum(r?.goals);
      const a    = safeNum(r?.assists);
      const w    = safeNum(r?.win);
      const o    = safeNum(r?.otl);
      const s    = safeNum(r?.so);
      const pts  = safeNum(r?.points);

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${name}</td>
        <td>${pos}</td>
        <td>${team}</td>
        <td>${mj}</td>
        <td>${g}</td>
        <td>${a}</td>
        <td>${w}</td>
        <td>${o}</td>
        <td>${s}</td>
        <td><strong>${safeFixed(pts, 1)}</strong></td>
        <td><button class="secondary" data-open-player="${name}">Voir</button></td>`;
      tbody.appendChild(tr);
    });
  }

  table.appendChild(tbody);
  cont.innerHTML = '';
  cont.appendChild(table);

  // Bind "Voir" -> table quotidienne
  
cont.querySelectorAll('button[data-open-player]').forEach(function (btn) {
  btn.onclick = function () {
    const playerName = btn.getAttribute('data-open-player');
    const from = (document.getElementById('pooler-from')?.value) || '';
    const to   = (document.getElementById('pooler-to')?.value)   || '';
    renderPoolerDailyTable(poolerName, playerName, from, to);
  };
});


  // Réinitialise la zone quotidienne si aucun joueur sélectionné
  const titleDaily = document.getElementById('pooler-daily-title');
  const daily = document.getElementById('pooler-daily-table');
  if (titleDaily) titleDaily.style.display = 'none';
  if (daily) daily.innerHTML = '';
}
function renderPoolerDailyTable(poolerName, playerName, fromStr, toStr) {
  const titleEl = document.getElementById('pooler-daily-title');
  const cont = document.getElementById('pooler-daily-table');
  if (!titleEl || !cont) return;

  // Désactive le zébrage dans cette zone
  cont.classList.add('no-zebra');

  // Affiche le titre
  titleEl.textContent = 'Détail par date — ' + playerName;
  titleEl.style.display = '';

  // Bornes de dates (par défaut, Au = aujourd’hui si toStr vide)
  const from = fromStr ? new Date(fromStr + 'T00:00:00') : null;
  const toEff = toStr || new Date().toISOString().slice(0, 10);
  const to = new Date(toEff + 'T23:59:59');

  // Récupère les stats du joueur
  const days = (state.stats && state.stats[playerName]) ? state.stats[playerName] : {};
  const s = state.scoring || { goal:1, assist:1, goalie_win:2, goalie_otl:1, shutout:3 };

  // Transforme en lignes {date, goals, assists, win, otl, so, played, points}
  const data = Object.keys(days)
    .filter(function (d) {
      // sécurité : d doit ressembler à YYYY-MM-DD
      if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return false;
      const dt = new Date(d + 'T12:00:00'); // milieu de journée pour éviter TZ bizarres
      if (from && dt < from) return false;
      if (to && dt > to) return false;
      return true;
    })
    .sort(function (a, b) { return a.localeCompare(b); })
    .map(function (d) {
      const v = days[d] || {};
      const goals   = Number(v.goals   || 0);
      const assists = Number(v.assists || 0);
      const win     = Number(v.win     || 0);
      const otl     = Number(v.otl     || 0);
      const so      = Number(v.so      || 0);
      // MJ depuis la colonne "played" si elle existe, sinon 1 (une ligne = un match)
      const played  = (v.hasOwnProperty('played')) ? (Number(v.played) || 0) : 1;
      const points  = (goals * s.goal) + (assists * s.assist) + (win * s.goalie_win) + (otl * s.golie_otl || 0) + (so * s.shutout);
      // NB: typo possible sur s.golie_otl => corrigeons si ta clé est s.goalie_otl
      const ptsSafe = Number.isFinite(points)
        ? points
        : (goals * s.goal) + (assists * s.assist) + (win * s.goalie_win) + (otl * (s.goalie_otl || 0)) + (so * s.shutout);

      return { date: d, played: played, goals: goals, assists: assists, win: win, otl: otl, so: so, points: ptsSafe };
    });

  // Construit le tableau (inclut MJ)
  const table = document.createElement('table');
  table.classList.add('table');
  table.innerHTML = '' +
    '<thead>' +
      '<tr>' +
        '<th>Date</th>' +
        '<th>MJ</th>' +
        '<th>Buts</th>' +
        '<th>Passes</th>' +
        '<th>Win</th>' +
        '<th>OTL</th>' +
        '<th>SO</th>' +
        '<th>Points</th>' +
      '</tr>' +
    '</thead>';

  const tbody = document.createElement('tbody');

  // Accumulateurs
  var sumMJ = 0, sumG = 0, sumA = 0, sumW = 0, sumO = 0, sumS = 0, sumPts = 0;

  if (!data.length) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td colspan="8"><em>Aucune donnée dans la période sélectionnée.</em></td>';
    tbody.appendChild(tr);
  } else {
    data.forEach(function (r) {
      sumMJ  += r.played || 0;
      sumG   += r.goals   || 0;
      sumA   += r.assists || 0;
      sumW   += r.win     || 0;
      sumO   += r.otl     || 0;
      sumS   += r.so      || 0;
      sumPts += r.points  || 0;

      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td>' + r.date + '</td>' +
        '<td>' + (r.played || 0) + '</td>' +
        '<td>' + (r.goals || 0) + '</td>' +
        '<td>' + (r.assists || 0) + '</td>' +
        '<td>' + (r.win || 0) + '</td>' +
        '<td>' + (r.otl || 0) + '</td>' +
        '<td>' + (r.so || 0) + '</td>' +
        '<td><strong>' + (Number(r.points || 0).toFixed(1)) + '</strong></td>';
      tbody.appendChild(tr);
    });
  }

  // Ligne total
  const trSum = document.createElement('tr');
  trSum.innerHTML =
    '<td><strong>Total</strong></td>' +
    '<td><strong>' + sumMJ + '</strong></td>' +
    '<td><strong>' + sumG + '</strong></td>' +
    '<td><strong>' + sumA + '</strong></td>' +
    '<td><strong>' + sumW + '</strong></td>' +
    '<td><strong>' + sumO + '</strong></td>' +
    '<td><strong>' + sumS + '</strong></td>' +
    '<td><strong>' + (Number(sumPts).toFixed(1)) + '</strong></td>';
  tbody.appendChild(trSum);

  table.appendChild(tbody);
  cont.innerHTML = '';
  cont.appendChild(table);
}

function renderPoolerPlayersCards(poolerName, fromStr, toStr) {
  if (!SAFE_MOBILE_CARDS || !isMobile()) { showModalListsMode('table'); return; }

  var host = document.getElementById('pooler-players-cards');
  if (!host) return;
  host.innerHTML = '';

  var rows = (aggregatePoolerStats(poolerName, fromStr, toStr) || []);
  if (!rows.length) {
    host.innerHTML = '<div class="pl-card"><em>Aucun joueur dans la période.</em></div>';
  } else {
    for (var i=0; i<rows.length; i++) {
      var r = rows[i];
      var mj = countMatches(r.name, fromStr, toStr);
      var c = document.createElement('div');
      c.className = 'pl-card';
      c.innerHTML =
        '<div class="pl-head">' +
          '<div class="pl-name">'+ r.name +'</div>' +
          '<div class="pl-meta">'+ (r.position||'') + (r.team ? ' · ' + r.team : '') +'</div>' +
        '</div>' +
        '<div class="pl-stats">' +
          '<div class="stat"><span class="v">'+ (mj||0) +'</span>MJ</div>' +
          '<div class="stat"><span class="v">'+ (r.goals||0) +'</span>Buts</div>' +
          '<div class="stat"><span class="v">'+ (r.assists||0) +'</span>Passes</div>' +
          '<div class="stat"><span class="v">'+ (r.win||0) +'</span>Win</div>' +
          '<div class="stat"><span class="v">'+ (r.otl||0) +'</span>OTL</div>' +
          '<div class="stat"><span class="v">'+ (r.so||0) +'</span>SO</div>' +
          '<div class="stat" style="grid-column: span 3;"><span class="v">'+ Number(r.points||0).toFixed(1) +'</span>Points</div>' +
        '</div>' +
        '<div class="actions" style="margin-top:8px;"><button class="secondary" data-open-player="'+ r.name +'">Voir le détail</button></div>';
      host.appendChild(c);
    }
  }

  if (host.children.length > 0) showModalListsMode('cards');

  // Détail quotidien (cartes)
  var btns = host.querySelectorAll('[data-open-player]');
  for (var j=0; j<btns.length; j++) {
    (function(b){
      b.onclick = function(){
        var name = b.getAttribute('data-open-player');
        var fEl = document.getElementById('pooler-from');
        var tEl = document.getElementById('pooler-to');
        var f = fEl ? fEl.value : '';
        var t = tEl ? tEl.value : '';
        renderPoolerDailyCards(poolerName, name, f, t);
      };
    })(btns[j]);
  }
}

function renderPoolerDailyCards(poolerName, playerName, fromStr, toStr) {
  if (!SAFE_MOBILE_CARDS || !isMobile()) { showModalListsMode('table'); return; }

  var host = document.getElementById('pooler-daily-cards');
  var title = document.getElementById('pooler-daily-title');
  if (!host || !title) return;
  host.innerHTML = '';

  title.textContent = 'Détail par date — ' + playerName;
  title.style.display = '';

  var s = (state && state.scoring) ? state.scoring : { goal:1, assist:1, goalie_win:2, goalie_otl:1, shutout:3 };
  var days = (state && state.stats && state.stats[playerName]) ? state.stats[playerName] : {};
  var from = fromStr ? new Date(fromStr + 'T00:00:00') : null;
  var toEff = toStr || new Date().toISOString().slice(0,10);
  var to   = new Date(toEff + 'T23:59:59');

  var keys = Object.keys(days).sort();
  var any = false;
  for (var i=0; i<keys.length; i++) {
    var d = keys[i];
    if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) continue;
    var dt = new Date(d + 'T12:00:00');
    if (from && dt < from) continue;
    if (to && dt > to) continue;

    any = true;
    var v = days[d] || {};
    var gg = Number(v.goals||0), aa = Number(v.assists||0), ww = Number(v.win||0), oo = Number(v.otl||0), ss = Number(v.so||0);
    var pts = gg*s.goal + aa*s.assist + ww*s.goalie_win + oo*(s.goalie_otl||0) + ss*s.shutout;
    var mj  = v.hasOwnProperty('played') ? Number(v.played||0) : 1;

    var c = document.createElement('div');
    c.className = 'day-card';
    c.innerHTML =
      '<div class="day-head"><div>'+ d +'</div><div><strong>'+ pts.toFixed(1) +'</strong> pts</div></div>' +
      '<div class="day-stats">' +
        '<div class="stat"><span class="v">'+ mj +'</span>MJ</div>' +
        '<div class="stat"><span class="v">'+ gg +'</span>Buts</div>' +
        '<div class="stat"><span class="v">'+ aa +'</span>Passes</div>' +
        '<div class="stat"><span class="v">'+ ww +'</span>Win</div>' +
        '<div class="stat"><span class="v">'+ oo +'</span>OTL</div>' +
        '<div class="stat"><span class="v">'+ ss +'</span>SO</div>' +
      '</div>';
    host.appendChild(c);
  }
  if (!any) host.innerHTML = '<div class="day-card"><em>Aucune donnée dans la période.</em></div>';
}

function openDialogSafe(dlg){
  if (!dlg) return;
  if (typeof dlg.showModal === 'function') dlg.showModal();
  else dlg.setAttribute('open',''); // fallback simple
}
function closeDialogSafe(dlg){
  if (!dlg) return;
  if (typeof dlg.close === 'function') dlg.close();
  else dlg.removeAttribute('open');
}
function openPoolerModal(poolerName) {
  const dlg = document.getElementById('pooler-modal');
  if (!dlg) return;

  // bornes de date (comme tu l’avais)
  const roster = (state.poolers || []).find(p => p.name === poolerName)?.players || [];
  const set = new Set();
  roster.forEach(n => Object.keys(state.stats?.[n] || {}).forEach(d => set.add(d)));
  const arr = Array.from(set).sort();
  const minD = arr[0] || '';
  const today = new Date().toISOString().slice(0,10);
  const maxD = arr[arr.length-1] || today;

  document.getElementById('pooler-modal-title').textContent = 'Vue — ' + poolerName;
  const fromEl = document.getElementById('pooler-from');
  const toEl   = document.getElementById('pooler-to');
  if (fromEl) fromEl.value = minD;
  if (toEl)   toEl.value   = maxD;

  // Rendu agrégé (table desktop existante)
  renderPoolerPlayersTable?.(poolerName, minD, maxD);
  // Nouveau : cartes mobile
  renderPoolerPlayersCards(poolerName, minD, maxD);

  // reset du quotidien
  const titleDaily = document.getElementById('pooler-daily-title');
  const dailyTbl = document.getElementById('pooler-daily-table');
  const dailyCards = document.getElementById('pooler-daily-cards');
  if (titleDaily) titleDaily.style.display = 'none';
  if (dailyTbl) dailyTbl.innerHTML = '';
  if (dailyCards) dailyCards.innerHTML = '';

  // Filtre
  const applyBtn = document.getElementById('pooler-apply');
  if (applyBtn) {
    applyBtn.onclick = () => {
      const f = fromEl?.value || '';
      const t = toEl?.value   || today;
      renderPoolerPlayersTable?.(poolerName, f, t);
      renderPoolerPlayersCards(poolerName, f, t);
      // détail quotidien vidé tant que pas “Voir”
      if (titleDaily) titleDaily.style.display = 'none';
      if (dailyTbl) dailyTbl.innerHTML = '';
      if (dailyCards) dailyCards.innerHTML = '';
    };
  }

  const closeBtn = document.getElementById('pooler-close');
  if (closeBtn) closeBtn.onclick = () => closeDialogSafe?.(dlg);

  openDialogSafe?.(dlg) || dlg.showModal?.();
}

function placeLeaderboardFirstOnMobile(){
  const isMobile = window.matchMedia && window.matchMedia('(max-width: 768px)').matches;
  if (!isMobile) return;
  const main = document.querySelector('main');
  const lb  = document.getElementById('leaderboard-section');
  if (main && lb && main.firstElementChild !== lb) {
    main.insertBefore(lb, main.firstElementChild);
  }
}

function init(){
  renderScoring(); bindScoring();
  renderPlayers(); bindPlayers(); refreshPlayersDatalist();
  renderPoolers(); bindPoolers(); refreshDraftPooler(); bindDraft();
  // box mode init
  const cb = document.querySelector('#box-mode'); if(cb){ cb.checked = !!state.boxRulesEnabled; cb.onchange = (e)=>{ state.boxRulesEnabled = e.target.checked; State.save(state); }; }
  bindStats(); bindLeagueIO();
  computeAndRender();
   bindPlayerStatsUI();
  document.querySelector('#draft-pooler').addEventListener('change', renderRosterView);
}

// --- INIT AUTH + BOOT APP ---
// Remplace ton ancien DOMContentLoaded par ce boot.
async function bootAuthThenApp() {
  // 1) Auth en premier : on ne démarre rien tant que l'accès n'est pas validé
  bindGateUI();           // active le bouton "Entrer" (collage manuel d'un token)
  takeRemoteFromURL();    // option : ?poolers=...&rosters=...&stats=... => mémorise les URLs CSV
  await tryTokenFromURL(); // option : ?token=... (ou #token=...), vérifie signature/audience/exp/role
  applyAccessControls();  // montre/masque la gate et les sections [data-role="manager-only"]
  setStatusWarn('Prêt — en attente de synchronisation…');
  // 2) Pas authentifié -> on s'arrête ici (l'app reste masquée derrière la gate)
  const appRoot = document.getElementById('app-root');
  if (!appRoot || appRoot.hidden) return;

  // 3) Auth OK -> on lance l'application (tes initialisations existantes)
  renderScoring();            bindScoring();
  
// Joueurs : seulement si la section/les éléments existent
if (document.getElementById('players-list')) {
  renderPlayers('');
  bindPlayers();
  refreshPlayersDatalist();
}

  renderPoolers();            bindPoolers();          refreshDraftPooler(); bindDraft();
  renderBoxDraftUI();         bindBoxDraft();
  bindStats();                bindRemoteSourcesUI();
  computeAndRender();
  renderPoolersCardsMobile();
  renderLeaderboardCardsMobile();

  const recomputeBtn = document.getElementById('recompute');
if (recomputeBtn) {
  recomputeBtn.onclick = () => computeAndRender();
}
  // Changement de pooler -> maj du roster
  const draftSel = document.getElementById('draft-pooler');
  if (draftSel) draftSel.addEventListener('change', renderRosterView);

  

// 4) auto‑refresh pour TOUS (viewer + manager)
  setInterval(async () => {
  try {
    setStatusWarn('Synchronisation automatique…');
    await refreshAllRemote();
    const p  = (state.players||[]).length;
    const pl = (state.poolers||[]).length;
    const sp = Object.keys(state.stats||{}).length;
    setStatusOK(`Players: ${p} · Poolers: ${pl} · Stats-joueurs: ${sp}`);
    computeAndRender();
  } catch (e) {
    console.warn('auto-refresh error:', e);
    setStatusErr('Erreur de synchronisation (auto)');
  }
}, REFRESH_INTERVAL_MS);

const clientRefreshBtn = document.getElementById('client-refresh');
if (clientRefreshBtn) {
  clientRefreshBtn.onclick = async () => {
    try {
      setStatusWarn('Rafraîchissement…');
      await refreshAllRemote();
      const p  = (state.players||[]).length;
      const pl = (state.poolers||[]).length;
      const sp = Object.keys(state.stats||{}).length;
      setStatusOK(`Players: ${p} · Poolers: ${pl} · Stats-joueurs: ${sp}`);
      computeAndRender();
    } catch (e) {
      console.warn('client refresh error:', e);
      setStatusErr('Erreur durant le rafraîchissement');
    }
  };
}

}

window.addEventListener('DOMContentLoaded', bootAuthThenApp);
window.addEventListener('resize', placeLeaderboardFirstOnMobile, { passive: true });
window.addEventListener('resize', renderLeaderboardCardsMobile, { passive: true });
window.addEventListener('orientationchange', renderLeaderboardCardsMobile, { passive: true });
placeLeaderboardFirstOnMobile();


document.addEventListener('visibilitychange', function(){
  if (document.visibilityState === 'visible') {
    refreshAllRemote()
      .then(function(){ computeAndRender(); })
      .catch(console.warn);
  }
});

/***** =========================
 *  STATS DES JOUEURS (UI)
 *========================== ***/

/** Agrège les stats par joueur (avec filtre date inclusif). */
function aggregatePlayerStats(fromStr, toStr){
  // bornes temporelles
  const from = fromStr ? new Date(fromStr + 'T00:00:00') : null;
  const to   = toStr   ? new Date(toStr   + 'T23:59:59') : null;

  // init accumulateur
  const acc = new Map(); // name -> {g,a,win,otl,so,points}

  const s = state.scoring;
  const addTo = (name, g=0,a=0,win=0,otl=0,so=0)=>{
    if(!acc.has(name)) acc.set(name,{g:0,a:0,win:0,otl:0,so:0,points:0});
    const o = acc.get(name);
    o.g += g; o.a += a; o.win += win; o.otl += otl; o.so += so;
    o.points += g*s.goal + a*s.assist + win*s.goalie_win + otl*s.goalie_otl + so*s.shutout;
  };

  // parcourir state.stats[player][date] = {goals, assists, win, otl, so}
  Object.entries(state.stats || {}).forEach(([name, days])=>{
    Object.entries(days || {}).forEach(([dateStr, v])=>{
      const d = new Date(dateStr + 'T12:00:00'); // éviter décalages TZ
      if(from && d < from) return;
      if(to && d > to) return;
      addTo(name, v.goals||0, v.assists||0, v.win||0, v.otl||0, v.so||0);
    });
  });

  // transforme en tableau et enrichit avec position/team si connu
  const rows = Array.from(acc.entries()).map(([name,vals])=>{
    const meta = state.players.find(p=>p.name === name) || {};
    return {
      name,
      position: meta.position || '',
      team: meta.team || '',
      box: meta.box || '',
      goals: vals.g,
      assists: vals.a,
      win: vals.win,
      otl: vals.otl,
      so: vals.so,
      points: vals.points
    };
  });

  // trier par points desc puis nom
  rows.sort((a,b)=> b.points - a.points || a.name.localeCompare(b.name));
  return rows;
}

/** Construit la table HTML principale (stats agrégées par joueur). */
function renderPlayerStatsTable(rows, searchText=''){
  const cont = document.getElementById('player-stats-table');
  cont.innerHTML = '';
  const table = document.createElement('table');
  table.innerHTML = `
    <thead>
      <tr>
        <th>Joueur</th>
        <th>Pos</th>
        <th>Équipe</th>
        <th>Boîte</th>
        <th>Buts</th>
        <th>Passes</th>
        <th>Win</th>
        <th>OTL</th>
        <th>SO</th>
        <th>Points</th>
        <th>Détails</th>
      </tr>
    </thead>
  `;
  const tbody = document.createElement('tbody');

  const q = (searchText||'').trim().toLowerCase();
  rows
    .filter(r => !q || r.name.toLowerCase().includes(q))
    .forEach(r=>{
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${r.name}</td>
        <td>${r.position}</td>
        <td>${r.team}</td>
        <td>${r.box||''}</td>
        <td>${r.goals}</td>
        <td>${r.assists}</td>
        <td>${r.win}</td>
        <td>${r.otl}</td>
        <td>${r.so}</td>
        <td><strong>${r.points.toFixed(1)}</strong></td>
        <td><button class="secondary" data-player="${r.name}">Voir</button></td>
      `;
      tbody.appendChild(tr);
    });

  table.appendChild(tbody);
  cont.appendChild(table);

  // bind boutons "Voir" -> ouvre la modale fiche joueur
  cont.querySelectorAll('button[data-player]').forEach(btn=>{
    btn.onclick = ()=> openPlayerModal(btn.getAttribute('data-player'));
  });
}

/** Ouvre la modale et affiche les stats journalières d’un joueur. */
function openPlayerModal(playerName){
  const dlg = document.getElementById('player-modal');
  document.getElementById('modal-title').textContent = `Fiche – ${playerName}`;

  // préremplir bornes avec min/max des dates existantes
  const allDates = Object.keys(state.stats[playerName]||{});
  const minD = allDates.length ? allDates.slice().sort()[0] : '';
  const maxD = allDates.length ? allDates.slice().sort().slice(-1)[0] : '';
  document.getElementById('modal-from').value = minD || '';
  document.getElementById('modal-to').value = maxD || '';

  // dessine le tableau initial
  renderPlayerDailyTable(playerName, minD, maxD);

  // handlers
  document.getElementById('modal-apply').onclick = ()=>{
    const f = document.getElementById('modal-from').value;
    const t = document.getElementById('modal-to').value;
    renderPlayerDailyTable(playerName, f, t);
  };
  document.getElementById('modal-close').onclick = ()=> dlg.close();

  dlg.showModal();
}

/** Tableau journalier pour la modale (avec total au bas). */
function renderPlayerDailyTable(playerName, fromStr, toStr){
  const cont = document.getElementById('player-daily-table');
  cont.innerHTML = '';

  const s = state.scoring;
  const from = fromStr ? new Date(fromStr + 'T00:00:00') : null;
  const to   = toStr   ? new Date(toStr   + 'T23:59:59') : null;

  const data = Object.entries(state.stats[playerName]||{})
    .filter(([d])=>{
      const dt = new Date(d + 'T12:00:00');
      if(from && dt < from) return false;
      if(to && dt > to) return false;
      return true;
    })
    .sort(([a],[b])=> a.localeCompare(b))
    .map(([d,v])=>{
      const points = (v.goals||0)*s.goal + (v.assists||0)*s.assist +
                     (v.win||0)*s.goalie_win + (v.otl||0)*s.goalie_otl +
                     (v.so||0)*s.shutout;
      return {date:d, ...v, points};
    });

  const table = document.createElement('table');
  table.innerHTML = `
    <thead>
      <tr>
        <th>Date</th><th>Buts</th><th>Passes</th><th>Win</th><th>OTL</th><th>SO</th><th>Points</th>
      </tr>
    </thead>
  `;
  const tbody = document.createElement('tbody');

  let sum = {g:0,a:0,win:0,otl:0,so:0,pts:0};

  data.forEach(r=>{
    sum.g+=r.goals||0; sum.a+=r.assists||0; sum.win+=r.win||0; sum.otl+=r.otl||0; sum.so+=r.so||0; sum.pts+=r.points||0;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${r.date}</td>
      <td>${r.goals||0}</td>
      <td>${r.assists||0}</td>
      <td>${r.win||0}</td>
      <td>${r.otl||0}</td>
      <td>${r.so||0}</td>
      <td><strong>${r.points.toFixed(1)}</strong></td>
    `;
    tbody.appendChild(tr);
  });

  // ligne total
  const trSum = document.createElement('tr');
  trSum.innerHTML = `
    <td><strong>Total</strong></td>
    <td><strong>${sum.g}</strong></td>
    <td><strong>${sum.a}</strong></td>
    <td><strong>${sum.win}</strong></td>
    <td><strong>${sum.otl}</strong></td>
    <td><strong>${sum.so}</strong></td>
    <td><strong>${sum.pts.toFixed(1)}</strong></td>
  `;
  tbody.appendChild(trSum);

  table.appendChild(tbody);
  cont.appendChild(table);
}

/** Export CSV des stats agrégées affichées. */
function exportAggregatedCSV(rows){
  const header = 'name,position,team,box,goals,assists,win,otl,so,points\n';
  const body = rows.map(r =>
    `${CSV.escape(r.name)},${r.position},${r.team},${r.box},${r.goals},${r.assists},${r.win},${r.otl},${r.so},${r.points}`
  ).join('\n');
  const blob = new Blob([header+body], {type:'text/csv;charset=utf-8;'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'player_stats_aggregated.csv';
  a.click();
}

/** Bind de la section Stats des joueurs. */
function bindPlayerStatsUI(){
  const search = document.getElementById('player-stats-search');
  const fromEl = document.getElementById('stats-from');
  const toEl   = document.getElementById('stats-to');
  const btnRef = document.getElementById('stats-refresh');
  const btnExp = document.getElementById('stats-export');

  // bornes par défaut : toutes dates présentes
  const allDates = new Set();
  Object.values(state.stats||{}).forEach(days=>{
    Object.keys(days||{}).forEach(d=> allDates.add(d));
  });
  const sortDates = Array.from(allDates).sort();
  if(sortDates.length){
    fromEl.value = sortDates[0];
    toEl.value = sortDates[sortDates.length-1];
  }

  let currentRows = aggregatePlayerStats(fromEl.value, toEl.value);
  renderPlayerStatsTable(currentRows, search.value);

  const refresh = ()=>{
    currentRows = aggregatePlayerStats(fromEl.value, toEl.value);
    renderPlayerStatsTable(currentRows, search.value);
  };

  btnRef.onclick = refresh;
  search.oninput = ()=> renderPlayerStatsTable(currentRows, search.value);
  btnExp.onclick = ()=> exportAggregatedCSV(currentRows);
}


function setupLogoutButton() {
  const btnExit = document.getElementById('btn-exit-manager'); // s'il existe dans ton UI
  if (btnExit) {
    btnExit.hidden = false;
    btnExit.onclick = () => {
      clearAuth();
      applyAccessControls();
      alert('Déconnecté');
    };
  }
}


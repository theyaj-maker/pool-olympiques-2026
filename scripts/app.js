/*** =========================================================
 * ACCÈS PAR JETON SIGNÉ — ZÉRO SECRET DANS LE REPO
 * ECDSA P‑256 (clé privée conservée par toi), SHA‑256
 * Token compact = base64url(JSON payload) + "." + base64url(signature)
 * Payload conseillé : { role:"viewer"|"manager", exp:"ISO", aud:"https://<user>.github.io/<repo>", sub?:... }
 *========================================================= ***/

// 1) <<< Colle ici ta CLÉ PUBLIQUE JWK (non secrète) générée au §4 >>>
const PUBLIC_JWK = {
"crv": "P-256",
  "ext": true,
  "key_ops": [
    "verify"
  ],
  "kty": "EC",
  "x": "yhuI022ZqJOwpoB1o8NvywoDWBNEqRaIP7gwdCi8j6M",
  "y": "34j5Ghey2nwlSnhIi23nXhY8jcnDdgwu5OJ9k592w-0"
};

// 2) Helpers base64url
const b64urlToBytes = (s) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
  s += '='.repeat(pad);
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
};
const bytesToB64url = (buf) => {
  const b = Array.from(new Uint8Array(buf)).map(ch => String.fromCharCode(ch)).join('');
  return btoa(b).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
};

// 3) Import clé publique WebCrypto (ECDSA P‑256)
async function importPublicKey(jwk) {
  return crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, ['verify']
  );
}

// 4) Vérifie un token (signature + exp/nbf/aud + rôle)
async function verifyToken(token) {
  try {
    if (!token) return { ok:false, msg:'Token manquant' };

    const dot = token.indexOf('.');
    if (dot <= 0) return { ok:false, msg:'Format token invalide' };

    const pB64 = token.slice(0, dot);
    const sB64 = token.slice(dot+1);

    const payloadJSON = new TextDecoder().decode(b64urlToBytes(pB64));
    const payload = JSON.parse(payloadJSON);

    // dates / audience
    const now = new Date();
    if (payload.nbf && now < new Date(payload.nbf)) return { ok:false, msg:'Token non actif (nbf)' };
    if (payload.exp && now > new Date(payload.exp)) return { ok:false, msg:'Token expiré' };
    if (payload.aud) {
  const expectedOrigin = location.origin; // ex: https://theyaj-maker.github.io
  const repoBase = location.pathname.split('/').slice(0,2).join('/'); // ex: /pool-olympiques-2026
  const expectedWithRepo = expectedOrigin + repoBase;                 // ex: https://theyaj-maker.github.io/pool-olympiques-2026
  if (payload.aud !== expectedOrigin && payload.aud !== expectedWithRepo) {
    return { ok:false, msg:'Audience invalide' };
  }
}

    // rôle
    if (payload.role !== 'viewer' && payload.role !== 'manager') return { ok:false, msg:'Rôle invalide' };

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

// 5) Stockage local (non sensible) du statut d’accès
function setAuth(role, payload, token) {
  localStorage.setItem('pool-auth', JSON.stringify({ role, payload, token }));
}
function getAuth() {
  try { return JSON.parse(localStorage.getItem('pool-auth')); }
  catch { return null; }
}
function clearAuth() {
  localStorage.removeItem('pool-auth');
}

// 6) Applique l’accès (affiche/masque portail et blocs admin)
function applyAccessControls() {
  const auth = getAuth();
  const app = document.getElementById('app-root');
  const gate = document.getElementById('access-gate');

  if (auth) { gate.hidden = true; app.hidden = false; }
  else      { gate.hidden = false; app.hidden = true; }

  document.querySelectorAll('[data-role="manager-only"]').forEach(el => {
    el.style.display = (auth && auth.role === 'manager') ? '' : 'none';
  });
}

// 7) Essaie ?token=... ou #token=...
async function tryTokenFromURL() {
  const url = new URL(location.href);
  const token = url.searchParams.get('token') ||
                (location.hash.startsWith('#token=') ? location.hash.slice(7) : null);
  if (!token) return false;

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

// 8) Collage manuel dans le portail
function bindGateUI() {
  const btn = document.getElementById('btn-try-token');
  const ta  = document.getElementById('paste-token');
  const msg = document.getElementById('gate-msg');

  if (btn && ta) {
    btn.onclick = async () => {
      const token = ta.value.trim();
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

// app.js
import { State } from './state.js';
import { CSV } from './csv.js';
import { Adapters } from './adapters.js';

const qs = (s) => document.querySelector(s);

const state = State.load();

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
  try{
    const raw = localStorage.getItem(REMOTE_KEY);
    if(raw) return JSON.parse(raw);
  }catch(_) {}
  return { poolersUrl:'', rostersUrl:'', statsUrl:'' }; // statsUrl peut rester vide si géré par l'UI existante
}

function setRemoteSources(s){
  localStorage.setItem(REMOTE_KEY, JSON.stringify(s));
}

// Option "bootstrap par URL" : ?poolers=...&rosters=...&stats=...
function takeRemoteFromURL(){
  const u = new URL(location.href);
  const src = getRemoteSources();
  let changed = false;
  ['poolers','rosters','stats'].forEach(k=>{
    const v = u.searchParams.get(k);
    if(v){ src[k+'Url'] = v; changed = true; }
  });
  if(changed) setRemoteSources(src);
}

async function fetchTextNoCache(url){
  if(!url) return '';
  const r = await fetch(url, { cache:'no-store' });
  if(!r.ok) throw new Error(`HTTP ${r.status} sur ${url}`);
  return await r.text();
}

// Poolers CSV attendu : pooler,skaters,goalies
async function loadPoolersFromCSV(url){
  if(!url) return;
  const text = await fetchTextNoCache(url);
  if(!text) throw new Error('Poolers CSV vide');

  const rows = CSV.parse(text);
  if(!rows.length) throw new Error('Poolers CSV: aucune ligne');

  const header = rows.shift().map(h=>h.toLowerCase().trim());
  const idx = {
    pooler: header.indexOf('pooler'),
    skaters: header.indexOf('skaters'),
    goalies: header.indexOf('goalies'),
  };
  if(idx.pooler<0 || idx.skaters<0 || idx.goalies<0){
    throw new Error('Poolers CSV: en-têtes requis = pooler,skaters,goalies');
  }

  // On préserve les rosters existants (si Rosters CSV non fourni)
  const byName = Object.create(null);
  state.poolers.forEach(p=> byName[p.name.toLowerCase()] = p);

  const newPoolers = [];
  rows.forEach(r=>{
    const name = (r[idx.pooler]||'').toString().trim();
    if(!name) return;
    const sk = parseInt(r[idx.skaters]||'15',10) || 15;
    const go = parseInt(r[idx.goalies]||'2',10) || 2;

    const existing = byName[name.toLowerCase()];
    newPoolers.push({
      name,
      roster: { skaters: sk, goalies: go },
      players: existing ? (existing.players||[]) : [] // roster conservé tant que Rosters CSV n’écrase pas
    });
  });

  state.poolers = newPoolers;
  State.save(state);
  renderPoolers(); refreshDraftPooler(); renderRosterView();
}

async function refreshAllRemote(){
  const src = getRemoteSources();
  const ops = [];

  if(src.poolersUrl){
    ops.push(loadPoolersFromCSV(src.poolersUrl).catch(e=>console.warn('Poolers CSV:', e.message||e)));
  }
  if(src.rostersUrl){
    ops.push(loadRostersFromCSV(src.rostersUrl).catch(e=>console.warn('Rosters CSV:', e.message||e)));
  }

  // Stats : si tu veux forcer la même logique dans un seul bouton
  const statsUrlEl = document.getElementById('stats-url');
  const statsUrl = (statsUrlEl && statsUrlEl.value) ? statsUrlEl.value.trim() : (src.statsUrl||'');
  if(statsUrl){
    ops.push(fetchTextNoCache(statsUrl).then(ingestStatsFromCSVText).catch(e=>console.warn('Stats CSV:', e.message||e)));
  }

  await Promise.all(ops);
  computeAndRender();
}


// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
//  Fonction demandée : bindRemoteSourcesUI()
// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
function bindRemoteSourcesUI(){
  const { poolersUrl, rostersUrl, statsUrl } = getRemoteSources();

  // Remplir les inputs (si présents dans l’UI manager-only)
  const elP = document.getElementById('poolers-url');
  const elR = document.getElementById('rosters-url');
  if (elP && poolersUrl) elP.value = poolersUrl;
  if (elR && rostersUrl) elR.value = rostersUrl;

  // Sauvegarder
  const btnSave = document.getElementById('save-remote-sources');
  if (btnSave) {
    btnSave.onclick = () => {
      const src = getRemoteSources();
      const p = document.getElementById('poolers-url');
      const r = document.getElementById('rosters-url');
      if (p) src.poolersUrl = (p.value || '').trim();
      if (r) src.rostersUrl = (r.value || '').trim();
      setRemoteSources(src);
      alert('Sources sauvegardées.');
    };
  }

  // Rafraîchir maintenant (Poolers+Rosters+Stats)
  const btnRef = document.getElementById('refresh-remote');
  if (btnRef) btnRef.onclick = () => refreshAllRemote();

  // Premier chargement auto si on a déjà des URLs mémorisées
  if (poolersUrl || rostersUrl || statsUrl) {
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
  if (!cont) return; // ← TOLÉRANT : si la section n'existe pas, on sort

  const players = (state.players || [])
    .filter(p => `${p.name} ${p.team} ${p.position} ${p.box || ''}`
      .toLowerCase().includes((filter || '').toLowerCase()))
    .sort((a, b) => a.name.localeCompare(b.name));

  const table = document.createElement('table');
  table.innerHTML = `
    <thead>
      <tr>
        <th>Nom</th>
        <th>Pos</th>
        <th>Équipe</th>
        <th>Boîte</th>
        <th></th>
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
    del.className = 'secondary';
    del.textContent = 'Supprimer';
    del.onclick = () => {
      state.players = state.players.filter(x => x !== p);
      State.save(state);
      renderPlayers(filter);
      refreshPlayersDatalist();
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
  State.save(state); renderPlayers(); refreshPlayersDatalist();
  renderBoxDraftUI();
}

// --- Poolers & draft ---
function renderPoolers(){
  const cont = qs('#poolers-list');
  const table = document.createElement('table');
  table.innerHTML = '<thead><tr><th>Pooler</th><th>Skaters</th><th>Gardiens</th><th>Roster</th><th></th></tr></thead>';
  const tbody = document.createElement('tbody');
  state.poolers.forEach(pl=>{
    const rosterCounts = countRoster(pl);
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${pl.name}</td><td>${rosterCounts.sk}/${pl.roster.skaters}</td><td>${rosterCounts.go}/${pl.roster.goalies}</td>`;
    const tdRoster = document.createElement('td');
    tdRoster.textContent = (pl.players||[]).join(', ');
    const tdActions = document.createElement('td');
    const del = document.createElement('button'); del.className='secondary'; del.textContent='Supprimer'; del.onclick = ()=>{ state.poolers = state.poolers.filter(x=>x!==pl); State.save(state); renderPoolers(); refreshDraftPooler(); computeAndRender(); };
    tdActions.appendChild(del);
    tr.appendChild(tdRoster); tr.appendChild(tdActions);
    tbody.appendChild(tr);
  });
  table.appendChild(tbody); cont.innerHTML=''; cont.appendChild(table);
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
function renderRosterView(){
  const cont = qs('#roster-view');
  const poolerName = qs('#draft-pooler').value; const pl = state.poolers.find(p=>p.name===poolerName);
  if(!pl){ cont.innerHTML=''; return; }
  const picked = (pl.players||[]).map(n=>state.players.find(p=>p.name===n)).filter(Boolean);
  const table = document.createElement('table');
  table.innerHTML = '<thead><tr><th>Nom</th><th>Pos</th><th>Équipe</th><th>Boîte</th><th></th></tr></thead>';
  const tbody = document.createElement('tbody');
  picked.sort((a,b)=> (a.box||'').localeCompare(b.box||'') || a.position.localeCompare(b.position) || a.name.localeCompare(b.name)).forEach(p=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${p.name}</td><td>${p.position}</td><td>${p.team||''}</td><td>${p.box||''}</td>`;
    const td = document.createElement('td');
    const rm = document.createElement('button'); rm.className='secondary'; rm.textContent='Retirer'; rm.onclick=()=>{ pl.players = pl.players.filter(n=>n!==p.name); State.save(state); renderPoolers(); renderRosterView(); computeAndRender(); };
    td.appendChild(rm); tr.appendChild(td); tbody.appendChild(tr);
  });
  table.appendChild(tbody); cont.innerHTML=''; cont.appendChild(table);
}

// --- Stats ingest ---
let autoTimer = null;
async function ingestStatsFromCSVText(text){
  const rows = CSV.parse(text);
  if(!rows.length) return;
  const header = rows.shift().map(h=>h.toLowerCase());
  const idx = { date: header.indexOf('date'), player: header.indexOf('player'), goals: header.indexOf('goals'), assists: header.indexOf('assists'), win: header.indexOf('goalie_win'), otl: header.indexOf('goalie_otl'), so: header.indexOf('shutout') };
  rows.forEach(r=>{
    const player = (r[idx.player]||'').trim(); if(!player) return;
    const key = (r[idx.date]||'').slice(0,10);
    const goals = parseFloat(r[idx.goals]||0)||0; const assists = parseFloat(r[idx.assists]||0)||0; const win = parseInt(r[idx.win]||0)||0; const otl = parseInt(idx.otl>=0 ? (r[idx.otl]||0) : 0)||0; const so = parseInt(r[idx.so]||0)||0;
    state.stats[player] = state.stats[player] || {};
    state.stats[player][key] = {goals, assists, win, otl, so};
  });
  state.lastUpdate = new Date().toISOString();
  State.save(state);
  computeAndRender();
  qs('#last-update').textContent = `Dernière mise à jour: ${new Date(state.lastUpdate).toLocaleString()}`;
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

// --- Compute leaderboard ---
function computeScores(){
  const s = state.scoring;
  const totals = [];
  state.poolers.forEach(pl=>{
    let sum = 0;
    (pl.players||[]).forEach(name=>{
      const days = state.stats[name] || {};
      Object.values(days).forEach(vals=>{
        const pts = (vals.goals||0)*s.goal + (vals.assists||0)*s.assist + (vals.win||0)*s.goalie_win + (vals.otl||0)*s.goalie_otl + (vals.so||0)*s.shutout;
        sum += pts;
      });
    });
    totals.push({pooler: pl.name, points: sum});
  });
  totals.sort((a,b)=> b.points - a.points || a.pooler.localeCompare(b.pooler));
  return {totals};
}
function renderLeaderboard(res){
  const cont = qs('#leaderboard');
  const table = document.createElement('table');
  table.innerHTML = '<thead><tr><th>#</th><th>Pooler</th><th>Points</th></tr></thead>';
  const tbody = document.createElement('tbody');
  res.totals.forEach((row, i)=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${i+1}</td><td>${row.pooler}</td><td>${row.points.toFixed(1)}</td>`;
    tbody.appendChild(tr);
  });
  table.appendChild(tbody); cont.innerHTML=''; cont.appendChild(table);
}
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
  const res = computeScores();
  renderLeaderboard(res);
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

  // Changement de pooler -> maj du roster
  const draftSel = document.getElementById('draft-pooler');
  if (draftSel) draftSel.addEventListener('change', renderRosterView);

  
// 4) Auto‑refresh forcé pour VISITEUR (viewer) : toutes les 5 min
const auth = (typeof getAuth === 'function') ? getAuth() : null;
const role = auth?.role || 'viewer';

if (role === 'viewer') {
  // Cache la case côté viewer si elle existe
  const autoCb = document.getElementById('auto-refresh');
  if (autoCb && autoCb.closest('label')) {
    autoCb.closest('label').style.display = 'none';
  }

  // Rafraîchit Poolers + Rosters + Stats périodiquement
  setInterval(() => {
    refreshAllRemote().catch(console.warn);
  }, REFRESH_INTERVAL_MS);
}

}

window.addEventListener('DOMContentLoaded', bootAuthThenApp);

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


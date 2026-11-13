/* Kyber KEM Platform — client for the stateless REST API. */
"use strict";

const $ = id => document.getElementById(id);
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; } },
  set(k, v) { localStorage.setItem(k, JSON.stringify(v)); },
};

const LS_PROFILES = "kyber.profiles";   // {name: {name, impl, alg, pk, sk}}
const state = {
  profiles: store.get(LS_PROFILES, {}),
  selected: null,          // profile name
  encResult: null,         // {ct, ss, alg, impl}
  decResult: null,         // {ss, alg, impl}
  channel: null,           // {ssHex, alg, key (CryptoKey), fingerprint}
};

/* ---------- API helpers ---------- */

async function api(path, body) {
  const res = await fetch("/api/v1/" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const d = data.detail;
    throw new Error(typeof d === "string" ? d : JSON.stringify(d ?? res.statusText));
  }
  return data;
}

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(res.statusText);
  return res.json();
}

function setErr(el, msg) { el.textContent = msg || ""; }
function show(el, on) { el.style.display = on ? "" : "none"; }

function busy(btn, label, fn) {
  return async (...args) => {
    const orig = btn.innerHTML;
    btn.disabled = true; btn.innerHTML = `<span class="spinner"></span> ${label}…`;
    try { await fn(...args); }
    catch (e) { console.error(e); }
    finally { btn.disabled = false; btn.innerHTML = orig; }
  };
}

/* ---------- tabs ---------- */

document.querySelectorAll(".tab").forEach(t => t.onclick = () => {
  document.querySelectorAll(".tab").forEach(x => x.classList.toggle("active", x === t));
  document.querySelectorAll(".tabpane").forEach(p =>
    p.classList.toggle("active", p.id === "tab-" + t.dataset.tab));
});

/* ---------- health / parameters ---------- */

async function refreshHealth() {
  const el = $("health");
  try {
    const h = await fetchJSON("/health");
    const impls = h.implementations || {};
    const names = Object.keys(impls);
    el.textContent = names.length
      ? "● " + names.map(n => `${n}: Kyber${impls[n].join("/")}`).join("  ")
      : "no libraries";
    el.className = "health " + (names.length ? "ok" : "bad");
    syncAvailability(impls);
  } catch {
    el.textContent = "API unreachable"; el.className = "health bad";
  }
}

let implsCache = {};
function syncAvailability(impls) {
  implsCache = impls;
  for (const sel of [$("impl"), $("encImpl"), $("decImpl"), $("exImpl")]) {
    for (const opt of sel.options) opt.disabled = !(impls[opt.value] || []).length;
    if (sel.selectedOptions[0]?.disabled) sel.selectedIndex = 0;
  }
  for (const sel of [$("alg"), $("encAlg"), $("decAlg"), $("exAlg")]) {
    const implSel = sel.id === "alg" ? $("impl")
      : sel.id === "encAlg" ? $("encImpl")
      : sel.id === "decAlg" ? $("decImpl") : $("exImpl");
    const algs = impls[implSel.value] || [];
    for (const opt of sel.options) opt.disabled = !algs.includes(Number(opt.value));
    if (sel.selectedOptions[0]?.disabled) {
      const avail = [...sel.options].find(o => !o.disabled);
      if (avail) sel.value = avail.value;
    }
  }
  $("genBtn").disabled = !((impls[$("impl").value] || []).includes(Number($("alg").value)));
  refreshSizes();
}

async function refreshSizes() {
  const impl = $("impl").value, alg = $("alg").value;
  try {
    const p = await fetchJSON(`/api/v1/parameters?impl=${impl}`);
    const e = (p[impl]?.kyber_algorithms || []).find(a => String(a.id) === alg);
    $("sizes").innerHTML = e
      ? `pk <b>${e.public_key_bytes}B</b> · sk <b>${e.secret_key_bytes}B</b> · ct <b>${e.ciphertext_bytes}B</b> · ss <b>${e.shared_secret_bytes}B</b>`
      : `<span class="warn">algorithm not available for this implementation</span>`;
  } catch { $("sizes").textContent = ""; }
}

/* ---------- keypair profiles ---------- */

function saveProfiles() { store.set(LS_PROFILES, state.profiles); }

function profileSelectOptions() {
  return Object.values(state.profiles)
    .sort((a, b) => a.name.localeCompare(b.name))
    .map(p => `<option value="${esc(p.name)}">${esc(p.name)} — Kyber${p.alg} (${p.impl})</option>`).join("");
}
function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

function renderProfiles() {
  const names = Object.keys(state.profiles).sort();
  $("profileList").innerHTML = names.length ? names.map(n => {
    const p = state.profiles[n];
    return `<div class="profile-item ${n === state.selected ? "active" : ""}" data-name="${esc(n)}">
      <span class="pname">${esc(n)}</span>
      <span class="pmeta">Kyber${p.alg} · ${p.impl}</span>
      <button class="secondary small pdel" data-del="${esc(n)}" title="delete">&times;</button>
    </div>`;
  }).join("") : "";
  $("profileEmpty").style.display = names.length ? "none" : "";
  document.querySelectorAll(".profile-item").forEach(el =>
    el.onclick = e => { if (!e.target.dataset.del) selectProfile(el.dataset.name); });
  document.querySelectorAll("[data-del]").forEach(b => b.onclick = e => {
    e.stopPropagation();
    if (confirm(`Delete profile "${b.dataset.del}"?`)) {
      delete state.profiles[b.dataset.del];
      if (state.selected === b.dataset.del) state.selected = null;
      saveProfiles(); renderProfiles();
    }
  });
  if (state.selected) showProfile(state.selected);
}

function selectProfile(name) {
  state.selected = name;
  renderProfiles();
}

function showProfile(name) {
  const p = state.profiles[name];
  if (!p) { show($("profileDetail"), false); return; }
  show($("profileDetail"), true);
  $("pdImpl").textContent = p.impl;
  $("pdAlg").textContent = "Kyber" + p.alg;
  $("pdPkHex").textContent = p.pk;
  $("pdSkHex").textContent = p.sk;
  detail = { pk: p.pk, sk: p.sk, name: p.name, alg: p.alg, impl: p.impl };
}
let detail = { pk: "", sk: "" };

function upsertProfile(name, impl, alg, pk, sk) {
  state.profiles[name] = { name, impl, alg, pk, sk, created: Date.now() };
  state.selected = name;
  saveProfiles(); renderProfiles();
}

$("genBtn").onclick = busy($("genBtn"), "generating", async () => {
  setErr($("genErr"));
  const impl = $("impl").value, alg = Number($("alg").value);
  const name = $("profileName").value.trim() || `${impl}-kyber${alg}-${Date.now() % 100000}`;
  const r = await api(`${impl}/${alg}/keypair`);
  upsertProfile(name, impl, alg, r.public_key, r.secret_key);
});

$("importBtn").onclick = () => $("importFile").click();
$("importFile").onchange = async e => {
  setErr($("importErr"));
  const f = e.target.files[0]; e.target.value = "";
  if (!f) return;
  try {
    const j = JSON.parse(await f.text());
    if (!j.public_key || !j.secret_key) throw new Error("JSON must contain public_key and secret_key");
    const name = $("profileName").value.trim() || j.name || f.name.replace(/\.\w+$/, "");
    upsertProfile(name, j.implementation || "ref", Number(j.algorithm?.replace(/\D/g, "")) || 768,
                  j.public_key, j.secret_key);
  } catch (err) { setErr($("importErr"), err.message); }
};

$("pdDelete").onclick = () => {
  if (state.selected && confirm(`Delete profile "${state.selected}"?`)) {
    delete state.profiles[state.selected]; state.selected = null;
    saveProfiles(); renderProfiles();
  }
};
$("pdExport").onclick = () => {
  if (!detail.pk) return;
  const blob = new Blob([JSON.stringify({
    name: detail.name, algorithm: "Kyber" + detail.alg, implementation: detail.impl,
    public_key: detail.pk, secret_key: detail.sk,
  }, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = `${detail.name || "kyber"}-keypair.json`; a.click();
  URL.revokeObjectURL(a.href);
};
$("pdUseEnc").onclick = () => {
  $("encPk").value = detail.pk;
  document.querySelector('[data-tab="exchange"]').click();
};

document.querySelectorAll("[data-copy]").forEach(b => b.onclick = () => {
  const map = { pdPk: detail.pk, pdSk: detail.sk, ct: state.encResult?.ct,
                ssEnc: state.encResult?.ss, ssDec: state.decResult?.ss, chanOut: $("chanOut").textContent };
  const v = map[b.dataset.copy];
  if (v) { navigator.clipboard.writeText(v); b.textContent = "copied"; setTimeout(() => b.textContent = "copy", 800); }
});
document.querySelectorAll("#tab-keys [data-dl]").forEach(b => b.onclick = () => {
  const hex = b.dataset.dl === "pk" ? detail.pk : detail.sk;
  if (hex) download(`${detail.name || "key"}_${b.dataset.dl}.bin`, hex);
});
function download(name, hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  a.download = name; a.click(); URL.revokeObjectURL(a.href);
}

/* ---------- key exchange ---------- */

function wireExchange(prefix) {
  const implSel = $(prefix + "Impl"), algSel = $(prefix + "Alg");
  const refresh = () => {
    const algs = implsCache[implSel.value] || [];
    for (const opt of algSel.options) opt.disabled = !algs.includes(Number(opt.value));
    if (algSel.selectedOptions[0]?.disabled) {
      const avail = [...algSel.options].filter(o => !o.disabled);
      if (avail.length) algSel.value = avail[avail.length - 1].value;
    }
  };
  implSel.onchange = refresh; refresh();
}
wireExchange("enc"); wireExchange("dec");
$("encImpl").onchange = $("decImpl").onchange = refreshHealth;

$("encFromProfile").onclick = () => {
  if (detail.pk) $("encPk").value = detail.pk;
  else setErr($("encErr"), "select a profile first");
};
$("decFromProfile").onclick = () => {
  if (!detail.sk) return setErr($("decErr"), "select a profile first");
  $("decSk").value = detail.sk;
  $("decAlg").value = String(detail.alg);
  $("decImpl").value = detail.impl;
};

$("encBtn").onclick = busy($("encBtn"), "encapsulating", async () => {
  setErr($("encErr")); show($("encOut"), false);
  const impl = $("encImpl").value, alg = $("encAlg").value;
  const r = await api(`${impl}/${alg}/encapsulate`, { public_key: $("encPk").value.trim() });
  state.encResult = { ct: r.ciphertext, ss: r.shared_secret, alg, impl };
  $("ctHex").textContent = r.ciphertext;
  $("ssEncHex").textContent = r.shared_secret;
  show($("encOut"), true);
});

$("sendCtToDec").onclick = () => {
  $("decCt").value = state.encResult.ct;
  $("decAlg").value = state.encResult.alg;
  $("decImpl").value = state.encResult.impl;
  document.querySelector('[data-tab="exchange"]').click();
  $("decCt").scrollIntoView({ behavior: "smooth", block: "center" });
};

$("decBtn").onclick = busy($("decBtn"), "decapsulating", async () => {
  setErr($("decErr")); show($("decOut"), false);
  const impl = $("decImpl").value, alg = $("decAlg").value;
  const r = await api(`${impl}/${alg}/decapsulate`,
    { ciphertext: $("decCt").value.trim(), secret_key: $("decSk").value.trim() });
  state.decResult = { ss: r.shared_secret, alg, impl };
  $("ssDecHex").textContent = r.shared_secret;
  const v = $("verdict");
  if (state.encResult) {
    const ok = state.encResult.ss === r.shared_secret && String(state.encResult.alg) === String(alg);
    v.innerHTML = ok
      ? '<span class="match">✔ Shared secrets match — key exchange successful.</span>'
      : '<span class="mismatch">✘ Shared secrets differ (wrong key, ciphertext, or algorithm).</span>';
  } else {
    v.innerHTML = '<span class="warn">Run an encapsulation first to compare shared secrets.</span>';
  }
  show($("decOut"), true);
});

$("keepSs").onclick = () => keepSecret(state.encResult);
$("keepSsDec").onclick = () => keepSecret(state.decResult);

/* ---------- secure channel (AES-GCM over the KEM shared secret) ---------- */

async function keepSecret(res) {
  if (!res) return;
  setErr($("chanErr"), "");
  try {
    const raw = hexToBytes(res.ss);
    const ikm = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new TextEncoder().encode("kyber-kem-channel-v1") },
      ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const fp = await fingerprint(key);
    state.channel = { ssHex: res.ss, alg: res.alg, impl: res.impl, key, fingerprint: fp };
    renderChannel();
    document.querySelector('[data-tab="channel"]').click();
  } catch (e) { setErr($("chanErr"), "key derivation failed: " + e.message); }
}

async function fingerprint(key) {
  // Export is not allowed for non-extractable keys; hash a known plaintext instead.
  const iv = new Uint8Array(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode("kyber-fingerprint"));
  const digest = await crypto.subtle.digest("SHA-256", ct);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}

function renderChannel() {
  const c = state.channel;
  if (!c) {
    show($("chanInfo"), false);
    $("chanStatus").textContent = 'No shared secret yet. Complete a key exchange and click "Keep shared secret".';
    $("chanGo").disabled = true; $("chanDecGo").disabled = true;
    return;
  }
  $("chanStatus").textContent = "";
  show($("chanInfo"), true);
  $("chanAlg").textContent = `Kyber${c.alg} · ${c.impl}`;
  $("chanFp").textContent = c.fingerprint + "…";
  $("chanGo").disabled = false; $("chanDecGo").disabled = false;
  const isSender = $("chanRole").value === "sender";
  $("chanOpTitle").textContent = isSender ? "Encrypt message" : "Decrypt message";
  $("chanMsgLabel").textContent = isSender ? "Message (UTF-8)" : "Ciphertext (base64)";
  $("chanGo").textContent = isSender ? "Encrypt & send" : "Decrypt";
  show($("chanDecWrap"), isSender);   // sender can also test-decrypt; recipient's input IS the message box
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), ch => ch.charCodeAt(0));

$("chanRole").onchange = renderChannel;
$("chanClear").onclick = () => { state.channel = null; renderChannel(); };

$("chanGo").onclick = async () => {
  setErr($("chanErr")); show($("chanOutWrap"), false); show($("chanPlainWrap"), false);
  const c = state.channel; if (!c) return;
  const isSender = $("chanRole").value === "sender";
  try {
    if (isSender) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv }, c.key, new TextEncoder().encode($("chanMsg").value));
      const blob = b64(concat(iv, ct));
      $("chanOutLbl").textContent = "Ciphertext (base64) — send this to the recipient";
      $("chanOut").textContent = blob;
      $("chanBlob").value = blob;  // convenience: fills decrypt box
      show($("chanOutWrap"), true);
    } else {
      const raw = unb64($("chanMsg").value.trim());
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: raw.slice(0, 12) }, c.key, raw.slice(12));
      $("chanOutLbl").textContent = "Decrypted message";
      $("chanOut").textContent = new TextDecoder().decode(plain);
      show($("chanOutWrap"), true);
    }
  } catch (e) { setErr($("chanErr"), "crypto operation failed: " + e.message); }
};

// Sender decrypt box: paste a blob produced by the peer.
$("chanDecGo").onclick = async () => {
  setErr($("chanErr")); show($("chanPlainWrap"), false);
  const c = state.channel; if (!c) return;
  try {
    const raw = unb64($("chanBlob").value.trim());
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: raw.slice(0, 12) }, c.key, raw.slice(12));
    $("chanPlain").textContent = new TextDecoder().decode(plain);
    show($("chanPlainWrap"), true);
  } catch (e) { setErr($("chanErr"), "decrypt failed: " + e.message); }
};

function concat(a, b) {
  const out = new Uint8Array(a.length + b.byteLength ?? b.length);
  out.set(a, 0); out.set(b instanceof ArrayBuffer ? new Uint8Array(b) : b, a.length);
  return out;
}

/* ---------- API explorer ---------- */

const ENDPOINTS = [
  { method: "POST", path: "/{impl}/{alg}/keypair",       body: null,                                   desc: "Generate a keypair" },
  { method: "POST", path: "/{impl}/{alg}/encapsulate",   body: '{\n  "public_key": "<hex>"\n}',       desc: "Encapsulate to a public key" },
  { method: "POST", path: "/{impl}/{alg}/decapsulate",   body: '{\n  "ciphertext": "<hex>",\n  "secret_key": "<hex>"\n}', desc: "Decapsulate a ciphertext" },
  { method: "GET",  path: "/parameters",                 body: null,                                   desc: "List algorithms and sizes", noImpl: true },
  { method: "GET",  path: "/health",                     body: null,                                   desc: "Liveness probe", root: true },
];

function fillExplorerPaths() {
  const cur = $("exPath").value;
  $("exPath").innerHTML = ENDPOINTS.map((e, i) =>
    `<option value="${i}">${e.method} ${e.path} — ${e.desc}</option>`).join("");
  if (cur) $("exPath").value = cur;
  syncExplorer();
}
function syncExplorer() {
  const e = ENDPOINTS[Number($("exPath").value) || 0];
  $("exMethod").value = e.method;
  $("exBody").value = e.body || "";
  $("exBody").disabled = e.method === "GET";
  $("exImpl").disabled = !!e.noImpl;
  $("exAlg").disabled = !!e.noImpl;
}
$("exPath").onchange = syncExplorer;
fillExplorerPaths();

function explorerURL() {
  const e = ENDPOINTS[Number($("exPath").value) || 0];
  if (e.root) return null;
  if (e.noImpl) return e.path;
  return `${$("exImpl").value}/${$("exAlg").value}${e.path}`;
}
function explorerFetchPath() {
  const e = ENDPOINTS[Number($("exPath").value) || 0];
  const u = explorerURL();
  return e.root ? e.path : "/api/v1" + u;
}

$("exSend").onclick = async () => {
  setErr($("exErr"));
  $("exResp").textContent = "…";
  const e = ENDPOINTS[Number($("exPath").value) || 0];
  try {
    let data;
    if (e.method === "GET") {
      const res = await fetch(explorerFetchPath());
      data = await res.json();
      if (!res.ok) throw new Error(JSON.stringify(data.detail ?? data));
    } else {
      data = await api(explorerURL(), JSON.parse($("exBody").value || "{}"));
    }
    $("exResp").textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    $("exResp").textContent = "";
    setErr($("exErr"), err.message);
  }
};

$("exCurl").onclick = () => {
  const e = ENDPOINTS[Number($("exPath").value) || 0];
  let cmd = `curl -X ${e.method} http://localhost:8000${explorerFetchPath()}`;
  if (e.method === "POST") cmd += ` -H 'Content-Type: application/json' -d '${$("exBody").value.replace(/'/g, "'\\''")}'`;
  $("exResp").textContent = cmd;
};

/* ---------- init ---------- */

for (const sel of [$("impl"), $("encImpl"), $("decImpl"), $("exImpl")])
  sel.onchange = () => { refreshHealth(); if (sel === $("impl")) refreshSizes(); };
for (const sel of [$("alg"), $("encAlg"), $("decAlg"), $("exAlg")])
  sel.onchange = refreshHealth;
$("impl").onchange = refreshSizes;

refreshHealth();
setInterval(refreshHealth, 15000);
renderProfiles();
renderChannel();

"use strict";

// ---------- i18n ----------
// Turkish source strings are the keys; web/i18n/<lang>.json maps them to other
// languages. Text produced by the backend already arrives in the chosen language.
let DICT = {};
let LANG = "tr";
function t(s, vars) {
  let out = DICT[s] ?? s;
  if (vars) out = out.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
  return out;
}
const LOCALE = () => (LANG === "en" ? "en-GB" : "tr-TR");
async function loadLanguage(lang) {
  LANG = lang === "en" ? "en" : "tr";
  document.documentElement.lang = LANG;
  if (LANG === "tr") { DICT = {}; return; }
  try {
    const r = await fetch(`/static/i18n/${LANG}.json`);
    if (r.ok) DICT = await r.json();
  } catch { DICT = {}; }  // fail soft: stay in Turkish
}
function applyStatic() {
  document.querySelectorAll("[data-i18n]").forEach((el) => (el.textContent = t(el.dataset.i18n)));
  document.querySelectorAll("[data-i18n-aria]").forEach((el) => el.setAttribute("aria-label", t(el.dataset.i18nAria)));
}

// ---------- helpers ----------
const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtDate = (ts) => ts ? new Date(typeof ts === "number" ? ts * 1000 : ts).toLocaleString(LOCALE(), { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "—";
const fmtDay = (ts) => ts ? new Date(typeof ts === "number" ? ts * 1000 : ts).toLocaleDateString(LOCALE(), { day: "numeric", month: "long", year: "numeric" }) : "—";
const fmtNum = (n) => Number(n).toLocaleString(LOCALE());
function ago(ts) {
  if (!ts) return t("hiç");
  const s = Math.round(Date.now() / 1000 - ts);
  if (s < 60) return t("az önce");
  if (s < 3600) return t("{n} dk önce", { n: Math.floor(s / 60) });
  if (s < 86400) return t("{n} sa önce", { n: Math.floor(s / 3600) });
  return t("{n} gün önce", { n: Math.floor(s / 86400) });
}
function until(ts) {
  const s = Math.round(ts - Date.now() / 1000);
  if (s <= 0) return t("şimdi");
  if (s < 3600) return t("{n} dk", { n: Math.ceil(s / 60) });
  if (s < 86400) return t("{n} sa", { n: Math.round(s / 3600) });
  return t("{n} gün", { n: Math.round(s / 86400 * 10) / 10 });
}

async function api(path, body) {
  const opt = body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Requested-With": "aug" },
    body: JSON.stringify(body),
  };
  const r = await fetch(path, opt);
  let data = null;
  try { data = await r.json(); } catch { /* non-JSON */ }
  if (!r.ok) throw new Error((data && data.error) || `HTTP ${r.status}`);
  return data;
}

let toastTimer;
function toast(msg, isError = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.className = "show" + (isError ? " error" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.className = ""), isError ? 6000 : 3000);
}

// ---------- state ----------
const ui = {
  data: null,
  tab: "aur",
  selected: new Map(),   // "name@target" -> bool (user's explicit choice)
  newsAck: false,
  repoFilter: "",
  openDetails: new Set(),
  pollTimer: null,
};

// Label maps are functions so they pick up the dictionary loaded at startup.
const STATUS = () => ({
  clean: ["ok", t("Temiz")],
  warning: ["warn", t("Dikkat")],
  danger: ["danger", t("Tehlikeli")],
  unreviewed: ["neutral", t("İncelenmedi")],
  missing: ["warn", t("AUR'da yok")],
  error: ["danger", t("Hata")],
});
const SEV = () => ({ high: ["danger", t("Yüksek")], medium: ["warn", t("Orta")], low: ["info", t("Düşük")], info: ["info", t("Bilgi")] });
const AVG_SEV = { Critical: "danger", High: "danger", Medium: "warn", Low: "info", Unknown: "neutral" };
const AVG_SEV_TR = () => ({ Critical: t("Kritik"), High: t("Yüksek"), Medium: t("Orta"), Low: t("Düşük"), Unknown: t("Bilinmiyor") });

const keyOf = (a) => `${a.name}@${a.target}`;
const canSelect = (a) => a.target && (a.approved || a.auto_ok);
const isSelected = (a) => canSelect(a) && (ui.selected.has(keyOf(a)) ? ui.selected.get(keyOf(a)) : true);

// ---------- polling ----------
async function refresh() {
  try {
    ui.data = await api("/api/state");
    render();
  } catch (e) {
    $("#status-line").textContent = t("Sunucuya ulaşılamıyor: {msg}", { msg: e.message });
  }
  schedulePoll();
}
function schedulePoll() {
  clearTimeout(ui.pollTimer);
  const d = ui.data;
  const fast = d && (d.busy || d.update?.running || (d.reviewing || []).length || (d.analyzing || []).length || (d.news_analyzing || []).length);
  ui.pollTimer = setTimeout(refresh, fast ? 2000 : 30000);
}

// ---------- rendering ----------
function render() {
  const d = ui.data;
  const r = d.report;
  renderTop(d);
  const app = $("#app");
  if (!r) {
    app.innerHTML = `<div class="card card-pad empty">
      <h2>${t("Henüz kontrol yapılmadı")}</h2>
      <p>${t("İlk kontrol resmi depoları, AUR paketlerini, Arch haberlerini ve güvenlik açıklarını tarar.")}</p>
      <button class="btn primary" data-act="check" ${d.busy ? "disabled" : ""}>${t("İlk kontrolü başlat")}</button></div>`;
    return;
  }
  const scrollY = window.scrollY;
  app.innerHTML = renderAlerts(d, r) + renderStats(r) + renderPlan(d, r) + renderTabs(r);
  window.scrollTo(0, scrollY);
}

function renderTop(d) {
  const r = d.report;
  const line = r
    ? t("Son kontrol {ago} ({date}) · {n} paket kurulu", { ago: ago(r.generated_at), date: fmtDate(r.generated_at), n: r.system.installed_count })
    : t("Henüz kontrol yapılmadı");
  $("#status-line").textContent = line;
  $("#btn-check").disabled = d.busy;
  $("#btn-check").textContent = d.busy ? t("Kontrol ediliyor…") : t("Şimdi kontrol et");
  const p = $("#progress");
  p.hidden = !d.busy;
  if (d.busy) {
    const pr = d.progress || {};
    const fill = $("#progress-fill");
    if (pr.total) {
      fill.className = "";
      fill.style.width = `${Math.round((pr.done / pr.total) * 100)}%`;
    } else {
      fill.className = "indeterminate";
      fill.style.width = "";
    }
    $("#progress-text").textContent = (pr.message || t("Hazırlanıyor")) + (pr.total ? ` (${pr.done}/${pr.total})` : "");
  }
}

function renderAlerts(d, r) {
  const out = [];
  for (const i of (r.incidents || []).filter((x) => x.severity === "high"))
    out.push(alertBox("danger", "⛔", esc(i.title), esc(i.detail)));
  const oldBad = (r.incidents || []).filter((x) => x.severity !== "high");
  if (oldBad.length) out.push(alertBox("info", "ℹ", t("Kurulu bazı paketler bilinen bir saldırı listesinde, ama saldırıdan önce kurulmuş"),
    t("{list}. Zararlı sürüm kurulmamış görünüyor; bir sonraki güncellemelerini dikkatle incele.",
      { list: oldBad.map((x) => `<b>${esc(x.package)}</b> (${esc(x.campaign)})`).join(", ") })));
  const danger = r.aur.filter((a) => a.status === "danger");
  if (danger.length) out.push(alertBox("danger", "⛔", t("{n} AUR güncellemesinde tehlikeli bulgu var", { n: danger.length }),
    t("İncelemeden kurma: {list}. Ayrıntılar AUR sekmesinde.", { list: danger.map((a) => `<b>${esc(a.name)}</b>`).join(", ") })));
  const missing = r.aur.filter((a) => a.status === "missing");
  if (missing.length) out.push(alertBox("warn", "⚠", t("Kurulu bazı paketler artık AUR'da yok"),
    t("{list}. AUR'dan kaldırılan paketler bazen zararlı oldukları için silinir; neden kaldırıldığına bak.", { list: missing.map((a) => esc(a.name)).join(", ") })));
  const unread = r.news.filter((n) => n.since_last_upgrade && !n.read);
  if (unread.length) out.push(alertBox("warn", "📰", t("Son güncellemenden sonra Arch haberi yayımlandı"),
    `${t("Güncellemeden önce oku:")} <ul>${unread.map((n) => `<li><a href="${esc(n.link)}" target="_blank" rel="noopener">${esc(n.title)}</a>${renderNewsAi(n.ai, true)}</li>`).join("")}</ul>`));
  const rt = r.runtime;
  if (rt && rt.reboot_recommended) out.push(alertBox("info", "↻", t("Bilgisayarı yeniden başlatman öneriliyor"),
    `${rt.kernel_updated ? t("Çalışan çekirdek güncellendi.") + " " : ""}${rt.reboot_packages.length ? t("Açılıştan sonra güncellenen temel paketler: {list}.", { list: esc(rt.reboot_packages.join(", ")) }) + " " : ""}${t("Ayrıntılar Sistem sekmesinde.")}`));
  else if (rt && rt.services.some((s) => s.safe)) out.push(alertBox("info", "↻", t("{n} servis eski kütüphaneyle çalışıyor", { n: rt.services.filter((s) => s.safe).length }),
    t("Güncellemenin bu servislerde etkin olması için yeniden başlatılmaları gerekiyor. Sistem sekmesinden tek tıkla yapabilirsin.")));
  else if (r.system.reboot_needed) out.push(alertBox("info", "↻", t("Yeniden başlatma bekliyor"), t("Çalışan çekirdek güncellendi; değişikliklerin etkin olması için bilgisayarı yeniden başlat.")));
  if (d.check_error) out.push(alertBox("danger", "✕", t("Son kontrol başarısız oldu"), esc(d.check_error)));
  for (const e of r.errors) out.push(alertBox("warn", "⚠", t("Kontrolün bir bölümü tamamlanamadı"), esc(e)));
  const last = d.update?.last;
  if (last && last.finished && Date.now() / 1000 - last.finished < 3600) {
    const ok = last.repo_rc === 0 && (last.aur_rc === 0 || last.aur_rc === -1);
    out.push(alertBox(ok ? "info" : "danger", ok ? "✓" : "✕", ok ? t("Güncelleme tamamlandı") : t("Güncelleme hatayla bitti"),
      `${fmtDate(last.finished)} · ${t("pacman kodu {a}, yay kodu {b}", { a: last.repo_rc, b: last.aur_rc })}${last.aur ? " · AUR: " + esc(last.aur) : ""}`));
  }
  return out.length ? `<section class="alerts">${out.join("")}</section>` : "";
}
const alertBox = (kind, icon, title, body) =>
  `<div class="alert ${kind}"><span class="alert-icon">${icon}</span><div><b>${title}</b><div class="small">${body}</div></div></div>`;

function renderStats(r) {
  const imp = r.repo.filter((x) => x.important).length;
  const cve = r.repo.filter((x) => x.fixes_cve).length;
  const aurUp = r.aur.filter((a) => a.new_version);
  const bad = r.aur.filter((a) => ["danger", "warning", "missing"].includes(a.status)).length;
  const unrev = r.aur.filter((a) => a.status === "unreviewed").length;
  const activeV = r.vulns.filter((v) => vulnGroup(v) === "active");
  const highV = activeV.filter((v) => ["Critical", "High"].includes(v.severity)).length;
  const fixable = activeV.filter((v) => v.fix_pending).length;
  const setAside = r.vulns.length - activeV.length;
  const unread = r.news.filter((n) => n.since_last_upgrade && !n.read).length;
  const latest = r.news[0];
  const stat = (tab, label, value, sub) =>
    `<button class="card stat" data-tab="${tab}"><div class="label">${label}</div><div class="value">${value}</div><div class="sub">${sub}</div></button>`;
  return `<section class="stats">
    ${stat("repo", t("Resmi depo güncellemesi"), r.repo.length, `${imp ? `<span>${t("{n} önemli", { n: imp })}</span>` : ""}${cve ? `<span>${t("{n} güvenlik düzeltmesi", { n: cve })}</span>` : ""}${!imp && !cve ? t("imzalı resmi paketler") : ""}`)}
    ${stat("aur", t("AUR güncellemesi"), aurUp.length, bad ? `<span class="badge warn">${t("{n} dikkat", { n: bad })}</span>` : unrev ? `<span>${t("{n} incelenmedi", { n: unrev })}</span>` : t("sorun bulunmadı"))}
    ${stat("vulns", t("Bilinen güvenlik açığı"), activeV.length, `${highV ? `<span>${t("{n} yüksek/kritik", { n: highV })}</span>` : ""}<span>${t("{n} bu güncellemeyle kapanıyor", { n: fixable })}</span>${setAside ? `<span>${t("{n} düzeltilmiş/eski kayıt ayrıldı", { n: setAside })}</span>` : ""}`)}
    ${stat("news", t("Yeni Arch haberi"), unread, unread ? t("son güncellemenden sonra yayımlandı") : latest ? t("son haber: {date}", { date: fmtDay(latest.published) }) : t("haber alınamadı"))}
  </section>`;
}

function renderPlan(d, r) {
  const aur = r.aur.filter((a) => a.target);
  const sel = aur.filter(isSelected);
  const unread = r.news.filter((n) => n.since_last_upgrade && !n.read);
  const running = d.update?.running;
  const nothing = !r.repo.length && !sel.length;
  const blocked = (unread.length && !ui.newsAck) || running || d.busy || nothing;
  const stale = Date.now() / 1000 - r.generated_at > 6 * 3600;
  const ST = STATUS();
  const rows = aur.map((a) => {
    const [cls, label] = ST[a.status] || ["neutral", a.status];
    let why;
    if (a.approved) why = t("Elle onaylandı");
    else if (a.auto_ok) why = t("İnceleme temiz, bekleme süresi doldu");
    else if (srcPending(a)) why = t("Kaynak dosyalar hâlâ iniyor; incelenince seçilebilir (elle onaylayabilirsin)");
    else if (a.status === "clean" && a.held) why = t("Bekleme süresinde: {left} sonra hazır ({date})", { left: until(a.hold_until), date: fmtDate(a.hold_until) });
    else if (a.status === "unreviewed") why = t("İncelenmedi; diff'e bakıp elle onaylaman gerekiyor");
    else why = t("Bulgular var; incelemeden onaylanamaz");
    return `<label class="plan-row">
      <input type="checkbox" data-sel="${esc(keyOf(a))}" ${isSelected(a) ? "checked" : ""} ${canSelect(a) ? "" : "disabled"}>
      <span><b>${esc(a.name)}</b> <span class="ver">${esc(a.installed)} → <b>${esc(a.new_version)}</b></span></span>
      <span class="badge ${cls}">${label}</span>
      <span class="why">${why}</span></label>`;
  }).join("");
  return `<section class="card card-pad">
    <div class="plan">
      <div>
        <h2>${t("Güncelleme planı")}</h2>
        <p class="muted small" style="margin:4px 0 0">${t("{n} resmi depo paketinin hepsi güncellenir (Arch'ta kısmi güncelleme desteklenmez). AUR paketlerinden yalnızca işaretlediklerin kurulur.", { n: r.repo.length })}</p>
        ${aur.length ? `<div class="plan-list">${rows}</div>` : `<p class="muted small">${t("Bekleyen AUR güncellemesi yok.")}</p>`}
      </div>
      <div class="plan-side">
        <div class="checks">
          <span>${r.system.autosnap ? "✓ " + t("Timeshift kurulumdan önce anlık görüntü alacak") : "⚠ " + t("timeshift-autosnap bulunamadı")}</span>
          <span>${r.system.disk_free_gb > 10 ? "✓" : "⚠"} ${t("{n} GB boş alan", { n: r.system.disk_free_gb })}</span>
          <span>${stale ? "⚠ " + t("Rapor 6 saatten eski, önce yeniden kontrol et") : "✓ " + t("Rapor güncel ({ago})", { ago: ago(r.generated_at) })}</span>
        </div>
        ${unread.length ? `<label class="ack"><input type="checkbox" id="news-ack" ${ui.newsAck ? "checked" : ""}><span>${t("Son güncellememden sonra yayımlanan {n} Arch haberini okudum.", { n: unread.length })}</span></label>` : ""}
        <button class="btn primary lg" data-act="update" ${blocked || stale ? "disabled" : ""}>
          ${running ? t("Güncelleme sürüyor…") : nothing ? t("Güncellenecek bir şey yok") : t("Güncellemeyi başlat ({n} paket)", { n: r.repo.length + sel.length })}</button>
        <span class="muted small">${t("Konsole penceresinde açılır; parolanı ve pacman sorularını orada yanıtlarsın.")}</span>
      </div>
    </div>
  </section>`;
}

function renderTabs(r) {
  const tabs = [
    ["aur", "AUR", r.aur.length],
    ["repo", t("Resmi depo"), r.repo.length],
    ["vulns", t("Güvenlik"), r.vulns.filter((v) => vulnGroup(v) === "active").length],
    ["news", t("Haberler"), r.news.filter((n) => n.since_last_upgrade && !n.read).length || ""],
    ["system", t("Sistem"), r.system.pacnew.length || ""],
  ];
  const body = { aur: renderAur, repo: renderRepo, vulns: renderVulns, news: renderNews, system: renderSystem }[ui.tab](r);
  return `<section class="card">
    <nav class="tabs" role="tablist">${tabs.map(([id, label, n]) =>
      `<button class="tab ${ui.tab === id ? "active" : ""}" data-tab="${id}" role="tab">${label}${n !== "" && n !== undefined ? `<span class="count">${n}</span>` : ""}</button>`).join("")}</nav>
    <div class="tab-body">${body}</div></section>`;
}

function renderAur(r) {
  if (!r.aur.length) {
    return `<div class="empty">${t("Bekleyen AUR güncellemesi yok. {n} AUR paketinin hepsi güncel ve AUR'da duruyor.", { n: r.system.foreign_count })}</div>`;
  }
  const order = { danger: 0, error: 1, missing: 2, warning: 3, unreviewed: 4, clean: 5 };
  const items = [...r.aur].sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9) || a.name.localeCompare(b.name));
  const reviewing = new Set(ui.data.reviewing || []);
  return `<div class="pkgs">${items.map((a) => renderPkg(a, reviewing.has(a.name), r)).join("")}</div>
    <p class="note">${t("İnceleme iki katmanlıdır: sabit kural taraması her zaman çalışır ve yapay zekâ kararı bir kural bulgusunu asla temizleyemez. Yapay zekânın gerekçeleri doğrulanmamış yorumdur; paketin yazdığı metinden etkilenmiş olabilir.")}</p>`;
}

function renderPkg(a, reviewing, r) {
  const [cls, label] = STATUS()[a.status] || ["neutral", a.status];
  if (a.status === "missing" || a.status === "error") {
    return `<article class="pkg ${a.status}"><div class="pkg-head"><span class="pkg-name">${esc(a.name)}</span>
      <span class="ver">${t("kurulu")} <b>${esc(a.installed)}</b></span><span class="badge ${cls}">${label}</span></div>
      <div class="pkg-body">${a.error ? `<div class="verdict">${esc(a.error)}</div>` : ""}${renderFindings(a.findings)}</div></article>`;
  }
  const verdict = renderVerdict(a.llm);
  const holdBadge = a.held ? `<span class="badge neutral" title="${esc(fmtDate(a.hold_until))}">⏳ ${t("{left} bekleme", { left: until(a.hold_until) })}</span>` : "";
  const apprBadge = a.approved ? `<span class="badge accent">✓ ${t("Onaylandı")}</span>` : "";
  const dk = `diff:${keyOf(a)}`;
  const providers = (ui.settings?.providers || []);
  return `<article class="pkg ${a.status}">
    <div class="pkg-head">
      <span class="pkg-name">${esc(a.name)}</span>
      <span class="ver">${esc(a.installed)} → <b>${esc(a.new_version)}</b>${a.vcs ? " · " + t("geliştirme sürümü") : ""}</span>
      <span class="badge ${cls}">${label}</span>${holdBadge}${apprBadge}
      <span class="spacer"></span>
      <a class="small" href="${esc(a.aur_url)}" target="_blank" rel="noopener">${t("AUR sayfası")} ↗</a>
    </div>
    <div class="pkg-body">
      ${verdict}
      ${renderFindings(a.findings)}
      ${renderDeps(a.new_aur_deps, a.name)}
      ${renderSourcesLine(a.sources)}
      <div class="meta-grid">
        <span>${t("Bakımcı:")} <b>${esc(a.maintainer || t("yok"))}</b>${a.known_maintainer && a.known_maintainer !== a.maintainer ? ` (${t("önceden {who}", { who: esc(a.known_maintainer) })})` : ""}</span>
        <span>${t("Oy:")} <b>${a.votes ?? "?"}</b></span>
        <span>${t("AUR'a ilk ekleniş:")} <b>${fmtDay(a.first_submitted)}</b></span>
        <span>${t("Bu sürüm:")} <b>${fmtDate(a.last_modified)}</b></span>
        <span>${t("Karşılaştırma:")} <b>${a.diff?.base ? esc(a.diff.base.slice(0, 10)) : t("yok")}</b> → <b>${esc(a.target.slice(0, 10))}</b> (${esc(a.base_source)})</span>
      </div>
      <div class="pkg-actions">
        ${a.approved
          ? `<button class="btn sm" data-act="unapprove" data-name="${esc(a.name)}">${t("Onayı kaldır")}</button>`
          : `<button class="btn sm ${a.status === "clean" ? "" : "primary"}" data-act="approve" data-name="${esc(a.name)}" data-commit="${esc(a.approval_key || a.target)}" data-status="${a.status}">
              ${a.status === "clean" && a.held ? t("Beklemeden onayla") : a.status === "clean" ? t("Onayla") : t("İnceledim, onayla")}</button>`}
        <button class="btn sm ghost" data-act="rereview" data-name="${esc(a.name)}" ${reviewing ? "disabled" : ""}>${reviewing ? t("İnceleniyor…") : t("Yeniden incelet")}</button>
        ${providers.length > 1 ? `<select class="input" style="height:28px" data-provider-for="${esc(a.name)}">${providers.map((p) =>
          `<option value="${esc(p.id)}" ${p.id === ui.settings.review.active_provider ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select>` : ""}
      </div>
    </div>
    <details class="more" data-key="${esc(dk)}" ${ui.openDetails.has(dk) ? "open" : ""}>
      <summary>${a.diff.truncated ? t("Diff'i ve commit'leri göster ({n} karakter, kısaltıldı)", { n: fmtNum(a.diff.chars) }) : t("Diff'i ve commit'leri göster ({n} karakter)", { n: fmtNum(a.diff.chars) })}</summary>
      <div class="more-body">
        <ul class="commits">${(a.commits || []).map((c) => `<li><code>${esc(c.hash.slice(0, 10))}</code> ${esc(c.subject)} <span class="muted">— ${esc(c.author)} &lt;${esc(c.email)}&gt;, ${fmtDate(c.time)}</span></li>`).join("")}</ul>
        ${ui.openDetails.has(dk) ? renderDiff(a.diff.text) : ""}
      </div>
    </details>
    ${renderSources(a.sources, `src:${keyOf(a)}`)}
  </article>`;
}

const srcPending = (a) => (a.sources?.sources || []).some((s) => s.status === "deferred");
const fmtSize = (n) => n == null ? "?" : n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} B`;
const SRC_STATUS = () => ({
  ok: t("incelendi"), "in-repo": t("AUR deposunda (diff'te)"), vcs: t("git/svn deposu, önceden incelenemez"),
  deferred: t("iniyor, sonraki kontrolde"), "too-large": t("boyut sınırını aşıyor"), "download-failed": t("indirilemedi"),
  unsupported: t("desteklenmeyen adres"), skipped: t("atlandı"),
});
const CAT_TR = () => ({ persist: t("kalıcılık"), system: t("sistem"), "deb-script": t("deb betiği"), build: t("derleme"), script: t("betik"), text: t("metin") });

function renderSourcesLine(src) {
  if (!src) return "";
  if (src.error) return `<div class="srcline muted small">${t("Kaynak dosyalar incelenemedi: {msg}", { msg: esc(src.error) })}</div>`;
  const remote = (src.sources || []).filter((s) => !["in-repo"].includes(s.status));
  if (!remote.length) return `<div class="srcline muted small">${t("İndirilecek dış kaynak yok; paketin tüm dosyaları yukarıdaki diff'te.")}</div>`;
  const ok = remote.filter((s) => s.status === "ok");
  const bad = remote.filter((s) => s.verified === false).length;
  const parts = [t("{ok}/{all} kaynak dosya indirilip incelendi", { ok: ok.length, all: remote.length })];
  if (ok.length) parts.push(bad ? `<b class="warn-text">${t("{n} dosyanın sağlama toplamı tutmuyor", { n: bad })}</b>` : ok.every((s) => s.verified) ? t("sağlama toplamları doğrulandı") : t("bazı dosyaların sabitlenmiş sağlama toplamı yok"));
  const sm = src.summaries || [];
  if (sm.some((x) => x.baseline)) {
    const tot = sm.reduce((acc, x) => ({ a: acc.a + (x.added || 0), r: acc.r + (x.removed || 0), c: acc.c + (x.changed || 0) }), { a: 0, r: 0, c: 0 });
    parts.push(t("kurulu sürüme göre {a} dosya eklendi, {r} silindi, {c} değişti", tot));
  } else if (ok.length) parts.push(t("karşılaştırılacak eski sürüm yok, yalnızca içerik tarandı"));
  for (const tc of src.tag_compare || []) {
    if (tc.status === "ok") parts.push(tc.modified.length || tc.only_tar.length
      ? `<b class="warn-text">${t("sürüm arşivi git etiketinden farklı ({m} değişik, {o} fazla dosya)", { m: tc.modified.length, o: tc.only_tar.length })}</b>`
      : t("sürüm arşivi git etiketiyle ({tag}) uyumlu", { tag: esc(tc.tag) }));
    else if (tc.status === "git-archive") parts.push(t("arşiv doğrudan git'ten üretilmiş"));
  }
  return `<div class="srcline small">📦 ${parts.join(" · ")}</div>`;
}

function renderSources(src, dk) {
  if (!src || !(src.sources || []).some((s) => s.status !== "in-repo")) return "";
  const open = ui.openDetails.has(dk);
  const SS = SRC_STATUS();
  const CT = CAT_TR();
  const rows = src.sources.filter((s) => s.status !== "in-repo").map((s) => {
    const sm = (src.summaries || []).find((x) => x.file === s.file);
    const ver = s.verified === true ? `<span class="badge ok">✓ ${t("sağlama toplamı")}</span>` : s.verified === false ? `<span class="badge danger">${t("sağlama toplamı tutmuyor")}</span>` : s.status === "ok" ? `<span class="badge neutral">${t("sağlama toplamı yok (SKIP)")}</span>` : "";
    let detail = "";
    if (sm) {
      detail = `<div class="muted small">${esc(sm.format)} · ${fmtSize(sm.size)} · ${t("{n} dosya", { n: sm.members })} · ${t("{n} derlenmiş ikili", { n: sm.elf })}${sm.root ? ` · ${t("kök:")} ${esc(sm.root)}` : ""}</div>`;
      if (sm.baseline) {
        detail += `<div class="small">${t("Kurulu sürümdeki {file} ({size}) ile: {a} eklendi, {r} silindi, {c} değişti",
          { file: `<code>${esc(sm.old_file)}</code>`, size: fmtSize(sm.old_size), a: `<b>${sm.added}</b>`, r: `<b>${sm.removed}</b>`, c: `<b>${sm.changed}</b>` })}${sm.size_only ? ` <span class='muted'>${t("(bu biçimde yalnızca boyutlar karşılaştırılabildi)")}</span>` : ""}</div>`;
        const list = (label, arr) => arr.length ? `<div class="small"><span class="muted">${label}:</span> ${arr.map((p) => `<code>${esc(p)}</code>`).join(" ")}</div>` : "";
        detail += list(t("Eklenenler"), sm.added_list) + list(t("Değişenler"), sm.changed_list) + list(t("Silinenler"), sm.removed_list);
      } else {
        detail += `<div class="small muted">${t("Kurulu sürümün kaynağı karşılaştırma için elde yok; içerik yalnızca tarandı.")}</div>`;
      }
      if (sm.notable.length) detail += `<div class="small"><span class="muted">${t("Sisteme yerleşen dosyalar:")}</span> ${sm.notable.map((n) => `<code>${esc(n.path)}</code> <span class="muted">(${CT[n.cat] || n.cat})</span>`).join(" ")}</div>`;
      if (open && sm.diffs.length) detail += sm.diffs.map((d) => `<div class="small"><b>${esc(d.path)}</b> <span class="muted">(${CT[d.cat] || d.cat || t("metin")})</span></div>${renderDiff(d.diff)}`).join("");
    }
    const tc = (src.tag_compare || []).find((x) => x.file === s.file);
    if (tc) {
      const TC = { "git-archive": t("Arşiv, git deposundan doğrudan üretilmiş; git etiketiyle aynı içerik."),
        "no-repo": t("Kaynağın git deposu bilinmiyor; git etiketiyle karşılaştırılamadı."),
        "no-tag": t("Git deposunda ({repo}) bu sürüme uyan etiket bulunamadı.", { repo: esc(tc.repo || "") }),
        deferred: t("Git etiketiyle karşılaştırma sonraki kontrolde tamamlanacak."),
        failed: t("Git etiketiyle karşılaştırılamadı: {msg}", { msg: esc(tc.error || "") }) };
      if (tc.status === "ok") {
        const list = (label, arr) => arr.length ? `<div class="small"><span class="muted">${label}:</span> ${arr.slice(0, 40).map((p) => `<code>${esc(p)}</code>`).join(" ")}${arr.length > 40 ? " …" : ""}</div>` : "";
        detail += `<div class="small"><b>${t("Git etiketiyle karşılaştırma")}</b> (<a href="${esc(tc.repo)}" target="_blank" rel="noopener">${esc(tc.repo)}</a> @ <code>${esc(tc.tag)}</code>): ${t("{m} dosya git'tekinden farklı, {o} beklenmeyen dosya yalnızca arşivde, {e} dosya autotools/gettext çıktısı olarak yalnızca arşivde (normal).", { m: tc.modified.length, o: tc.only_tar.length, e: tc.only_tar_expected.length })}</div>`
          + list(t("Git'tekinden farklı"), tc.modified) + list(t("Yalnızca arşivde"), tc.only_tar)
          + (open ? `<details class="small"><summary class="muted">${t("Autotools/gettext çıktısı olarak yalnızca arşivde olanlar ({n})", { n: tc.only_tar_expected.length })}</summary>${tc.only_tar_expected.map((p) => `<code>${esc(p)}</code>`).join(" ")}</details>` : "")
          + (open ? tc.diffs.map((d) => `<div class="small"><b>${esc(d.path)}</b> <span class="muted">(${t("git → sürüm arşivi")})</span></div>${renderDiff(d.diff)}`).join("") : "");
      } else detail += `<div class="small muted">${TC[tc.status] || tc.status}</div>`;
    }
    return `<div class="srcfile"><div><b>${esc(s.file)}</b> <span class="muted small">${esc(SS[s.status] || s.status)}${s.error ? `: ${esc(s.error)}` : ""}</span> ${ver}</div>
      <div class="muted small url">${esc(s.url)}</div>${detail}</div>`;
  }).join("");
  return `<details class="more" data-key="${esc(dk)}" ${open ? "open" : ""}>
    <summary>${t("Kaynak dosyaların içini göster")}</summary>
    <div class="more-body">
      <p class="help" style="margin:0">${t("Yeni sürümün indirdiği dosyalar, kurulmadan önce hiçbir şey çalıştırılmadan açılıp incelendi. Sağlama toplamı doğrulanan dosyalar saklanır ve güncellemede yay'a verilir; ikinci kez indirilmez.")}</p>
      ${rows}
    </div>
  </details>`;
}

function renderVerdict(llm) {
  if (!llm) return `<div class="verdict">${t("Yapay zekâ incelemesi kapalı. Diff'e kendin bakıp karar ver.")}</div>`;
  if (llm.status !== "ok") return `<div class="verdict"><b>${t("İnceleme yapılamadı:")}</b> ${esc(llm.error)}<div class="who">${t("Bu paket incelenmemiş sayılır ve onayın olmadan kurulmaz.")}</div></div>`;
  const vmap = { clean: ["ok", t("Temiz")], suspicious: ["warn", t("Şüpheli")], malicious: ["danger", t("Zararlı")] };
  const [vc, vl] = vmap[llm.verdict];
  const cost = llm.usage?.cost_usd != null ? ` · $${llm.usage.cost_usd.toFixed(3)}` : llm.usage?.input_tokens ? ` · ${llm.usage.input_tokens + llm.usage.output_tokens} token` : "";
  return `<div class="verdict"><span class="badge ${vc}">${t("Yapay zekâ: {v}", { v: vl })}</span> ${esc(llm.summary)}
    ${llm.findings?.length ? `<ul class="findings" style="margin-top:8px">${llm.findings.map((f) => findingRow(f.severity, f.explanation, f.file, f.excerpt)).join("")}</ul>` : ""}
    <div class="who">${esc(llm.provider)} · ${esc(llm.model || "")} · ${t("{n} sn", { n: llm.seconds ?? "?" })}${cost} · ${fmtDate(llm.at)} · ${t("doğrulanmamış yorum")}</div></div>`;
}

function renderDeps(list, parent) {
  if (!list || !list.length) return "";
  return `<div class="deps"><h3>${t("Bu güncellemenin getirdiği yeni AUR bağımlılıkları")}</h3>
    <p class="help">${t("Bunlar henüz kurulu değil; yay ana paketi kurarken bunları da derleyip kurar. Ana paketin onayı bu bağımlılıkların incelenen commit'lerini de kapsar.")}</p>
    ${list.map((d) => renderDep(d, parent)).join("")}</div>`;
}

function renderDep(d, parent) {
  const [cls, label] = STATUS()[d.status] || ["neutral", d.status];
  if (!d.target) {
    return `<div class="dep ${d.status}"><div class="pkg-head"><span class="pkg-name">${esc(d.name)}</span><span class="badge ${cls}">${label}</span></div>
      <div class="verdict">${esc(d.error || "")}</div></div>`;
  }
  const dk = `dep:${parent}:${d.name}@${d.target}`;
  return `<div class="dep ${d.status}">
    <div class="pkg-head">
      <span class="pkg-name">${esc(d.name)}</span><span class="ver">${t("yeni · {ver} · {by} tarafından isteniyor", { ver: `<b>${esc(d.version)}</b>`, by: esc(d.required_by) })}</span>
      <span class="badge ${cls}">${label}</span><span class="spacer"></span>
      <a class="small" href="${esc(d.aur_url)}" target="_blank" rel="noopener">${t("AUR sayfası")} ↗</a>
    </div>
    ${renderVerdict(d.llm)}
    ${renderFindings(d.findings)}
    <div class="meta-grid">
      <span>${t("Bakımcı:")} <b>${esc(d.maintainer || t("yok"))}</b></span><span>${t("Oy:")} <b>${d.votes ?? "?"}</b></span>
      <span>${t("AUR'a ilk ekleniş:")} <b>${fmtDay(d.first_submitted)}</b></span><span>${t("Bu sürüm:")} <b>${fmtDate(d.last_modified)}</b></span>
      ${d.repo_deps?.length ? `<span>${t("Resmi depodan da kurulacak:")} <b>${d.repo_deps.map(esc).join(", ")}</b></span>` : ""}
    </div>
    <details class="more" data-key="${esc(dk)}" ${ui.openDetails.has(dk) ? "open" : ""}>
      <summary>${t("Paketin tamamını göster ({n} karakter)", { n: fmtNum(d.diff.chars) })}</summary>
      <div class="more-body">${ui.openDetails.has(dk) ? renderDiff(d.diff.text) : ""}</div>
    </details>
    ${renderSourcesLine(d.sources)}
    ${renderSources(d.sources, `src:${dk}`)}
    ${renderDeps(d.deps, parent)}
  </div>`;
}

function renderFindings(findings) {
  const list = (findings || []);
  if (!list.length) return "";
  return `<ul class="findings">${list.map((f) => findingRow(f.severity, f.title + (f.detail ? `: ${f.detail}` : ""), f.file, f.line)).join("")}</ul>`;
}
function findingRow(sev, text, file, line) {
  const [cls, label] = SEV()[sev] || ["neutral", sev];
  return `<li class="finding"><span class="badge ${cls}">${label}</span><div>${esc(text)}${file ? ` <span class="muted">(${esc(file)})</span>` : ""}${line ? `<code class="line">${esc(line)}</code>` : ""}</div></li>`;
}

function renderDiff(text) {
  const lines = text.split("\n").map((l) => {
    let c = "";
    if (l.startsWith("diff --git")) c = "file";
    else if (l.startsWith("+++") || l.startsWith("---") || l.startsWith("index ") || l.startsWith("new file") || l.startsWith("deleted file")) c = "file";
    else if (l.startsWith("@@")) c = "hunk";
    else if (l.startsWith("+")) c = "add";
    else if (l.startsWith("-")) c = "del";
    return `<span class="l ${c}">${esc(l)}</span>`;
  });
  return `<pre class="diff">${lines.join("")}</pre>`;
}

function renderRepo(r) {
  if (!r.repo.length) return `<div class="empty">${t("Resmi depolarda bekleyen güncelleme yok.")}</div>`;
  const f = ui.repoFilter.toLowerCase();
  const rows = [...r.repo]
    .sort((a, b) => (b.important - a.important) || (b.fixes_cve - a.fixes_cve) || a.name.localeCompare(b.name))
    .filter((x) => !f || x.name.includes(f));
  return `<div class="toolbar"><input class="input" id="repo-filter" placeholder="${esc(t("Paket ara…"))}" value="${esc(ui.repoFilter)}" style="width:240px">
      <span class="muted small">${t("{shown} / {all} paket · Resmi paketler Arch geliştiricileri tarafından imzalanır ve pacman imzayı doğrular.", { shown: rows.length, all: r.repo.length })}</span></div>
    <div class="table-wrap"><table><thead><tr><th>${t("Paket")}</th><th>${t("Depo")}</th><th>${t("Kurulu")}</th><th>${t("Yeni")}</th><th>${t("Not")}</th></tr></thead><tbody>
    ${rows.map((x) => `<tr><td><b>${esc(x.name)}</b></td><td class="muted">${esc(x.repo)}</td><td class="mono">${esc(x.old)}</td><td class="mono">${esc(x.new)}</td>
      <td><div class="tags">${x.fixes_cve ? `<span class="badge ok">${t("güvenlik düzeltmesi")}</span>` : ""}${x.important ? `<span class="badge accent">${t("önemli")}</span>` : ""}${x.major ? `<span class="badge warn">${t("ana sürüm")}</span>` : ""}${x.reboot ? `<span class="badge neutral">${t("yeniden başlatma")}</span>` : ""}</div></td></tr>`).join("")}
    </tbody></table></div>`;
}

function renderVulns(r) {
  const lists = r.incident_lists || [];
  const inc = r.incidents || [];
  const listNote = lists.length ? `<div class="srcline small" style="margin-bottom:12px">🛡 ${t("Bilinen saldırı listeleri:")} ${lists.map((l) => `${esc(l.name)} (${t("{n} paket", { n: l.count })})`).join(", ")} — ${inc.length ? `<b class="warn-text">${t("{n} eşleşme, yukarıdaki uyarılara bak", { n: inc.length })}</b>` : t("bu bilgisayarda kurulmuş ya da kurulu hiçbir paket listede yok; sudo/ssh'yi gölgeleyen sahte komut da yok")}.</div>` : "";
  if (!r.vulns.length) return listNote + `<div class="empty">${t("Kurulu sürümleri etkileyen kayıtlı bir güvenlik açığı yok.")}</div>`;
  const groups = { active: [], fixed: [], stale: [], acked: [] };
  for (const v of r.vulns) groups[vulnGroup(v)].push(v);
  const analyzing = new Set(ui.data.analyzing || []);
  const pendingAi = r.vulns.filter((v) => v.evidence_verdict !== "fixed" && v.ai?.status !== "ok").length;
  const section = (key, title, intro, list) => !list.length ? "" : `
    <details class="more vgroup" data-key="vg-${key}" ${key === "active" || ui.openDetails.has("vg-" + key) ? "open" : ""}>
      <summary>${title} (${list.length})</summary>
      <div class="more-body">${intro ? `<p class="note" style="margin:0">${intro}</p>` : ""}${list.map((v) => renderVuln(v, key, analyzing)).join("")}</div>
    </details>`;
  return listNote + `<div class="toolbar">
      <button class="btn sm" data-act="analyze-all" ${pendingAi && !analyzing.size ? "" : "disabled"}>${analyzing.size ? t("Analiz ediliyor… ({n})", { n: analyzing.size }) : t("Yapay zekâya değerlendirt ({n})", { n: pendingAi })}</button>
      <span class="muted small">${r.cve_pending ? t("{n} CVE'nin ayrıntısı NVD'den sonraki kontrollerde gelecek.", { n: r.cve_pending }) + " " : ""}${t("Kayıtlar: Arch güvenlik takipçisi; CVE ayrıntıları: NVD.")}</span>
    </div>
    ${groups.active.length ? "" : `<div class="empty" style="padding:12px">${t("Etkin bir güvenlik açığı yok.")}</div>`}
    ${section("active", t("Etkin açıklar"), t("Önem derecesine, çalışan bir servisin paketi yüklemesine (⚙) ve düzeltmenin bekleyen güncellemede olmasına göre sıralı."), groups.active)}
    ${section("fixed", t("Düzeltildiği doğrulananlar"), t("NVD sürüm verisine ya da CVE açıklamasına göre kurulu upstream sürüm düzeltmeyi içeriyor; takipçi kaydı güncellenmemiş."), groups.fixed)}
    ${section("stale", t("Büyük olasılıkla eski kayıtlar"), t("Takipçi düzeltme sürümünü girmemiş, CVE'ler önceki yıllara ait ve kurulu upstream sürüm açığın bildirildiği sürümden yeni. Bu bir tahmindir; yapay zekâ değerlendirmesiyle teyit edebilirsin."), groups.stale)}
    ${section("acked", t("İncelediğin ve gizlediğin kayıtlar"), t("Paket sürümü değişince yeniden görünürler."), groups.acked)}`;
}

function vulnGroup(v) {
  if (v.ack) return "acked";
  if (v.evidence_verdict === "fixed") return "fixed";
  if (v.stale) return "stale";
  return "active";
}

const AV_TR = () => ({ NETWORK: t("ağdan"), ADJACENT_NETWORK: t("yerel ağdan"), ADJACENT: t("yerel ağdan"), LOCAL: t("yerel"), PHYSICAL: t("fiziksel erişimle") });
const ASSESS = () => ({ affected: ["danger", t("Etkileniyor")], fixed: ["ok", t("Düzeltilmiş")], not_applicable: ["ok", t("Bu sistemi etkilemiyor")], unknown: ["neutral", t("Belirsiz")] });
const RISK_TR = () => ({ critical: ["danger", t("kritik risk")], high: ["danger", t("yüksek risk")], medium: ["warn", t("orta risk")], low: ["info", t("düşük risk")], none: ["ok", t("risk yok")] });
const CONF_TR = () => ({ high: t("yüksek güven"), medium: t("orta güven"), low: t("düşük güven") });

function renderVuln(v, group, analyzing) {
  const sevCls = group === "active" ? AVG_SEV[v.severity] || "neutral" : "neutral";
  const key = `${v.avg}:${v.package}`;
  const busy = analyzing.has(key);
  const ai = v.ai;
  const ev = v.evidence_verdict;
  const AS = ASSESS();
  const fixBadge = v.fix_pending ? `<span class="badge ok">${t("düzeltme güncellemede: {v}", { v: esc(v.fixed) })}</span>`
    : ev === "fixed" ? `<span class="badge ok">${t("kurulu sürümde düzeltilmiş (kanıtlı)")}</span>`
    : ev === "open" ? `<span class="badge danger">${t("kurulu sürüm etkileniyor (kanıtlı)")}</span>`
    : v.fixed ? `<span class="badge neutral">${t("düzeltme: {v}", { v: esc(v.fixed) })}</span>` : "";
  const aiBadge = ai?.status === "ok" ? `<span class="badge ${AS[ai.assessment][0]}">${t("Yapay zekâ: {v}", { v: AS[ai.assessment][1] })}</span>` : "";
  const users = [
    v.services?.length ? `<span class="tags">${v.services.map((s) => `<span class="badge warn" title="${esc(t("Çalışan bir sistem servisi bu paketi yüklüyor"))}">⚙ ${esc(s.replace(/\.service$/, ""))}</span>`).join("")}</span>` : "",
    v.explicit ? `<span>${t("senin kurduğun paket")}</span>` : "",
    v.used_by?.length ? `<span title="${esc(v.used_by.join(", "))}">${t("kullanan:")} ${v.used_by.slice(0, 6).map(esc).join(", ")}${v.used_by.length > 6 ? ` +${v.used_by.length - 6}` : ""}</span>` : "",
  ].filter(Boolean).join(" · ");
  const dk = `vuln:${key}`;
  const providers = ui.settings?.providers || [];
  return `<article class="pkg vuln">
    <div class="pkg-head">
      <span class="badge ${sevCls}">${AVG_SEV_TR()[v.severity] || esc(v.severity)}</span>
      <span class="pkg-name">${esc(v.package)}</span><span class="ver">${esc(v.installed)}</span>
      ${fixBadge}${aiBadge}
      <span class="spacer"></span>
      <a class="small" href="${esc(v.url)}" target="_blank" rel="noopener">${esc(v.avg)} ↗</a>
    </div>
    <div class="pkg-body">
      <div class="meta-grid"><span>${esc(v.type)}</span><span>${v.issues.map(esc).join(", ")}</span>${users ? `<span>${users}</span>` : ""}</div>
      ${renderVulnAi(ai)}
      <div class="pkg-actions">
        <button class="btn sm ${ai?.status === "ok" ? "ghost" : ""}" data-act="analyze" data-avg="${esc(v.avg)}" data-pkg="${esc(v.package)}" ${busy ? "disabled" : ""}>${busy ? t("Analiz ediliyor…") : ai?.status === "ok" ? t("Yeniden değerlendirt") : t("Yapay zekâya değerlendirt")}</button>
        ${providers.length > 1 ? `<select class="input" style="height:28px" data-vprovider-for="${esc(key)}">${providers.map((p) => `<option value="${esc(p.id)}" ${p.id === ui.settings.review.active_provider ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select>` : ""}
        ${group === "acked"
          ? `<button class="btn sm ghost" data-act="unack" data-avg="${esc(v.avg)}" data-pkg="${esc(v.package)}">${t("Geri al")}</button><span class="small muted">${v.ack.note ? t("Not:") + " " + esc(v.ack.note) : ""}</span>`
          : `<button class="btn sm ghost" data-act="ack" data-avg="${esc(v.avg)}" data-pkg="${esc(v.package)}">${t("İnceledim, gizle")}</button>`}
      </div>
    </div>
    <details class="more" data-key="${esc(dk)}" ${ui.openDetails.has(dk) ? "open" : ""}>
      <summary>${t("CVE ayrıntıları ({n})", { n: v.cves?.length || v.issue_count })}</summary>
      <div class="more-body">${(v.cves || []).map(renderCve).join("") || `<p class="muted">${t("Ayrıntı yok.")}</p>`}</div>
    </details>
  </article>`;
}

function renderVulnAi(ai) {
  if (!ai) return "";
  if (ai.status !== "ok") return `<div class="verdict"><b>${t("Değerlendirme yapılamadı:")}</b> ${esc(ai.error)}</div>`;
  const [rc, rl] = RISK_TR()[ai.risk] || ["neutral", ai.risk];
  const AS = ASSESS();
  return `<div class="verdict">
    <span class="badge ${AS[ai.assessment][0]}">${AS[ai.assessment][1]}</span> <span class="badge ${rc}">${rl}</span>
    ${ai.fixed_in ? `<span class="badge neutral">${t("upstream düzeltme: {v}", { v: esc(ai.fixed_in) })}</span>` : ""}
    <div style="margin-top:6px">${esc(ai.summary)}</div>
    ${ai.actions?.length ? `<ul style="margin:6px 0 0;padding-left:18px">${ai.actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ul>` : ""}
    ${ai.reasoning ? `<details style="margin-top:6px"><summary class="small muted" style="cursor:pointer">${t("Gerekçe")}</summary><p class="small" style="margin:4px 0 0">${esc(ai.reasoning)}</p></details>` : ""}
    <div class="who">${esc(ai.provider)} · ${esc(ai.model || "")} · ${CONF_TR()[ai.confidence] || ""} · ${t("{n} sn", { n: ai.seconds ?? "?" })} · ${fmtDate(ai.at)} · ${t("doğrulanmamış yorum; modelin bilgisi bir tarihe kadar günceldir")}</div>
  </div>`;
}

function renderCve(c) {
  const i = c.info;
  const e = c.evidence;
  if (!i) return `<div class="cve"><b>${esc(c.id)}</b> <span class="muted small">${t("NVD ayrıntısı henüz alınmadı")}</span> · <a class="small" href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank" rel="noopener">NVD ↗</a></div>`;
  const cv = i.cvss || {};
  const evBadge = !e ? "" : e.affected === true ? `<span class="badge danger">${t("kurulu sürüm etkileniyor")}</span>`
    : e.affected === false ? `<span class="badge ok">${t("kurulu sürümde düzeltilmiş")}</span>` : `<span class="badge neutral">${t("sürüm bilgisi yok")}</span>`;
  const patches = (i.references || []).filter((r) => (r.tags || []).some((tag) => ["Patch", "Release Notes", "Vendor Advisory"].includes(tag))).slice(0, 4);
  return `<div class="cve">
    <div><b>${esc(c.id)}</b> ${cv.score != null ? `<span class="badge ${cv.score >= 7 ? "danger" : cv.score >= 4 ? "warn" : "info"}">CVSS ${cv.score}</span>` : ""}
      ${cv.attack_vector ? `<span class="badge neutral">${AV_TR()[cv.attack_vector] || esc(cv.attack_vector)}</span>` : ""}
      ${cv.user_interaction === "REQUIRED" ? `<span class="badge neutral">${t("kullanıcı etkileşimi gerekir")}</span>` : ""}
      ${evBadge} <span class="muted small">${e ? esc(e.source) : ""}${e?.fixed_in?.length ? ` · ${t("düzeltme: {v}", { v: e.fixed_in.map(esc).join(", ") })}` : ""}</span></div>
    <p class="small" style="margin:4px 0">${esc(i.description)}</p>
    <div class="small muted">${t("NVD durumu: {s} · yayın: {d}", { s: esc(i.status || "?"), d: esc(String(i.published || "").slice(0, 10)) })} · <a href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank" rel="noopener">NVD ↗</a>
      ${patches.map((p) => ` · <a href="${esc(p.url)}" target="_blank" rel="noopener">${esc(new URL(p.url).hostname)}</a>`).join("")}</div>
  </div>`;
}

function renderNews(r) {
  if (!r.news.length) return `<div class="empty">${t("Haber alınamadı.")}</div>`;
  const unread = r.news.filter((n) => !n.read);
  const busy = new Set(ui.data.news_analyzing || []);
  return `<div class="toolbar">${unread.length ? `<button class="btn sm" data-act="read-all">${t("Tümünü okundu say")}</button>` : ""}<a class="small" href="https://archlinux.org/news/" target="_blank" rel="noopener">archlinux.org/news ↗</a></div>
    <div class="news">${r.news.map((n) => `<article class="news-item ${n.read || !n.since_last_upgrade ? "" : "unread"}">
      <h3><a href="${esc(n.link)}" target="_blank" rel="noopener">${esc(n.title)}</a></h3>
      <span class="muted small">${fmtDay(n.published)}${n.since_last_upgrade ? ` · <span class="badge warn">${t("son güncellemenden sonra")}</span>` : ""}${n.read ? " · " + t("okundu") : ""}</span>
      <p>${esc(n.summary)}</p>
      ${renderNewsAi(n.ai)}
      <div class="pkg-actions">
        ${n.read ? "" : `<button class="btn sm ghost" data-act="read" data-id="${esc(n.id)}">${t("Okundu say")}</button>`}
        <button class="btn sm ghost" data-act="news-analyze" data-id="${esc(n.id)}" ${busy.has(n.id) ? "disabled" : ""}>${busy.has(n.id) ? t("Değerlendiriliyor…") : n.ai?.status === "ok" ? t("Yeniden değerlendirt") : t("Beni etkiliyor mu? (yapay zekâ)")}</button>
      </div>
    </article>`).join("")}</div>`;
}

const AFFECTS = () => ({ yes: ["warn", t("Seni etkiliyor")], maybe: ["neutral", t("Etkileyebilir")], no: ["ok", t("Seni etkilemiyor")] });
const WHEN = () => ({ before_update: t("güncellemeden önce"), during_update: t("güncelleme sırasında"), after_update: t("güncellemeden sonra"), anytime: t("istediğin zaman"), none: "" });
function renderNewsAi(ai, compact = false) {
  if (!ai) return "";
  if (ai.status !== "ok") return `<div class="verdict small"><b>${t("Değerlendirme yapılamadı:")}</b> ${esc(ai.error || "")}</div>`;
  const [cls, label] = AFFECTS()[ai.affects] || ["neutral", ai.affects];
  const w = WHEN()[ai.when];
  const when = w ? ` <span class="badge neutral">${esc(w)}</span>` : "";
  const steps = (ai.actions || []).map((a) => `<li>${esc(a.text)}${a.command ? `<code class="line">${esc(a.command)}</code>` : ""}</li>`).join("");
  return `<div class="verdict"><span class="badge ${cls}">${t("Yapay zekâ: {v}", { v: label })}</span>${when} ${esc(ai.summary)}
    ${steps ? `<ol class="steps">${steps}</ol>` : ""}
    ${compact ? "" : `<div class="who">${esc(ai.reasoning || "")}</div>`}
    <div class="who">${esc(ai.provider || "")} · ${esc(ai.model || "")} · ${fmtDate(ai.at)} · ${t("doğrulanmamış yorum; komutları çalıştırmadan önce haberin kendisiyle karşılaştır")}</div></div>`;
}

function renderRuntime(r) {
  const rt = r.runtime;
  if (!rt) return "";
  const safe = rt.services.filter((s) => s.safe);
  const unsafe = rt.services.filter((s) => !s.safe);
  const parts = [`<h3>${t("Yeniden başlatma")}</h3>`];
  if (!rt.services.length && !rt.user_processes.length && !rt.reboot_recommended) {
    parts.push(`<p class="muted">${t("Gerek yok: çalışan her şey diskteki güncel kütüphaneleri kullanıyor (son açılış {date}).", { date: fmtDate(rt.boot_time) })}</p>`);
  } else {
    parts.push(`<p class="note">${t("Güncellenen bir kütüphane, onu yüklemiş programlar yeniden başlatılana kadar bellekte eski (açıklı) haliyle çalışmaya devam eder.")}</p>`);
    if (rt.reboot_recommended) {
      const why = [rt.kernel_updated && t("çekirdek güncellendi"), rt.reboot_packages.length && t("{list} açılıştan sonra güncellendi", { list: rt.reboot_packages.join(", ") }),
        unsafe.length && t("oturumu yöneten servisler etkilendi"), rt.user_processes.some((u) => u.session) && t("masaüstü oturumu eski kütüphaneleri kullanıyor")].filter(Boolean);
      parts.push(`<div class="alert warn"><span class="alert-icon">↻</span><div><b>${t("Bilgisayarı yeniden başlatman öneriliyor")}</b><div class="small">${esc(why.join("; "))}.</div></div></div>`);
    }
    if (safe.length) {
      parts.push(`<div class="table-wrap"><table><thead><tr><th>${t("Servis")}</th><th>${t("Başlama")}</th><th>${t("Sonradan güncellenen paketler")}</th></tr></thead><tbody>
        ${safe.map((s) => `<tr><td><b>${esc(s.unit)}</b></td><td class="mono">${fmtDate(s.started)}</td><td>${s.packages.map(esc).join(", ")}</td></tr>`).join("")}
        </tbody></table></div>
        <div class="toolbar" style="margin-top:8px"><button class="btn sm primary" data-act="restart">${t("Bu {n} servisi yeniden başlat", { n: safe.length })}</button>
        <code class="small muted">sudo systemctl restart ${safe.map((s) => esc(s.unit)).join(" ")}</code></div>`);
    }
    if (unsafe.length) parts.push(`<p class="small">${t("Yeniden başlatılırsa oturumu kapatacak servisler (bunun yerine bilgisayarı yeniden başlat):")} <b>${unsafe.map((s) => esc(s.unit)).join(", ")}</b></p>`);
    if (rt.user_processes.length) {
      parts.push(`<p class="small" style="margin-bottom:4px">${t("Eski kütüphaneyi hâlâ kullanan uygulamaların (kapatıp yeniden aç):")}</p>
        <div class="tags">${rt.user_processes.map((u) => `<span class="badge ${u.session ? "warn" : "neutral"}" title="${esc(u.files.join("\n"))}">${esc(u.name)}${u.count > 1 ? ` ×${u.count}` : ""}</span>`).join("")}</div>`);
    }
  }
  const pub = rt.open_ports.filter((p) => p.public);
  parts.push(`<h3 style="margin-top:20px">${t("Ağa açık portlar")}</h3>
    <p class="note">${t("Yalnızca bu bilgisayarın dışından erişilebilecek adreslerde dinleyenler listelenir. \"Tüm ağ\" yazanlara bağlı olduğun ağdaki herkes ulaşabilir. Docker'ın yayımladığı portlar ufw kurallarını atlar.")}</p>
    ${rt.open_ports.length ? `<div class="table-wrap"><table><thead><tr><th>${t("Port")}</th><th>${t("Ne")}</th><th>${t("Adres")}</th></tr></thead><tbody>
      ${rt.open_ports.map((p) => `<tr><td class="mono">${p.port}/${esc(p.proto)}</td>
        <td>${p.container ? `<span class="badge ${p.public ? "danger" : "neutral"}">Docker: ${esc(p.container)}</span> ${esc(p.service || "")}` : esc(p.service || p.process || t("bilinmiyor (root süreci)"))}</td>
        <td>${p.public ? `<span class="badge warn">${t("tüm ağ")}</span>` : `<span class="mono small">${esc(p.address)}</span>`}</td></tr>`).join("")}
      </tbody></table></div>` : `<p class="muted">${t("Yok.")}</p>`}
    ${pub.some((p) => p.container) ? `<p class="small">${t("Docker kapsayıcısını yalnızca bu bilgisayardan erişilebilir yapmak için compose dosyasında portu {fmt} biçiminde yaz.", { fmt: `<code>"127.0.0.1:PORT:PORT"</code>` })}</p>` : ""}`);
  return parts.join("");
}

function renderSystem(r) {
  const s = r.system;
  return `${renderRuntime(r)}<h3 style="margin-top:20px">${t("Genel")}</h3><dl class="kv" style="margin-top:8px">
      <dt>${t("Son tam güncelleme")}</dt><dd>${s.last_upgrade ? fmtDate(s.last_upgrade) : t("bulunamadı")}</dd>
      <dt>${t("Kurulu paket")}</dt><dd>${t("{n} ({f} AUR / depo dışı)", { n: s.installed_count, f: s.foreign_count })}</dd>
      <dt>${t("Boş disk alanı")}</dt><dd>${s.disk_free_gb} GB</dd>
      <dt>${t("Timeshift otomatik anlık görüntü")}</dt><dd>${s.autosnap ? t("kurulu") : t("kurulu değil")}</dd>
      <dt>${t("Yeniden başlatma")}</dt><dd>${s.reboot_needed ? t("gerekiyor (çekirdek güncellendi)") : t("gerekmiyor")}</dd>
      <dt>${t("Son kontrol süresi")}</dt><dd>${t("{n} sn", { n: r.duration })}</dd>
      <dt>${t("İnceleme sağlayıcısı")}</dt><dd>${r.review_provider ? esc(r.review_provider) : t("kapalı")}</dd>
      <dt>${t("AUR bekleme süresi")}</dt><dd>${t("{n} gün", { n: r.hold_days })}</dd>
    </dl>
    <h3 style="margin-top:20px">${t("Birleştirilmeyi bekleyen yapılandırma dosyaları (.pacnew)")}</h3>
    ${s.pacnew.length ? `<p class="note">${t("Paket yeni bir varsayılan yapılandırma getirdiğinde, senin değiştirdiğin dosyanın yanına {ext} olarak bırakılır. Farkları birleştirmek için terminalde {a} ya da {b} çalıştır.", { ext: "<code>.pacnew</code>", a: `<code>sudo DIFFPROG="kdiff3" pacdiff</code>`, b: "<code>sudo pacdiff</code>" })}</p>
      <ul class="mono small">${s.pacnew.map((p) => `<li>${esc(p)}</li>`).join("")}</ul>` : `<p class="muted">${t("Yok.")}</p>`}`;
}

// ---------- actions ----------
document.addEventListener("click", async (ev) => {
  const el = ev.target.closest("[data-tab],[data-act]");
  if (!el) return;
  if (el.dataset.tab) {
    ui.tab = el.dataset.tab;
    render();
    if (el.classList.contains("stat")) document.querySelector(".tabs")?.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  const act = el.dataset.act;
  try {
    if (act === "check") await startCheck();
    else if (act === "read") { await api("/api/news/read", { ids: [el.dataset.id] }); await refresh(); }
    else if (act === "read-all") { await api("/api/news/read", { ids: ui.data.report.news.map((n) => n.id) }); await refresh(); }
    else if (act === "approve") await approve(el.dataset.name, el.dataset.commit, el.dataset.status);
    else if (act === "unapprove") { await api("/api/unapprove", { name: el.dataset.name }); toast(t("Onay kaldırıldı")); await refresh(); }
    else if (act === "rereview") await rereview(el.dataset.name);
    else if (act === "update") await startUpdate();
    else if (act === "restart") await restartServices();
    else if (act === "ack") await ackVuln(el.dataset.avg, el.dataset.pkg);
    else if (act === "analyze") await analyzeVuln(el.dataset.avg, el.dataset.pkg);
    else if (act === "news-analyze") {
      toast(t("Haber değerlendiriliyor…"));
      const p = api("/api/news/analyze", { id: el.dataset.id });
      setTimeout(refresh, 300);
      const res = await p;
      toast(res.status === "ok" ? t("Değerlendirme tamamlandı") : res.error, res.status !== "ok");
      await refresh();
    }
    else if (act === "analyze-all") { const r = await api("/api/vuln/analyze-all", {}); toast(r.started ? t("{n} kayıt sırayla değerlendiriliyor", { n: r.started }) : t("Değerlendirilecek kayıt yok")); await refresh(); }
    else if (act === "unack") { await api("/api/vuln/ack", { avg: el.dataset.avg, package: el.dataset.pkg, undo: true }); await refresh(); }
  } catch (e) {
    toast(e.message, true);
  }
});

document.addEventListener("change", (ev) => {
  const el = ev.target;
  if (el.dataset.sel) { ui.selected.set(el.dataset.sel, el.checked); render(); }
  else if (el.id === "news-ack") { ui.newsAck = el.checked; render(); }
});
document.addEventListener("input", (ev) => {
  if (ev.target.id === "repo-filter") {
    ui.repoFilter = ev.target.value;
    const pos = ev.target.selectionStart;
    render();
    const el = $("#repo-filter");
    el.focus();
    el.setSelectionRange(pos, pos);
  }
});
document.addEventListener("toggle", (ev) => {
  const d = ev.target;
  if (d.matches?.("details.more")) {
    const k = d.dataset.key;
    if (d.open) ui.openDetails.add(k); else ui.openDetails.delete(k);
    if (d.open && !d.querySelector(".diff")) render();
  }
}, true);

$("#btn-check").addEventListener("click", () => startCheck().catch((e) => toast(e.message, true)));

async function startCheck() {
  const r = await api("/api/check", {});
  toast(r.started ? t("Kontrol başladı") : t("Bir kontrol zaten çalışıyor"));
  await refresh();
}

async function rereview(name) {
  const sel = document.querySelector(`[data-provider-for="${CSS.escape(name)}"]`);
  const provider = sel ? sel.value : undefined;
  toast(t("{name} yeniden inceleniyor…", { name }));
  const p = api("/api/rereview", { name, provider });
  setTimeout(refresh, 300);
  const res = await p;
  toast(res.status === "ok" ? t("{name}: inceleme tamamlandı", { name }) : `${name}: ${res.error}`, res.status !== "ok");
  await refresh();
}

async function approve(name, commit, status) {
  if (status === "clean") {
    await api("/api/approve", { name, commit });
    toast(t("{name} onaylandı", { name }));
    return refresh();
  }
  const warn = status === "danger"
    ? t("Bu güncellemede <b>tehlikeli</b> bulgular var. Bulguların yanlış alarm olduğundan emin değilsen onaylama.")
    : status === "unreviewed"
      ? t("Bu güncelleme otomatik olarak incelenemedi. Diff'i kendin okuduysan onaylayabilirsin.")
      : t("Bu güncellemede dikkat gerektiren bulgular var. Diff'i ve bulguları okuduysan onaylayabilirsin.");
  const needType = status === "danger" || status === "warning";
  const ok = await confirmDialog(t("{name} onaylansın mı?", { name }),
    `<p style="margin:0">${warn}</p>${needType ? `<label class="field"><span>${t("Onaylamak için paket adını yaz:")} <b>${esc(name)}</b></span><input class="input" id="confirm-input" autocomplete="off"></label>` : ""}
     <p class="help">${t("Onay yalnızca şu an incelenen commit için geçerlidir; paket yeniden değişirse onay düşer.")}</p>`,
    needType ? () => $("#confirm-input").value.trim() === name : null);
  if (!ok) return;
  await api("/api/approve", { name, commit, confirm: needType ? name : undefined });
  toast(t("{name} onaylandı", { name }));
  await refresh();
}

function confirmDialog(title, html, validate) {
  return new Promise((resolve) => {
    const dlg = $("#dlg-confirm");
    $("#confirm-title").textContent = title;
    $("#confirm-body").innerHTML = html;
    const okBtn = $("#confirm-ok");
    const check = () => (okBtn.disabled = validate ? !validate() : false);
    check();
    dlg.addEventListener("input", check);
    dlg.addEventListener("close", function onClose() {
      dlg.removeEventListener("close", onClose);
      dlg.removeEventListener("input", check);
      resolve(dlg.returnValue === "ok");
    });
    dlg.returnValue = "";
    dlg.showModal();
  });
}

async function startUpdate() {
  const r = ui.data.report;
  const aur = r.aur.filter((a) => a.target && isSelected(a)).map((a) => a.name);
  const list = aur.length ? `<p style="margin:0">AUR: <b>${aur.map(esc).join(", ")}</b></p>` : "";
  const what = aur.length
    ? t("{n} resmi depo paketi ve {m} AUR paketi güncellenecek.", { n: r.repo.length, m: aur.length })
    : t("{n} resmi depo paketi güncellenecek.", { n: r.repo.length });
  const ok = await confirmDialog(t("Güncelleme başlatılsın mı?"),
    `<p style="margin:0">${what}</p>${list}
     <p class="help">${t("Bir Konsole penceresi açılır. sudo parolanı orada girersin; Timeshift işlem başlamadan anlık görüntü alır.")}</p>`);
  if (!ok) return;
  const res = await api("/api/update", { aur, news_ack: ui.newsAck });
  toast(res.aur.length ? t("Güncelleme Konsole'da başladı (AUR: {list})", { list: res.aur.join(", ") }) : t("Güncelleme Konsole'da başladı"));
  await refresh();
}

async function analyzeVuln(avg, pkg) {
  const sel = document.querySelector(`[data-vprovider-for="${CSS.escape(avg + ":" + pkg)}"]`);
  toast(t("{pkg} değerlendiriliyor…", { pkg }));
  const p = api("/api/vuln/analyze", { avg, package: pkg, provider: sel ? sel.value : undefined });
  setTimeout(refresh, 300);
  const res = await p;
  toast(res.status === "ok" ? t("{pkg}: değerlendirme tamamlandı", { pkg }) : `${pkg}: ${res.error}`, res.status !== "ok");
  await refresh();
}

async function ackVuln(avg, pkg) {
  const ok = await confirmDialog(t("{pkg} · {avg} gizlensin mi?", { pkg, avg }),
    `<p style="margin:0">${t("Kayıt, {pkg} paketinin şu anki sürümü için listeden kalkar. Paket güncellenince yeniden kontrol edilir.", { pkg: `<b>${esc(pkg)}</b>` })}</p>
     <label class="field"><span>${t("Not (isteğe bağlı): neden güvenli ya da ne önlem aldın?")}</span><input class="input" id="confirm-input" placeholder="${esc(t("örn. upstream 1.7.1'de düzeltilmiş"))}" autocomplete="off"></label>`);
  if (!ok) return;
  const v = ui.data.report.vulns.find((x) => x.avg === avg && x.package === pkg);
  const typed = $("#confirm-input")?.value || "";
  const note = typed || (v?.ai?.status === "ok" ? t("Yapay zekâ: {v}", { v: v.ai.summary }) : "");
  await api("/api/vuln/ack", { avg, package: pkg, note });
  toast(t("Gizlendi"));
  await refresh();
}

async function restartServices() {
  const units = ui.data.report.runtime.services.filter((s) => s.safe).map((s) => s.unit);
  const ok = await confirmDialog(t("Servisler yeniden başlatılsın mı?"),
    `<p style="margin:0"><b>${units.map(esc).join(", ")}</b></p><p class="help">${t("Konsole'da {cmd} çalışır. Ağ servisleri birkaç saniyeliğine kesilebilir.", { cmd: "<code>sudo systemctl restart</code>" })}</p>`);
  if (!ok) return;
  await api("/api/restart", { units });
  toast(t("Konsole'da başlatıldı"));
}

// ---------- settings ----------
async function loadSettings() {
  ui.settings = await api("/api/settings");
}

$("#btn-settings").addEventListener("click", async () => {
  try {
    await loadSettings();
    renderSettings();
    $("#settings-msg").textContent = "";
    $("#dlg-settings").showModal();
  } catch (e) { toast(e.message, true); }
});

const TYPE_LABEL = () => ({ "claude-code": t("Claude Code (kurulu CLI, abonelik)"), anthropic: t("Anthropic API (API anahtarı)"), openai: t("OpenAI uyumlu (LiteLLM, Ollama, OpenRouter…)") });

function renderSettings() {
  const s = ui.settings;
  const body = $("#settings-body");
  const lang = s.language === "en" ? "en" : "tr";
  body.innerHTML = `
    <fieldset><legend>${t("Genel")}</legend>
      <div class="field-row">
        <label class="field"><span>Dil / Language</span><select class="input" name="language">
          <option value="tr" ${lang === "tr" ? "selected" : ""}>Türkçe</option>
          <option value="en" ${lang === "en" ? "selected" : ""}>English</option></select></label>
        <label class="field"><span>${t("AUR bekleme süresi (gün)")}</span><input class="input" type="number" min="0" max="30" name="hold_days" value="${s.hold_days}"></label>
        <label class="field"><span>${t("Otomatik kontrol sıklığı")}</span><select class="input" name="schedule">
          ${[["daily", t("Günde bir (09:00)")], ["twice", t("Günde iki (09:00, 19:00)")], ["weekly", t("Haftada bir (Pazartesi)")]].map(([v, l]) => `<option value="${v}" ${s.schedule === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>
        <label class="field"><span>${t("Pano penceresi")}</span><select class="input" name="browser">
          <option value="chromium-app" ${s.browser === "chromium-app" ? "selected" : ""}>${t("Chromium uygulama penceresi")}</option>
          <option value="default" ${s.browser === "default" ? "selected" : ""}>${t("Varsayılan tarayıcı")}</option></select></label>
      </div>
      <label class="check"><input type="checkbox" name="notifications" ${s.notifications ? "checked" : ""}> ${t("Zamanlanmış kontrolden sonra masaüstü bildirimi göster")}</label>
      <div class="field-row">
        <label class="field"><span>${t("Ne zaman bildirilsin")}</span><select class="input" name="notify_level">
          <option value="important" ${s.notify_level === "important" ? "selected" : ""}>${t("Yalnızca önemli ve yeni bir şey olunca")}</option>
          <option value="all" ${s.notify_level === "all" ? "selected" : ""}>${t("Güncelleme olan her kontrolde")}</option></select></label>
        <label class="field"><span>${t("Açılıştan sonra bekleme (dakika)")}</span><input class="input" type="number" min="0" max="120" name="startup_delay_minutes" value="${s.startup_delay_minutes}"></label>
      </div>
      <p class="help">${t("\"Önemli\" şunlardır: tehlikeli ya da uyarılı bir AUR güncellemesi, okunmamış bir Arch haberi, düzeltmesi olmayan kritik/yüksek bir açık ya da bekleyen güncellemeyle kapanan bir açık. Aynı şey bir kez bildirilir. Sıradan güncellemeler sessizce panoda bekler; 14 günden uzun güncelleme yapılmazsa haftada bir hatırlatılır.")}</p>
      <p class="help">${t("Bekleme süresi: yeni bir AUR sürümü, AUR'a yüklendikten bu kadar gün sonra otomatik olarak güncellemeye eklenir. Zararlı paketler genellikle ilk 1-3 gün içinde fark edilip kaldırılır. Süreyi beklemeden elle onaylayabilirsin.")}</p>
    </fieldset>
    <fieldset><legend>${t("Yapay zekâ incelemesi")}</legend>
      <label class="check"><input type="checkbox" name="review_enabled" ${s.review.enabled ? "checked" : ""}> ${t("AUR diff'lerini yapay zekâya inceletir")}</label>
      <div class="field-row">
        <label class="field"><span>${t("Kullanılacak sağlayıcı")}</span><select class="input" name="active_provider">
          ${s.providers.map((p) => `<option value="${esc(p.id)}" ${p.id === s.review.active_provider ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select></label>
        <label class="field"><span>${t("En fazla diff boyutu (karakter)")}</span><input class="input" type="number" name="max_diff_chars" value="${s.review.max_diff_chars}"></label>
        <label class="field"><span>${t("Zaman aşımı (saniye)")}</span><input class="input" type="number" name="timeout_seconds" value="${s.review.timeout_seconds}"></label>
      </div>
      <p class="help">${t("İnceleme yapılamazsa (hata, zaman aşımı, ret) paket \"İncelenmedi\" sayılır ve onayın olmadan kurulmaz.")}</p>
    </fieldset>
    <fieldset><legend>${t("Kaynak inceleme")}</legend>
      <label class="check"><input type="checkbox" name="src_enabled" ${s.sources.enabled ? "checked" : ""}> ${t("AUR güncellemelerinin indirdiği dosyaları (tarball, .deb, AppImage…) kurulmadan önce indirip içini incele")}</label>
      <label class="check"><input type="checkbox" name="src_baseline" ${s.sources.baseline ? "checked" : ""}> ${t("Bir paket için ilk kez: kurulu sürümün kaynaklarını da indirip karşılaştır")}</label>
      <label class="check"><input type="checkbox" name="src_tag" ${s.sources.tag_compare ? "checked" : ""}> ${t("Yüklenmiş sürüm arşivlerini (tarball) projenin git etiketiyle karşılaştır (xz tarzı saldırılara karşı)")}</label>
      <div class="field-row">
        <label class="field"><span>${t("En büyük dosya (MB)")}</span><input class="input" type="number" min="1" max="4096" name="src_max_file_mb" value="${s.sources.max_file_mb}"></label>
        <label class="field"><span>${t("Kontrol başına indirme süresi (dakika)")}</span><input class="input" type="number" min="1" max="240" name="src_time_budget" value="${s.sources.time_budget_minutes}"></label>
        <label class="field"><span>${t("Zamanlanmış kontrolde hız sınırı (MB/s, 0 = sınırsız)")}</span><input class="input" type="number" min="0" max="1000" step="0.5" name="src_rate" value="${s.sources.background_rate_mb}"></label>
      </div>
      <p class="help">${t("Hiçbir dosya çalıştırılmaz ya da diske açılmaz; arşivler bellekte okunur. Süre dolarsa indirme bir sonraki kontrolde kaldığı yerden sürer; inceleme bitene kadar paket otomatik seçilmez. Sağlama toplamı doğrulanan dosyalar saklanıp güncellemede yay'a verilir, ikinci kez indirilmez.")}</p>
    </fieldset>
    <fieldset><legend>${t("Güvenlik açıkları")}</legend>
      <label class="check"><input type="checkbox" name="news_ai" ${s.security.news_ai ? "checked" : ""}> ${t("Son Arch haberlerini yapay zekâya değerlendirt: bu bilgisayarı etkiliyor mu, ne yapmalıyım")}</label>
      <label class="check"><input type="checkbox" name="auto_analyze" ${s.security.auto_analyze ? "checked" : ""}> ${t("Her kontrolde etkin açıkları yapay zekâya otomatik değerlendirt (eski ve düzeltilmiş kayıtlar elle)")}</label>
      <div class="field-row" style="align-items:end">
        <label class="field"><span>${t("NVD'den CVE ayrıntısı çekme süresi (saniye / kontrol)")}</span><input class="input" type="number" min="0" max="900" name="nvd_budget_seconds" value="${s.security.nvd_budget_seconds}"></label>
        <label class="field"><span>${t("NVD API anahtarı")} ${s.security.has_nvd_key ? `· <b>${t("kasada kayıtlı ✓")}</b>` : "· " + t("isteğe bağlı")}</span><input class="input" type="password" id="nvd-key" placeholder="${s.security.has_nvd_key ? esc(t("değiştirmek için yeni anahtar")) : "nvd.nist.gov/developers/request-an-api-key"}" autocomplete="off"></label>
        <div style="display:flex;gap:8px"><button type="button" class="btn sm" data-nvd="save">${t("Kaydet")}</button>${s.security.has_nvd_key ? `<button type="button" class="btn sm ghost" data-nvd="clear">${t("Sil")}</button>` : ""}</div>
      </div>
      <p class="help">${t("Değerlendirme, Yapay zekâ incelemesi bölümünde seçili sağlayıcıyı kullanır. NVD anahtarsız istemcilere 30 saniyede 5 istek izin verir; ayrıntılar önbelleğe alınır ve eksikler sonraki kontrollerde tamamlanır. Ücretsiz bir anahtarla sınır 10 kat artar.")}</p>
    </fieldset>
    <fieldset><legend>${t("Sağlayıcılar")}</legend>
      <div id="providers" style="display:grid;gap:10px">${s.providers.map(providerForm).join("")}</div>
      <div><button type="button" class="btn sm" id="add-provider">+ ${t("Sağlayıcı ekle")}</button></div>
      <p class="help">${t("API anahtarları ayarlar dosyasına değil, masaüstünün anahtar kasasına (Secret Service) kaydedilir. Anahtarı kaydettikten sonra \"Dene\" ile bağlantıyı sına.")}</p>
    </fieldset>`;
  $("#add-provider").onclick = () => {
    const id = "p" + Math.random().toString(36).slice(2, 7);
    $("#providers").insertAdjacentHTML("beforeend", providerForm({ id, name: t("Yeni sağlayıcı"), type: "openai", model: "", base_url: "http://localhost:4000/v1", json_mode: "json_schema", _new: true }));
  };
}

function providerForm(p) {
  const keyed = p.type === "anthropic" || p.type === "openai";
  return `<div class="provider" data-pid="${esc(p.id)}">
    <div class="provider-head">
      <input class="input" data-f="name" value="${esc(p.name)}" style="font-weight:600;width:200px" aria-label="${esc(t("Ad"))}">
      <select class="input" data-f="type">${Object.entries(TYPE_LABEL()).map(([v, l]) => `<option value="${v}" ${p.type === v ? "selected" : ""}>${l}</option>`).join("")}</select>
      <span class="spacer"></span>
      <code class="muted small">${esc(p.id)}</code>
      <button type="button" class="btn sm ghost" data-pact="test">${t("Dene")}</button>
      <button type="button" class="icon-btn" data-pact="remove" aria-label="${esc(t("Sil"))}">🗑</button>
    </div>
    <div class="field-row">
      <label class="field"><span>Model</span><input class="input" data-f="model" value="${esc(p.model || "")}" placeholder="${p.type === "claude-code" ? "sonnet, opus, haiku…" : p.type === "anthropic" ? "claude-opus-5-5" : esc(t("model adı"))}"></label>
      ${p.type !== "claude-code" ? `<label class="field"><span>${t("Adres")}${p.type === "anthropic" ? " " + t("(boş = api.anthropic.com)") : ""}</span><input class="input" data-f="base_url" value="${esc(p.base_url || "")}" placeholder="${p.type === "openai" ? "http://localhost:4000/v1" : ""}"></label>` : ""}
      ${p.type === "anthropic" ? `<label class="field"><span>Effort</span><select class="input" data-f="effort">${["low", "medium", "high", "xhigh", "max", ""].map((e) => `<option value="${e}" ${(p.effort || "") === e ? "selected" : ""}>${e || t("gönderme")}</option>`).join("")}</select></label>` : ""}
      ${p.type === "openai" ? `<label class="field"><span>${t("JSON kipi")}</span><select class="input" data-f="json_mode">${[["json_schema", t("json_schema (katı şema)")], ["json_object", "json_object"], ["none", t("yok (yalnızca istem)")]].map(([v, l]) => `<option value="${v}" ${(p.json_mode || "json_schema") === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>` : ""}
    </div>
    ${keyed ? `<div class="field-row" style="align-items:end">
      <label class="field"><span>${t("API anahtarı")} ${p.has_key ? `· <b>${t("kasada kayıtlı ✓")}</b>` : p.type === "openai" ? "· " + t("isteğe bağlı") : "· " + t("girilmedi")}</span><input class="input" type="password" data-key placeholder="${esc(p.has_key ? t("değiştirmek için yeni anahtar gir") : t("anahtarı yapıştır"))}" autocomplete="off"></label>
      <div style="display:flex;gap:8px"><button type="button" class="btn sm" data-pact="save-key">${t("Anahtarı kaydet")}</button>${p.has_key ? `<button type="button" class="btn sm ghost" data-pact="clear-key">${t("Anahtarı sil")}</button>` : ""}</div>
    </div>` : `<p class="help">${t("Kurulu {cmd} komutunu araçsız modda çalıştırır; Claude aboneliğinin kotasından harcar.", { cmd: "<code>claude</code>" })}</p>`}
    ${p.type === "anthropic" ? `<p class="help">${t("Opus 5.5, Sonnet 5.5 ve Fable modellerinde, güvenlik sınıflandırıcısı incelemeyi reddederse istek otomatik olarak başka bir modelle yeniden denenir (server-side fallback).")}</p>` : ""}
    <div class="test-result" hidden></div>
  </div>`;
}

function collectSettings() {
  const f = $("#settings-form");
  const s = structuredClone(ui.settings);
  s.language = f.language.value;
  s.hold_days = Number(f.hold_days.value);
  s.schedule = f.schedule.value;
  s.browser = f.browser.value;
  s.notifications = f.notifications.checked;
  s.notify_level = f.notify_level.value;
  s.startup_delay_minutes = Number(f.startup_delay_minutes.value);
  s.review.enabled = f.review_enabled.checked;
  s.review.active_provider = f.active_provider.value;
  s.review.max_diff_chars = Number(f.max_diff_chars.value);
  s.review.timeout_seconds = Number(f.timeout_seconds.value);
  s.security = { ...s.security, auto_analyze: f.auto_analyze.checked, news_ai: f.news_ai.checked,
                 nvd_budget_seconds: Number(f.nvd_budget_seconds.value) };
  delete s.security.has_nvd_key;
  s.sources = { ...s.sources, enabled: f.src_enabled.checked, baseline: f.src_baseline.checked, tag_compare: f.src_tag.checked,
                max_file_mb: Number(f.src_max_file_mb.value), time_budget_minutes: Number(f.src_time_budget.value),
                background_rate_mb: Number(f.src_rate.value) };
  s.providers = [...document.querySelectorAll("#providers .provider")].map((el) => {
    const p = { id: el.dataset.pid };
    el.querySelectorAll("[data-f]").forEach((i) => (p[i.dataset.f] = i.value));
    return p;
  });
  return s;
}

$("#settings-body").addEventListener("change", (ev) => {
  // Re-render a provider card when its type changes so the right fields show.
  const sel = ev.target.closest('[data-f="type"]');
  if (!sel) return;
  const card = sel.closest(".provider");
  const p = collectSettings().providers.find((x) => x.id === card.dataset.pid);
  const defaults = { anthropic: { model: "claude-opus-5-5", effort: "medium", base_url: "" }, openai: { base_url: "http://localhost:4000/v1", json_mode: "json_schema" }, "claude-code": { model: "sonnet" } };
  card.outerHTML = providerForm({ ...p, ...defaults[p.type], name: p.name });
  if (ev.target.name === "active_provider") return;
});

$("#settings-body").addEventListener("click", async (ev) => {
  const n = ev.target.closest("[data-nvd]");
  if (n) {
    try {
      const value = n.dataset.nvd === "save" ? $("#nvd-key").value.trim() : "";
      if (n.dataset.nvd === "save" && !value) return toast(t("Önce anahtarı yapıştır"), true);
      await saveSettings(false);
      await api("/api/secret", { provider: "nvd", value });
      await loadSettings();
      renderSettings();
      toast(value ? t("NVD anahtarı kaydedildi") : t("NVD anahtarı silindi"));
    } catch (e) { toast(e.message, true); }
    return;
  }
  const b = ev.target.closest("[data-pact]");
  if (!b) return;
  const card = b.closest(".provider");
  const pid = card.dataset.pid;
  const out = card.querySelector(".test-result");
  const show = (msg) => { out.hidden = false; out.textContent = msg; };
  try {
    if (b.dataset.pact === "remove") {
      if (document.querySelectorAll("#providers .provider").length <= 1) return toast(t("En az bir sağlayıcı kalmalı"), true);
      card.remove();
    } else if (b.dataset.pact === "save-key" || b.dataset.pact === "clear-key") {
      const value = b.dataset.pact === "save-key" ? card.querySelector("[data-key]").value : "";
      if (b.dataset.pact === "save-key" && !value) return toast(t("Önce anahtarı yapıştır"), true);
      await saveSettings(false);  // provider must exist server-side first
      await api("/api/secret", { provider: pid, value });
      await loadSettings();
      renderSettings();
      toast(value ? t("Anahtar kasaya kaydedildi") : t("Anahtar silindi"));
    } else if (b.dataset.pact === "test") {
      show(t("Deneniyor… (bir örnek diff gönderiliyor)"));
      b.disabled = true;
      const res = await api("/api/test-provider", { provider: pid, settings: collectSettings() });
      b.disabled = false;
      show(res.status === "ok"
        ? "✓ " + t("Çalışıyor: {model} · {sec} sn · karar \"{verdict}\"", { model: res.model || "", sec: res.seconds, verdict: res.verdict }) + `\n${res.summary}`
        : `✕ ${res.error}`);
    }
  } catch (e) {
    b.disabled = false;
    show("✕ " + e.message);
  }
});

async function saveSettings(close = true) {
  const before = ui.settings?.language === "en" ? "en" : "tr";
  const saved = await api("/api/settings", collectSettings());
  ui.settings = saved.settings;
  const updated = saved.schedule === "güncellendi" || saved.schedule === "updated";
  $("#settings-msg").textContent = t("Kaydedildi") + (updated ? " · " + t("zamanlayıcı güncellendi") : "");
  const after = ui.settings?.language === "en" ? "en" : "tr";
  if (close && after !== before) {
    location.reload();  // the dictionary applies on load
    return;
  }
  if (close) {
    $("#dlg-settings").close();
    toast(t("Ayarlar kaydedildi"));
    render();
  }
}

$("#btn-save-settings").addEventListener("click", async (ev) => {
  ev.preventDefault();
  try { await saveSettings(true); } catch (e) { $("#settings-msg").textContent = e.message; toast(e.message, true); }
});

// ---------- boot ----------
loadSettings().catch(() => {})
  .then(() => loadLanguage(ui.settings?.language))
  .then(applyStatic)
  .finally(refresh);

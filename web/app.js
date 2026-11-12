"use strict";

// ---------- helpers ----------
const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtDate = (ts) => ts ? new Date(typeof ts === "number" ? ts * 1000 : ts).toLocaleString("tr-TR", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "—";
const fmtDay = (ts) => ts ? new Date(typeof ts === "number" ? ts * 1000 : ts).toLocaleDateString("tr-TR", { day: "numeric", month: "long", year: "numeric" }) : "—";
function ago(ts) {
  if (!ts) return "hiç";
  const s = Math.round(Date.now() / 1000 - ts);
  if (s < 60) return "az önce";
  if (s < 3600) return `${Math.floor(s / 60)} dk önce`;
  if (s < 86400) return `${Math.floor(s / 3600)} sa önce`;
  return `${Math.floor(s / 86400)} gün önce`;
}
function until(ts) {
  const s = Math.round(ts - Date.now() / 1000);
  if (s <= 0) return "şimdi";
  if (s < 3600) return `${Math.ceil(s / 60)} dk`;
  if (s < 86400) return `${Math.round(s / 3600)} sa`;
  return `${Math.round(s / 86400 * 10) / 10} gün`;
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
  const t = $("#toast");
  t.textContent = msg;
  t.className = "show" + (isError ? " error" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = ""), isError ? 6000 : 3000);
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

const STATUS = {
  clean: ["ok", "Temiz"],
  warning: ["warn", "Dikkat"],
  danger: ["danger", "Tehlikeli"],
  unreviewed: ["neutral", "İncelenmedi"],
  missing: ["warn", "AUR'da yok"],
  error: ["danger", "Hata"],
};
const SEV = { high: ["danger", "Yüksek"], medium: ["warn", "Orta"], low: ["info", "Düşük"], info: ["info", "Bilgi"] };
const AVG_SEV = { Critical: "danger", High: "danger", Medium: "warn", Low: "info", Unknown: "neutral" };
const AVG_SEV_TR = { Critical: "Kritik", High: "Yüksek", Medium: "Orta", Low: "Düşük", Unknown: "Bilinmiyor" };

const keyOf = (a) => `${a.name}@${a.target}`;
const canSelect = (a) => a.target && (a.approved || a.auto_ok);
const isSelected = (a) => canSelect(a) && (ui.selected.has(keyOf(a)) ? ui.selected.get(keyOf(a)) : true);

// ---------- polling ----------
async function refresh() {
  try {
    ui.data = await api("/api/state");
    render();
  } catch (e) {
    $("#status-line").textContent = "Sunucuya ulaşılamıyor: " + e.message;
  }
  schedulePoll();
}
function schedulePoll() {
  clearTimeout(ui.pollTimer);
  const d = ui.data;
  const fast = d && (d.busy || d.update?.running || (d.reviewing || []).length || (d.analyzing || []).length);
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
      <h2>Henüz kontrol yapılmadı</h2>
      <p>İlk kontrol resmi depoları, AUR paketlerini, Arch haberlerini ve güvenlik açıklarını tarar.</p>
      <button class="btn primary" data-act="check" ${d.busy ? "disabled" : ""}>İlk kontrolü başlat</button></div>`;
    return;
  }
  const scrollY = window.scrollY;
  app.innerHTML = renderAlerts(d, r) + renderStats(r) + renderPlan(d, r) + renderTabs(r);
  window.scrollTo(0, scrollY);
}

function renderTop(d) {
  const r = d.report;
  const line = r
    ? `Son kontrol ${ago(r.generated_at)} (${fmtDate(r.generated_at)}) · ${r.system.installed_count} paket kurulu`
    : "Henüz kontrol yapılmadı";
  $("#status-line").textContent = line;
  $("#btn-check").disabled = d.busy;
  $("#btn-check").textContent = d.busy ? "Kontrol ediliyor…" : "Şimdi kontrol et";
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
    $("#progress-text").textContent = (pr.message || "Hazırlanıyor") + (pr.total ? ` (${pr.done}/${pr.total})` : "");
  }
}

function renderAlerts(d, r) {
  const out = [];
  const danger = r.aur.filter((a) => a.status === "danger");
  if (danger.length) out.push(alertBox("danger", "⛔", `${danger.length} AUR güncellemesinde tehlikeli bulgu var`,
    `İncelemeden kurma: ${danger.map((a) => `<b>${esc(a.name)}</b>`).join(", ")}. Ayrıntılar AUR sekmesinde.`));
  const missing = r.aur.filter((a) => a.status === "missing");
  if (missing.length) out.push(alertBox("warn", "⚠", "Kurulu bazı paketler artık AUR'da yok",
    `${missing.map((a) => esc(a.name)).join(", ")}. AUR'dan kaldırılan paketler bazen zararlı oldukları için silinir; neden kaldırıldığına bak.`));
  const unread = r.news.filter((n) => n.since_last_upgrade && !n.read);
  if (unread.length) out.push(alertBox("warn", "📰", "Son güncellemenden sonra Arch haberi yayımlandı",
    `Güncellemeden önce oku: <ul>${unread.map((n) => `<li><a href="${esc(n.link)}" target="_blank" rel="noopener">${esc(n.title)}</a></li>`).join("")}</ul>`));
  const rt = r.runtime;
  if (rt && rt.reboot_recommended) out.push(alertBox("info", "↻", "Bilgisayarı yeniden başlatman öneriliyor",
    `${rt.kernel_updated ? "Çalışan çekirdek güncellendi. " : ""}${rt.reboot_packages.length ? `Açılıştan sonra güncellenen temel paketler: ${esc(rt.reboot_packages.join(", "))}. ` : ""}Ayrıntılar Sistem sekmesinde.`));
  else if (rt && rt.services.some((s) => s.safe)) out.push(alertBox("info", "↻", `${rt.services.filter((s) => s.safe).length} servis eski kütüphaneyle çalışıyor`,
    "Güncellemenin bu servislerde etkin olması için yeniden başlatılmaları gerekiyor. Sistem sekmesinden tek tıkla yapabilirsin."));
  else if (r.system.reboot_needed) out.push(alertBox("info", "↻", "Yeniden başlatma bekliyor", "Çalışan çekirdek güncellendi; değişikliklerin etkin olması için bilgisayarı yeniden başlat."));
  if (d.check_error) out.push(alertBox("danger", "✕", "Son kontrol başarısız oldu", esc(d.check_error)));
  for (const e of r.errors) out.push(alertBox("warn", "⚠", "Kontrolün bir bölümü tamamlanamadı", esc(e)));
  const last = d.update?.last;
  if (last && last.finished && Date.now() / 1000 - last.finished < 3600) {
    const ok = last.repo_rc === 0 && (last.aur_rc === 0 || last.aur_rc === -1);
    out.push(alertBox(ok ? "info" : "danger", ok ? "✓" : "✕", ok ? "Güncelleme tamamlandı" : "Güncelleme hatayla bitti",
      `${fmtDate(last.finished)} · pacman kodu ${last.repo_rc}, yay kodu ${last.aur_rc}${last.aur ? " · AUR: " + esc(last.aur) : ""}`));
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
    ${stat("repo", "Resmi depo güncellemesi", r.repo.length, `${imp ? `<span>${imp} önemli</span>` : ""}${cve ? `<span>${cve} güvenlik düzeltmesi</span>` : ""}${!imp && !cve ? "imzalı resmi paketler" : ""}`)}
    ${stat("aur", "AUR güncellemesi", aurUp.length, bad ? `<span class="badge warn">${bad} dikkat</span>` : unrev ? `<span>${unrev} incelenmedi</span>` : "sorun bulunmadı")}
    ${stat("vulns", "Bilinen güvenlik açığı", activeV.length, `${highV ? `<span>${highV} yüksek/kritik</span>` : ""}<span>${fixable} bu güncellemeyle kapanıyor</span>${setAside ? `<span>${setAside} düzeltilmiş/eski kayıt ayrıldı</span>` : ""}`)}
    ${stat("news", "Yeni Arch haberi", unread, unread ? "son güncellemenden sonra yayımlandı" : latest ? `son haber: ${fmtDay(latest.published)}` : "haber alınamadı")}
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
  const rows = aur.map((a) => {
    const [cls, label] = STATUS[a.status] || ["neutral", a.status];
    let why;
    if (a.approved) why = "Elle onaylandı";
    else if (a.auto_ok) why = "İnceleme temiz, bekleme süresi doldu";
    else if (a.status === "clean" && a.held) why = `Bekleme süresinde: ${until(a.hold_until)} sonra hazır (${fmtDate(a.hold_until)})`;
    else if (a.status === "unreviewed") why = "İncelenmedi; diff'e bakıp elle onaylaman gerekiyor";
    else why = "Bulgular var; incelemeden onaylanamaz";
    return `<label class="plan-row">
      <input type="checkbox" data-sel="${esc(keyOf(a))}" ${isSelected(a) ? "checked" : ""} ${canSelect(a) ? "" : "disabled"}>
      <span><b>${esc(a.name)}</b> <span class="ver">${esc(a.installed)} → <b>${esc(a.new_version)}</b></span></span>
      <span class="badge ${cls}">${label}</span>
      <span class="why">${why}</span></label>`;
  }).join("");
  return `<section class="card card-pad">
    <div class="plan">
      <div>
        <h2>Güncelleme planı</h2>
        <p class="muted small" style="margin:4px 0 0">${r.repo.length} resmi depo paketinin hepsi güncellenir (Arch'ta kısmi güncelleme desteklenmez). AUR paketlerinden yalnızca işaretlediklerin kurulur.</p>
        ${aur.length ? `<div class="plan-list">${rows}</div>` : `<p class="muted small">Bekleyen AUR güncellemesi yok.</p>`}
      </div>
      <div class="plan-side">
        <div class="checks">
          <span>${r.system.autosnap ? "✓ Timeshift kurulumdan önce anlık görüntü alacak" : "⚠ timeshift-autosnap bulunamadı"}</span>
          <span>${r.system.disk_free_gb > 10 ? "✓" : "⚠"} ${r.system.disk_free_gb} GB boş alan</span>
          <span>${stale ? "⚠ Rapor 6 saatten eski, önce yeniden kontrol et" : `✓ Rapor güncel (${ago(r.generated_at)})`}</span>
        </div>
        ${unread.length ? `<label class="ack"><input type="checkbox" id="news-ack" ${ui.newsAck ? "checked" : ""}><span>Son güncellememden sonra yayımlanan ${unread.length} Arch haberini okudum.</span></label>` : ""}
        <button class="btn primary lg" data-act="update" ${blocked || stale ? "disabled" : ""}>
          ${running ? "Güncelleme sürüyor…" : nothing ? "Güncellenecek bir şey yok" : `Güncellemeyi başlat (${r.repo.length + sel.length} paket)`}</button>
        <span class="muted small">Konsole penceresinde açılır; parolanı ve pacman sorularını orada yanıtlarsın.</span>
      </div>
    </div>
  </section>`;
}

function renderTabs(r) {
  const tabs = [
    ["aur", "AUR", r.aur.length],
    ["repo", "Resmi depo", r.repo.length],
    ["vulns", "Güvenlik", r.vulns.filter((v) => vulnGroup(v) === "active").length],
    ["news", "Haberler", r.news.filter((n) => n.since_last_upgrade && !n.read).length || ""],
    ["system", "Sistem", r.system.pacnew.length || ""],
  ];
  const body = { aur: renderAur, repo: renderRepo, vulns: renderVulns, news: renderNews, system: renderSystem }[ui.tab](r);
  return `<section class="card">
    <nav class="tabs" role="tablist">${tabs.map(([id, label, n]) =>
      `<button class="tab ${ui.tab === id ? "active" : ""}" data-tab="${id}" role="tab">${label}${n !== "" && n !== undefined ? `<span class="count">${n}</span>` : ""}</button>`).join("")}</nav>
    <div class="tab-body">${body}</div></section>`;
}

function renderAur(r) {
  if (!r.aur.length) {
    return `<div class="empty">Bekleyen AUR güncellemesi yok. ${r.system.foreign_count} AUR paketinin hepsi güncel ve AUR'da duruyor.</div>`;
  }
  const order = { danger: 0, error: 1, missing: 2, warning: 3, unreviewed: 4, clean: 5 };
  const items = [...r.aur].sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9) || a.name.localeCompare(b.name));
  const reviewing = new Set(ui.data.reviewing || []);
  return `<div class="pkgs">${items.map((a) => renderPkg(a, reviewing.has(a.name), r)).join("")}</div>
    <p class="note">İnceleme iki katmanlıdır: sabit kural taraması her zaman çalışır ve yapay zekâ kararı bir kural bulgusunu asla temizleyemez. Yapay zekânın gerekçeleri doğrulanmamış yorumdur; paketin yazdığı metinden etkilenmiş olabilir.</p>`;
}

function renderPkg(a, reviewing, r) {
  const [cls, label] = STATUS[a.status] || ["neutral", a.status];
  if (a.status === "missing" || a.status === "error") {
    return `<article class="pkg ${a.status}"><div class="pkg-head"><span class="pkg-name">${esc(a.name)}</span>
      <span class="ver">kurulu <b>${esc(a.installed)}</b></span><span class="badge ${cls}">${label}</span></div>
      <div class="pkg-body">${a.error ? `<div class="verdict">${esc(a.error)}</div>` : ""}${renderFindings(a.findings)}</div></article>`;
  }
  const verdict = renderVerdict(a.llm);
  const holdBadge = a.held ? `<span class="badge neutral" title="${esc(fmtDate(a.hold_until))}">⏳ ${until(a.hold_until)} bekleme</span>` : "";
  const apprBadge = a.approved ? `<span class="badge accent">✓ Onaylandı</span>` : "";
  const dk = `diff:${keyOf(a)}`;
  const providers = (ui.settings?.providers || []);
  return `<article class="pkg ${a.status}">
    <div class="pkg-head">
      <span class="pkg-name">${esc(a.name)}</span>
      <span class="ver">${esc(a.installed)} → <b>${esc(a.new_version)}</b>${a.vcs ? " · geliştirme sürümü" : ""}</span>
      <span class="badge ${cls}">${label}</span>${holdBadge}${apprBadge}
      <span class="spacer"></span>
      <a class="small" href="${esc(a.aur_url)}" target="_blank" rel="noopener">AUR sayfası ↗</a>
    </div>
    <div class="pkg-body">
      ${verdict}
      ${renderFindings(a.findings)}
      ${renderDeps(a.new_aur_deps, a.name)}
      <div class="meta-grid">
        <span>Bakımcı: <b>${esc(a.maintainer || "yok")}</b>${a.known_maintainer && a.known_maintainer !== a.maintainer ? ` (önceden ${esc(a.known_maintainer)})` : ""}</span>
        <span>Oy: <b>${a.votes ?? "?"}</b></span>
        <span>AUR'a ilk ekleniş: <b>${fmtDay(a.first_submitted)}</b></span>
        <span>Bu sürüm: <b>${fmtDate(a.last_modified)}</b></span>
        <span>Karşılaştırma: <b>${a.diff?.base ? esc(a.diff.base.slice(0, 10)) : "yok"}</b> → <b>${esc(a.target.slice(0, 10))}</b> (${esc(a.base_source)})</span>
      </div>
      <div class="pkg-actions">
        ${a.approved
          ? `<button class="btn sm" data-act="unapprove" data-name="${esc(a.name)}">Onayı kaldır</button>`
          : `<button class="btn sm ${a.status === "clean" ? "" : "primary"}" data-act="approve" data-name="${esc(a.name)}" data-commit="${esc(a.approval_key || a.target)}" data-status="${a.status}">
              ${a.status === "clean" && a.held ? "Beklemeden onayla" : a.status === "clean" ? "Onayla" : "İnceledim, onayla"}</button>`}
        <button class="btn sm ghost" data-act="rereview" data-name="${esc(a.name)}" ${reviewing ? "disabled" : ""}>${reviewing ? "İnceleniyor…" : "Yeniden incelet"}</button>
        ${providers.length > 1 ? `<select class="input" style="height:28px" data-provider-for="${esc(a.name)}">${providers.map((p) =>
          `<option value="${esc(p.id)}" ${p.id === ui.settings.review.active_provider ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select>` : ""}
      </div>
    </div>
    <details class="more" data-key="${esc(dk)}" ${ui.openDetails.has(dk) ? "open" : ""}>
      <summary>Diff'i ve commit'leri göster (${a.diff.chars.toLocaleString("tr-TR")} karakter${a.diff.truncated ? ", kısaltıldı" : ""})</summary>
      <div class="more-body">
        <ul class="commits">${(a.commits || []).map((c) => `<li><code>${esc(c.hash.slice(0, 10))}</code> ${esc(c.subject)} <span class="muted">— ${esc(c.author)} &lt;${esc(c.email)}&gt;, ${fmtDate(c.time)}</span></li>`).join("")}</ul>
        ${ui.openDetails.has(dk) ? renderDiff(a.diff.text) : ""}
      </div>
    </details>
  </article>`;
}

function renderVerdict(llm) {
  if (!llm) return `<div class="verdict">Yapay zekâ incelemesi kapalı. Diff'e kendin bakıp karar ver.</div>`;
  if (llm.status !== "ok") return `<div class="verdict"><b>İnceleme yapılamadı:</b> ${esc(llm.error)}<div class="who">Bu paket incelenmemiş sayılır ve onayın olmadan kurulmaz.</div></div>`;
  const vmap = { clean: ["ok", "Temiz"], suspicious: ["warn", "Şüpheli"], malicious: ["danger", "Zararlı"] };
  const [vc, vl] = vmap[llm.verdict];
  const cost = llm.usage?.cost_usd != null ? ` · $${llm.usage.cost_usd.toFixed(3)}` : llm.usage?.input_tokens ? ` · ${llm.usage.input_tokens + llm.usage.output_tokens} token` : "";
  return `<div class="verdict"><span class="badge ${vc}">Yapay zekâ: ${vl}</span> ${esc(llm.summary)}
    ${llm.findings?.length ? `<ul class="findings" style="margin-top:8px">${llm.findings.map((f) => findingRow(f.severity, f.explanation, f.file, f.excerpt)).join("")}</ul>` : ""}
    <div class="who">${esc(llm.provider)} · ${esc(llm.model || "")} · ${llm.seconds ?? "?"} sn${cost} · ${fmtDate(llm.at)} · doğrulanmamış yorum</div></div>`;
}

function renderDeps(list, parent) {
  if (!list || !list.length) return "";
  return `<div class="deps"><h3>Bu güncellemenin getirdiği yeni AUR bağımlılıkları</h3>
    <p class="help">Bunlar henüz kurulu değil; yay ana paketi kurarken bunları da derleyip kurar. Ana paketin onayı bu bağımlılıkların incelenen commit'lerini de kapsar.</p>
    ${list.map((d) => renderDep(d, parent)).join("")}</div>`;
}

function renderDep(d, parent) {
  const [cls, label] = STATUS[d.status] || ["neutral", d.status];
  if (!d.target) {
    return `<div class="dep ${d.status}"><div class="pkg-head"><span class="pkg-name">${esc(d.name)}</span><span class="badge ${cls}">${label}</span></div>
      <div class="verdict">${esc(d.error || "")}</div></div>`;
  }
  const dk = `dep:${parent}:${d.name}@${d.target}`;
  return `<div class="dep ${d.status}">
    <div class="pkg-head">
      <span class="pkg-name">${esc(d.name)}</span><span class="ver">yeni · <b>${esc(d.version)}</b> · ${esc(d.required_by)} tarafından isteniyor</span>
      <span class="badge ${cls}">${label}</span><span class="spacer"></span>
      <a class="small" href="${esc(d.aur_url)}" target="_blank" rel="noopener">AUR sayfası ↗</a>
    </div>
    ${renderVerdict(d.llm)}
    ${renderFindings(d.findings)}
    <div class="meta-grid">
      <span>Bakımcı: <b>${esc(d.maintainer || "yok")}</b></span><span>Oy: <b>${d.votes ?? "?"}</b></span>
      <span>AUR'a ilk ekleniş: <b>${fmtDay(d.first_submitted)}</b></span><span>Bu sürüm: <b>${fmtDate(d.last_modified)}</b></span>
      ${d.repo_deps?.length ? `<span>Resmi depodan da kurulacak: <b>${d.repo_deps.map(esc).join(", ")}</b></span>` : ""}
    </div>
    <details class="more" data-key="${esc(dk)}" ${ui.openDetails.has(dk) ? "open" : ""}>
      <summary>Paketin tamamını göster (${d.diff.chars.toLocaleString("tr-TR")} karakter)</summary>
      <div class="more-body">${ui.openDetails.has(dk) ? renderDiff(d.diff.text) : ""}</div>
    </details>
    ${renderDeps(d.deps, parent)}
  </div>`;
}

function renderFindings(findings) {
  const list = (findings || []);
  if (!list.length) return "";
  return `<ul class="findings">${list.map((f) => findingRow(f.severity, f.title + (f.detail ? `: ${f.detail}` : ""), f.file, f.line)).join("")}</ul>`;
}
function findingRow(sev, text, file, line) {
  const [cls, label] = SEV[sev] || ["neutral", sev];
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
  if (!r.repo.length) return `<div class="empty">Resmi depolarda bekleyen güncelleme yok.</div>`;
  const f = ui.repoFilter.toLowerCase();
  const rows = [...r.repo]
    .sort((a, b) => (b.important - a.important) || (b.fixes_cve - a.fixes_cve) || a.name.localeCompare(b.name))
    .filter((x) => !f || x.name.includes(f));
  return `<div class="toolbar"><input class="input" id="repo-filter" placeholder="Paket ara…" value="${esc(ui.repoFilter)}" style="width:240px">
      <span class="muted small">${rows.length} / ${r.repo.length} paket · Resmi paketler Arch geliştiricileri tarafından imzalanır ve pacman imzayı doğrular.</span></div>
    <div class="table-wrap"><table><thead><tr><th>Paket</th><th>Depo</th><th>Kurulu</th><th>Yeni</th><th>Not</th></tr></thead><tbody>
    ${rows.map((x) => `<tr><td><b>${esc(x.name)}</b></td><td class="muted">${esc(x.repo)}</td><td class="mono">${esc(x.old)}</td><td class="mono">${esc(x.new)}</td>
      <td><div class="tags">${x.fixes_cve ? `<span class="badge ok">güvenlik düzeltmesi</span>` : ""}${x.important ? `<span class="badge accent">önemli</span>` : ""}${x.major ? `<span class="badge warn">ana sürüm</span>` : ""}${x.reboot ? `<span class="badge neutral">yeniden başlatma</span>` : ""}</div></td></tr>`).join("")}
    </tbody></table></div>`;
}

function renderVulns(r) {
  if (!r.vulns.length) return `<div class="empty">Kurulu sürümleri etkileyen kayıtlı bir güvenlik açığı yok.</div>`;
  const groups = { active: [], fixed: [], stale: [], acked: [] };
  for (const v of r.vulns) groups[vulnGroup(v)].push(v);
  const analyzing = new Set(ui.data.analyzing || []);
  const pendingAi = r.vulns.filter((v) => v.evidence_verdict !== "fixed" && v.ai?.status !== "ok").length;
  const section = (key, title, intro, list) => !list.length ? "" : `
    <details class="more vgroup" data-key="vg-${key}" ${key === "active" || ui.openDetails.has("vg-" + key) ? "open" : ""}>
      <summary>${title} (${list.length})</summary>
      <div class="more-body">${intro ? `<p class="note" style="margin:0">${intro}</p>` : ""}${list.map((v) => renderVuln(v, key, analyzing)).join("")}</div>
    </details>`;
  return `<div class="toolbar">
      <button class="btn sm" data-act="analyze-all" ${pendingAi && !analyzing.size ? "" : "disabled"}>${analyzing.size ? `Analiz ediliyor… (${analyzing.size})` : `Yapay zekâya değerlendirt (${pendingAi})`}</button>
      <span class="muted small">${r.cve_pending ? `${r.cve_pending} CVE'nin ayrıntısı NVD'den sonraki kontrollerde gelecek. ` : ""}Kayıtlar: Arch güvenlik takipçisi; CVE ayrıntıları: NVD.</span>
    </div>
    ${groups.active.length ? "" : `<div class="empty" style="padding:12px">Etkin bir güvenlik açığı yok.</div>`}
    ${section("active", "Etkin açıklar", "Önem derecesine, çalışan bir servisin paketi yüklemesine (⚙) ve düzeltmenin bekleyen güncellemede olmasına göre sıralı.", groups.active)}
    ${section("fixed", "Düzeltildiği doğrulananlar", "NVD sürüm verisine ya da CVE açıklamasına göre kurulu upstream sürüm düzeltmeyi içeriyor; takipçi kaydı güncellenmemiş.", groups.fixed)}
    ${section("stale", "Büyük olasılıkla eski kayıtlar", "Takipçi düzeltme sürümünü girmemiş, CVE'ler önceki yıllara ait ve kurulu upstream sürüm açığın bildirildiği sürümden yeni. Bu bir tahmindir; yapay zekâ değerlendirmesiyle teyit edebilirsin.", groups.stale)}
    ${section("acked", "İncelediğin ve gizlediğin kayıtlar", "Paket sürümü değişince yeniden görünürler.", groups.acked)}`;
}

function vulnGroup(v) {
  if (v.ack) return "acked";
  if (v.evidence_verdict === "fixed") return "fixed";
  if (v.stale) return "stale";
  return "active";
}

const AV_TR = { NETWORK: "ağdan", ADJACENT_NETWORK: "yerel ağdan", ADJACENT: "yerel ağdan", LOCAL: "yerel", PHYSICAL: "fiziksel erişimle" };
const ASSESS = { affected: ["danger", "Etkileniyor"], fixed: ["ok", "Düzeltilmiş"], not_applicable: ["ok", "Bu sistemi etkilemiyor"], unknown: ["neutral", "Belirsiz"] };
const RISK_TR = { critical: ["danger", "kritik risk"], high: ["danger", "yüksek risk"], medium: ["warn", "orta risk"], low: ["info", "düşük risk"], none: ["ok", "risk yok"] };
const CONF_TR = { high: "yüksek güven", medium: "orta güven", low: "düşük güven" };

function renderVuln(v, group, analyzing) {
  const sevCls = group === "active" ? AVG_SEV[v.severity] || "neutral" : "neutral";
  const key = `${v.avg}:${v.package}`;
  const busy = analyzing.has(key);
  const ai = v.ai;
  const ev = v.evidence_verdict;
  const fixBadge = v.fix_pending ? `<span class="badge ok">düzeltme güncellemede: ${esc(v.fixed)}</span>`
    : ev === "fixed" ? `<span class="badge ok">kurulu sürümde düzeltilmiş (kanıtlı)</span>`
    : ev === "open" ? `<span class="badge danger">kurulu sürüm etkileniyor (kanıtlı)</span>`
    : v.fixed ? `<span class="badge neutral">düzeltme: ${esc(v.fixed)}</span>` : "";
  const aiBadge = ai?.status === "ok" ? `<span class="badge ${ASSESS[ai.assessment][0]}">Yapay zekâ: ${ASSESS[ai.assessment][1]}</span>` : "";
  const users = [
    v.services?.length ? `<span class="tags">${v.services.map((s) => `<span class="badge warn" title="Çalışan bir sistem servisi bu paketi yüklüyor">⚙ ${esc(s.replace(/\.service$/, ""))}</span>`).join("")}</span>` : "",
    v.explicit ? `<span>senin kurduğun paket</span>` : "",
    v.used_by?.length ? `<span title="${esc(v.used_by.join(", "))}">kullanan: ${v.used_by.slice(0, 6).map(esc).join(", ")}${v.used_by.length > 6 ? ` +${v.used_by.length - 6}` : ""}</span>` : "",
  ].filter(Boolean).join(" · ");
  const dk = `vuln:${key}`;
  const providers = ui.settings?.providers || [];
  return `<article class="pkg vuln">
    <div class="pkg-head">
      <span class="badge ${sevCls}">${AVG_SEV_TR[v.severity] || esc(v.severity)}</span>
      <span class="pkg-name">${esc(v.package)}</span><span class="ver">${esc(v.installed)}</span>
      ${fixBadge}${aiBadge}
      <span class="spacer"></span>
      <a class="small" href="${esc(v.url)}" target="_blank" rel="noopener">${esc(v.avg)} ↗</a>
    </div>
    <div class="pkg-body">
      <div class="meta-grid"><span>${esc(v.type)}</span><span>${v.issues.map(esc).join(", ")}</span>${users ? `<span>${users}</span>` : ""}</div>
      ${renderVulnAi(ai)}
      <div class="pkg-actions">
        <button class="btn sm ${ai?.status === "ok" ? "ghost" : ""}" data-act="analyze" data-avg="${esc(v.avg)}" data-pkg="${esc(v.package)}" ${busy ? "disabled" : ""}>${busy ? "Analiz ediliyor…" : ai?.status === "ok" ? "Yeniden değerlendirt" : "Yapay zekâya değerlendirt"}</button>
        ${providers.length > 1 ? `<select class="input" style="height:28px" data-vprovider-for="${esc(key)}">${providers.map((p) => `<option value="${esc(p.id)}" ${p.id === ui.settings.review.active_provider ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select>` : ""}
        ${group === "acked"
          ? `<button class="btn sm ghost" data-act="unack" data-avg="${esc(v.avg)}" data-pkg="${esc(v.package)}">Geri al</button><span class="small muted">${v.ack.note ? "Not: " + esc(v.ack.note) : ""}</span>`
          : `<button class="btn sm ghost" data-act="ack" data-avg="${esc(v.avg)}" data-pkg="${esc(v.package)}">İnceledim, gizle</button>`}
      </div>
    </div>
    <details class="more" data-key="${esc(dk)}" ${ui.openDetails.has(dk) ? "open" : ""}>
      <summary>CVE ayrıntıları (${v.cves?.length || v.issue_count})</summary>
      <div class="more-body">${(v.cves || []).map(renderCve).join("") || `<p class="muted">Ayrıntı yok.</p>`}</div>
    </details>
  </article>`;
}

function renderVulnAi(ai) {
  if (!ai) return "";
  if (ai.status !== "ok") return `<div class="verdict"><b>Değerlendirme yapılamadı:</b> ${esc(ai.error)}</div>`;
  const [rc, rl] = RISK_TR[ai.risk] || ["neutral", ai.risk];
  return `<div class="verdict">
    <span class="badge ${ASSESS[ai.assessment][0]}">${ASSESS[ai.assessment][1]}</span> <span class="badge ${rc}">${rl}</span>
    ${ai.fixed_in ? `<span class="badge neutral">upstream düzeltme: ${esc(ai.fixed_in)}</span>` : ""}
    <div style="margin-top:6px">${esc(ai.summary)}</div>
    ${ai.actions?.length ? `<ul style="margin:6px 0 0;padding-left:18px">${ai.actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ul>` : ""}
    ${ai.reasoning ? `<details style="margin-top:6px"><summary class="small muted" style="cursor:pointer">Gerekçe</summary><p class="small" style="margin:4px 0 0">${esc(ai.reasoning)}</p></details>` : ""}
    <div class="who">${esc(ai.provider)} · ${esc(ai.model || "")} · ${CONF_TR[ai.confidence] || ""} · ${ai.seconds ?? "?"} sn · ${fmtDate(ai.at)} · doğrulanmamış yorum; modelin bilgisi bir tarihe kadar günceldir</div>
  </div>`;
}

function renderCve(c) {
  const i = c.info;
  const e = c.evidence;
  if (!i) return `<div class="cve"><b>${esc(c.id)}</b> <span class="muted small">NVD ayrıntısı henüz alınmadı</span> · <a class="small" href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank" rel="noopener">NVD ↗</a></div>`;
  const cv = i.cvss || {};
  const evBadge = !e ? "" : e.affected === true ? `<span class="badge danger">kurulu sürüm etkileniyor</span>`
    : e.affected === false ? `<span class="badge ok">kurulu sürümde düzeltilmiş</span>` : `<span class="badge neutral">sürüm bilgisi yok</span>`;
  const patches = (i.references || []).filter((r) => (r.tags || []).some((t) => ["Patch", "Release Notes", "Vendor Advisory"].includes(t))).slice(0, 4);
  return `<div class="cve">
    <div><b>${esc(c.id)}</b> ${cv.score != null ? `<span class="badge ${cv.score >= 7 ? "danger" : cv.score >= 4 ? "warn" : "info"}">CVSS ${cv.score}</span>` : ""}
      ${cv.attack_vector ? `<span class="badge neutral">${AV_TR[cv.attack_vector] || esc(cv.attack_vector)}</span>` : ""}
      ${cv.user_interaction === "REQUIRED" ? `<span class="badge neutral">kullanıcı etkileşimi gerekir</span>` : ""}
      ${evBadge} <span class="muted small">${e ? esc(e.source) : ""}${e?.fixed_in?.length ? ` · düzeltme: ${e.fixed_in.map(esc).join(", ")}` : ""}</span></div>
    <p class="small" style="margin:4px 0">${esc(i.description)}</p>
    <div class="small muted">NVD durumu: ${esc(i.status || "?")} · yayın: ${esc(String(i.published || "").slice(0, 10))} · <a href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank" rel="noopener">NVD ↗</a>
      ${patches.map((p) => ` · <a href="${esc(p.url)}" target="_blank" rel="noopener">${esc(new URL(p.url).hostname)}</a>`).join("")}</div>
  </div>`;
}

function renderNews(r) {
  if (!r.news.length) return `<div class="empty">Haber alınamadı.</div>`;
  const unread = r.news.filter((n) => !n.read);
  return `<div class="toolbar">${unread.length ? `<button class="btn sm" data-act="read-all">Tümünü okundu say</button>` : ""}<a class="small" href="https://archlinux.org/news/" target="_blank" rel="noopener">archlinux.org/news ↗</a></div>
    <div class="news">${r.news.map((n) => `<article class="news-item ${n.read || !n.since_last_upgrade ? "" : "unread"}">
      <h3><a href="${esc(n.link)}" target="_blank" rel="noopener">${esc(n.title)}</a></h3>
      <span class="muted small">${fmtDay(n.published)}${n.since_last_upgrade ? ` · <span class="badge warn">son güncellemenden sonra</span>` : ""}${n.read ? " · okundu" : ""}</span>
      <p>${esc(n.summary)}</p>
      ${n.read ? "" : `<div><button class="btn sm ghost" data-act="read" data-id="${esc(n.id)}">Okundu say</button></div>`}
    </article>`).join("")}</div>`;
}

function renderRuntime(r) {
  const rt = r.runtime;
  if (!rt) return "";
  const safe = rt.services.filter((s) => s.safe);
  const unsafe = rt.services.filter((s) => !s.safe);
  const parts = [`<h3>Yeniden başlatma</h3>`];
  if (!rt.services.length && !rt.user_processes.length && !rt.reboot_recommended) {
    parts.push(`<p class="muted">Gerek yok: çalışan her şey diskteki güncel kütüphaneleri kullanıyor (son açılış ${fmtDate(rt.boot_time)}).</p>`);
  } else {
    parts.push(`<p class="note">Güncellenen bir kütüphane, onu yüklemiş programlar yeniden başlatılana kadar bellekte eski (açıklı) haliyle çalışmaya devam eder.</p>`);
    if (rt.reboot_recommended) {
      const why = [rt.kernel_updated && "çekirdek güncellendi", rt.reboot_packages.length && `${rt.reboot_packages.join(", ")} açılıştan sonra güncellendi`,
        unsafe.length && "oturumu yöneten servisler etkilendi", rt.user_processes.some((u) => u.session) && "masaüstü oturumu eski kütüphaneleri kullanıyor"].filter(Boolean);
      parts.push(`<div class="alert warn"><span class="alert-icon">↻</span><div><b>Bilgisayarı yeniden başlatman öneriliyor</b><div class="small">${esc(why.join("; "))}.</div></div></div>`);
    }
    if (safe.length) {
      parts.push(`<div class="table-wrap"><table><thead><tr><th>Servis</th><th>Başlama</th><th>Sonradan güncellenen paketler</th></tr></thead><tbody>
        ${safe.map((s) => `<tr><td><b>${esc(s.unit)}</b></td><td class="mono">${fmtDate(s.started)}</td><td>${s.packages.map(esc).join(", ")}</td></tr>`).join("")}
        </tbody></table></div>
        <div class="toolbar" style="margin-top:8px"><button class="btn sm primary" data-act="restart">Bu ${safe.length} servisi yeniden başlat</button>
        <code class="small muted">sudo systemctl restart ${safe.map((s) => esc(s.unit)).join(" ")}</code></div>`);
    }
    if (unsafe.length) parts.push(`<p class="small">Yeniden başlatılırsa oturumu kapatacak servisler (bunun yerine bilgisayarı yeniden başlat): <b>${unsafe.map((s) => esc(s.unit)).join(", ")}</b></p>`);
    if (rt.user_processes.length) {
      parts.push(`<p class="small" style="margin-bottom:4px">Eski kütüphaneyi hâlâ kullanan uygulamaların (kapatıp yeniden aç):</p>
        <div class="tags">${rt.user_processes.map((u) => `<span class="badge ${u.session ? "warn" : "neutral"}" title="${esc(u.files.join("\n"))}">${esc(u.name)}${u.count > 1 ? ` ×${u.count}` : ""}</span>`).join("")}</div>`);
    }
  }
  const pub = rt.open_ports.filter((p) => p.public);
  parts.push(`<h3 style="margin-top:20px">Ağa açık portlar</h3>
    <p class="note">Yalnızca bu bilgisayarın dışından erişilebilecek adreslerde dinleyenler listelenir. "Tüm ağ" yazanlara bağlı olduğun ağdaki herkes ulaşabilir. Docker'ın yayımladığı portlar ufw kurallarını atlar.</p>
    ${rt.open_ports.length ? `<div class="table-wrap"><table><thead><tr><th>Port</th><th>Ne</th><th>Adres</th></tr></thead><tbody>
      ${rt.open_ports.map((p) => `<tr><td class="mono">${p.port}/${esc(p.proto)}</td>
        <td>${p.container ? `<span class="badge ${p.public ? "danger" : "neutral"}">Docker: ${esc(p.container)}</span> ${esc(p.service || "")}` : esc(p.service || p.process || "bilinmiyor (root süreci)")}</td>
        <td>${p.public ? `<span class="badge warn">tüm ağ</span>` : `<span class="mono small">${esc(p.address)}</span>`}</td></tr>`).join("")}
      </tbody></table></div>` : `<p class="muted">Yok.</p>`}
    ${pub.some((p) => p.container) ? `<p class="small">Docker kapsayıcısını yalnızca bu bilgisayardan erişilebilir yapmak için compose dosyasında portu <code>"127.0.0.1:PORT:PORT"</code> biçiminde yaz.</p>` : ""}`);
  return parts.join("");
}

function renderSystem(r) {
  const s = r.system;
  return `${renderRuntime(r)}<h3 style="margin-top:20px">Genel</h3><dl class="kv" style="margin-top:8px">
      <dt>Son tam güncelleme</dt><dd>${s.last_upgrade ? fmtDate(s.last_upgrade) : "bulunamadı"}</dd>
      <dt>Kurulu paket</dt><dd>${s.installed_count} (${s.foreign_count} AUR / depo dışı)</dd>
      <dt>Boş disk alanı</dt><dd>${s.disk_free_gb} GB</dd>
      <dt>Timeshift otomatik anlık görüntü</dt><dd>${s.autosnap ? "kurulu" : "kurulu değil"}</dd>
      <dt>Yeniden başlatma</dt><dd>${s.reboot_needed ? "gerekiyor (çekirdek güncellendi)" : "gerekmiyor"}</dd>
      <dt>Son kontrol süresi</dt><dd>${r.duration} sn</dd>
      <dt>İnceleme sağlayıcısı</dt><dd>${r.review_provider ? esc(r.review_provider) : "kapalı"}</dd>
      <dt>AUR bekleme süresi</dt><dd>${r.hold_days} gün</dd>
    </dl>
    <h3 style="margin-top:20px">Birleştirilmeyi bekleyen yapılandırma dosyaları (.pacnew)</h3>
    ${s.pacnew.length ? `<p class="note">Paket yeni bir varsayılan yapılandırma getirdiğinde, senin değiştirdiğin dosyanın yanına <code>.pacnew</code> olarak bırakılır. Farkları birleştirmek için terminalde <code>sudo DIFFPROG="kdiff3" pacdiff</code> ya da <code>sudo pacdiff</code> çalıştır.</p>
      <ul class="mono small">${s.pacnew.map((p) => `<li>${esc(p)}</li>`).join("")}</ul>` : `<p class="muted">Yok.</p>`}`;
}

// ---------- actions ----------
document.addEventListener("click", async (ev) => {
  const t = ev.target.closest("[data-tab],[data-act]");
  if (!t) return;
  if (t.dataset.tab) {
    ui.tab = t.dataset.tab;
    render();
    if (t.classList.contains("stat")) document.querySelector(".tabs")?.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  const act = t.dataset.act;
  try {
    if (act === "check") await startCheck();
    else if (act === "read") { await api("/api/news/read", { ids: [t.dataset.id] }); await refresh(); }
    else if (act === "read-all") { await api("/api/news/read", { ids: ui.data.report.news.map((n) => n.id) }); await refresh(); }
    else if (act === "approve") await approve(t.dataset.name, t.dataset.commit, t.dataset.status);
    else if (act === "unapprove") { await api("/api/unapprove", { name: t.dataset.name }); toast("Onay kaldırıldı"); await refresh(); }
    else if (act === "rereview") await rereview(t.dataset.name);
    else if (act === "update") await startUpdate();
    else if (act === "restart") await restartServices();
    else if (act === "ack") await ackVuln(t.dataset.avg, t.dataset.pkg);
    else if (act === "analyze") await analyzeVuln(t.dataset.avg, t.dataset.pkg);
    else if (act === "analyze-all") { const r = await api("/api/vuln/analyze-all", {}); toast(r.started ? `${r.started} kayıt sırayla değerlendiriliyor` : "Değerlendirilecek kayıt yok"); await refresh(); }
    else if (act === "unack") { await api("/api/vuln/ack", { avg: t.dataset.avg, package: t.dataset.pkg, undo: true }); await refresh(); }
  } catch (e) {
    toast(e.message, true);
  }
});

document.addEventListener("change", (ev) => {
  const t = ev.target;
  if (t.dataset.sel) { ui.selected.set(t.dataset.sel, t.checked); render(); }
  else if (t.id === "news-ack") { ui.newsAck = t.checked; render(); }
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
  toast(r.started ? "Kontrol başladı" : "Bir kontrol zaten çalışıyor");
  await refresh();
}

async function rereview(name) {
  const sel = document.querySelector(`[data-provider-for="${CSS.escape(name)}"]`);
  const provider = sel ? sel.value : undefined;
  toast(`${name} yeniden inceleniyor…`);
  const p = api("/api/rereview", { name, provider });
  setTimeout(refresh, 300);
  const res = await p;
  toast(res.status === "ok" ? `${name}: inceleme tamamlandı` : `${name}: ${res.error}`, res.status !== "ok");
  await refresh();
}

async function approve(name, commit, status) {
  if (status === "clean") {
    await api("/api/approve", { name, commit });
    toast(`${name} onaylandı`);
    return refresh();
  }
  const warn = status === "danger"
    ? "Bu güncellemede <b>tehlikeli</b> bulgular var. Bulguların yanlış alarm olduğundan emin değilsen onaylama."
    : status === "unreviewed"
      ? "Bu güncelleme otomatik olarak incelenemedi. Diff'i kendin okuduysan onaylayabilirsin."
      : "Bu güncellemede dikkat gerektiren bulgular var. Diff'i ve bulguları okuduysan onaylayabilirsin.";
  const needType = status === "danger" || status === "warning";
  const ok = await confirmDialog(`${name} onaylansın mı?`,
    `<p style="margin:0">${warn}</p>${needType ? `<label class="field"><span>Onaylamak için paket adını yaz: <b>${esc(name)}</b></span><input class="input" id="confirm-input" autocomplete="off"></label>` : ""}
     <p class="help">Onay yalnızca şu an incelenen commit için geçerlidir; paket yeniden değişirse onay düşer.</p>`,
    needType ? () => $("#confirm-input").value.trim() === name : null);
  if (!ok) return;
  await api("/api/approve", { name, commit, confirm: needType ? name : undefined });
  toast(`${name} onaylandı`);
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
  const ok = await confirmDialog("Güncelleme başlatılsın mı?",
    `<p style="margin:0">${r.repo.length} resmi depo paketi${aur.length ? ` ve ${aur.length} AUR paketi` : ""} güncellenecek.</p>${list}
     <p class="help">Bir Konsole penceresi açılır. sudo parolanı orada girersin; Timeshift işlem başlamadan anlık görüntü alır.</p>`);
  if (!ok) return;
  const res = await api("/api/update", { aur, news_ack: ui.newsAck });
  toast(`Güncelleme Konsole'da başladı${res.aur.length ? ` (AUR: ${res.aur.join(", ")})` : ""}`);
  await refresh();
}

async function analyzeVuln(avg, pkg) {
  const sel = document.querySelector(`[data-vprovider-for="${CSS.escape(avg + ":" + pkg)}"]`);
  toast(`${pkg} değerlendiriliyor…`);
  const p = api("/api/vuln/analyze", { avg, package: pkg, provider: sel ? sel.value : undefined });
  setTimeout(refresh, 300);
  const res = await p;
  toast(res.status === "ok" ? `${pkg}: değerlendirme tamamlandı` : `${pkg}: ${res.error}`, res.status !== "ok");
  await refresh();
}

async function ackVuln(avg, pkg) {
  const ok = await confirmDialog(`${pkg} · ${avg} gizlensin mi?`,
    `<p style="margin:0">Kayıt, <b>${esc(pkg)}</b> paketinin şu anki sürümü için listeden kalkar. Paket güncellenince yeniden kontrol edilir.</p>
     <label class="field"><span>Not (isteğe bağlı): neden güvenli ya da ne önlem aldın?</span><input class="input" id="confirm-input" placeholder="örn. upstream 1.7.1'de düzeltilmiş" autocomplete="off"></label>`);
  if (!ok) return;
  const v = ui.data.report.vulns.find((x) => x.avg === avg && x.package === pkg);
  const typed = $("#confirm-input")?.value || "";
  const note = typed || (v?.ai?.status === "ok" ? `Yapay zekâ: ${v.ai.summary}` : "");
  await api("/api/vuln/ack", { avg, package: pkg, note });
  toast("Gizlendi");
  await refresh();
}

async function restartServices() {
  const units = ui.data.report.runtime.services.filter((s) => s.safe).map((s) => s.unit);
  const ok = await confirmDialog("Servisler yeniden başlatılsın mı?",
    `<p style="margin:0"><b>${units.map(esc).join(", ")}</b></p><p class="help">Konsole'da <code>sudo systemctl restart</code> çalışır. Ağ servisleri birkaç saniyeliğine kesilebilir.</p>`);
  if (!ok) return;
  await api("/api/restart", { units });
  toast("Konsole'da başlatıldı");
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

const TYPE_LABEL = { "claude-code": "Claude Code (kurulu CLI, abonelik)", anthropic: "Anthropic API (API anahtarı)", openai: "OpenAI uyumlu (LiteLLM, Ollama, OpenRouter…)" };

function renderSettings() {
  const s = ui.settings;
  const body = $("#settings-body");
  body.innerHTML = `
    <fieldset><legend>Genel</legend>
      <div class="field-row">
        <label class="field"><span>AUR bekleme süresi (gün)</span><input class="input" type="number" min="0" max="30" name="hold_days" value="${s.hold_days}"></label>
        <label class="field"><span>Otomatik kontrol sıklığı</span><select class="input" name="schedule">
          ${[["daily", "Günde bir (09:00)"], ["twice", "Günde iki (09:00, 19:00)"], ["weekly", "Haftada bir (Pazartesi)"]].map(([v, l]) => `<option value="${v}" ${s.schedule === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>
        <label class="field"><span>Pano penceresi</span><select class="input" name="browser">
          <option value="chromium-app" ${s.browser === "chromium-app" ? "selected" : ""}>Chromium uygulama penceresi</option>
          <option value="default" ${s.browser === "default" ? "selected" : ""}>Varsayılan tarayıcı</option></select></label>
      </div>
      <label class="check"><input type="checkbox" name="notifications" ${s.notifications ? "checked" : ""}> Kontrol bitince masaüstü bildirimi göster</label>
      <p class="help">Bekleme süresi: yeni bir AUR sürümü, AUR'a yüklendikten bu kadar gün sonra otomatik olarak güncellemeye eklenir. Zararlı paketler genellikle ilk 1-3 gün içinde fark edilip kaldırılır. Süreyi beklemeden elle onaylayabilirsin.</p>
    </fieldset>
    <fieldset><legend>Yapay zekâ incelemesi</legend>
      <label class="check"><input type="checkbox" name="review_enabled" ${s.review.enabled ? "checked" : ""}> AUR diff'lerini yapay zekâya inceletir</label>
      <div class="field-row">
        <label class="field"><span>Kullanılacak sağlayıcı</span><select class="input" name="active_provider">
          ${s.providers.map((p) => `<option value="${esc(p.id)}" ${p.id === s.review.active_provider ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select></label>
        <label class="field"><span>En fazla diff boyutu (karakter)</span><input class="input" type="number" name="max_diff_chars" value="${s.review.max_diff_chars}"></label>
        <label class="field"><span>Zaman aşımı (saniye)</span><input class="input" type="number" name="timeout_seconds" value="${s.review.timeout_seconds}"></label>
      </div>
      <p class="help">İnceleme yapılamazsa (hata, zaman aşımı, ret) paket "İncelenmedi" sayılır ve onayın olmadan kurulmaz.</p>
    </fieldset>
    <fieldset><legend>Güvenlik açıkları</legend>
      <label class="check"><input type="checkbox" name="auto_analyze" ${s.security.auto_analyze ? "checked" : ""}> Her kontrolde etkin açıkları yapay zekâya otomatik değerlendirt (eski ve düzeltilmiş kayıtlar elle)</label>
      <div class="field-row" style="align-items:end">
        <label class="field"><span>NVD'den CVE ayrıntısı çekme süresi (saniye / kontrol)</span><input class="input" type="number" min="0" max="900" name="nvd_budget_seconds" value="${s.security.nvd_budget_seconds}"></label>
        <label class="field"><span>NVD API anahtarı ${s.security.has_nvd_key ? "· <b>kasada kayıtlı ✓</b>" : "· isteğe bağlı"}</span><input class="input" type="password" id="nvd-key" placeholder="${s.security.has_nvd_key ? "değiştirmek için yeni anahtar" : "nvd.nist.gov/developers/request-an-api-key"}" autocomplete="off"></label>
        <div style="display:flex;gap:8px"><button type="button" class="btn sm" data-nvd="save">Kaydet</button>${s.security.has_nvd_key ? `<button type="button" class="btn sm ghost" data-nvd="clear">Sil</button>` : ""}</div>
      </div>
      <p class="help">Değerlendirme, Yapay zekâ incelemesi bölümünde seçili sağlayıcıyı kullanır. NVD anahtarsız istemcilere 30 saniyede 5 istek izin verir; ayrıntılar önbelleğe alınır ve eksikler sonraki kontrollerde tamamlanır. Ücretsiz bir anahtarla sınır 10 kat artar.</p>
    </fieldset>
    <fieldset><legend>Sağlayıcılar</legend>
      <div id="providers" style="display:grid;gap:10px">${s.providers.map(providerForm).join("")}</div>
      <div><button type="button" class="btn sm" id="add-provider">+ Sağlayıcı ekle</button></div>
      <p class="help">API anahtarları ayarlar dosyasına değil, masaüstünün anahtar kasasına (Secret Service) kaydedilir. Anahtarı kaydettikten sonra "Dene" ile bağlantıyı sına.</p>
    </fieldset>`;
  $("#add-provider").onclick = () => {
    const id = "p" + Math.random().toString(36).slice(2, 7);
    $("#providers").insertAdjacentHTML("beforeend", providerForm({ id, name: "Yeni sağlayıcı", type: "openai", model: "", base_url: "http://localhost:4000/v1", json_mode: "json_schema", _new: true }));
  };
}

function providerForm(p) {
  const keyed = p.type === "anthropic" || p.type === "openai";
  return `<div class="provider" data-pid="${esc(p.id)}">
    <div class="provider-head">
      <input class="input" data-f="name" value="${esc(p.name)}" style="font-weight:600;width:200px" aria-label="Ad">
      <select class="input" data-f="type">${Object.entries(TYPE_LABEL).map(([v, l]) => `<option value="${v}" ${p.type === v ? "selected" : ""}>${l}</option>`).join("")}</select>
      <span class="spacer"></span>
      <code class="muted small">${esc(p.id)}</code>
      <button type="button" class="btn sm ghost" data-pact="test">Dene</button>
      <button type="button" class="icon-btn" data-pact="remove" aria-label="Sil">🗑</button>
    </div>
    <div class="field-row">
      <label class="field"><span>Model</span><input class="input" data-f="model" value="${esc(p.model || "")}" placeholder="${p.type === "claude-code" ? "sonnet, opus, haiku…" : p.type === "anthropic" ? "claude-opus-5-5" : "model adı"}"></label>
      ${p.type !== "claude-code" ? `<label class="field"><span>Adres${p.type === "anthropic" ? " (boş = api.anthropic.com)" : ""}</span><input class="input" data-f="base_url" value="${esc(p.base_url || "")}" placeholder="${p.type === "openai" ? "http://localhost:4000/v1" : ""}"></label>` : ""}
      ${p.type === "anthropic" ? `<label class="field"><span>Effort</span><select class="input" data-f="effort">${["low", "medium", "high", "xhigh", "max", ""].map((e) => `<option value="${e}" ${(p.effort || "") === e ? "selected" : ""}>${e || "gönderme"}</option>`).join("")}</select></label>` : ""}
      ${p.type === "openai" ? `<label class="field"><span>JSON kipi</span><select class="input" data-f="json_mode">${[["json_schema", "json_schema (katı şema)"], ["json_object", "json_object"], ["none", "yok (yalnızca istem)"]].map(([v, l]) => `<option value="${v}" ${(p.json_mode || "json_schema") === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>` : ""}
    </div>
    ${keyed ? `<div class="field-row" style="align-items:end">
      <label class="field"><span>API anahtarı ${p.has_key ? "· <b>kasada kayıtlı ✓</b>" : p.type === "openai" ? "· isteğe bağlı" : "· girilmedi"}</span><input class="input" type="password" data-key placeholder="${p.has_key ? "değiştirmek için yeni anahtar gir" : "anahtarı yapıştır"}" autocomplete="off"></label>
      <div style="display:flex;gap:8px"><button type="button" class="btn sm" data-pact="save-key">Anahtarı kaydet</button>${p.has_key ? `<button type="button" class="btn sm ghost" data-pact="clear-key">Anahtarı sil</button>` : ""}</div>
    </div>` : `<p class="help">Kurulu <code>claude</code> komutunu araçsız modda çalıştırır; Claude aboneliğinin kotasından harcar.</p>`}
    ${p.type === "anthropic" ? `<p class="help">Opus 5.5, Sonnet 5.5 ve Fable modellerinde, güvenlik sınıflandırıcısı incelemeyi reddederse istek otomatik olarak başka bir modelle yeniden denenir (server-side fallback).</p>` : ""}
    <div class="test-result" hidden></div>
  </div>`;
}

function collectSettings() {
  const f = $("#settings-form");
  const s = structuredClone(ui.settings);
  s.hold_days = Number(f.hold_days.value);
  s.schedule = f.schedule.value;
  s.browser = f.browser.value;
  s.notifications = f.notifications.checked;
  s.review.enabled = f.review_enabled.checked;
  s.review.active_provider = f.active_provider.value;
  s.review.max_diff_chars = Number(f.max_diff_chars.value);
  s.review.timeout_seconds = Number(f.timeout_seconds.value);
  s.security = { auto_analyze: f.auto_analyze.checked, nvd_budget_seconds: Number(f.nvd_budget_seconds.value) };
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
      if (n.dataset.nvd === "save" && !value) return toast("Önce anahtarı yapıştır", true);
      await saveSettings(false);
      await api("/api/secret", { provider: "nvd", value });
      await loadSettings();
      renderSettings();
      toast(value ? "NVD anahtarı kaydedildi" : "NVD anahtarı silindi");
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
      if (document.querySelectorAll("#providers .provider").length <= 1) return toast("En az bir sağlayıcı kalmalı", true);
      card.remove();
    } else if (b.dataset.pact === "save-key" || b.dataset.pact === "clear-key") {
      const value = b.dataset.pact === "save-key" ? card.querySelector("[data-key]").value : "";
      if (b.dataset.pact === "save-key" && !value) return toast("Önce anahtarı yapıştır", true);
      await saveSettings(false);  // provider must exist server-side first
      await api("/api/secret", { provider: pid, value });
      await loadSettings();
      renderSettings();
      toast(value ? "Anahtar kasaya kaydedildi" : "Anahtar silindi");
    } else if (b.dataset.pact === "test") {
      show("Deneniyor… (bir örnek diff gönderiliyor)");
      b.disabled = true;
      const res = await api("/api/test-provider", { provider: pid, settings: collectSettings() });
      b.disabled = false;
      show(res.status === "ok"
        ? `✓ Çalışıyor: ${res.model || ""} · ${res.seconds} sn · karar "${res.verdict}"\n${res.summary}`
        : `✕ ${res.error}`);
    }
  } catch (e) {
    b.disabled = false;
    show("✕ " + e.message);
  }
});

async function saveSettings(close = true) {
  const saved = await api("/api/settings", collectSettings());
  ui.settings = saved.settings;
  $("#settings-msg").textContent = "Kaydedildi" + (saved.schedule === "güncellendi" ? " · zamanlayıcı güncellendi" : "");
  if (close) {
    $("#dlg-settings").close();
    toast("Ayarlar kaydedildi");
    render();
  }
}

$("#btn-save-settings").addEventListener("click", async (ev) => {
  ev.preventDefault();
  try { await saveSettings(true); } catch (e) { $("#settings-msg").textContent = e.message; toast(e.message, true); }
});

// ---------- boot ----------
loadSettings().catch(() => {}).finally(refresh);

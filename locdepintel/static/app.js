"use strict";
const $ = (id) => document.getElementById(id);
const esc = (v) =>
  String(v ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );
// Tagged template for markup: lets long templates span several lines. Any whitespace that
// contains a line break is removed, so the HTML produced is identical to a one-line template.
// Values are inserted as given; callers escape untrusted text with esc().
// (.prettierrc turns off embedded formatting so prettier never re-wraps text inside these.)
const html = (strings, ...values) =>
  strings.reduce(
    (out, part, i) => out + part.replace(/\s*\n\s*/g, "") + (i < values.length ? values[i] : ""),
    "",
  );
const fmt = (t) => (t ? new Date(t).toLocaleString() : "Not recorded");
const short = (s, n = 58) =>
  String(s || "").length > n ? String(s).slice(0, n - 1) + "…" : String(s || "");
const url = (v) => {
  try {
    const u = new URL(v);
    return ["http:", "https:"].includes(u.protocol) ? u.href : null;
  } catch {
    return null;
  }
};
const quote = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";
let overview = {},
  state = {},
  inventory = [],
  groups = [],
  pulse = { advisories: [] },
  activeView = "overview",
  invPage = 0,
  visibleInventory = [],
  visibleActions = [],
  visiblePulse = [],
  jobPolling = null,
  inventoryMode = "grouped",
  noticeTimer = null;
// Fixed UI text inserted into markup. Must not contain HTML special characters.
const TEXT = {
  locationsHelp:
    "Each location is independently actionable. Choose one to inspect its advisories, " +
    "Finder and Terminal shortcuts, and review-only remediation steps.",
  malwareNextStep:
    "Stop using affected environments and review possible execution and credential " +
    "exposure. Removal alone may not reverse earlier harm.",
  vulnerabilityNextStep:
    "Review the source advisory and identify a patched, compatible version. " +
    "Resolve transitive dependencies through their parent package.",
  firstObservedCaveat: "First observed is not proof of original installation date.",
  noAdvisory:
    "No matching advisory in stored results. This does not establish that the package is safe.",
};
const LOCAL_STATUS = {
  affected: "Exact advisory match in inventory",
  "package-present": "Package name present · verify versions",
  "not-detected": "Not detected in covered inventory",
};
const advisoryLink = (a, label) =>
  url(a.url)
    ? `<a href="${esc(url(a.url))}" target="_blank" rel="noopener noreferrer">${label} ↗</a>`
    : "";
function locationCell(p) {
  if (inventoryMode !== "grouped") return esc(short(p.env, 43));
  const noun = p.installation_count === 1 ? "location" : "locations";
  return `<strong>${p.installation_count}</strong> ${noun}`;
}
function securityEvidence(findings) {
  if (!findings.length) return `<p>${TEXT.noAdvisory}</p>`;
  return findings
    .map(
      (a) => html`<div class="advisory">${riskLabel(a.kind)} &nbsp; ${esc(a.advisory)}
        <p>${esc(a.summary)}</p>
        ${advisoryLink(a, "View original advisory")}</div>`,
    )
    .join("");
}
function checkSummary(check) {
  if (!check) return "No advisory check recorded.";
  const count = check.packages || 0;
  return `${esc(check.state)} · ${esc(fmt(check.timestamp))} · ${count} package versions checked`;
}
const PER_PAGE = 35;
async function api(endpoint, method = "GET", obj) {
  const r = await fetch("/api/" + endpoint, {
    method,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: obj ? JSON.stringify(obj) : undefined,
  });
  if (r.status === 401) {
    // Session cookie missing or from a previous server run: the page cannot recover by itself.
    throw Error("Session expired. Open the new link printed in the terminal by locdepintel serve.");
  }
  const data = await r.json();
  if (!r.ok) throw Error(data.error || "Request failed");
  return data;
}
function notice(message, error = false) {
  const el = $("notice");
  if (noticeTimer) clearTimeout(noticeTimer);
  el.hidden = false;
  $("notice-text").textContent = message;
  el.classList.toggle("error", error);
  if (!error)
    noticeTimer = setTimeout(
      () => {
        el.hidden = true;
      },
      message.startsWith("Scan") ? 5000 : 6000,
    );
}
$("notice-close").onclick = () => {
  if (noticeTimer) clearTimeout(noticeTimer);
  $("notice").hidden = true;
};
function folderOf(path) {
  const parts = String(path || "")
    .replace(/\\/g, "/")
    .split("/")
    .filter(Boolean);
  if (!parts.length) return "Other locations";
  const home = parts.findIndex(
    (p, i) => i > 0 && (parts[i - 1] === "Users" || parts[i - 1] === "home"),
  );
  if (home >= 0) {
    const p = parts[home + 1];
    return p && !p.startsWith(".") ? p : "Hidden locations";
  }
  return "Other locations";
}
function groupInventory(entries) {
  const grouped = new Map();
  for (const p of entries) {
    const k = packageKey(p);
    if (!grouped.has(k))
      grouped.set(k, { ...p, locations: [], origins: new Set(), first_observed: p.discovered });
    const g = grouped.get(k);
    g.locations.push(p);
    g.origins.add(p.direct || "unknown");
    if (p.discovered < g.first_observed) g.first_observed = p.discovered;
    if (p.seen > g.seen) g.seen = p.seen;
  }
  return [...grouped.values()].map((g) => ({
    ...g,
    installation_count: g.locations.length,
    direct: g.origins.size === 1 ? [...g.origins][0] : "mixed",
  }));
}

function riskType(g) {
  return g.kind === "malware" ? "malware" : "vulnerability";
}
function riskLabel(t) {
  return `<span class="risk ${esc(t)}">${t === "malware" ? "MALWARE" : t === "vulnerability" ? "VULNERABLE" : "NO MATCH"}</span>`;
}
function packageKey(x) {
  return [x.ecosystem, x.name.toLowerCase().replace(/_/g, "-"), x.version].join("|");
}
function relevantGroup(p) {
  return groups.find((g) => packageKey(g) === packageKey(p));
}
function riskFor(p) {
  return relevantGroup(p)?.kind || "none";
}
function view(name) {
  activeView = name;
  document.querySelectorAll(".view").forEach((el) => (el.hidden = el.id !== "view-" + name));
  document
    .querySelectorAll(".navbtn")
    .forEach((el) => el.classList.toggle("active", el.dataset.view === name));
  const label =
    {
      overview: "Overview",
      action: "Action Center",
      inventory: "Inventory",
      pulse: "Threat Pulse",
      history: "History",
    }[name] || name;
  $("breadcrumb").innerHTML = "Workspace <span>/</span> " + esc(label);
  if (name === "action") renderAction();
  if (name === "inventory") renderInventory();
  if (name === "pulse") renderPulse();
  if (name === "history") renderHistory();
  window.scrollTo({ top: 0, behavior: "instant" });
}
function fillSelect(id, items, allName) {
  const el = $(id),
    current = el.value;
  el.innerHTML =
    `<option value="">${esc(allName)}</option>` +
    items.map((x) => `<option value="${esc(x)}">${esc(short(x, 65))}</option>`).join("");
  el.value = items.includes(current) ? current : "";
}
function renderOverview() {
  const s = overview.stats || {};
  $("metric-affected").textContent = s.affected_packages ?? "-";
  $("metric-envs").textContent = s.environments ?? "-";
  $("metric-new").textContent =
    s.new_advisory_matches === null ? "N/A" : (s.new_advisory_matches ?? "-");
  $("nav-findings").textContent = s.affected_packages || "";
  const scan = overview.scans?.[0],
    check = overview.checks?.[0],
    dot = $("health-dot");
  dot.classList.remove("warning", "error");
  const health = $("health-label");
  const last = $("last-scan");
  if (!scan) {
    health.textContent = "No discovery scan yet";
    dot.classList.add("warning");
  } else if (check?.state === "error" || scan.status === "error") {
    health.textContent = "Last check failed - review scan details";
    dot.classList.add("error");
  } else if (scan.status === "partial" || check?.state !== "ok") {
    health.textContent = "Coverage incomplete or advisory check pending";
    dot.classList.add("warning");
  } else health.textContent = "Last discovery and advisory check completed";
  last.textContent = scan ? "· " + fmt(scan.ended || scan.started) : "";
  $("scope-note").textContent = overview.scope_note || "";
  const items = (overview.action_queue || []).slice(0, 6);
  $("queue-body").innerHTML =
    items
      .map(
        (g, i) =>
          html`<tr tabindex="0" data-queue="${i}">
            <td>
            <div class="pkg-title">${esc(g.name)} <span class="muted">${esc(g.version)}</span>
            </div>
            <div class="pkg-sub">${esc(g.ecosystem)}</div>
            </td>
            <td>${riskLabel(g.kind)}</td>
            <td>${g.advisory_count}</td>
            <td>${g.installation_count}</td>
            <td class="chev">›</td>
            </tr>`,
      )
      .join("") ||
    '<tr><td colspan="5" class="empty">No matching advisories in the current inventory. This is not a guarantee of safety.</td></tr>';
  const envs = (overview.environments || []).slice(0, 6);
  $("overview-envs").innerHTML =
    envs
      .map(
        (x, i) =>
          html`<button class="env-item" data-envi="${i}">
            <span>
            <strong>${esc(x.path.split("/").filter(Boolean).slice(-2).join(" / ") || x.path)}</strong>
            <small title="${esc(x.path)}">${esc(x.ecosystem || "")} · ${esc(x.path)}</small>
            </span>
            <span class="count">${x.package_count} packages</span>
            <span class="count">${groups.filter((g) => g.locations.includes(x.path)).length} affected</span>
            <span class="chev">›</span>
            </button>`,
      )
      .join("") ||
    '<p class="footnote">No environments discovered. Open Settings to choose folders and Scan to begin.</p>';
}
function renderAction() {
  const needle = $("action-search").value.toLowerCase().trim(),
    type = $("action-kind").value,
    newOnly = $("action-new").checked;
  const fresh = new Set((overview.new_packages || []).map(packageKey));
  $("action-new").disabled = overview.stats?.new_advisory_matches === null;
  visibleActions = groups.filter(
    (x) =>
      (!newOnly || fresh.has(packageKey(x))) &&
      (!type || x.kind === type) &&
      (!needle ||
        (
          x.name +
          " " +
          x.version +
          " " +
          x.ecosystem +
          " " +
          x.advisories.map((a) => a.id).join(" ")
        )
          .toLowerCase()
          .includes(needle)),
  );
  $("action-count").textContent = `${visibleActions.length} affected package versions`;
  $("action-body").innerHTML =
    visibleActions
      .map(
        (g, i) =>
          html`<tr tabindex="0" data-action="${i}">
            <td>
            <div class="pkg-title">${esc(g.name)} <span class="muted">${esc(g.version)}</span>
            </div>
            <div class="pkg-sub">${esc(g.ecosystem)}</div>
            </td>
            <td>${riskLabel(g.kind)}</td>
            <td>${g.advisory_count}</td>
            <td>${g.installation_count}</td>
            <td class="chev">›</td>
            </tr>`,
      )
      .join("") || '<tr><td colspan="5" class="empty">No findings match these filters.</td></tr>';
}
function renderInventory(reset = false) {
  if (reset) invPage = 0;
  const needle = $("inv-search").value.toLowerCase().trim(),
    eco = $("inv-eco").value,
    env = $("inv-env").value,
    folder = $("inv-folder").value,
    ri = $("inv-risk").value;
  const filtered = inventory.filter(
    (p) =>
      (!needle ||
        (p.name + " " + p.version + " " + p.env + " " + p.ecosystem)
          .toLowerCase()
          .includes(needle)) &&
      (!eco || p.ecosystem === eco) &&
      (!env || p.env === env) &&
      (!folder || folderOf(p.env) === folder) &&
      (!ri || riskFor(p) === ri),
  );
  visibleInventory = inventoryMode === "grouped" ? groupInventory(filtered) : filtered;
  const sort = $("inv-sort").value;
  visibleInventory.sort((a, b) =>
    sort === "recent"
      ? String(b.seen).localeCompare(String(a.seen))
      : sort === "risk"
        ? { malware: 2, vulnerability: 1, none: 0 }[riskFor(b)] -
            { malware: 2, vulnerability: 1, none: 0 }[riskFor(a)] || a.name.localeCompare(b.name)
        : a.name.localeCompare(b.name) || a.env.localeCompare(b.env),
  );
  const pages = Math.max(1, Math.ceil(visibleInventory.length / PER_PAGE));
  invPage = Math.min(invPage, pages - 1);
  const rows = visibleInventory.slice(invPage * PER_PAGE, (invPage + 1) * PER_PAGE);
  $("inventory-count").textContent =
    inventoryMode === "grouped"
      ? `${visibleInventory.length} unique package versions · ${filtered.length} installations`
      : `${visibleInventory.length} installations`;
  $("inv-location-head").textContent =
    inventoryMode === "grouped" ? "INSTALLATIONS" : "ENVIRONMENT";
  $("page-count").textContent = `${invPage + 1} / ${pages}`;
  $("inv-prev").disabled = invPage <= 0;
  $("inv-next").disabled = invPage >= pages - 1;
  $("inv-grouped").setAttribute("aria-pressed", String(inventoryMode === "grouped"));
  $("inv-individual").setAttribute("aria-pressed", String(inventoryMode === "individual"));
  $("inventory-body").innerHTML =
    rows
      .map(
        (p, i) =>
          html`<tr tabindex="0" data-row="${i}">
            <td>
            <span class="pkg-title">${esc(p.name)}</span>
            <div class="pkg-sub">${esc(p.ecosystem)}</div>
            </td>
            <td class="mono">${esc(p.version)}</td>
            <td>${esc(p.direct || "unknown")}</td>
            <td>${riskLabel(riskFor(p))}</td>
            <td title="${esc(p.env)}">${locationCell(p)}</td>
            <td class="chev">›</td>
            </tr>`,
      )
      .join("") ||
    '<tr><td colspan="6" class="empty">No packages match. Adjust filters or expand scan locations.</td></tr>';
}
function groupedPackageDetails(p) {
  if (!p.locations || p.locations.length === 1) {
    packageDetails(p.locations?.[0] || p);
    return;
  }
  const g = relevantGroup(p);
  const content = html`<h2 id="drawer-heading">${esc(p.name)} <span class="muted">${esc(p.version)}</span>
    </h2>
    <p class="muted">${esc(p.ecosystem)} · ${p.installation_count} installations · ${g?.advisory_count || 0} published advisories</p>
    <div class="drawer-section">
    <h3>Where it's installed</h3>
    <p>${TEXT.locationsHelp}</p>${p.locations
      .map(
        (x, i) => html`<div class="detail-row">
    <div>
    <strong>${esc(folderOf(x.env))}</strong>
    <div class="detail-path">${esc(x.env)}</div>
    </div>
    <button class="secondary-button" data-install="${i}">Inspect →</button>
    </div>`,
      )
      .join("")}</div>
    <div class="drawer-section">
    <p>Grouping counts reflect the current search and folder filters. LocDepIntel does not uninstall anything automatically.</p>
    </div>`;
  openDrawer("PACKAGE INSTALLATIONS", content);
  $("drawer-body")
    .querySelectorAll("[data-install]")
    .forEach((b) => (b.onclick = () => packageDetails(p.locations[Number(b.dataset.install)])));
}
function renderHistory() {
  const events = overview.history || [];
  $("history-body").innerHTML =
    events
      .map(
        (e) =>
          html`<div class="history-item">
            <div class="history-time">${esc(fmt(e.occurred))}</div>
            <div>
            <strong>${esc(e.kind)}</strong> · ${esc(e.name || "Inventory event")} ${esc(e.version || "")}<p>${esc(short(e.env, 100))}</p>
            <p>${esc(e.description || "")}</p>
            </div>
            </div>`,
      )
      .join("") || '<div class="empty">No recorded changes.</div>';
}
function registry(p) {
  return p.ecosystem === "PyPI"
    ? "https://pypi.org/project/" +
        encodeURIComponent(p.name) +
        "/" +
        encodeURIComponent(p.version) +
        "/"
    : p.ecosystem === "npm"
      ? "https://www.npmjs.com/package/" +
        encodeURIComponent(p.name) +
        "/v/" +
        encodeURIComponent(p.version)
      : null;
}
function openDrawer(heading, content) {
  $("drawer-eyebrow").textContent = heading;
  $("drawer-body").innerHTML = content;
  $("drawer").hidden = false;
  $("overlay").hidden = false;
  document.body.style.overflow = "hidden";
  $("drawer-close").focus();
}
function closeDrawer() {
  $("drawer").hidden = true;
  $("overlay").hidden = true;
  document.body.style.overflow = "";
}
function controlsForEnv(env, compact = false) {
  const id = encodeURIComponent(env);
  return html`<div class="detail-actions">
    <button class="secondary-button" data-reveal="${esc(id)}">Reveal folder</button>
    <button class="secondary-button" data-terminal="${esc(id)}">Open Terminal</button>
    <button class="quiet-button" data-copy="${esc(id)}">Copy path</button>
    </div>`;
}
function groupDetails(g) {
  const content = html`<h2 id="drawer-heading">${esc(g.name)} <span class="muted">${esc(g.version)}</span>
    </h2>
    <p class="muted">${esc(g.ecosystem)} · ${g.advisory_count} unique advisories · ${g.installation_count} installations</p>
    <div class="drawer-section">
    <h3>Source advisories</h3>${g.advisories
      .map(
        (a) => html`<div class="advisory">${riskLabel(a.kind)} &nbsp; <strong>${esc(a.id)}</strong>
    <p>${esc(a.summary || "No advisory summary supplied.")}</p>
    ${advisoryLink(a, "Original advisory")}</div>`,
      )
      .join("")}</div>
    <div class="drawer-section">
    <h3>Where it's installed</h3>
    <p>Select an environment to see review-only removal instructions and filesystem shortcuts.</p>${g.locations
      .map(
        (env, i) => html`<div class="detail-row">
    <div class="detail-path">${esc(env)}</div>
    <button class="quiet-button" data-open-location="${i}">Review →</button>
    </div>`,
      )
      .join("")}</div>
    <div class="drawer-section">
    <h3>Recommended next step</h3>
    <p>${g.kind === "malware" ? TEXT.malwareNextStep : TEXT.vulnerabilityNextStep}</p>
    <button class="secondary-button" data-open-location="0">Review first installation →</button>
    </div>`;
  openDrawer("GROUPED FINDING", content);
  $("drawer-body")
    .querySelectorAll("[data-open-location]")
    .forEach((btn) =>
      btn.addEventListener("click", () => {
        const env = g.locations[Number(btn.dataset.openLocation)];
        const p = inventory.find((x) => x.env === env && packageKey(x) === packageKey(g));
        if (p) packageDetails(p);
        else
          notice(
            "This package is not present in the currently active inventory; rescan before remediation.",
            true,
          );
      }),
    );
}
function envKind(path) {
  const env = (overview.environments || []).find((e) => e.path === path);
  return (env && env.ecosystem) || "";
}
function remedial(p) {
  const kind = envKind(p.env);
  const name = quote(p.name);
  const cd = `cd ${quote(p.env)}\n`;
  const transitive = p.direct === "transitive";
  if (p.ecosystem === "PyPI") {
    const msg = transitive
      ? "This may be transitive. Identify and update the parent dependency; do not uninstall it blindly."
      : "Review the advisory and dependencies before removing or upgrading this package. For malicious packages, use a trusted environment to investigate exposure first.";
    if (kind.includes("poetry.lock"))
      return {
        msg,
        command: `${cd}poetry show --why ${name}\n# After review, if appropriate:\npoetry remove ${name}`,
      };
    if (kind.includes("uv.lock"))
      return {
        msg,
        command: `${cd}uv tree --invert --package ${name}\n# After review, if appropriate:\nuv remove ${name}`,
      };
    if (kind.includes("Pipfile.lock"))
      return {
        msg,
        command: `${cd}pipenv graph --reverse | grep -i -A3 ${name}\n# After review, if appropriate:\npipenv uninstall ${name}`,
      };
    if (kind === "Python pipx")
      return {
        msg,
        command: `pipx list\n# This package lives in a pipx tool environment. Reinstall or uninstall the tool:\npipx uninstall <tool-name>`,
      };
    const isVenv = kind === "Python venv" || kind === "Python conda" || /venv$/.test(p.env);
    const exe = isVenv
      ? p.env + (navigator.platform.startsWith("Win") ? "\\Scripts\\python.exe" : "/bin/python")
      : "python3";
    return {
      msg,
      command: `${quote(exe)} -m pip show ${name}\n# After review, if appropriate:\n${quote(exe)} -m pip uninstall ${name}`,
    };
  }
  if (p.ecosystem === "npm") {
    const msg = transitive
      ? "A transitive package should be resolved by updating its parent dependency."
      : "Check the lockfile and dependency tree before removing a direct package.";
    if (kind === "npm global")
      return {
        msg,
        command: `npm ls -g ${name}\n# If this is a global tool you installed, after review:\nnpm uninstall -g ${name}`,
      };
    if (kind.includes("pnpm-lock.yaml"))
      return {
        msg,
        command: `${cd}pnpm why ${name}\n# If this is direct and removal is appropriate:\npnpm remove ${name}`,
      };
    if (kind.includes("yarn.lock"))
      return {
        msg,
        command: `${cd}yarn why ${name}\n# If this is direct and removal is appropriate:\nyarn remove ${name}`,
      };
    return {
      msg,
      command: `${cd}npm explain ${name}\n# If this is direct and removal is appropriate:\nnpm uninstall ${name}`,
    };
  }
  return {
    msg: "Consult your package manager and source advisory.",
    command: "# No safe command available for this ecosystem.",
  };
}
function packageDetails(p) {
  const g = relevantGroup(p),
    findings = (state.findings || []).filter(
      (x) =>
        x.env === p.env &&
        x.ecosystem === p.ecosystem &&
        x.name === p.name &&
        x.version === p.version,
    ),
    r = remedial(p),
    link = registry(p);
  const content = html`<h2 id="drawer-heading">${esc(p.name)}</h2>
    <p class="muted">${esc(p.ecosystem)} · ${esc(p.version)} · ${esc(p.direct || "unknown")} dependency</p>
    <p>${riskLabel(riskFor(p))}</p>
    <div class="drawer-section">
    <h3>Installed environment</h3>
    <div class="detail-path">${esc(p.env)}</div>${controlsForEnv(p.env)}
    <p>First observed: ${esc(fmt(p.discovered))}. Last seen: ${esc(fmt(p.seen))}. ${
      TEXT.firstObservedCaveat
    }</p>
    </div>
    <div class="drawer-section">
    <h3>Security evidence</h3>${securityEvidence(findings)}${
      g && g.installation_count > 1
        ? html`<p>Also found in ${g.installation_count - 1} other installation(s).</p>
    <button class="quiet-button" id="all-locations">See all locations →</button>`
        : ""
    }</div>
    <div class="drawer-section">
    <h3>Remediation guidance</h3>
    <div class="warnbox">
    <p>${esc(r.msg)}</p>
    </div>
    <div class="command" id="remedy">${esc(r.command)}</div>
    <div class="detail-actions">
    <button class="secondary-button" id="copy-command">Copy instructions</button>
    <button class="quiet-button" id="recheck-advisories">Recheck advisories</button>
    </div>
    <p>No installation, removal or update commands are run automatically. For malware, consider credentials and a trusted rebuild.</p>
    </div>
    <div class="drawer-section">
    <h3>Versions and research</h3>
    <p>Investigate current published versions; newer does not necessarily mean fixed or compatible.</p>
    <button class="secondary-button" id="version-lookup">Look up published versions</button>
    <div id="versions-result">
    </div>${
      link
        ? html`<p>
    <a href="${esc(link)}" target="_blank" rel="noopener noreferrer">Open package registry ↗</a>
    </p>`
        : ""
    }</div>`;
  openDrawer("PACKAGE ACTION PLAN", content);
  if ($("all-locations")) $("all-locations").onclick = () => groupDetails(g);
  $("copy-command").onclick = () =>
    navigator.clipboard
      .writeText(r.command)
      .then(() => notice("Review-only instructions copied."))
      .catch(() => notice("Clipboard unavailable; select the visible commands.", true));
  $("recheck-advisories").onclick = async () => {
    try {
      notice("Checking published advisories…");
      const res = await api("check", "POST");
      await reload();
      notice(
        res.state === "ok"
          ? "Security advisories refreshed."
          : "Advisory check failed: " + (res.error || res.state),
        res.state !== "ok",
      );
    } catch (err) {
      notice(err.message, true);
    }
  };
  $("version-lookup").onclick = async () => {
    const el = $("versions-result");
    el.textContent = "Looking up published versions…";
    try {
      const r = await api("package-intel", "POST", {
        ecosystem: p.ecosystem,
        name: p.name,
        env: p.env,
        version: p.version,
      });
      el.innerHTML =
        `<p>Registry default: <strong>${esc(r.default_version || "Unknown")}</strong>. Last retrieved ${esc(fmt(r.retrieved))}.</p>` +
        (r.recent_versions || [])
          .slice(0, 6)
          .map(
            (v) =>
              html`<div class="detail-row">
                <span class="mono">${esc(v.version)}</span>
                <span class="muted mini">${esc((v.published || "").slice(0, 10))}</span>
              </div>`,
          )
          .join("") +
        "<p>Check affected version ranges in the advisory before updating.</p>";
    } catch (err) {
      el.textContent = "Unable to get current version information: " + err.message;
    }
  };
}
async function reload() {
  const results = await Promise.all([
    api("overview"),
    api("state"),
    api("inventory"),
    api("grouped-findings"),
  ]);
  [overview, state, inventory, groups] = results;
  renderOverview();
  fillSelect("inv-eco", [...new Set(inventory.map((x) => x.ecosystem))].sort(), "All ecosystems");
  fillSelect("inv-env", [...new Set(inventory.map((x) => x.env))].sort(), "All environments");
  fillSelect(
    "inv-folder",
    [...new Set(inventory.map((x) => folderOf(x.env)))].sort(),
    "All locations",
  );
  $("roots").value = (overview.config?.roots || []).join("\n");
  $("include-global").checked = !!overview.config?.include_global;
  renderAction();
  renderInventory();
  renderHistory();
}
function focusEnvironment(path) {
  view("inventory");
  $("inv-env").value = path;
  $("inv-search").value = "";
  $("inv-risk").value = "";
  renderInventory(true);
}
function onRow(id, selector, getItem, fn) {
  $(id).addEventListener("click", (e) => {
    const row = e.target.closest(selector);
    if (!row) return;
    const item = getItem(
      Number(
        row.dataset[
          selector.includes("queue") ? "queue" : selector.includes("action") ? "action" : "row"
        ],
      ),
    );
    if (item) fn(item);
  });
  $(id).addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      const row = e.target.closest(selector);
      if (row) {
        e.preventDefault();
        row.click();
      }
    }
  });
}
onRow("queue-body", "[data-queue]", (i) => (overview.action_queue || [])[i], groupDetails);
onRow("action-body", "[data-action]", (i) => visibleActions[i], groupDetails);
onRow(
  "inventory-body",
  "[data-row]",
  (i) => visibleInventory[invPage * PER_PAGE + i],
  (p) => (inventoryMode === "grouped" ? groupedPackageDetails(p) : packageDetails(p)),
);
$("overview-envs").addEventListener("click", (e) => {
  const b = e.target.closest("[data-envi]");
  if (b) focusEnvironment(overview.environments[Number(b.dataset.envi)].path);
});
$("drawer").addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-reveal],[data-terminal],[data-copy]");
  if (!btn) return;
  const field = btn.hasAttribute("data-reveal")
      ? "reveal"
      : btn.hasAttribute("data-terminal")
        ? "terminal"
        : "copy",
    path = decodeURIComponent(btn.dataset[field]);
  try {
    if (field === "copy") {
      await navigator.clipboard.writeText(path);
      notice("Path copied.");
    } else {
      await api(field, "POST", { path });
      notice(
        field === "terminal"
          ? "Opened Terminal in the selected location; no commands executed."
          : "Requested opening the folder in your file manager.",
      );
    }
  } catch (err) {
    notice(err.message, true);
  }
});
$("drawer-close").onclick = closeDrawer;
$("overlay").onclick = closeDrawer;
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("drawer").hidden) closeDrawer();
});
document
  .querySelectorAll("[data-view]")
  .forEach((el) => (el.onclick = () => view(el.dataset.view)));
document
  .querySelectorAll("[data-goto]")
  .forEach((el) => (el.onclick = () => view(el.dataset.goto)));
document.querySelectorAll("[data-stat]").forEach(
  (el) =>
    (el.onclick = () => {
      const k = el.dataset.stat;
      if (k === "environments") {
        view("inventory");
        $("inv-env").focus();
      } else if (k === "affected") {
        view("action");
      } else {
        if (overview.stats?.new_advisory_matches === null) {
          view("history");
          notice(
            "New findings require at least two successful advisory checks to establish a comparison baseline.",
          );
        } else {
          view("action");
          $("action-new").checked = true;
          renderAction();
        }
      }
    }),
);
$("scan-details").onclick = () => {
  const scan = overview.scans?.[0],
    check = overview.checks?.[0];
  openDrawer(
    "SCAN DETAILS",
    html`<h2 id="drawer-heading">Last checks</h2>
      <div class="drawer-section">
      <h3>Discovery</h3>
      <p>${scan ? `${esc(scan.status)} · ${esc(fmt(scan.ended || scan.started))} · ${scan.packages} entries` : "No scan recorded."}</p>
      <p>${esc(scan?.error || "No discovery errors recorded.")}</p>
      </div>
      <div class="drawer-section">
      <h3>Security advisories</h3>
      <p>${checkSummary(check)}</p>
      <p>${esc(check?.note || "")}. No successful check means exposure status is unknown.</p>
      </div>`,
  );
};
for (const id of ["action-search", "action-kind", "action-new"])
  $(id).addEventListener(id.endsWith("search") ? "input" : "change", renderAction);
for (const id of ["inv-search", "inv-eco", "inv-folder", "inv-env", "inv-risk", "inv-sort"])
  $(id).addEventListener(id === "inv-search" ? "input" : "change", () => renderInventory(true));
$("inv-clear").onclick = () => {
  for (const id of ["inv-search", "inv-eco", "inv-folder", "inv-env", "inv-risk"]) $(id).value = "";
  renderInventory(true);
};
$("inv-grouped").onclick = () => {
  inventoryMode = "grouped";
  renderInventory(true);
};
$("inv-individual").onclick = () => {
  inventoryMode = "individual";
  renderInventory(true);
};
$("inv-prev").onclick = () => {
  invPage--;
  renderInventory();
};
$("inv-next").onclick = () => {
  invPage++;
  renderInventory();
};
$("settings-button").onclick = () => $("settings-dialog").showModal();
$("settings-close").onclick = () => $("settings-dialog").close();
$("settings-cancel").onclick = () => $("settings-dialog").close();
$("save-roots").onclick = async () => {
  try {
    const roots = $("roots")
      .value.split("\n")
      .map((x) => x.trim())
      .filter(Boolean);
    await api("roots", "POST", { roots, include_global: $("include-global").checked });
    $("settings-dialog").close();
    notice("Directories saved. Run Scan to refresh coverage.");
    await reload();
  } catch (err) {
    notice(err.message, true);
  }
};
async function scanRun() {
  const btn = $("scan");
  btn.disabled = true;
  $("scan-progress").hidden = false;
  $("scan-stage").textContent = "Starting…";
  try {
    await api("scan-full", "POST");
    await pollJob();
  } catch (err) {
    btn.disabled = false;
    $("scan-progress").hidden = true;
    notice("Scan could not start: " + err.message, true);
  }
}
async function pollJob() {
  // Sequential polling; no overlapping requests.
  let finished = false;
  while (!finished) {
    await new Promise((r) => setTimeout(r, 900));
    let job;
    try {
      job = await api("scan-status");
    } catch (err) {
      notice("Cannot check scan status: " + err.message, true);
      break;
    }
    $("scan-stage").textContent = job.stage || "Processing…";
    if (["complete", "partial", "error"].includes(job.state)) {
      finished = true;
      await reload();
      const err =
        job.error ||
        job.result?.security?.error ||
        (job.result?.discovery?.warnings || []).join(" ");
      notice(
        job.state === "complete"
          ? "Scan and security assessment completed."
          : `Scan ${job.state}: ${err || "Review scan details."}`,
        job.state !== "complete",
      );
    }
  }
  $("scan").disabled = false;
  $("scan-progress").hidden = true;
}
$("scan").onclick = scanRun;
$("theme-button").onclick = () => {
  const mode = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = mode;
  try {
    localStorage.setItem("locdepintel-theme", mode);
  } catch {}
  $("theme-button").textContent = mode === "dark" ? "Light mode" : "Dark mode";
};
let theme = "light";
try {
  theme = localStorage.getItem("locdepintel-theme") === "dark" ? "dark" : "light";
} catch {}
document.documentElement.dataset.theme = theme;
$("theme-button").textContent = theme === "dark" ? "Light mode" : "Dark mode";
function renderPulse() {
  const needle = $("pulse-search").value.toLowerCase(),
    kind = $("pulse-kind").value,
    eco = $("pulse-eco").value,
    local = $("pulse-local").value;
  const records = pulse.advisories || [];
  visiblePulse = records.filter(
    (a) =>
      (!kind || a.kind === kind) &&
      (!eco || a.affected.some((x) => x.ecosystem === eco)) &&
      (!local || a.local_status === local) &&
      (!needle ||
        (a.summary + " " + a.id + " " + a.affected.map((x) => x.name).join(" "))
          .toLowerCase()
          .includes(needle)),
  );
  $("pulse-count").textContent = `${visiblePulse.length} of ${records.length} cached advisories`;
  $("pulse-list").innerHTML =
    visiblePulse
      .map(
        (a, i) =>
          html`<article class="pulseentry">
            <div class="pulsemeta">
            <span>${riskLabel(a.kind)}</span>
            <span>${esc((a.published || "").slice(0, 10))}</span>
            <span>${esc(a.severity)}</span>
            <span>${LOCAL_STATUS[a.local_status] || LOCAL_STATUS["not-detected"]}</span>
            </div>
            <h3>${esc(a.summary)}</h3>
            <p class="pkg-sub">${esc(
              a.affected
                .slice(0, 5)
                .map((x) => x.ecosystem + " / " + x.name)
                .join(" · "),
            )}</p>
            <div class="pulse-actions">
            <a href="${esc(url(a.url) || "#")}" target="_blank" rel="noopener noreferrer">Original source ↗</a>
            <button data-pulse="${i}">Check inventory →</button>
            <span class="muted mono">${esc(a.id)}</span>
            </div>
            </article>`,
      )
      .join("") ||
    '<p class="empty">No matching disclosures. Refresh sources or change filters.</p>';
}
async function loadPulse() {
  try {
    pulse = await api("pulse");
    const last = pulse.last_sync;
    $("pulse-status").textContent = last
      ? `Last source refresh: ${fmt(last.timestamp)} · ${last.state} · ${last.count} fetched${last.note ? " · " + last.note : ""}`
      : "No disclosures fetched yet. Use Refresh sources.";
    renderPulse();
  } catch (err) {
    $("pulse-status").textContent = "Threat feed unavailable: " + err.message;
  }
}
$("pulse-refresh").onclick = async () => {
  const btn = $("pulse-refresh");
  btn.disabled = true;
  $("pulse-status").textContent = "Fetching currently published advisories…";
  try {
    const r = await api("pulse-sync", "POST");
    await loadPulse();
    notice(
      r.state === "ok"
        ? `Refreshed ${r.fetched} public advisories.`
        : `Source refresh ${r.state}: ${(r.errors || []).join("; ")}`,
      r.state !== "ok",
    );
  } catch (err) {
    notice(err.message, true);
  } finally {
    btn.disabled = false;
  }
};
for (const id of ["pulse-search", "pulse-kind", "pulse-eco", "pulse-local"])
  $(id).addEventListener(id === "pulse-search" ? "input" : "change", renderPulse);
$("pulse-list").addEventListener("click", (e) => {
  const btn = e.target.closest("[data-pulse]");
  if (!btn) return;
  const a = visiblePulse[Number(btn.dataset.pulse)];
  if (!a) return;
  const installed = inventory.find((p) =>
    a.affected.some(
      (x) => x.ecosystem === p.ecosystem && x.name.toLowerCase() === p.name.toLowerCase(),
    ),
  );
  if (!installed) {
    notice("No matching package name in covered environments. This does not establish safety.");
    return;
  }
  view("inventory");
  $("inv-search").value = installed.name;
  $("inv-eco").value = installed.ecosystem;
  $("inv-env").value = "";
  $("inv-risk").value = "";
  renderInventory(true);
  notice("Showing package-name matches. Exact affected versions require the OSV advisory check.");
});
async function firstLaunch() {
  try {
    const setup = await api("onboarding");
    if (setup.complete) return;
    const roots = setup.suggested_roots.filter((x) => x.exists);
    $("welcome-roots").innerHTML =
      roots
        .map(
          (x, i) =>
            html`<label class="welcome-root">
              <input type="checkbox" data-welcome-root="${i}" ${x.default ? "checked" : ""}>
              <span>
              <strong>${esc(x.name)}</strong>
              <small>${esc(x.path)}</small>
              </span>
              </label>`,
        )
        .join("") ||
      "<p>No common project folders found. Open Settings to enter custom locations.</p>";
    $("welcome-dialog").showModal();
    $("welcome-start").onclick = async () => {
      const chosen = [...$("welcome-roots").querySelectorAll("input:checked")].map(
        (el) => roots[Number(el.dataset.welcomeRoot)].path,
      );
      if (!chosen.length) {
        notice("Select at least one available location, or skip for now.", true);
        return;
      }
      try {
        await api("onboarding", "POST", { roots: chosen, skip: false });
        $("welcome-dialog").close();
        await reload();
        view("overview");
        await scanRun();
      } catch (err) {
        notice("Setup failed: " + err.message, true);
      }
    };
    $("welcome-skip").onclick = async () => {
      try {
        await api("onboarding", "POST", { skip: true });
        $("welcome-dialog").close();
        notice("You can start discovery anytime with Scan machine or Settings.");
      } catch (err) {
        notice(err.message, true);
      }
    };
  } catch (err) {
    notice("Unable to load first-run setup: " + err.message, true);
  }
}
reload()
  .then(async () => {
    await loadPulse();
    await firstLaunch();
  })
  .catch((err) => notice("Could not load local data: " + err.message, true));

// Dashboard for the threat intelligence platform. Plain JavaScript, no build step.
// Every value from the API passes through esc() before it reaches innerHTML.

const TYPES = ["ipv4", "ipv6", "cidr", "domain", "url", "email", "md5", "sha1", "sha256"];

const RELATION_NAMES = {
  resolves_to: "resolves to",
  hosted_on: "hosted on",
  subdomain_of: "subdomain of",
  in_range: "in range",
  email_domain: "email domain",
  downloaded_from: "downloaded from",
  co_reported: "reported together",
  related_to: "reported alongside",
};

const RELATION_COLOR = {
  resolves_to: "#2b4c6f",
  hosted_on: "#1d6b63",
  subdomain_of: "#5b6b77",
  in_range: "#b46a00",
  email_domain: "#6b4e9b",
  downloaded_from: "#b42318",
  co_reported: "#15202b",
  related_to: "#8a97a1",
};

const SEVERITY_COLOR = { critical: "#b42318", high: "#c2410c", medium: "#b46a00", low: "#1d6b63" };

const state = { type: "", q: "", min: 0 };

const $ = (selector) => document.querySelector(selector);
const pct = (value) => `${Math.round(value * 100)}%`;
const esc = (value) =>
  String(value).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);

async function api(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

function showError(error) {
  $("#status").textContent = `Error: ${error.message}`;
}

function renderFigures(stats) {
  const cells = [
    ["Indicators", stats.indicators],
    ["Sightings", stats.sightings],
    ["Clusters", stats.clusters],
    ["Shared infrastructure", stats.shared_infrastructure],
  ];
  $("#figures").innerHTML = cells
    .map(([label, value]) => `<figure><strong>${esc(value)}</strong><span>${esc(label)}</span></figure>`)
    .join("");
}

function rowHtml(item) {
  return `<tr tabindex="0" data-type="${esc(item.type)}" data-value="${esc(item.value)}">
    <td class="mono">${esc(item.value)}</td>
    <td>${esc(item.type)}</td>
    <td><span class="bar"><i style="width:${pct(item.score)}"></i></span>${pct(item.score)}</td>
    <td>${esc(item.sources)}</td>
    <td><span class="sev sev-${esc(item.severity)}">${esc(item.severity)}</span></td>
  </tr>`;
}

async function loadRows() {
  const params = new URLSearchParams({ limit: "200", min_score: (state.min / 100).toFixed(2) });
  if (state.type) params.set("type", state.type);
  if (state.q) params.set("q", state.q);
  const rows = await api(`/api/iocs?${params}`);
  $("#rows").innerHTML = rows.length
    ? rows.map(rowHtml).join("")
    : `<tr><td colspan="5" class="empty">No indicators match these filters.</td></tr>`;
  $("#count").textContent = `${rows.length} shown, highest triage first`;
}

function legendHtml() {
  return Object.entries(RELATION_NAMES)
    .map(([relation, label]) =>
      `<span><i style="background:${RELATION_COLOR[relation]}"></i>${esc(label)}</span>`)
    .join("");
}

function graphSvg(data) {
  const width = 700;
  const height = 580;
  const cx = width / 2;
  const cy = height / 2;
  const ring = { 1: 140, 2: 230 };
  const positions = new Map();
  positions.set(data.root.id, { x: cx, y: cy, angle: 0 });

  for (const hop of [1, 2]) {
    const members = data.nodes.filter((n) => n.hop === hop);
    members.forEach((node, index) => {
      const offset = hop === 2 ? Math.PI / Math.max(members.length, 1) : 0;
      const angle = (2 * Math.PI * index) / Math.max(members.length, 1) - Math.PI / 2 + offset;
      positions.set(node.id, {
        x: cx + ring[hop] * Math.cos(angle),
        y: cy + ring[hop] * Math.sin(angle),
        angle,
      });
    });
  }

  const lines = data.edges
    .map((edge) => {
      const a = positions.get(edge.from);
      const b = positions.get(edge.to);
      if (!a || !b) return "";
      const suggestion = edge.origin === "cooccurrence";
      const dash = suggestion ? ' stroke-dasharray="4 4"' : "";
      const opacity = suggestion ? 0.4 : 0.85;
      const color = RELATION_COLOR[edge.relation] || "#8a97a1";
      return `<line x1="${a.x.toFixed(1)}" y1="${a.y.toFixed(1)}" x2="${b.x.toFixed(1)}" y2="${b.y.toFixed(1)}" stroke="${color}" stroke-width="1.6" stroke-opacity="${opacity}"${dash}/>`;
    })
    .join("");

  const nodes = data.nodes
    .map((node) => {
      const p = positions.get(node.id);
      if (!p) return "";
      const radius = node.hop === 0 ? 14 : 6 + 6 * node.score;
      const cos = Math.cos(p.angle);
      const sin = Math.sin(p.angle);
      const lx = p.x + cos * (radius + 12);
      const ly = p.y + sin * (radius + 12) + 4;
      const anchor = cos > 0.3 ? "start" : cos < -0.3 ? "end" : "middle";
      const label = node.value.length > 16 ? `${node.value.slice(0, 15)}…` : node.value;
      return `<g class="node" tabindex="0" role="button" data-type="${esc(node.type)}" data-value="${esc(node.value)}" aria-label="${esc(node.type)} ${esc(node.value)}, triage ${pct(node.score)}">
        <circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${radius.toFixed(1)}" fill="${SEVERITY_COLOR[node.severity]}" stroke="#f8fafb" stroke-width="2.5"/>
        <text x="${lx.toFixed(1)}" y="${ly.toFixed(1)}" text-anchor="${anchor}">${esc(label)}</text>
      </g>`;
    })
    .join("");

  return `<svg class="graph" viewBox="0 0 ${width} ${height}" role="img" aria-label="Correlation graph around the selected indicator">${lines}${nodes}</svg>`;
}

function relationsHtml(data) {
  const names = new Map(data.nodes.map((n) => [n.id, n.value]));
  const rows = data.edges
    .filter((e) => e.from === data.root.id || e.to === data.root.id)
    .sort((a, b) => (a.origin === "cooccurrence") - (b.origin === "cooccurrence"));
  if (!rows.length) return `<li class="empty">No direct links.</li>`;
  return rows
    .map((edge) => {
      const other = edge.from === data.root.id ? edge.to : edge.from;
      const origin = edge.origin === "structural"
        ? "structural fact"
        : edge.origin === "feed" ? `feed ${edge.source_name}` : "suggestion, not evidence";
      const label = RELATION_NAMES[edge.relation] || edge.relation;
      return `<li><span class="mono">${esc(names.get(other) ?? other)}</span><span>${esc(label)}, ${esc(origin)}</span></li>`;
    })
    .join("");
}

function renderDossier(data) {
  const root = data.root;
  const tags = root.tags.map((t) => `<span class="chip">${esc(t)}</span>`).join("");
  const campaigns = root.campaigns
    .map((c) => `<span class="chip">${esc(c.replace(/^report:/, "report "))}</span>`)
    .join("");
  $("#dossier").innerHTML = `
    <h2>${esc(root.type)} indicator</h2>
    <p class="dossier-value">${esc(root.value)}</p>
    <div class="meta">
      <span class="sev sev-${esc(root.severity)}">${esc(root.severity)}</span>
      <span>Triage ${pct(root.score)}</span>
      <span>${esc(root.sources)} source${root.sources === 1 ? "" : "s"}</span>
    </div>
    <div class="meta">${tags}${campaigns}</div>
    ${graphSvg(data)}
    <div class="legend">${legendHtml()}</div>
    <ul class="relations">${relationsHtml(data)}</ul>`;
}

async function investigate(type, value) {
  const params = new URLSearchParams({ type, value, depth: "2" });
  const data = await api(`/api/correlate?${params}`);
  renderDossier(data);
  document.querySelectorAll("#rows tr[data-value]").forEach((row) => {
    row.classList.toggle("active", row.dataset.value === value && row.dataset.type === type);
  });
}

function clusterHtml(cluster, index) {
  const members = cluster.members
    .slice(0, 4)
    .map((m) => `<button class="member" data-type="${esc(m.type)}" data-value="${esc(m.value)}">${esc(m.value)}</button>`)
    .join("");
  const relations = Object.entries(cluster.relations)
    .map(([relation, count]) => `${RELATION_NAMES[relation] || relation} ${count}`)
    .join(", ");
  const campaigns = cluster.campaigns.length ? cluster.campaigns.map(esc).join(", ") : "none";
  const reports = cluster.reports.length ? `<p class="small">Reports: ${cluster.reports.map(esc).join(", ")}</p>` : "";
  return `<article class="cluster">
    <h3>Cluster ${index + 1}</h3>
    <p class="small">${esc(cluster.size)} indicators, top triage ${pct(cluster.max_score)}</p>
    <p class="small">Campaigns: ${campaigns}</p>
    ${reports}
    <p class="small">${esc(relations)}</p>
    ${members}
  </article>`;
}

function sharedHtml(item) {
  return `<li>
    <button class="member" data-type="${esc(item.type)}" data-value="${esc(item.value)}">${esc(item.value)}</button>
    <span class="small">${esc(item.reasons.join("; "))}</span>
  </li>`;
}

async function loadClusters() {
  const data = await api("/api/clusters?limit=6");
  $("#clusters").innerHTML = data.clusters.length
    ? data.clusters.map(clusterHtml).join("")
    : `<p class="empty">No corroborated clusters at the current threshold.</p>`;
  $("#shared").innerHTML = data.shared_infrastructure.length
    ? data.shared_infrastructure.map(sharedHtml).join("")
    : `<li class="empty">None.</li>`;
}

function setupFilters() {
  $("#type").innerHTML = `<option value="">All types</option>` +
    TYPES.map((t) => `<option value="${t}">${t}</option>`).join("");

  let timer;
  $("#q").addEventListener("input", (event) => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      state.q = event.target.value.trim();
      loadRows().catch(showError);
    }, 250);
  });
  $("#type").addEventListener("change", (event) => {
    state.type = event.target.value;
    loadRows().catch(showError);
  });
  $("#min").addEventListener("input", (event) => {
    state.min = Number(event.target.value);
    $("#minOut").textContent = `${state.min}%`;
    loadRows().catch(showError);
  });
}

function openFromEvent(event) {
  const target = event.target.closest("[data-value][data-type]");
  if (target) investigate(target.dataset.type, target.dataset.value).catch(showError);
}

document.addEventListener("click", openFromEvent);
document.addEventListener("keydown", (event) => {
  if (event.key === "Enter") openFromEvent(event);
});

async function boot() {
  setupFilters();
  try {
    const [health, stats] = await Promise.all([api("/api/health"), api("/api/stats")]);
    $("#status").textContent = `API ${health.version}, ${stats.feeds} feeds configured`;
    renderFigures(stats);
    await Promise.all([loadRows(), loadClusters()]);
    const first = document.querySelector("#rows tr[data-value]");
    if (first) await investigate(first.dataset.type, first.dataset.value);
  } catch (error) {
    showError(error);
  }
}

boot();

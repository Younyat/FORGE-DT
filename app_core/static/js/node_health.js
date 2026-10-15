const NH = {
  graphHost: document.getElementById("nh-graph"),
  statusPill: document.getElementById("nh-status-pill"),
  lastUpdate: document.getElementById("nh-last-update"),
  identity: document.getElementById("nh-node-identity"),
  cpuCard: document.getElementById("nh-cpu-card"),
  memoryCard: document.getElementById("nh-memory-card"),
  diskCard: document.getElementById("nh-disk-card"),
  services: document.getElementById("nh-services"),
  timeSyncCard: document.getElementById("nh-time-sync-card"),
  openstackHealthCard: document.getElementById("nh-openstack-health-card"),
  healthAlerts: document.getElementById("nh-health-alerts"),
  fleetTable: document.getElementById("nh-fleet-table"),
  fleetMeta: document.getElementById("nh-fleet-meta"),
  floatingIpStatus: document.getElementById("nh-floating-ip-status"),
  floatingIpJob: document.getElementById("nh-floating-ip-job"),
  floatingIpHistory: document.getElementById("nh-floating-ip-history"),
  btnCleanupFloatingIps: document.getElementById("nh-cleanup-floating-ips"),
  securityMeta: document.getElementById("nh-security-meta"),
  securitySummary: document.getElementById("nh-security-summary"),
  securityDetail: document.getElementById("nh-security-detail"),
  securityRules: document.getElementById("nh-security-rules"),
  storageTable: document.getElementById("nh-storage-table"),
  topCpu: document.getElementById("nh-top-cpu"),
  topMem: document.getElementById("nh-top-mem"),
  console: document.getElementById("nh-console"),
  btnRefreshNodes: document.getElementById("nh-refresh-nodes"),
  btnRefreshHealth: document.getElementById("nh-refresh-health"),
  btnRefreshSelected: document.getElementById("nh-refresh-selected"),
  btnMeasureClock: document.getElementById("nh-measure-clock"),
  btnFixTimeSync: document.getElementById("nh-fix-time-sync"),
  btnCleanupSelected: document.getElementById("nh-cleanup-selected"),
  btnPowerOnStopped: document.getElementById("nh-power-on-stopped"),
  btnRestartOpenstack: document.getElementById("nh-restart-openstack"),
  btnFreeHostMemory: document.getElementById("nh-free-host-memory"),
  btnRefreshMemoryPressure: document.getElementById("nh-refresh-memory-pressure"),
  memoryPressureCard: document.getElementById("nh-memory-pressure-card"),
  memoryPressureEvents: document.getElementById("nh-memory-pressure-events"),
  btnOpenHealthAlertCenter: document.getElementById("nh-open-health-alert-center"),
  btnClearConsole: document.getElementById("nh-clear-console"),
};

const STATE = {
  nodes: [],
  nodeMap: new Map(),
  selectedId: null,
  selectedToolId: null,
  toolingPayload: null,
  cy: null,
  cleanupSource: null,
  restartSource: null,
  timeSyncStatus: null,
  timeSyncPollTimer: null,
  healthSummary: null,
  floatingIpPollTimer: null,
};

function now() {
  return new Date().toLocaleTimeString();
}

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function consoleWrite(line) {
  NH.console.textContent += `[${now()}] ${line}\n`;
  NH.console.scrollTop = NH.console.scrollHeight;
}

function setStatus(label, tone = "idle") {
  const klass = tone === "ok"
    ? "border-emerald-500/40 text-emerald-300"
    : tone === "warn"
    ? "border-amber-500/40 text-amber-300"
    : tone === "error"
    ? "border-red-500/40 text-red-300"
    : "border-slate-700 text-slate-300";
  NH.statusPill.className = `rounded-full border px-3 py-1 text-xs font-black uppercase tracking-[0.2em] ${klass}`;
  NH.statusPill.textContent = label;
}

function severityBadge(sev) {
  const cls = sev === "critical"
    ? "text-red-300 border-red-500/40 bg-red-500/10"
    : sev === "warning"
    ? "text-amber-300 border-amber-500/40 bg-amber-500/10"
    : sev === "ok"
    ? "text-emerald-300 border-emerald-500/40 bg-emerald-500/10"
    : "text-slate-300 border-slate-700 bg-slate-800/50";
  return `<span class="inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-black uppercase tracking-[0.2em] ${cls}">${esc(sev || "unknown")}</span>`;
}

function severityRank(sev) {
  const value = String(sev || "unknown").toLowerCase();
  if (value === "critical") return 3;
  if (value === "warning") return 2;
  if (value === "ok") return 1;
  return 0;
}

function healthStateTone(state) {
  const value = String(state || "unknown").toLowerCase();
  if (["completed", "ok", "healthy"].includes(value)) return "ok";
  if (["partial", "warning", "degraded", "stale_fallback"].includes(value)) return "warn";
  if (["failed", "critical", "down", "unavailable"].includes(value)) return "error";
  return "idle";
}

function timeSyncTone(syncStatus) {
  const value = String(syncStatus || "not_measured").toLowerCase();
  if (value === "synchronized") return "ok";
  if (value === "degraded" || value === "not_measured" || value === "running") return "warning";
  if (value === "not_synchronized" || value === "failed") return "critical";
  return "unknown";
}

function toolCategoryBadge(category) {
  const normalized = String(category || "other").toLowerCase();
  const cls = normalized === "ids"
    ? "text-red-300 border-red-500/40 bg-red-500/10"
    : normalized === "siem"
    ? "text-sky-300 border-sky-500/40 bg-sky-500/10"
    : normalized === "agent"
    ? "text-emerald-300 border-emerald-500/40 bg-emerald-500/10"
    : normalized === "fim"
    ? "text-lime-300 border-lime-500/40 bg-lime-500/10"
    : normalized === "integration"
    ? "text-violet-300 border-violet-500/40 bg-violet-500/10"
    : normalized === "rule_pack"
    ? "text-amber-300 border-amber-500/40 bg-amber-500/10"
    : "text-slate-300 border-slate-700 bg-slate-800/50";
  return `<span class="inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-black uppercase tracking-[0.2em] ${cls}">${esc(normalized)}</span>`;
}

function bytesHuman(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return "not_available";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = n;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(value >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}

function normalizeToolStatus(status) {
  const value = String(status || "unknown").toLowerCase();
  if (value === "active" || value === "installed") return "ok";
  if (value === "inactive" || value === "failed") return "warning";
  if (value === "not_installed" || value === "unknown") return "unknown";
  return "unknown";
}

function categoryLabel(category) {
  const map = {
    ids: "IDS",
    siem: "SIEM",
    agent: "Agents",
    fim: "FIM",
    integration: "Integrations",
    rule_pack: "Rule Packs",
    orchestrator: "Orchestrators",
    other: "Other Tools",
  };
  return map[category] || category;
}

function presenceLabel(tool) {
  if (tool.runtime_presence === "installed") return "installed_on_node";
  if (tool.runtime_presence === "not_installed") return "not_present_on_node";
  if (tool.inventory_status === "installed") return "installed_in_inventory";
  return "unknown";
}

function effectiveRuntimePresence(tool) {
  if (tool.runtime_presence === "installed") return "installed_on_node";
  if (tool.inventory_status === "installed") return "runtime_not_confirmed";
  if (tool.runtime_presence === "not_installed") return "not_present_on_node";
  return "unknown";
}

function effectiveRuntimeState(tool) {
  return tool.runtime_presence === "installed"
    ? (tool.runtime_status || "unknown")
    : "runtime_not_confirmed";
}

function effectiveRuntimeVersion(tool) {
  return tool.runtime_presence === "installed"
    ? (tool.runtime_version || "not_available")
    : "not_runtime_confirmed";
}

function effectiveToolSeverity(tool) {
  return tool.runtime_presence === "installed"
    ? normalizeToolStatus(tool.runtime_status || "unknown")
    : "unknown";
}

function isPrimaryTool(tool) {
  const id = tool?.id || "";
  if (!id) return false;
  if (id.startsWith("rollback_")) return false;
  if (id === "wazuh_fim_realtime") return false;
  return true;
}

function capabilitiesForTool(tool, allTools) {
  const id = tool?.id || "";
  if (!id) return [];
  return (allTools || []).filter(candidate => {
    const cid = candidate.id || "";
    if (!cid) return false;
    if (id === "suricata") {
      return cid.startsWith("rollback_suricata_");
    }
    if (id === "wazuh" || id === "wazuh_agent") {
      return cid === "wazuh_fim_realtime" || cid === "rollback_wazuh_suricata_integration";
    }
    return false;
  });
}

function linesToHtml(lines, emptyText = "No data.") {
  return (lines || []).length
    ? (lines || []).map(line => `<div>${esc(line)}</div>`).join("")
    : `<div class="text-slate-500">${esc(emptyText)}</div>`;
}

function signaturesForTool(toolId, runtime) {
  const all = runtime?.suricata?.custom_signatures || [];
  if (toolId === "rollback_suricata_ping_detection") {
    return all.filter(line => line.includes("nics-ping.rules"));
  }
  if (toolId === "rollback_suricata_modbus_register_detection") {
    return all.filter(line => line.includes("nics-modbus-register-manipulation.rules"));
  }
  return all;
}

function ruleInventoryForTool(toolId, runtime) {
  const suricataFiles = runtime?.suricata?.rule_inventory || [];
  const wazuhFiles = runtime?.wazuh?.rule_inventory || [];
  if (toolId === "suricata" || toolId.startsWith("rollback_suricata_")) {
    return suricataFiles;
  }
  if (toolId.startsWith("wazuh")) {
    return wazuhFiles;
  }
  return [];
}

function renderNodeServices(_probe, toolingPayload = null) {
  const tools = ((toolingPayload?.inventory?.tools || []).filter(isPrimaryTool)).filter(tool => {
    return tool.inventory_status === "installed";
  });

  NH.services.innerHTML = tools.map(tool => {
    return `<div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2"><div class="text-[10px] uppercase tracking-[0.2em] text-slate-500 font-black">${esc(tool.display_name)}</div><div class="mt-1">${severityBadge(effectiveToolSeverity(tool))} <span class="ml-2">${esc(effectiveRuntimeState(tool))}</span></div><div class="mt-2 text-[11px] text-slate-400">inventory=installed node=${esc(effectiveRuntimePresence(tool))}</div></div>`;
  }).join("") || '<div class="text-slate-500">No installed tools reported on this node.</div>';
}

async function requestJson(url, options, label) {
  const res = await fetch(url, options);
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch {}
  if (!res.ok) {
    throw new Error(data?.error || text || `${label} failed (${res.status})`);
  }
  return data;
}

async function fetchJson(url, label) {
  return requestJson(url, undefined, label);
}

function graphColorForRole(role) {
  switch ((role || "").toLowerCase()) {
    case "attacker": return "#ef4444";
    case "victim": return "#38bdf8";
    case "monitor": return "#22c55e";
    case "plc": return "#f59e0b";
    case "scada": return "#a855f7";
    default: return "#64748b";
  }
}

function renderScenarioOverview(summary, nodes) {
  const host = summary?.host || {};
  const scenario = summary?.scenario || {};
  const roleCounts = Object.entries(scenario.role_counts || {}).map(([role, count]) => `<div>${esc(role)}: <span class="font-bold">${esc(count)}</span></div>`).join("") || "<div>not_available</div>";
  const statusCounts = Object.entries(scenario.status_counts || {}).map(([status, count]) => `<div>${esc(status)}: <span class="font-bold">${esc(count)}</span></div>`).join("") || "<div>not_available</div>";

  NH.lastUpdate.textContent = host.date_utc || "Overview mode";
  NH.identity.innerHTML = `
    <div><strong>Scenario nodes:</strong> ${esc(scenario.node_count ?? nodes.length ?? 0)}</div>
    <div><strong>Networks:</strong> ${esc(scenario.network_count ?? "not_available")}</div>
    <div><strong>Host:</strong> ${esc(host.hostname || "not_available")}</div>
    <div><strong>Host loadavg:</strong> ${esc(host.loadavg || "not_available")}</div>
    <div class="pt-2"><strong>Roles</strong></div>
    <div class="space-y-1">${roleCounts}</div>
    <div class="pt-2"><strong>Node status distribution</strong></div>
    <div class="space-y-1">${statusCounts}</div>
  `;

  NH.cpuCard.innerHTML = `
    <div>OpenStack nodes: <span class="font-bold">${esc(scenario.node_count ?? nodes.length ?? 0)}</span></div>
    <div class="mt-2">Host loadavg: <span class="font-bold">${esc(host.loadavg || "not_available")}</span></div>
  `;

  NH.memoryCard.innerHTML = `
    <div>Total: <span class="font-bold">${esc(host.mem_total_mb ?? "not_available")} MB</span></div>
    <div class="mt-2">Used: <span class="font-bold">${esc(host.mem_used_mb ?? "not_available")} MB</span></div>
    <div class="mt-1">Available: <span class="font-bold">${esc(host.mem_avail_mb ?? "not_available")} MB</span></div>
    <div class="mt-1">Swap: <span class="font-bold">${esc(host.swap_used_mb ?? "not_available")} / ${esc(host.swap_total_mb ?? "not_available")} MB</span></div>
  `;

  NH.diskCard.innerHTML = `
    <div>Used: <span class="font-bold">${bytesHuman(host.root_used_bytes)}</span></div>
    <div class="mt-2">Free: <span class="font-bold">${bytesHuman(host.root_avail_bytes)}</span></div>
    <div class="mt-1">Use: <span class="font-bold">${esc(host.root_use_pct || "not_available")}</span></div>
  `;

  NH.services.innerHTML = `
    <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2"><div class="text-[10px] uppercase tracking-[0.2em] text-slate-500 font-black">Nodes</div><div class="mt-1 text-slate-200">${esc(scenario.node_count ?? nodes.length ?? 0)}</div></div>
    <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2"><div class="text-[10px] uppercase tracking-[0.2em] text-slate-500 font-black">Networks</div><div class="mt-1 text-slate-200">${esc(scenario.network_count ?? "not_available")}</div></div>
    <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2"><div class="text-[10px] uppercase tracking-[0.2em] text-slate-500 font-black">Host Disk Free</div><div class="mt-1 text-slate-200">${bytesHuman(host.root_avail_bytes)}</div></div>
    <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2"><div class="text-[10px] uppercase tracking-[0.2em] text-slate-500 font-black">Host RAM Free</div><div class="mt-1 text-slate-200">${esc(host.mem_avail_mb ?? "not_available")} MB</div></div>
  `;

  NH.storageTable.innerHTML = `
    <div class="grid grid-cols-2 gap-3">
      <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">Host root used: <span class="font-bold">${bytesHuman(host.root_used_bytes)}</span></div>
      <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">Host root free: <span class="font-bold">${bytesHuman(host.root_avail_bytes)}</span></div>
      <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">Host RAM used: <span class="font-bold">${esc(host.mem_used_mb ?? "not_available")} MB</span></div>
      <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">Host RAM free: <span class="font-bold">${esc(host.mem_avail_mb ?? "not_available")} MB</span></div>
    </div>
    <div class="mt-4 rounded-lg border border-slate-800 bg-slate-950 p-3">
      <div class="text-[10px] uppercase tracking-[0.2em] text-slate-500 font-black">Scenario Summary</div>
      <pre class="mt-2 whitespace-pre-wrap text-xs text-slate-300">${esc(JSON.stringify(scenario, null, 2))}</pre>
    </div>
  `;

  NH.topCpu.textContent = "Select a node to inspect live top CPU processes.";
  NH.topMem.textContent = "Select a node to inspect live top memory processes.";
  NH.securityMeta.textContent = "Waiting for node selection";
  NH.securitySummary.innerHTML = `<div class="rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-sm text-slate-300">Select a node first. Tool inventory and rule files are only queried after node selection.</div>`;
  NH.securityDetail.innerHTML = `<div class="rounded-xl border border-slate-800 bg-slate-950/70 p-4">No tool detail is loaded until a node and then a tool are selected.</div>`;
  NH.securityRules.innerHTML = "";
  NH.timeSyncCard.innerHTML = `<div class="text-slate-500">Select a node to inspect time synchronization state, max clock offset and correction history.</div>`;
}

function renderOpenstackHealth(summary) {
  const openstack = summary?.openstack || {};
  const alerts = summary?.alerts || [];
  NH.openstackHealthCard.innerHTML = `
    <div class="flex items-center justify-between gap-3">
      <div class="text-xs uppercase tracking-[0.25em] text-slate-500 font-black">OpenStack Service Health</div>
      ${severityBadge(openstack.state === "completed" ? "ok" : "critical")}
    </div>
    <div class="mt-3 text-sm text-white font-bold">${esc(openstack.status_label || "OpenStack status unavailable")}</div>
    <div class="mt-2 text-xs text-slate-300">${esc(openstack.message || "No OpenStack health message available.")}</div>
    ${openstack.error ? `<div class="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-200">${esc(openstack.error)}</div>` : ""}
    ${openstack.recommendation ? `<div class="mt-3 rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-xs text-slate-300"><strong>Recommended action:</strong> ${esc(openstack.recommendation)}</div>` : ""}
    <div class="mt-3 text-xs text-slate-500">Instances visible: ${esc(openstack.instance_count ?? "not_available")} | Health alerts: ${esc(alerts.length)}</div>
  `;
}

function renderHealthAlerts(summary) {
  const alerts = summary?.alerts || [];
  const critical = alerts.filter(alert => String(alert.severity || "").toLowerCase() === "critical").length;
  const warning = alerts.filter(alert => String(alert.severity || "").toLowerCase() === "warning").length;
  if (!alerts.length) {
    NH.healthAlerts.innerHTML = `
      <div class="rounded-xl border border-emerald-500/20 bg-emerald-500/5 px-4 py-4 text-sm text-emerald-200">
        No active OpenStack, host or node health alerts are currently raised.
      </div>
    `;
    return;
  }
  const topTitles = alerts.slice(0, 3).map(alert => `
    <div class="rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-3 text-sm text-slate-300">
      <div class="flex items-center justify-between gap-3">
        <div class="font-bold text-white">${esc(alert.title || "Health alert")}</div>
        ${severityBadge(alert.severity)}
      </div>
      <div class="mt-2 text-xs text-slate-400">${esc(alert.scope || "health")} · ${esc(alert.target || "platform")} · ${esc(alert.generated_at || "--")}</div>
    </div>
  `).join("");
  NH.healthAlerts.innerHTML = `
    <div class="grid grid-cols-1 gap-3 lg:grid-cols-3">
      <div class="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-4">
        <div class="text-xs uppercase tracking-[0.25em] text-red-200 font-black">Critical</div>
        <div class="mt-2 text-2xl font-black text-white">${critical}</div>
      </div>
      <div class="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-4">
        <div class="text-xs uppercase tracking-[0.25em] text-amber-200 font-black">Warning</div>
        <div class="mt-2 text-2xl font-black text-white">${warning}</div>
      </div>
      <div class="rounded-xl border border-slate-800 bg-slate-950/70 px-4 py-4">
        <div class="text-xs uppercase tracking-[0.25em] text-slate-500 font-black">Alert Center</div>
        <div class="mt-2 text-sm text-slate-300">Use the global health-alert bell to review unread alerts and open the dedicated health alert center.</div>
      </div>
    </div>
    <div class="mt-4 grid grid-cols-1 gap-3">${topTitles}</div>
  `;
}

function renderFleetTable(summary) {
  const host = summary?.host || {};
  const nodes = summary?.nodes || [];
  NH.fleetMeta.textContent = `Summary generated ${summary?.generated_at || "--"} | nodes=${nodes.length}`;
  const rows = [
    {
      kind: "host",
      name: host.hostname || "host",
      role: "openstack_host",
      cpu_usage_pct: host.cpu_load_ratio != null ? `${host.cpu_load_ratio.toFixed(2)} load/core` : "not_available",
      cpu_severity: host.cpu_severity || "unknown",
      memory_usage_pct: host.memory_usage_pct,
      memory_available_mb: host.mem_avail_mb,
      memory_severity: host.memory_severity || "unknown",
      disk_root_use_pct: host.root_use_pct,
      disk_root_avail_bytes: host.root_avail_bytes,
      disk_severity: host.disk_severity || "unknown",
      overall_severity: host.overall_severity || "unknown",
      source: "local_host",
    },
    ...nodes,
  ];

  NH.fleetTable.innerHTML = `
    <div class="overflow-x-auto rounded-xl border border-slate-800">
      <table class="min-w-full divide-y divide-slate-800 text-sm">
        <thead class="bg-slate-950/70 text-xs uppercase tracking-[0.2em] text-slate-500">
          <tr>
            <th class="px-4 py-3 text-left">Scope</th>
            <th class="px-4 py-3 text-left">Role</th>
            <th class="px-4 py-3 text-left">CPU</th>
            <th class="px-4 py-3 text-left">Memory</th>
            <th class="px-4 py-3 text-left">Disk</th>
            <th class="px-4 py-3 text-left">State</th>
            <th class="px-4 py-3 text-left">Source</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-800 bg-slate-950/50">
          ${rows.map(row => `
            <tr>
              <td class="px-4 py-3 align-top">
                <div class="font-bold text-white">${esc(row.name || "unknown")}</div>
                <div class="mt-1 text-xs text-slate-500">${esc(row.kind || "node")}</div>
              </td>
              <td class="px-4 py-3 align-top text-slate-300">${esc(row.role || "not_available")}</td>
              <td class="px-4 py-3 align-top text-slate-300">${severityBadge(row.cpu_severity)} <span class="ml-2">${esc(row.cpu_usage_pct ?? "not_available")}${typeof row.cpu_usage_pct === "number" ? "%" : ""}</span></td>
              <td class="px-4 py-3 align-top text-slate-300">${severityBadge(row.memory_severity)} <span class="ml-2">${esc(row.memory_usage_pct ?? "not_available")}${typeof row.memory_usage_pct === "number" ? "%" : ""}</span><div class="mt-1 text-xs text-slate-500">free ${esc(row.memory_available_mb ?? "not_available")} MB</div></td>
              <td class="px-4 py-3 align-top text-slate-300">${severityBadge(row.disk_severity)} <span class="ml-2">${esc(row.disk_root_use_pct ?? "not_available")}${typeof row.disk_root_use_pct === "number" ? "%" : ""}</span><div class="mt-1 text-xs text-slate-500">free ${bytesHuman(row.disk_root_avail_bytes)}</div></td>
              <td class="px-4 py-3 align-top">${severityBadge(row.overall_severity)}</td>
              <td class="px-4 py-3 align-top text-xs text-slate-500">${esc(row.source || "not_available")}${row.error ? `<div class="mt-1 text-red-300">${esc(row.error)}</div>` : ""}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function fmtDurationSeconds(seconds) {
  if (seconds == null || Number.isNaN(Number(seconds))) return "not_available";
  const s = Number(seconds);
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  const rem = Math.round(s % 60);
  return `${m}m ${rem}s`;
}

function renderFloatingIps(summary) {
  if (!NH.floatingIpStatus) return;
  const fip = summary?.floating_ips || {};
  if (fip.error) {
    NH.floatingIpStatus.innerHTML = `<div class="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-200">Floating IP status unavailable: ${esc(fip.error)}</div>`;
  } else {
    const pct = fip.available_pct;
    NH.floatingIpStatus.innerHTML = `
      <div class="flex flex-wrap items-center gap-3">
        ${severityBadge(fip.severity)}
        <div class="text-sm text-white font-bold">${esc(fip.available ?? "not_available")} of ${esc(fip.quota_limit ?? "not_available")} available${pct != null ? ` (${esc(pct)}%)` : ""}</div>
        ${fip.below_threshold ? `<span class="text-xs text-amber-300 font-black uppercase tracking-[0.15em]">below ${esc(fip.threshold_pct)}% minimum</span>` : ""}
      </div>
      <div class="mt-2 text-xs text-slate-400">allocated=${esc(fip.allocated_total ?? "not_available")} · attached=${esc(fip.attached_count ?? "not_available")} · unattached=${esc(fip.unattached_count ?? "not_available")}</div>
      ${fip.quota_error ? `<div class="mt-2 text-xs text-amber-300">Quota could not be read: ${esc(fip.quota_error)}</div>` : ""}
    `;
  }
  refreshFloatingIpJobStatus();
}

function renderFloatingIpJob(payload) {
  const current = payload?.current || {};
  const history = payload?.history || [];
  if (!current.status || current.status === "not_available") {
    NH.floatingIpJob.innerHTML = "";
  } else if (current.status === "running") {
    NH.floatingIpJob.innerHTML = `
      <div class="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
        Cleanup in progress (triggered by ${esc(current.triggered_by || "unknown")})… released so far: ${esc(current.released_count ?? 0)}
      </div>
    `;
  } else {
    const tone = current.status === "completed" ? "text-emerald-200 border-emerald-500/30 bg-emerald-500/10" : "text-red-200 border-red-500/30 bg-red-500/10";
    NH.floatingIpJob.innerHTML = `
      <div class="rounded-lg border px-3 py-2 text-xs ${tone}">
        Last cleanup (${esc(current.triggered_by || "unknown")}): ${esc(current.status)} — released ${esc(current.released_count ?? 0)} unattached floating IP(s)
        in ${fmtDurationSeconds(current.duration_seconds)} (finished ${esc(current.finished_at || "not_available")}).
        ${current.before && current.after ? `Available before → after: ${esc(current.before.available_pct)}% → ${esc(current.after.available_pct)}%.` : ""}
        ${current.error ? ` Error: ${esc(current.error)}` : ""}
      </div>
    `;
  }
  if (history.length) {
    NH.floatingIpHistory.innerHTML = `
      <div class="text-xs uppercase tracking-[0.2em] text-slate-500 font-black mb-2">Cleanup History</div>
      <div class="space-y-1">
        ${history.map(h => `
          <div>${esc(h.finished_at || h.started_at || "not_available")} · ${esc(h.triggered_by || "unknown")} · ${esc(h.status)} · released ${esc(h.released_count ?? 0)} · took ${fmtDurationSeconds(h.duration_seconds)}</div>
        `).join("")}
      </div>
    `;
  } else {
    NH.floatingIpHistory.innerHTML = "";
  }
}

async function refreshFloatingIpJobStatus() {
  try {
    const payload = await fetchJson("/api/node-health/openstack/floating-ips/cleanup/status", "floating IP cleanup status");
    renderFloatingIpJob(payload);
    if (payload?.current?.status === "running") {
      scheduleFloatingIpPolling();
    }
    return payload;
  } catch (error) {
    consoleWrite(`Floating IP cleanup status check failed: ${error.message}`);
  }
}

function scheduleFloatingIpPolling() {
  if (STATE.floatingIpPollTimer) return;
  STATE.floatingIpPollTimer = window.setTimeout(async () => {
    STATE.floatingIpPollTimer = null;
    const payload = await refreshFloatingIpJobStatus();
    if (payload?.current?.status === "running") {
      scheduleFloatingIpPolling();
    } else {
      loadHealthSummary(false).catch(() => {});
    }
  }, 3000);
}

async function startFloatingIpCleanup() {
  const confirmed = window.confirm("Release all unattached (orphan) floating IPs until at least 65% of the quota is available? Floating IPs currently attached to running instances are never touched.");
  if (!confirmed) return;
  consoleWrite("Starting manual floating IP cleanup...");
  try {
    const payload = await requestJson("/api/node-health/openstack/floating-ips/cleanup", { method: "POST" }, "floating IP cleanup");
    renderFloatingIpJob({ current: payload, history: [] });
    scheduleFloatingIpPolling();
  } catch (error) {
    consoleWrite(`Floating IP cleanup failed to start: ${error.message}`);
  }
}

function renderHealthSummary(summary) {
  STATE.healthSummary = summary;
  renderOpenstackHealth(summary);
  renderHealthAlerts(summary);
  renderFleetTable(summary);
  renderFloatingIps(summary);
  const tone = healthStateTone(summary?.overall_state);
  if (tone !== "idle") {
    setStatus(`Health ${summary?.overall_state || "unknown"}`, tone);
  }
}

function buildGraph(graph) {
  if (STATE.cy) {
    STATE.cy.destroy();
  }

  STATE.cy = cytoscape({
    container: NH.graphHost,
    elements: [...(graph.nodes || []), ...(graph.edges || [])],
    style: [
      {
        selector: 'node[kind="instance"]',
        style: {
          "background-color": ele => graphColorForRole(ele.data("role")),
          "label": "data(label)",
          "color": "#e2e8f0",
          "text-outline-width": 2,
          "text-outline-color": "#0f172a",
          "font-size": 11,
          "font-weight": 700,
          "width": 56,
          "height": 56,
        }
      },
      {
        selector: 'node[kind="network"]',
        style: {
          "shape": "round-rectangle",
          "background-color": "#1e293b",
          "border-width": 1,
          "border-color": "#475569",
          "label": "data(label)",
          "color": "#cbd5e1",
          "font-size": 10,
          "padding": "12px",
          "text-outline-width": 0,
        }
      },
      {
        selector: "edge",
        style: {
          "width": 2,
          "line-color": "#334155",
          "target-arrow-shape": "none",
          "curve-style": "bezier",
          "label": "data(label)",
          "font-size": 8,
          "color": "#64748b",
          "text-background-color": "#020617",
          "text-background-opacity": 0.85,
          "text-background-padding": 2,
        }
      },
      {
        selector: ".selected-node",
        style: {
          "border-width": 4,
          "border-color": "#f8fafc",
          "shadow-blur": 18,
          "shadow-color": "#38bdf8",
          "shadow-opacity": 0.45,
        }
      }
    ],
    layout: {
      name: "cose",
      animate: false,
      nodeRepulsion: 120000,
      idealEdgeLength: 140,
      gravity: 0.4,
    }
  });

  STATE.cy.on("tap", "node", evt => {
    const node = evt.target;
    STATE.cy.nodes().removeClass("selected-node");
    node.addClass("selected-node");
    const kind = node.data("kind");
    if (kind !== "instance") {
      NH.identity.innerHTML = `<div class="text-slate-400">Network segment selected: <span class="font-bold text-slate-200">${esc(node.data("label"))}</span></div>`;
      return;
    }
    selectNode(node.id());
  });
}

function renderIdentity(node, probe) {
  NH.identity.innerHTML = `
    <div><strong>Name:</strong> ${esc(node.name)}</div>
    <div><strong>Role:</strong> ${esc(node.role)}</div>
    <div><strong>Status:</strong> ${esc(node.status)}</div>
    <div><strong>OS:</strong> ${esc(node.os)}</div>
    <div><strong>SSH user:</strong> ${esc(node.ssh_user)}</div>
    <div><strong>SSH target:</strong> ${esc(node.ssh_target_ip || "not_available")}</div>
    <div><strong>Private IP:</strong> ${esc(node.ip_private || "not_available")}</div>
    <div><strong>Floating IP:</strong> ${esc(node.ip_floating || "not_available")}</div>
    <div><strong>Hostname:</strong> ${esc(probe.identity.hostname)}</div>
    <div><strong>Kernel:</strong> ${esc(probe.identity.kernel)}</div>
    <div><strong>Uptime:</strong> ${esc(probe.identity.uptime)}</div>
  `;
}

function renderProbe(node, probe) {
  renderIdentity(node, probe);
  NH.lastUpdate.textContent = probe.identity.date_utc || "not_available";

  NH.cpuCard.innerHTML = `
    <div class="flex items-center justify-between">${severityBadge(probe.cpu.severity)} <span>${esc(probe.cpu.usage_pct ?? "not_available")}%</span></div>
    <div class="mt-2">Cores: <span class="font-bold">${esc(probe.cpu.cores ?? "not_available")}</span></div>
    <div class="mt-1">Loadavg: <span class="font-bold">${esc(probe.identity.loadavg)}</span></div>
  `;

  NH.memoryCard.innerHTML = `
    <div class="flex items-center justify-between">${severityBadge(probe.memory.severity)} <span>${esc(probe.memory.usage_pct ?? "not_available")}%</span></div>
    <div class="mt-2">Used: <span class="font-bold">${esc(probe.memory.used_mb ?? "not_available")} MB</span></div>
    <div class="mt-1">Available: <span class="font-bold">${esc(probe.memory.available_mb ?? "not_available")} MB</span></div>
    <div class="mt-1">Swap: <span class="font-bold">${esc(probe.memory.swap_used_mb ?? "not_available")} / ${esc(probe.memory.swap_total_mb ?? "not_available")} MB</span></div>
  `;

  NH.diskCard.innerHTML = `
    <div class="flex items-center justify-between">${severityBadge(probe.disk.severity)} <span>${esc(probe.disk.root_use_pct ?? "not_available")}%</span></div>
    <div class="mt-2">Used: <span class="font-bold">${bytesHuman(probe.disk.root_used_bytes)}</span></div>
    <div class="mt-1">Free: <span class="font-bold">${bytesHuman(probe.disk.root_avail_bytes)}</span></div>
    <div class="mt-1">Inodes: <span class="font-bold">${esc(probe.disk.root_inodes_use_pct ?? "not_available")}%</span></div>
  `;

  renderNodeServices(probe);

  NH.storageTable.innerHTML = `
    <div class="grid grid-cols-2 gap-3">
      <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">/var/log: <span class="font-bold">${bytesHuman(probe.disk.var_log_size_bytes)}</span></div>
      <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">/var/log/suricata: <span class="font-bold">${bytesHuman(probe.disk.suricata_log_size_bytes)}</span></div>
      <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">/tmp: <span class="font-bold">${bytesHuman(probe.disk.tmp_size_bytes)}</span></div>
      <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">/var/tmp: <span class="font-bold">${bytesHuman(probe.disk.var_tmp_size_bytes)}</span></div>
      <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">APT cache: <span class="font-bold">${bytesHuman(probe.disk.apt_cache_size_bytes)}</span></div>
    </div>
    <div class="mt-4 rounded-lg border border-slate-800 bg-slate-950 p-3">
      <div class="text-[10px] uppercase tracking-[0.2em] text-slate-500 font-black">Filesystem Snapshot</div>
      <pre class="mt-2 whitespace-pre-wrap text-xs text-slate-300">${esc((probe.tables.filesystems || []).join("\n"))}</pre>
    </div>
    <div class="mt-4 rounded-lg border border-slate-800 bg-slate-950 p-3">
      <div class="text-[10px] uppercase tracking-[0.2em] text-slate-500 font-black">Largest /var Paths</div>
      <pre class="mt-2 whitespace-pre-wrap text-xs text-slate-300">${esc((probe.tables.largest_var || []).join("\n"))}</pre>
    </div>
  `;

  NH.topCpu.textContent = (probe.tables.top_cpu || []).join("\n");
  NH.topMem.textContent = (probe.tables.top_mem || []).join("\n");
}

function renderTimeSyncCard(node, payload) {
  const jobStatus = payload?.status || "not_available";
  const summary = payload?.summary || {};
  const result = payload?.result || null;
  const policy = payload?.policy || {};
  const selected = summary?.selected_node_measurement || {};
  const before = result?.before || null;
  const after = result?.after || null;
  const worst = summary?.worst_node || null;
  const syncStatus = summary?.temporal_sync_status || (jobStatus === "running" ? "running" : "not_measured");
  const syncTone = jobStatus === "failed" ? "critical" : timeSyncTone(syncStatus);
  const correctionApplied = summary?.correction_applied ? "yes" : "no";
  const detailRows = [
    `<div><strong>Job status:</strong> ${esc(jobStatus)}</div>`,
    `<div><strong>Temporal sync status:</strong> ${severityBadge(syncTone)} <span class="ml-2">${esc(syncStatus)}</span></div>`,
    `<div><strong>Max clock offset:</strong> ${esc(summary?.max_clock_offset_ms ?? "not_available")} ms</div>`,
    `<div><strong>Node offset:</strong> ${esc(selected?.abs_offset_ms ?? "not_available")} ms</div>`,
    `<div><strong>Correction applied:</strong> ${esc(correctionApplied)}</div>`,
    `<div><strong>Nodes measured:</strong> ${esc(summary?.nodes_ok ?? 0)}</div>`,
    `<div><strong>Nodes failed:</strong> ${esc(summary?.nodes_failed ?? 0)}</div>`,
    `<div><strong>SSH user:</strong> ${esc(selected?.ssh_user || node?.ssh_user || "not_available")}</div>`,
    `<div><strong>Chrony available:</strong> ${esc(selected?.chrony_available ?? "not_available")}</div>`,
    `<div><strong>Chrony installed by script:</strong> ${esc(selected?.chrony_installed_by_script ?? false)}</div>`,
    `<div><strong>Makestep applied:</strong> ${esc(selected?.makestep_applied ?? false)}</div>`,
  ];
  if (before || after) {
    detailRows.push(`<div><strong>Before max offset:</strong> ${esc(before?.max_clock_offset_ms ?? "not_available")} ms</div>`);
    detailRows.push(`<div><strong>After max offset:</strong> ${esc(after?.max_clock_offset_ms ?? "not_available")} ms</div>`);
  }
  if (worst) {
    detailRows.push(`<div><strong>Worst node:</strong> ${esc(worst.name || "not_available")} (${esc(worst.ip || "not_available")})</div>`);
  }

  const policyInfo = `
    <div class="mt-3 rounded-lg border ${policy?.active_case_present ? "border-amber-500/30 bg-amber-500/10 text-amber-200" : "border-slate-800 bg-slate-900/70 text-slate-300"} px-3 py-2 text-xs">
      <div><strong>Policy:</strong> ${esc(policy?.policy_state || "not_available")}</div>
      <div class="mt-1">${esc(policy?.reason || "Time correction policy not available.")}</div>
      ${policy?.active_case_id ? `<div class="mt-1"><strong>Active case:</strong> ${esc(policy.active_case_id)}</div>` : ""}
    </div>
  `;

  const jobInfo = jobStatus === "running"
    ? `<div class="mt-3 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-xs text-cyan-200">Current step: ${esc(payload?.current_step || "executing_time_sync_script")} | Progress: ${esc(payload?.progress_percent ?? 0)}%</div>`
    : jobStatus === "blocked_policy"
    ? `<div class="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">Corrective time synchronization is blocked by policy: ${esc(payload?.error || policy?.reason || "not_available")}</div>`
    : jobStatus === "failed"
    ? `<div class="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-200">Time synchronization failed: ${esc(payload?.error || "not_available")}</div>`
    : result
    ? `<div class="mt-3 rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-xs text-slate-300">Artifacts: ${esc(payload?.artifacts?.json || "not_available")}</div>`
    : `<div class="mt-3 rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-xs text-slate-400">No time synchronization measurement has been run yet for this node.</div>`;

  NH.timeSyncCard.innerHTML = `
    <div class="grid grid-cols-1 gap-3 md:grid-cols-2">
      ${detailRows.map(row => `<div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">${row}</div>`).join("")}
    </div>
    ${policyInfo}
    ${jobInfo}
  `;
}

function renderSelectedToolDetail(tool, payload) {
  const runtime = payload?.runtime || {};
  const allTools = payload?.inventory?.tools || [];
  const runtimeStatus = effectiveRuntimeState(tool);
  const runtimeVersion = effectiveRuntimeVersion(tool);
  const runtimePresence = effectiveRuntimePresence(tool);
  const capabilities = capabilitiesForTool(tool, allTools);
  const realRuleFiles = runtime?.suricata?.active_rule_files || [];
  const realSignatures = signaturesForTool(tool.id, runtime);
  const realRuleInventory = ruleInventoryForTool(tool.id, runtime);
  const suricataParsedRules = runtime?.suricata?.parsed_rules || [];
  const suricataRuleContents = runtime?.suricata?.rule_contents || [];
  const wazuhRuleContents = runtime?.wazuh?.rule_contents || [];
  const fimPaths = runtime?.wazuh?.fim_paths || [];
  const localRules = runtime?.wazuh?.local_rules || [];
  const localDecoders = runtime?.wazuh?.local_decoders || [];
  const capabilityHtml = capabilities.length
    ? capabilities.map(cap => `<span class="rounded-md border border-violet-500/30 bg-violet-500/10 px-2 py-1 text-[11px] text-violet-200">${esc(cap.display_name)}</span>`).join(" ")
    : '<span class="text-slate-500">none mapped</span>';

  let basis = '<div class="text-slate-500">No runtime-specific detail available for this tool.</div>';

  if (tool.id === "suricata") {
    const suricataRuleDetail = suricataParsedRules.length
      ? suricataParsedRules.map((rule, idx) => `
        <details class="rounded-lg border border-slate-800 bg-slate-950/80" ${idx === 0 ? "open" : ""}>
          <summary class="cursor-pointer list-none px-4 py-3">
            <div class="flex items-center justify-between gap-3">
              <div class="min-w-0">
                <div class="truncate font-bold text-white">${esc(rule.path)}</div>
                <div class="mt-1 text-xs text-slate-400">${esc(rule.interpretation)}</div>
              </div>
              <span class="text-xs uppercase tracking-[0.2em] text-slate-500">rule</span>
            </div>
          </summary>
          <div class="border-t border-slate-800 p-4">
            <div class="text-[10px] font-black uppercase tracking-[0.25em] text-slate-500">Raw Rule</div>
            <pre class="mt-2 whitespace-pre-wrap text-xs text-emerald-300">${esc(rule.raw)}</pre>
            <div class="mt-4 text-[10px] font-black uppercase tracking-[0.25em] text-slate-500">Interpretation</div>
            <div class="mt-2 text-xs text-slate-300">${esc(rule.interpretation)}</div>
          </div>
        </details>
      `).join("")
      : '<div class="text-slate-500">No parsed Suricata rules found on node.</div>';
    const suricataFileDetail = suricataRuleContents.length
      ? suricataRuleContents.map((file, idx) => `
        <details class="rounded-lg border border-slate-800 bg-slate-950/80" ${idx === 0 ? "open" : ""}>
          <summary class="cursor-pointer list-none px-4 py-3">
            <div class="flex items-center justify-between gap-3">
              <div class="truncate font-bold text-white">${esc(file.path)}</div>
              <span class="text-xs uppercase tracking-[0.2em] text-slate-500">full file</span>
            </div>
          </summary>
          <div class="border-t border-slate-800 p-4">
            <pre class="whitespace-pre-wrap text-xs text-emerald-300">${esc((file.content_lines || []).join("\n"))}</pre>
          </div>
        </details>
      `).join("")
      : '<div class="text-slate-500">No Suricata rule file contents collected from node.</div>';
    basis = `
      <div class="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <div class="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <div class="text-xs font-black uppercase tracking-[0.25em] text-slate-500">Real Rule Files From Node</div>
          <div class="mt-3 space-y-1 text-xs text-slate-300">${linesToHtml(realRuleFiles, "No active Suricata rule-files reported from suricata.yaml.")}</div>
        </div>
        <div class="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <div class="text-xs font-black uppercase tracking-[0.25em] text-slate-500">Real Rule Inventory On Disk</div>
          <div class="mt-3 space-y-1 text-xs text-slate-300">${linesToHtml(realRuleInventory, "No Suricata rule files listed from /var/lib/suricata/rules.")}</div>
        </div>
      </div>
      <div class="mt-4 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
        <div class="text-xs font-black uppercase tracking-[0.25em] text-slate-500">Real NICS Signatures Parsed From Node Files</div>
        <div class="mt-3 space-y-1 text-xs text-slate-300">${linesToHtml(realSignatures, "No custom NICS Suricata signatures found on node.")}</div>
      </div>
      <div class="mt-4 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
        <div class="text-xs font-black uppercase tracking-[0.25em] text-slate-500">Installed Detection Rules</div>
        <div class="mt-3 space-y-3">${suricataRuleDetail}</div>
      </div>
      <div class="mt-4 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
        <div class="text-xs font-black uppercase tracking-[0.25em] text-slate-500">Full Rule File Contents</div>
        <div class="mt-3 space-y-3">${suricataFileDetail}</div>
      </div>
    `;
  } else if (tool.id === "wazuh" || tool.id === "wazuh_agent" || tool.id === "wazuh_fim_realtime" || tool.id === "rollback_wazuh_suricata_integration") {
    const wazuhFileDetails = wazuhRuleContents.length
      ? wazuhRuleContents.map((file, idx) => `
        <details class="rounded-lg border border-slate-800 bg-slate-950/80" ${idx === 0 ? "open" : ""}>
          <summary class="cursor-pointer list-none px-4 py-3">
            <div class="flex items-center justify-between gap-3">
              <div class="truncate font-bold text-white">${esc(file.path)}</div>
              <span class="text-xs uppercase tracking-[0.2em] text-slate-500">file</span>
            </div>
          </summary>
          <div class="border-t border-slate-800 p-4">
            <pre class="whitespace-pre-wrap text-xs text-emerald-300">${esc((file.content_lines || []).join("\n"))}</pre>
          </div>
        </details>
      `).join("")
      : '<div class="text-slate-500">No Wazuh local rule or decoder files collected from node.</div>';
    basis = `
      <div class="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <div class="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <div class="text-xs font-black uppercase tracking-[0.25em] text-slate-500">Real Wazuh Rule Inventory On Disk</div>
          <div class="mt-3 space-y-1 text-xs text-slate-300">${linesToHtml(realRuleInventory, "No local Wazuh rules or decoders found on node.")}</div>
        </div>
        <div class="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <div class="text-xs font-black uppercase tracking-[0.25em] text-slate-500">Real FIM Directories From ossec.conf</div>
          <div class="mt-3 space-y-1 text-xs text-slate-300">${linesToHtml(fimPaths, "No FIM directories reported from ossec.conf.")}</div>
        </div>
      </div>
      <div class="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <div class="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <div class="text-xs font-black uppercase tracking-[0.25em] text-slate-500">Local Rule Files</div>
          <div class="mt-3 space-y-1 text-xs text-slate-300">${linesToHtml(localRules, "No local Wazuh rule filenames reported.")}</div>
        </div>
        <div class="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <div class="text-xs font-black uppercase tracking-[0.25em] text-slate-500">Local Decoder Files</div>
          <div class="mt-3 space-y-1 text-xs text-slate-300">${linesToHtml(localDecoders, "No local Wazuh decoder filenames reported.")}</div>
        </div>
      </div>
      <div class="mt-4 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
        <div class="text-xs font-black uppercase tracking-[0.25em] text-slate-500">Installed Rule And Decoder File Contents</div>
        <div class="mt-3 space-y-3">${wazuhFileDetails}</div>
      </div>
    `;
  } else if (tool.id.startsWith("rollback_suricata_")) {
    basis = `
      <div class="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
        <div class="text-xs font-black uppercase tracking-[0.25em] text-slate-500">Rule Pack Files Present On Node</div>
        <div class="mt-3 space-y-1 text-xs text-slate-300">${linesToHtml(realRuleInventory, "No Suricata rule inventory found on node.")}</div>
      </div>
      <div class="mt-4 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
        <div class="text-xs font-black uppercase tracking-[0.25em] text-slate-500">Matching Parsed Signatures</div>
        <div class="mt-3 space-y-1 text-xs text-slate-300">${linesToHtml(realSignatures, "No matching signatures parsed for this rule pack.")}</div>
      </div>
    `;
  }

  NH.securityDetail.innerHTML = `
    <div class="rounded-2xl border border-slate-800 bg-slate-950/60 p-5">
      <div class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div class="text-xs font-black uppercase tracking-[0.25em] text-slate-500">Selected Tool</div>
          <h3 class="mt-2 text-xl font-black text-white">${esc(tool.display_name)}</h3>
          <div class="mt-2 flex flex-wrap items-center gap-2">
            ${toolCategoryBadge(tool.category)}
            ${severityBadge(effectiveToolSeverity(tool))}
          </div>
        </div>
        <div class="space-y-1 text-xs text-slate-300">
          <div><strong>Tool ID:</strong> ${esc(tool.id)}</div>
          <div><strong>Inventory status:</strong> ${esc(tool.inventory_status || "unknown")}</div>
          <div><strong>Installed on node:</strong> ${esc(runtimePresence)}</div>
          <div><strong>Service/runtime state:</strong> ${esc(runtimeStatus)}</div>
          <div><strong>Version:</strong> ${esc(runtimeVersion)}</div>
          <div><strong>Installed at:</strong> ${esc(tool.installed_at || "not_available")}</div>
        </div>
      </div>
      <div class="mt-4 rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs text-slate-300">
        <strong>Evidence basis:</strong> runtime details below are collected directly from the selected node over SSH from package presence, service state and on-node files such as suricata.yaml, /var/lib/suricata/rules and /var/ossec/etc.
      </div>
      <div class="mt-4 rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs text-slate-300">
        <div class="text-[10px] font-black uppercase tracking-[0.25em] text-slate-500">Tool Capabilities And Attached Detection Packs</div>
        <div class="mt-3 flex flex-wrap gap-2">${capabilityHtml}</div>
      </div>
      <div class="mt-4">${basis}</div>
    </div>
  `;
}

function renderTooling(node, payload) {
  const inventory = payload?.inventory || { tools: [], counts: {}, source_files: [], total: 0 };
  const runtime = payload?.runtime || null;
  const runtimeError = payload?.runtime_error || null;
  const allTools = inventory.tools || [];
  const tools = allTools.filter(isPrimaryTool);
  STATE.toolingPayload = payload;

  NH.securityMeta.textContent = runtime?.generated_at
    ? `Runtime inspected ${runtime.generated_at}`
    : runtimeError
    ? "Runtime inspection unavailable"
    : "Inventory only";

  const primaryCounts = tools.reduce((acc, tool) => {
    const key = tool.category || "other";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});

  const countsHtml = Object.entries(primaryCounts).map(([category, count]) => `
    <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">
      <div class="text-[10px] font-black uppercase tracking-[0.2em] text-slate-500">${esc(categoryLabel(category))}</div>
      <div class="mt-1 text-lg font-black text-white">${esc(count)}</div>
    </div>
  `).join("") || '<div class="text-slate-500">No installer inventory found for this node.</div>';

  const sources = (inventory.source_files || []).map(path => `<div>${esc(path)}</div>`).join("") || '<div>not_available</div>';

  const grouped = tools.reduce((acc, tool) => {
    const key = tool.category || "other";
    if (!acc[key]) acc[key] = [];
    acc[key].push(tool);
    return acc;
  }, {});

  const toolTree = Object.entries(grouped).map(([category, categoryTools]) => `
    <details class="rounded-xl border border-slate-800 bg-slate-950/70" open>
      <summary class="cursor-pointer list-none px-4 py-3">
        <div class="flex items-center justify-between gap-3">
          <div class="flex items-center gap-2">
            ${toolCategoryBadge(category)}
            <span class="font-black text-white">${esc(categoryLabel(category))}</span>
          </div>
          <span class="text-xs font-black uppercase tracking-[0.2em] text-slate-400">${esc(categoryTools.length)} tools</span>
        </div>
      </summary>
      <div class="border-t border-slate-800 p-3 space-y-2">
        ${categoryTools.map(tool => {
          const status = effectiveRuntimeState(tool);
          const statusSeverity = effectiveToolSeverity(tool);
          const version = effectiveRuntimeVersion(tool);
          const nodePresence = effectiveRuntimePresence(tool);
          const isSelected = tool.id === STATE.selectedToolId;
          return `
            <button type="button" data-tool-id="${esc(tool.id)}" class="nh-tool-card flex w-full items-start justify-between gap-3 rounded-lg border px-3 py-3 text-left ${isSelected ? "border-sky-500/60 bg-sky-500/10" : "border-slate-800 bg-slate-950 hover:border-sky-500/40"}">
              <div class="min-w-0">
                <div class="font-bold text-white">${esc(tool.display_name)}</div>
                <div class="mt-1 text-xs text-slate-400">${esc(tool.id)}</div>
                <div class="mt-2 flex flex-wrap gap-2 text-[11px]">
                  <span class="rounded-md border border-slate-800 bg-slate-900 px-2 py-1 text-slate-300">inventory: ${esc(tool.inventory_status || "unknown")}</span>
                  <span class="rounded-md border border-slate-800 bg-slate-900 px-2 py-1 text-slate-300">node: ${esc(nodePresence)}</span>
                  <span class="rounded-md border border-slate-800 bg-slate-900 px-2 py-1 text-slate-300">runtime: ${esc(status)}</span>
                  <span class="rounded-md border border-slate-800 bg-slate-900 px-2 py-1 text-slate-300">version: ${esc(version)}</span>
                </div>
              </div>
              <div class="shrink-0">${severityBadge(statusSeverity)}</div>
            </button>
          `;
        }).join("")}
      </div>
    </details>
  `).join("") || '<div class="rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-slate-500">No IDS, SIEM or agent inventory found.</div>';

  NH.securitySummary.innerHTML = `
    <div class="space-y-4 xl:col-span-1">
      <div class="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
        <div class="text-xs font-black uppercase tracking-[0.25em] text-slate-500">Inventory Sources</div>
        <div class="mt-3 text-sm text-slate-300">${sources}</div>
      </div>
      <div class="grid grid-cols-2 gap-3">${countsHtml}</div>
    </div>
    <div class="space-y-4 xl:col-span-1">
      <div class="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
        <div class="text-xs font-black uppercase tracking-[0.25em] text-slate-500">Security Tool Tree</div>
        <div class="mt-3 space-y-3">${toolTree}</div>
      </div>
    </div>
  `;

  const runtimeWarning = runtimeError?.message
    ? `<div class="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">Runtime probe warning: ${esc(runtimeError.message)}</div>`
    : "";

  // Auto-render Suricata rules panel on node selection (no second click required)
  const suricataPresent = (runtime?.tool_presence?.suricata || "").toLowerCase();
  const suricataStatus = (runtime?.tool_status?.suricata || "").toLowerCase();
  const parsedRules = runtime?.suricata?.parsed_rules || [];
  const activeRuleFiles = runtime?.suricata?.active_rule_files || [];

  let suricataPanel = "";
  if (runtime) {
    const isInstalled = suricataPresent === "installed";
    const statusBadge = isInstalled
      ? `<span class="px-2 py-1 rounded-md border border-emerald-500/40 bg-emerald-500/10 text-emerald-300 text-[10px] font-black uppercase tracking-widest">INSTALLED · ${suricataStatus || "unknown"}</span>`
      : `<span class="px-2 py-1 rounded-md border border-slate-600/40 bg-slate-800/40 text-slate-400 text-[10px] font-black uppercase tracking-widest">NOT INSTALLED</span>`;

    const ruleFilesHtml = activeRuleFiles.length
      ? activeRuleFiles.map(f => `<div class="font-mono text-xs text-slate-300 truncate">${esc(f)}</div>`).join("")
      : `<div class="text-xs text-slate-500">No active rule files detected</div>`;

    const rulesHtml = parsedRules.length
      ? parsedRules.map((rule, idx) => `
          <details class="rounded-lg border border-slate-800 bg-slate-950/80" ${idx === 0 ? "open" : ""}>
            <summary class="flex cursor-pointer list-none items-center justify-between gap-3 px-3 py-2">
              <div class="min-w-0">
                <div class="truncate font-bold text-white text-xs">${esc(rule.path)}</div>
                <div class="mt-1 text-[10px] text-slate-400">${esc(rule.interpretation)}</div>
              </div>
              <span class="shrink-0 text-[10px] uppercase tracking-[0.2em] text-slate-500">rule</span>
            </summary>
            <div class="border-t border-slate-800 px-3 py-2">
              <pre class="whitespace-pre-wrap text-xs text-emerald-300">${esc(rule.raw)}</pre>
              <div class="mt-2 text-xs text-slate-300">${esc(rule.interpretation)}</div>
            </div>
          </details>`)
          .join("")
      : `<div class="text-xs text-slate-500">No Suricata rules parsed from node${isInstalled ? " — rule files may be empty or unreadable" : ""}.</div>`;

    suricataPanel = `
      <div class="rounded-xl border border-slate-700/60 bg-slate-950/70 p-4 space-y-3">
        <div class="flex items-center justify-between gap-3">
          <div class="text-xs font-black uppercase tracking-[0.25em] text-slate-400">Suricata IDS — Active Rules</div>
          ${statusBadge}
        </div>
        <div class="space-y-1">
          <div class="text-[10px] font-black uppercase tracking-[0.2em] text-slate-500 mb-1">Rule Files</div>
          ${ruleFilesHtml}
        </div>
        <div class="space-y-2">
          <div class="text-[10px] font-black uppercase tracking-[0.2em] text-slate-500">Loaded Rules (${parsedRules.length})</div>
          ${rulesHtml}
        </div>
      </div>`;
  }

  NH.securityRules.innerHTML = [
    runtimeWarning,
    suricataPanel,
    suricataPanel
      ? ""
      : `<div class="rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-slate-400">Select a tool to inspect its real rule files, full rule content and interpretation.</div>`,
  ].filter(Boolean).join("\n");

  const selectedTool = tools.find(tool => tool.id === STATE.selectedToolId);
  if (selectedTool) {
    renderSelectedToolDetail(selectedTool, payload);
  } else {
    NH.securityDetail.innerHTML = `<div class="rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-slate-500">Select a tool from the tree to load version, runtime state and full rule content from the node.</div>`;
  }

  NH.securitySummary.querySelectorAll(".nh-tool-card").forEach(card => {
    card.addEventListener("click", () => {
      STATE.selectedToolId = card.dataset.toolId || null;
      renderTooling(node, STATE.toolingPayload);
    });
  });
}

function stopTimeSyncPolling() {
  if (STATE.timeSyncPollTimer) {
    clearTimeout(STATE.timeSyncPollTimer);
    STATE.timeSyncPollTimer = null;
  }
}

async function fetchTimeSyncStatus(nodeId) {
  const payload = await fetchJson(`/api/node-health/nodes/${encodeURIComponent(nodeId)}/time-sync/status`, "time sync status");
  STATE.timeSyncStatus = payload;
  const node = STATE.nodeMap.get(nodeId);
  if (node) {
    renderTimeSyncCard(node, payload);
  }
  return payload;
}

async function loadHealthSummary(refresh = false) {
  const query = refresh ? "?refresh=1" : "";
  const payload = await fetchJson(`/api/node-health/health-summary${query}`, "node health summary");
  renderHealthSummary(payload);
  return payload;
}

async function loadMemoryPressure() {
  try {
    const payload = await fetchJson("/api/node-health/host/memory-pressure", "memory pressure");
    const swapPct = payload.swap_used_pct;
    const overThreshold = typeof swapPct === "number" && swapPct >= (payload.threshold_swap_pct ?? 80);
    const swapColor = overThreshold ? "text-red-300" : (typeof swapPct === "number" && swapPct >= 60 ? "text-amber-300" : "text-emerald-300");
    NH.memoryPressureCard.innerHTML = `
      <div class="grid grid-cols-2 gap-3">
        <div>Swap used: <span class="font-bold ${swapColor}">${esc(swapPct ?? "not_available")}%</span> <span class="text-slate-500">(threshold ${esc(payload.threshold_swap_pct ?? 80)}%)</span></div>
        <div>Swap: <span class="font-bold">${esc(payload.swap_used_mb ?? "not_available")} / ${esc(payload.swap_total_mb ?? "not_available")} MB</span></div>
        <div>RAM available: <span class="font-bold">${esc(payload.mem_available_pct ?? "not_available")}%</span></div>
        <div>PSI (memory pressure): <span class="font-bold">${payload.psi_supported ? esc(payload.psi_some_avg10 ?? "not_available") + " (some avg10)" : "not supported by this kernel"}</span></div>
      </div>
    `;
    const events = payload.recent_watchdog_events || [];
    if (!events.length) {
      NH.memoryPressureEvents.innerHTML = `<div class="text-slate-500">No watchdog actions recorded yet (swap has not crossed ${esc(payload.threshold_swap_pct ?? 80)}% since this worker started).</div>`;
    } else {
      NH.memoryPressureEvents.innerHTML = `<div class="text-slate-500 font-black uppercase tracking-[0.2em] text-[10px]">Recent watchdog actions</div>` + events.map(ev => `
        <div class="rounded border border-slate-800 bg-slate-950 px-2 py-1">
          ${esc(ev.ts_utc || "")} -- swap ${esc(ev.swap_used_pct_before ?? "?")}% -> ${esc(ev.swap_used_pct_after ?? "?")}% -- gc_collected=${esc(ev.gc_collected_objects ?? "?")} drop_caches_ok=${esc(ev.drop_caches_ok ?? "?")}
        </div>
      `).join("");
    }
    return payload;
  } catch (error) {
    NH.memoryPressureCard.innerHTML = `<div class="text-red-300">Failed to load: ${esc(error.message)}</div>`;
  }
}

function scheduleTimeSyncPolling(nodeId) {
  stopTimeSyncPolling();
  STATE.timeSyncPollTimer = window.setTimeout(async () => {
    try {
      const payload = await fetchTimeSyncStatus(nodeId);
      if (payload?.status === "running") {
        scheduleTimeSyncPolling(nodeId);
      } else if (payload?.status === "completed") {
        consoleWrite(`Time synchronization completed. Max clock offset=${payload?.summary?.max_clock_offset_ms ?? "not_available"} ms status=${payload?.summary?.temporal_sync_status ?? "unknown"}`);
      } else if (payload?.status === "failed") {
        consoleWrite(`Time synchronization failed: ${payload?.error || "not_available"}`);
      }
    } catch (error) {
      consoleWrite(`Time sync status polling failed: ${error.message}`);
    }
  }, 2000);
}

async function runTimeSync(fixTime) {
  const node = STATE.nodeMap.get(STATE.selectedId);
  if (!node) {
    consoleWrite("Select a node first.");
    return;
  }
  let maintenanceOverride = false;
  const policy = STATE.timeSyncStatus?.policy || {};
  if (fixTime) {
    const confirmed = window.confirm(`Fix time synchronization on ${node.name}? This changes node state and may install/start chrony, apply chronyc makestep and alter timestamps, logs or volatile evidence ordering.`);
    if (!confirmed) {
      return;
    }
    if (policy?.active_case_present) {
      const overrideConfirmed = window.confirm(`An active forensic case (${policy.active_case_id || "unknown"}) is present. Corrective time synchronization is normally blocked during an active case. Continue only as explicit laboratory or maintenance override intervention?`);
      if (!overrideConfirmed) {
        consoleWrite("Corrective time synchronization cancelled because an active forensic case is present.");
        return;
      }
      maintenanceOverride = true;
    }
  }
  consoleWrite(`${fixTime ? "Starting corrective time synchronization" : "Starting clock offset measurement"} on ${node.name}...`);
  setStatus(`${fixTime ? "Fixing" : "Measuring"} ${node.name}`, "warn");
  let payload;
  try {
    payload = await requestJson(
      `/api/node-health/nodes/${encodeURIComponent(node.id)}/time-sync/run`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fix_time: fixTime, maintenance_override: maintenanceOverride }),
      },
      "time sync run",
    );
  } catch (error) {
    consoleWrite(`${fixTime ? "Time synchronization correction" : "Clock offset measurement"} failed: ${error.message}`);
    throw error;
  }
  STATE.timeSyncStatus = payload;
  renderTimeSyncCard(node, payload);
  if (payload?.status === "blocked_policy") {
    consoleWrite(`Corrective time synchronization blocked by policy: ${payload?.error || "not_available"}`);
    setStatus("Policy Blocked", "error");
    return;
  }
  if (payload?.status === "running") {
    scheduleTimeSyncPolling(node.id);
  }
}

async function loadNodes(autoSelect = true) {
  setStatus("Loading", "warn");
  consoleWrite("Loading OpenStack node inventory...");
  const data = await fetchJson("/api/node-health/nodes", "nodes");
  STATE.nodes = data.nodes || [];
  STATE.nodeMap = new Map(STATE.nodes.map(node => [node.id, node]));
  buildGraph(data.graph || { nodes: [], edges: [] });
  renderScenarioOverview(data.summary || {}, STATE.nodes);
  if (data.inventory_error) {
    consoleWrite(`OpenStack inventory warning: ${data.inventory_error}`);
  }
  setStatus(`Nodes ${STATE.nodes.length}`, "ok");
}

async function selectNode(nodeId) {
  stopTimeSyncPolling();
  STATE.selectedId = nodeId;
  STATE.selectedToolId = null;
  const node = STATE.nodeMap.get(nodeId);
  if (!node) return;
  setStatus(`Probing ${node.name}`, "warn");
  consoleWrite(`Probing node ${node.name} (${node.ssh_user}@${node.ssh_target_ip || node.ip_private || node.ip_floating || "?"})`);
  const [probeResult, toolingResult, timeSyncResult] = await Promise.allSettled([
    fetchJson(`/api/node-health/nodes/${encodeURIComponent(nodeId)}/probe`, "probe"),
    fetchJson(`/api/node-health/nodes/${encodeURIComponent(nodeId)}/tooling`, "tooling"),
    fetchJson(`/api/node-health/nodes/${encodeURIComponent(nodeId)}/time-sync/status`, "time sync status"),
  ]);

  if (probeResult.status === "fulfilled") {
    renderProbe(node, probeResult.value.probe);
    consoleWrite(`Probe completed for ${node.name}`);
  } else {
    consoleWrite(`Probe failed: ${probeResult.reason.message}`);
    NH.identity.innerHTML = `<div class="text-red-300">${esc(probeResult.reason.message)}</div>`;
  }

  if (toolingResult.status === "fulfilled") {
    if (probeResult.status === "fulfilled") {
      renderNodeServices(probeResult.value.probe, toolingResult.value);
    }
    renderTooling(node, toolingResult.value);
    consoleWrite(`Tooling inspection completed for ${node.name}`);
  } else {
    STATE.toolingPayload = null;
    NH.securityMeta.textContent = "Tooling inspection failed";
    NH.securitySummary.innerHTML = `<div class="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-red-200">${esc(toolingResult.reason.message)}</div>`;
    NH.securityDetail.innerHTML = "";
    NH.securityRules.innerHTML = "";
    consoleWrite(`Tooling inspection failed: ${toolingResult.reason.message}`);
  }

  if (timeSyncResult.status === "fulfilled") {
    STATE.timeSyncStatus = timeSyncResult.value;
    renderTimeSyncCard(node, timeSyncResult.value);
    if (timeSyncResult.value?.status === "running") {
      consoleWrite(`Time synchronization job is running for ${node.name}.`);
      scheduleTimeSyncPolling(node.id);
    }
  } else {
    NH.timeSyncCard.innerHTML = `<div class="text-red-300">${esc(timeSyncResult.reason.message)}</div>`;
    consoleWrite(`Time sync inspection failed: ${timeSyncResult.reason.message}`);
  }

  if (probeResult.status === "fulfilled" || toolingResult.status === "fulfilled") {
    setStatus(`Ready ${node.name}`, "ok");
  } else {
    setStatus("Probe Error", "error");
  }
}

function startCleanup() {
  const node = STATE.nodeMap.get(STATE.selectedId);
  if (!node) {
    consoleWrite("No node selected for cleanup.");
    return;
  }
  if (STATE.cleanupSource) {
    STATE.cleanupSource.close();
    STATE.cleanupSource = null;
  }
  setStatus(`Cleanup ${node.name}`, "warn");
  consoleWrite(`Starting safe disk cleanup on ${node.name}...`);
  const url = `/api/node-health/nodes/${encodeURIComponent(node.id)}/cleanup/stream`;
  const source = new EventSource(url);
  STATE.cleanupSource = source;
  source.onmessage = evt => {
    consoleWrite(evt.data);
  };
  source.addEventListener("done", async () => {
    consoleWrite("Cleanup stream finished.");
    source.close();
    STATE.cleanupSource = null;
    await selectNode(node.id);
  });
  source.onerror = () => {
    consoleWrite("Cleanup stream closed.");
    source.close();
    STATE.cleanupSource = null;
  };
}

async function startPowerOnStopped() {
  setStatus("Powering on stopped instances", "warn");
  consoleWrite("Checking for stopped instances to power on...");
  try {
    const response = await fetch("/api/node-health/nodes/power-on-stopped", { method: "POST" });
    const payload = await response.json();
    if (!response.ok) {
      consoleWrite(`Power-on request failed: ${payload?.error || "not_available"}`);
      setStatus("Power-on failed", "error");
      return;
    }
    if (!payload.attempted) {
      consoleWrite("No stopped instances found — every real instance is already running.");
    } else {
      for (const row of payload.results || []) {
        if (row.result === "start_requested") {
          consoleWrite(`Power-on requested for ${row.name} (${row.instance_id}).`);
        } else {
          consoleWrite(`Power-on for ${row.name} did not start: ${row.detail || "unknown error"}`);
        }
      }
    }
    setStatus("Power-on requested", "ok");
    await loadNodes(false);
  } catch (error) {
    consoleWrite(`Power-on request failed: ${error.message}`);
    setStatus("Power-on failed", "error");
  }
}

async function startFreeHostMemory() {
  const confirmed = window.confirm(
    "Free memory on THIS host (the OpenStack/gunicorn server itself, not the scenario VMs)?\n\n" +
    "This runs gc.collect() on the worker handling this request and drops the kernel page " +
    "cache/dentries/inodes (sync + echo 1 > /proc/sys/vm/drop_caches). It never deletes files " +
    "and never touches swap."
  );
  if (!confirmed) return;
  setStatus("Freeing host memory", "warn");
  consoleWrite("Requesting host memory free (gc.collect + drop_caches)...");
  try {
    const response = await fetch("/api/node-health/host/free-memory", { method: "POST" });
    const payload = await response.json();
    if (!response.ok) {
      consoleWrite(`Free-memory request failed: ${payload?.error || "not_available"}`);
      setStatus("Free-memory failed", "error");
      return;
    }
    consoleWrite(`gc.collect() released ${payload.gc_collected_objects} objects in this worker.`);
    if (payload.drop_caches?.ok) {
      consoleWrite("drop_caches: ok.");
    } else if (payload.drop_caches?.attempted) {
      consoleWrite(`drop_caches failed: ${payload.drop_caches.error || "unknown error"}. Install the NOPASSWD sudoers rule via start_dashboard.sh ("[2.9/6]") and retry.`);
    } else {
      consoleWrite("drop_caches script not found — only gc.collect() ran.");
    }
    const before = payload.before || {};
    const after = payload.after || {};
    consoleWrite(`mem_avail_mb: ${before.mem_avail_mb ?? "n/a"} -> ${after.mem_avail_mb ?? "n/a"} (delta ${payload.mem_avail_mb_delta ?? "n/a"})`);
    consoleWrite(`swap_used_mb: ${before.swap_used_mb ?? "n/a"} -> ${after.swap_used_mb ?? "n/a"} (swap is intentionally left untouched by this button)`);
    setStatus("Host memory free requested", "ok");
    await loadNodes(false);
  } catch (error) {
    consoleWrite(`Free-memory request failed: ${error.message}`);
    setStatus("Free-memory failed", "error");
  }
}

function startOpenstackRestart() {
  const confirmed = window.confirm("Restart OpenStack services from Node Health? This can temporarily degrade Horizon, Keystone, Nova and Neutron while containers restart.");
  if (!confirmed) return;
  if (STATE.restartSource) {
    STATE.restartSource.close();
    STATE.restartSource = null;
  }
  setStatus("Restarting OpenStack", "warn");
  consoleWrite("Starting OpenStack services restart from Node Health...");
  const source = new EventSource("/api/node-health/openstack/restart/stream");
  STATE.restartSource = source;
  source.onmessage = evt => {
    consoleWrite(evt.data);
  };
  source.addEventListener("done", async () => {
    consoleWrite("OpenStack restart stream finished.");
    source.close();
    STATE.restartSource = null;
    try {
      await loadNodes(false);
    } catch (error) {
      consoleWrite(`Post-restart node inventory refresh failed: ${error.message}`);
    }
    try {
      await loadHealthSummary(true);
    } catch (error) {
      consoleWrite(`Post-restart health refresh failed: ${error.message}`);
    }
  });
  source.onerror = () => {
    consoleWrite("OpenStack restart stream closed.");
    source.close();
    STATE.restartSource = null;
  };
}

function openHealthAlertCenter() {
  if (window.parent && typeof window.parent.openView === "function") {
    window.parent.openView("health_alerts");
    return;
  }
  window.location.href = "/health_alerts.html";
}

NH.btnRefreshNodes.addEventListener("click", () => loadNodes(false));
NH.btnRefreshHealth.addEventListener("click", () => loadHealthSummary(true).catch(error => {
  setStatus("Health Error", "error");
  consoleWrite(`Fleet health refresh failed: ${error.message}`);
}));
NH.btnRefreshSelected.addEventListener("click", () => STATE.selectedId ? selectNode(STATE.selectedId) : consoleWrite("Select a node first."));
NH.btnMeasureClock.addEventListener("click", () => runTimeSync(false).catch(error => {
  setStatus("Time Sync Error", "error");
  consoleWrite(`Clock offset measurement failed: ${error.message}`);
}));
NH.btnFixTimeSync.addEventListener("click", () => runTimeSync(true).catch(error => {
  setStatus("Time Sync Error", "error");
  consoleWrite(`Time synchronization correction failed: ${error.message}`);
}));
NH.btnCleanupSelected.addEventListener("click", startCleanup);
NH.btnPowerOnStopped.addEventListener("click", startPowerOnStopped);
NH.btnRestartOpenstack.addEventListener("click", startOpenstackRestart);
NH.btnFreeHostMemory.addEventListener("click", startFreeHostMemory);
NH.btnRefreshMemoryPressure.addEventListener("click", () => loadMemoryPressure().catch(() => {}));
NH.btnCleanupFloatingIps.addEventListener("click", startFloatingIpCleanup);
NH.btnOpenHealthAlertCenter.addEventListener("click", openHealthAlertCenter);
NH.btnClearConsole.addEventListener("click", () => { NH.console.textContent = ""; });

document.addEventListener("DOMContentLoaded", () => {
  Promise.allSettled([loadNodes(false), loadHealthSummary(true), loadMemoryPressure()]).then(results => {
    const firstError = results.find(result => result.status === "rejected");
    if (firstError) {
      setStatus("Load Error", "error");
      consoleWrite(`Failed to load node health module: ${firstError.reason.message}`);
    }
  });
  window.setInterval(() => loadMemoryPressure().catch(() => {}), 30000);
});

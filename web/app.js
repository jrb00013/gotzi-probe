(function () {
  const API = "/api";
  function escapeHtml(s) {
    if (s == null) return "";
    const div = document.createElement("div");
    div.textContent = s;
    return div.innerHTML;
  }

  // --- Tabs ---
  document.querySelectorAll("#main-tabs .tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tab = btn.dataset.tab;
      document.querySelectorAll("#main-tabs .tab").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const panel = document.getElementById("panel-" + tab);
      if (panel) panel.classList.add("active");
      if (tab === "rules") loadRules();
      if (tab === "rules") loadRuleMatches();
      if (tab === "attack") loadAttackSessions();
      if (tab === "honeypot") loadHoneypotEvents();
    });
  });

  // --- Capture panel ---
  const packetTbody = document.getElementById("packet-tbody");
  const detailContent = document.getElementById("detail-content");
  const hexContent = document.getElementById("hex-content");
  const statusEl = document.getElementById("status");
  const filterPort = document.getElementById("filter-port");
  const filterIp = document.getElementById("filter-ip");

  let selectedIndex = null;
  function params() {
    const p = new URLSearchParams();
    const port = filterPort.value.trim();
    const ip = filterIp.value.trim();
    if (port) p.set("port", port);
    if (ip) p.set("ip", ip);
    p.set("limit", "500");
    return p.toString();
  }
  function fetchPackets() {
    return fetch(`${API}/packets?${params()}`).then((r) => r.json());
  }
  function fetchPacket(index) {
    return fetch(`${API}/packets/${index}`).then((r) => (r.ok ? r.json() : null));
  }
  function clearPackets() {
    return fetch(`${API}/clear`, { method: "POST" }).then(() => {
      packetTbody.innerHTML = "";
      detailContent.innerHTML = "<p class=\"muted\">Select a packet</p>";
      hexContent.innerHTML = "<p class=\"muted\">Select a packet</p>";
      selectedIndex = null;
      statusEl.textContent = "Cleared";
    });
  }
  function renderPacketList(data) {
    const existing = new Set(Array.from(packetTbody.querySelectorAll("tr")).map((r) => r.dataset.index));
    (data.packets || []).forEach((p) => {
      if (existing.has(String(p.index))) return;
      existing.add(String(p.index));
      const tr = document.createElement("tr");
      tr.dataset.index = p.index;
      tr.innerHTML = `<td>${p.index}</td><td>${escapeHtml(p.time)}</td><td>${escapeHtml(p.src_ip)}</td><td>${escapeHtml(p.dest_ip)}</td><td>${p.src_port}</td><td>${p.dest_port}</td><td>${p.length}</td><td>${escapeHtml(p.info)}</td>`;
      tr.addEventListener("click", () => selectPacket(p.index));
      packetTbody.appendChild(tr);
    });
    if (data.total !== undefined) statusEl.textContent = `Packets: ${data.total}`;
  }
  function selectPacket(index) {
    selectedIndex = index;
    document.querySelectorAll(".packet-table tbody tr.selected").forEach((r) => r.classList.remove("selected"));
    const row = document.querySelector(`.packet-table tbody tr[data-index="${index}"]`);
    if (row) row.classList.add("selected");
    fetchPacket(index).then((p) => {
      if (!p) return;
      detailContent.innerHTML = `
        <div class="section"><div class="section-title">Frame</div><div class="field"><span class="field-name">Index:</span> ${p.index}</div><div class="field"><span class="field-name">Time:</span> ${escapeHtml(p.time)}</div></div>
        <div class="section"><div class="section-title">Internet Protocol</div><div class="field"><span class="field-name">Source:</span> ${escapeHtml(p.src_ip)}</div><div class="field"><span class="field-name">Destination:</span> ${escapeHtml(p.dest_ip)}</div></div>
        <div class="section"><div class="section-title">User Datagram Protocol</div><div class="field"><span class="field-name">Source port:</span> ${p.src_port}</div><div class="field"><span class="field-name">Destination port:</span> ${p.dest_port}</div><div class="field"><span class="field-name">Length:</span> ${p.length}</div></div>
        <div class="section"><div class="section-title">Payload</div><div class="field">${escapeHtml(p.payload_preview || p.info || "")}</div></div>`;
      hexContent.innerHTML = (p.hex_dump || []).length
        ? (p.hex_dump || []).map((l) => `<div class="hex-line"><span class="hex-offset">${l.offset}</span><span class="hex-bytes">${l.hex}</span><span class="hex-ascii">${l.ascii}</span></div>`).join("")
        : "<p class=\"muted\">No data</p>";
    });
  }
  document.getElementById("btn-apply").addEventListener("click", () => {
    packetTbody.innerHTML = "";
    fetchPackets().then(renderPacketList).catch(() => (statusEl.textContent = "Error"));
  });
  document.getElementById("btn-clear").addEventListener("click", () => {
    clearPackets();
  });
  function pollCapture() {
    fetchPackets().then(renderPacketList).catch(() => (statusEl.textContent = "Error"));
  }
  pollCapture();
  setInterval(pollCapture, 500);

  // --- Attack panel ---
  function loadAttackSessions() {
    fetch(`${API}/attack/sessions?limit=30`)
      .then((r) => r.json())
      .then((list) => {
        const tbody = document.getElementById("attack-sessions-tbody");
        tbody.innerHTML = (list || []).map((s) => `<tr><td>${s.id}</td><td>${escapeHtml(s.attack_type)}</td><td>${escapeHtml(s.target)}</td><td>${s.port ?? ""}</td><td>${escapeHtml(s.started_at || "")}</td></tr>`).join("");
      })
      .catch(() => {});
  }
  document.getElementById("btn-flood").addEventListener("click", () => {
    const target = document.getElementById("attack-target").value.trim();
    const port = parseInt(document.getElementById("attack-port").value, 10);
    const duration = parseFloat(document.getElementById("attack-duration").value) || 5;
    const protocol = document.getElementById("attack-protocol").value;
    if (!target || !port) return;
    fetch(`${API}/attack/flood`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, port, duration_sec: duration, protocol }),
    })
      .then((r) => r.json())
      .then((d) => { statusEl.textContent = d.message || "Flood completed"; loadAttackSessions(); })
      .catch((e) => (statusEl.textContent = "Error: " + e.message));
  });
  document.getElementById("btn-knock").addEventListener("click", () => {
    const target = document.getElementById("attack-target").value.trim();
    const portsStr = document.getElementById("knock-ports").value.trim();
    if (!target || !portsStr) return;
    const ports = portsStr.split(",").map((p) => parseInt(p.trim(), 10)).filter((n) => !isNaN(n));
    if (!ports.length) return;
    fetch(`${API}/attack/port-knock`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, ports, protocol: "udp", delay_sec: 0.2 }),
    })
      .then((r) => r.json())
      .then((d) => { statusEl.textContent = "Port knock done"; loadAttackSessions(); })
      .catch((e) => (statusEl.textContent = "Error: " + e.message));
  });
  document.getElementById("btn-slowloris").addEventListener("click", () => {
    const target = document.getElementById("attack-target").value.trim();
    const port = parseInt(document.getElementById("slowloris-port").value, 10) || 80;
    const duration = parseFloat(document.getElementById("slowloris-duration").value) || 30;
    if (!target) return;
    fetch(`${API}/attack/slowloris`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, port, duration_sec: duration, num_sockets: 200 }),
    })
      .then((r) => r.json())
      .then((d) => { statusEl.textContent = "Slowloris started (runs " + duration + "s)"; loadAttackSessions(); })
      .catch((e) => (statusEl.textContent = "Error: " + e.message));
  });

  // --- Rules panel ---
  function loadRules() {
    fetch(`${API}/rules`)
      .then((r) => r.json())
      .then((list) => {
        const tbody = document.getElementById("rules-tbody");
        tbody.innerHTML = (list || []).map((r) => `<tr><td>${r.id}</td><td>${escapeHtml(r.name)}</td><td>${r.port ?? "any"}</td><td>${escapeHtml((r.payload_regex || "").slice(0, 30))}</td><td>${r.enabled ? "yes" : "no"}</td></tr>`).join("");
      })
      .catch(() => {});
  }
  function loadRuleMatches() {
    fetch(`${API}/rules/matches?limit=50`)
      .then((r) => r.json())
      .then((list) => {
        const tbody = document.getElementById("rule-matches-tbody");
        tbody.innerHTML = (list || []).map((m) => `<tr><td>${m.id}</td><td>${m.rule_id}</td><td>${escapeHtml(m.src_ip)}:${m.src_port}</td><td>${escapeHtml(m.dst_ip)}:${m.dst_port}</td><td>${escapeHtml(m.matched_at || "")}</td></tr>`).join("");
      })
      .catch(() => {});
  }
  document.getElementById("btn-rule-add").addEventListener("click", () => {
    const name = document.getElementById("rule-name").value.trim();
    const regex = document.getElementById("rule-regex").value.trim() || null;
    const portVal = document.getElementById("rule-port").value.trim();
    const port = portVal ? parseInt(portVal, 10) : null;
    if (!name) return;
    fetch(`${API}/rules`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, payload_regex: regex, port, protocol: null, description: null, enabled: true }),
    })
      .then((r) => r.json())
      .then(() => { loadRules(); document.getElementById("rule-name").value = ""; document.getElementById("rule-regex").value = ""; document.getElementById("rule-port").value = ""; })
      .catch((e) => (statusEl.textContent = "Error: " + e.message));
  });

  // --- Honeypot panel ---
  function loadHoneypotEvents() {
    fetch(`${API}/honeypot/events?limit=50`)
      .then((r) => r.json())
      .then((list) => {
        const tbody = document.getElementById("honeypot-events-tbody");
        tbody.innerHTML = (list || []).map((e) => `<tr><td>${e.id}</td><td>${e.port}</td><td>${e.protocol}</td><td>${escapeHtml(e.src_ip)}:${e.src_port}</td><td>${escapeHtml(e.received_at || "")}</td><td>${escapeHtml((e.payload_snippet || "").slice(0, 40))}</td></tr>`).join("");
      })
      .catch(() => {});
  }
  document.getElementById("btn-honeypot-start").addEventListener("click", () => {
    const portsStr = document.getElementById("honeypot-ports").value.trim();
    const ports = portsStr.split(",").map((p) => parseInt(p.trim(), 10)).filter((n) => !isNaN(n));
    if (!ports.length) return;
    fetch(`${API}/honeypot/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ports, protocols: null }),
    })
      .then((r) => r.json())
      .then((d) => { statusEl.textContent = d.message || "Started"; loadHoneypotEvents(); })
      .catch((e) => (statusEl.textContent = "Error: " + e.message));
  });
  document.getElementById("btn-honeypot-stop").addEventListener("click", () => {
    fetch(`${API}/honeypot/stop`, { method: "POST" })
      .then((r) => r.json())
      .then((d) => { statusEl.textContent = d.message || "Stopped"; })
      .catch((e) => (statusEl.textContent = "Error: " + e.message));
  });

  // --- Security panel ---
  document.getElementById("btn-security-scan").addEventListener("click", () => {
    const target = document.getElementById("security-target").value.trim();
    if (!target) return;
    statusEl.textContent = "Scanning...";
    fetch(`${API}/security-scan?target=${encodeURIComponent(target)}`)
      .then((r) => r.json())
      .then((d) => {
        const tbody = document.getElementById("security-findings-tbody");
        tbody.innerHTML = (d.findings || []).map((f) => `<tr><td>${f.port}</td><td>${escapeHtml(f.severity)}</td><td>${escapeHtml(f.message)}</td></tr>`).join("");
        statusEl.textContent = `Found ${(d.findings || []).length} finding(s)`;
      })
      .catch((e) => (statusEl.textContent = "Error: " + e.message));
  });
})();

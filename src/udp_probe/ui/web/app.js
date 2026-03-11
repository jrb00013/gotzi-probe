(function () {
  const API = "/api";
  const packetTbody = document.getElementById("packet-tbody");
  const detailContent = document.getElementById("detail-content");
  const hexContent = document.getElementById("hex-content");
  const statusEl = document.getElementById("status");
  const filterPort = document.getElementById("filter-port");
  const filterIp = document.getElementById("filter-ip");
  const btnApply = document.getElementById("btn-apply");
  const btnClear = document.getElementById("btn-clear");

  let selectedIndex = null;
  let pollTimer = null;

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
      detailContent.innerHTML = '<p class="muted">Select a packet</p>';
      hexContent.innerHTML = '<p class="muted">Select a packet</p>';
      selectedIndex = null;
      statusEl.textContent = "Cleared";
    });
  }

  function renderPacketList(data) {
    const rows = packetTbody.querySelectorAll("tr");
    const existing = new Set(Array.from(rows).map((r) => r.dataset.index));
    const packets = data.packets || [];
    packets.forEach((p) => {
      if (existing.has(String(p.index))) return;
      existing.add(String(p.index));
      const tr = document.createElement("tr");
      tr.dataset.index = p.index;
      tr.innerHTML = `
        <td>${p.index}</td>
        <td>${escapeHtml(p.time)}</td>
        <td>${escapeHtml(p.src_ip)}</td>
        <td>${escapeHtml(p.dest_ip)}</td>
        <td>${p.src_port}</td>
        <td>${p.dest_port}</td>
        <td>${p.length}</td>
        <td>${escapeHtml(p.info)}</td>
      `;
      tr.addEventListener("click", () => selectPacket(p.index));
      packetTbody.appendChild(tr);
    });
    if (data.total !== undefined) statusEl.textContent = `Packets: ${data.total}`;
  }

  function escapeHtml(s) {
    if (s == null) return "";
    const div = document.createElement("div");
    div.textContent = s;
    return div.innerHTML;
  }

  function selectPacket(index) {
    selectedIndex = index;
    document.querySelectorAll(".packet-table tbody tr.selected").forEach((r) => r.classList.remove("selected"));
    const row = document.querySelector(`.packet-table tbody tr[data-index="${index}"]`);
    if (row) row.classList.add("selected");

    fetchPacket(index).then((p) => {
      if (!p) return;
      detailContent.innerHTML = renderDetail(p);
      hexContent.innerHTML = renderHexDump(p.hex_dump || []);
    });
  }

  function renderDetail(p) {
    return `
      <div class="section">
        <div class="section-title">Frame</div>
        <div class="field"><span class="field-name">Index:</span> ${p.index}</div>
        <div class="field"><span class="field-name">Time:</span> ${escapeHtml(p.time)}</div>
      </div>
      <div class="section">
        <div class="section-title">Internet Protocol</div>
        <div class="field"><span class="field-name">Source:</span> ${escapeHtml(p.src_ip)}</div>
        <div class="field"><span class="field-name">Destination:</span> ${escapeHtml(p.dest_ip)}</div>
      </div>
      <div class="section">
        <div class="section-title">User Datagram Protocol</div>
        <div class="field"><span class="field-name">Source port:</span> ${p.src_port}</div>
        <div class="field"><span class="field-name">Destination port:</span> ${p.dest_port}</div>
        <div class="field"><span class="field-name">Length:</span> ${p.length}</div>
        <div class="field"><span class="field-name">Checksum:</span> ${escapeHtml(p.checksum || "")}</div>
      </div>
      <div class="section">
        <div class="section-title">Payload</div>
        <div class="field">${escapeHtml(p.payload_preview || p.info || "")}</div>
      </div>
    `;
  }

  function renderHexDump(lines) {
    if (!lines || !lines.length) return '<p class="muted">No data</p>';
    return lines
      .map(
        (l) =>
          `<div class="hex-line"><span class="hex-offset">${l.offset}</span><span class="hex-bytes">${l.hex}</span><span class="hex-ascii">${l.ascii}</span></div>`
      )
      .join("");
  }

  function poll() {
    fetchPackets()
      .then(renderPacketList)
      .catch(() => (statusEl.textContent = "Error"));
  }

  btnApply.addEventListener("click", () => {
    packetTbody.innerHTML = "";
    poll();
  });

  btnClear.addEventListener("click", () => {
    clearPackets();
  });

  poll();
  pollTimer = setInterval(poll, 500);
})();

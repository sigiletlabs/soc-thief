// Soc Thief console: renders /api/snapshot with DOM APIs and textContent only.
// Every string in the snapshot is attacker-controlled alert text. Never parse it as HTML.
"use strict";

(function () {
  const POLL_MS = 2000;
  const CATEGORY_RANK = { failed: 0, new: 1, spike: 2, recurring: 3 };
  const KNOWN_STATUS = ["ok", "attention", "failed"];

  const state = {
    generation: -1,
    snapshot: null,
    view: "overview",
    selected: null, // group id
    offline: false,
  };

  const $ = (id) => document.getElementById(id);

  // Create an element with an optional class and text. Text always goes through textContent.
  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function str(v) {
    return typeof v === "string" ? v : "";
  }

  function num(v) {
    return typeof v === "number" && isFinite(v) ? v : 0;
  }

  function fmt(n) {
    return num(n).toLocaleString("en-AU");
  }

  function shortTime(t) {
    t = str(t);
    return t.length >= 16 && t[10] === "T" ? t.slice(0, 10) + " " + t.slice(11, 16) : t;
  }

  function hourOf(t) {
    t = str(t);
    return t.length >= 13 && t[10] === "T" ? t.slice(11, 13) : "??";
  }

  function statusClass(s) {
    return "st-" + (KNOWN_STATUS.includes(s) ? s : "unknown");
  }

  function setStatus(node, s) {
    node.textContent = str(s) ? str(s).toUpperCase() : "UNKNOWN";
    node.className = node.className.replace(/\bst-\w+/g, "").trim() + " " + statusClass(s);
  }

  function list(v) {
    return Array.isArray(v) ? v : [];
  }

  // ---------- views ----------

  function showView(name) {
    state.view = name;
    for (const b of document.querySelectorAll(".tab")) {
      b.classList.toggle("active", b.dataset.view === name);
      b.setAttribute("aria-selected", b.dataset.view === name ? "true" : "false");
    }
    for (const v of ["overview", "groups", "health", "history"]) {
      $("view-" + v).hidden = v !== name || !state.snapshot;
    }
  }

  function renderHeader(api) {
    const s = api.snapshot;
    const fresh = $("freshness");
    fresh.className = "pill " + str(api.state);
    fresh.textContent = { live: "● live", stale: "stale", unavailable: "no snapshot" }[api.state] || "unknown";

    const stale = $("stale");
    if (api.state === "stale") {
      stale.hidden = false;
      stale.textContent = "STALE: showing the last good snapshot. Reload failed: " + str(api.error);
    } else {
      stale.hidden = true;
    }

    $("demo").hidden = !(s && s.source === "demo");
    const paged = s ? list(s.breaches).filter((b) => b && b.paged).length : 0;
    $("paged").hidden = paged === 0;
    $("paged").textContent = paged + (paged === 1 ? " paged breach" : " paged breaches");
    document.title = (paged ? "(" + paged + " PAGED) " : "") + "Soc Thief Console";

    if (!s) {
      $("win-range").textContent = "-";
      $("generated").textContent = "-";
      setStatus($("health-top"), "");
      return;
    }
    const w = s.window || {};
    $("win-range").textContent = shortTime(w.start) + " → " + shortTime(w.end);
    $("win-tz").textContent = str(s.timezone);
    $("generated").textContent = shortTime(s.generated_at);
    setStatus($("health-top"), (s.health || {}).status);
  }

  function renderError(api) {
    const err = $("error");
    if (api.snapshot) {
      err.hidden = true;
      return;
    }
    err.hidden = false;
    $("error-file").textContent = str(api.file) || "(unknown)";
    $("error-text").textContent = str(api.error) || "no snapshot loaded";
  }

  function renderOverview(s) {
    const w = s.window || {};
    const groups = list(s.groups);
    $("t-events").textContent = fmt(w.events);
    $("t-groups").textContent = fmt(w.groups);
    $("t-dups").textContent = fmt(w.duplicates);
    $("t-muted").textContent = fmt(w.muted_by_tuning);
    $("t-deliver").textContent = fmt(groups.filter((g) => g && g.decision && g.decision.delivery_required).length);
    setStatus($("t-health"), (s.health || {}).status);

    // Timeline: events on one scale, delivery-required on its own scale below it.
    const tl = $("timeline");
    clear(tl);
    const buckets = list(s.timeline);
    const evMax = Math.max(1, ...buckets.map((b) => num(b && b.events)));
    const drMax = Math.max(1, ...buckets.map((b) => num(b && b.delivery_required)));
    const every = buckets.length > 12 ? 3 : 1;
    buckets.forEach((b, i) => {
      const col = el("div", "hour");
      col.title = shortTime(b.start) + "  events " + fmt(b.events) + "  delivery required " + fmt(b.delivery_required);
      const ev = el("div", "ev");
      const evBar = el("i");
      evBar.style.height = ((num(b.events) / evMax) * 100).toFixed(1) + "%";
      ev.appendChild(evBar);
      const dr = el("div", "dr");
      const drBar = el("i");
      const drH = (num(b.delivery_required) / drMax) * 100;
      drBar.style.height = (num(b.delivery_required) > 0 ? Math.max(drH, 4) : 0).toFixed(1) + "%";
      dr.appendChild(drBar);
      col.append(ev, dr, el("div", "hh", i % every === 0 ? hourOf(b.start) : ""));
      tl.appendChild(col);
    });
    if (buckets.length === 0) tl.appendChild(el("p", "dim", "No timeline in this snapshot."));

    const ul = $("breaches");
    clear(ul);
    const breaches = list(s.breaches);
    $("breach-panel").classList.toggle("hot", breaches.some((b) => b && b.paged));
    if (breaches.length === 0) {
      ul.appendChild(el("li", "green", "No breach signals in this window."));
    }
    for (const b of breaches) {
      if (!b) continue;
      const li = el("li", b.paged ? "paged" : "seen");
      li.append(
        el("span", b.paged ? "badge alarm" : "badge", b.paged ? "PAGED" : "seen"),
        el("span", "name", str(b.name)),
        el("span", "dim", str(b.agent)),
        el("span", "dim", shortTime(b.at)),
      );
      for (const sig of list(b.signals)) li.appendChild(el("span", "chip", str(sig)));
      ul.appendChild(li);
    }
  }

  function matches(g, needle) {
    if (!needle) return true;
    const hay = [g.rule_id, g.rule_description, g.id, g.category, g.tuning, g.decision && g.decision.reason]
      .concat(list(g.agents), list(g.breach_signals));
    if (g.model) hay.push(g.model.verdict, ...list(g.model.tags));
    return hay.some((h) => str(h).toLowerCase().includes(needle));
  }

  function digestCmp(a, b) {
    const ra = CATEGORY_RANK[a.category] ?? 4;
    const rb = CATEGORY_RANK[b.category] ?? 4;
    return ra - rb || num(b.level) - num(a.level) || num(b.count) - num(a.count);
  }

  function decisionCell(g) {
    const d = g.decision || {};
    const bang = d.health_failure ? "!" : "";
    if (d.delivery_required) return el("span", d.health_failure ? "dec-health" : "dec-deliver", "DELIVER" + bang);
    return el("span", d.health_failure ? "dec-health" : "dec-held", "held" + bang);
  }

  function visibleGroups(s) {
    const needle = $("filter").value.trim().toLowerCase();
    const cat = $("category").value;
    return list(s.groups)
      .filter((g) => g && typeof g === "object")
      .filter((g) => !cat || g.category === cat)
      .filter((g) => matches(g, needle))
      .sort(digestCmp);
  }

  function renderGroups(s) {
    const rows = $("group-rows");
    clear(rows);
    const groups = visibleGroups(s);
    $("group-count").textContent = groups.length + " of " + list(s.groups).length + " groups, digest order";
    const total = num((s.window || {}).groups);
    const capped = $("group-capped");
    capped.hidden = !(total > list(s.groups).length);
    capped.textContent = "showing " + fmt(list(s.groups).length) + " of " + fmt(total) + " groups";
    if (state.selected !== null && !groups.some((g) => g.id === state.selected)) state.selected = null;

    for (const g of groups) {
      const tr = el("tr");
      tr.tabIndex = 0;
      if (g.id === state.selected) tr.classList.add("sel");
      const cat = str(g.category) || "unknown";
      const tuning = str(g.tuning) || "none";
      const agents = list(g.agents);
      const tuneCell = el("td");
      tuneCell.appendChild(el("span", "tune-" + (["none", "low", "mute"].includes(tuning) ? tuning : "unknown"), tuning));
      if (g.protected) tuneCell.appendChild(el("span", "prot", "PROT"));
      const decCell = el("td");
      decCell.appendChild(decisionCell(g));
      tr.append(
        el("td", "cat-" + (cat in CATEGORY_RANK ? cat : "unknown"), cat.toUpperCase()),
        el("td", null, num(g.level)),
        el("td", null, str(g.rule_id)),
        el("td", "desc" + (str(g.rule_description) ? "" : " dim"), str(g.rule_description) || "(no description in state)"),
        el("td", "r", fmt(g.count)),
        el("td", null, agents.length === 0 ? "-" : agents.length === 1 ? str(agents[0]) : str(agents[0]) + " +" + (agents.length - 1)),
        tuneCell,
        decCell,
      );
      const pick = () => {
        state.selected = g.id;
        renderGroups(s);
        renderDetail(g);
      };
      tr.addEventListener("click", pick);
      tr.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          pick();
        }
      });
      rows.appendChild(tr);
    }
    if (groups.length === 0) {
      const tr = el("tr");
      const td = el("td", "dim", "No groups match.");
      td.colSpan = 8;
      tr.appendChild(td);
      rows.appendChild(tr);
    }
    const sel = groups.find((g) => g.id === state.selected);
    if (sel) renderDetail(sel);
    else {
      const d = $("detail");
      clear(d);
      d.appendChild(el("p", "dim", "Select a group to see why it was delivered."));
    }
  }

  function dl(pairs) {
    const d = el("dl");
    for (const [k, v] of pairs) {
      d.appendChild(el("dt", null, k));
      const dd = el("dd");
      if (v instanceof Node) dd.appendChild(v);
      else dd.textContent = String(v);
      d.appendChild(dd);
    }
    return d;
  }

  function renderDetail(g) {
    const box = $("detail");
    clear(box);
    const d = g.decision || {};
    box.appendChild(el("h2", null, "Group detail"));
    box.appendChild(el("h3", null, "Rule " + str(g.rule_id) + " · " + (str(g.rule_description) || "(no description in state)")));

    const prot = g.protected
      ? el("span", "green", "YES — tuning can never hide this group")
      : el("span", "dim", "no");
    const signals = el("span");
    if (list(g.breach_signals).length === 0) signals.appendChild(el("span", "dim", "none"));
    for (const sig of list(g.breach_signals)) signals.appendChild(el("span", "chip red", str(sig)));

    box.appendChild(
      dl([
        ["Decision", decisionCell(g)],
        ["Reason", str(d.reason) || "-"],
        ["Health failure", d.health_failure ? el("span", "red", "YES") : el("span", "dim", "no")],
        ["Protected", prot],
        ["Tuning", str(g.tuning) || "none"],
        ["Category", (str(g.category) || "unknown").toUpperCase()],
        ["Level", num(g.level)],
        ["Count", fmt(g.count)],
        ["Seen", shortTime(g.first_seen) + " → " + shortTime(g.last_seen)],
        ["Agents", list(g.agents).map(str).join(", ") || "-"],
        ["Breach signals", signals],
        ["Case ID", str(g.id)],
      ]),
    );

    const adv = el("div", "advice");
    adv.appendChild(el("p", "tag", "Model advice · advisory — cannot suppress"));
    const m = g.model;
    if (!m) {
      adv.appendChild(el("p", "dim", "No model ran for this group."));
    } else {
      const tags = el("span");
      for (const t of list(m.tags)) tags.appendChild(el("span", "chip", str(t)));
      adv.appendChild(
        dl([
          ["Model", str(m.name) || "-"],
          ["Verdict", str(m.verdict) || "-"],
          ["Confidence", typeof m.confidence === "number" ? m.confidence.toFixed(2) : "-"],
          ["Tags", tags],
          ["Summary", str(m.summary) || "-"],
        ]),
      );
    }
    box.appendChild(adv);
  }

  function renderHealth(s) {
    const h = s.health || {};
    setStatus($("health-overall"), h.status);
    const rows = $("health-rows");
    clear(rows);
    for (const c of list(h.checks)) {
      if (!c) continue;
      const tr = el("tr");
      tr.append(el("td", null, str(c.name)), el("td", "status " + statusClass(c.status), str(c.status).toUpperCase() || "UNKNOWN"), el("td", null, str(c.detail)));
      rows.appendChild(tr);
    }
  }

  function renderHistory(s) {
    const rows = $("history-rows");
    clear(rows);
    for (const r of list(s.history)) {
      if (!r) continue;
      const tr = el("tr");
      tr.append(
        el("td", null, shortTime(r.start)),
        el("td", null, shortTime(r.end)),
        el("td", "r", fmt(r.events)),
        el("td", "r", fmt(r.groups)),
        el("td", r.delivered ? "green" : "red", r.delivered ? "yes" : "NO"),
        el("td", r.health_failure ? "red" : "green", r.health_failure ? "FAILED" : "ok"),
      );
      rows.appendChild(tr);
    }
    if (list(s.history).length === 0) {
      const tr = el("tr");
      const td = el("td", "dim", "No earlier windows.");
      td.colSpan = 6;
      tr.appendChild(td);
      rows.appendChild(tr);
    }
  }

  function render(api) {
    state.snapshot = api.snapshot || null;
    renderHeader(api);
    renderError(api);
    if (state.snapshot) {
      renderOverview(state.snapshot);
      renderGroups(state.snapshot);
      renderHealth(state.snapshot);
      renderHistory(state.snapshot);
    }
    showView(state.view);
  }

  async function poll() {
    try {
      const res = await fetch("/api/snapshot", { cache: "no-store", credentials: "same-origin" });
      if (!res.ok) throw new Error("HTTP " + res.status);
      const api = await res.json();
      if (api && (api.generation !== state.generation || state.offline)) {
        state.generation = api.generation;
        state.offline = false;
        render(api);
      }
    } catch (e) {
      state.offline = true;
      const fresh = $("freshness");
      fresh.className = "pill stale";
      fresh.textContent = "console offline";
    }
  }

  function init() {
    for (const b of document.querySelectorAll(".tab")) {
      b.addEventListener("click", () => showView(b.dataset.view));
    }
    $("filter").addEventListener("input", () => state.snapshot && renderGroups(state.snapshot));
    $("category").addEventListener("change", () => state.snapshot && renderGroups(state.snapshot));
    document.addEventListener("keydown", (e) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLSelectElement) {
        if (e.key === "Escape") e.target.blur();
        return;
      }
      const views = ["overview", "groups", "health", "history"];
      if (e.key >= "1" && e.key <= "4") showView(views[Number(e.key) - 1]);
      else if (e.key === "/") {
        e.preventDefault();
        showView("groups");
        $("filter").focus();
      } else if (e.key === "Escape" && state.selected !== null) {
        state.selected = null;
        if (state.snapshot) renderGroups(state.snapshot);
      }
    });
    poll();
    setInterval(poll, POLL_MS);
  }

  document.addEventListener("DOMContentLoaded", init);
})();

"use strict";
const $ = (id) => document.getElementById(id);

/* ---------------- Scan ---------------- */
$("scanForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = $("email").value.trim();
  const password = $("password").value;
  const btn = $("scanBtn");
  const status = $("scanStatus");
  btn.disabled = true;
  btn.dataset.label = btn.textContent;
  btn.innerHTML = '<span class="spinner"></span>Scanning…';
  status.hidden = false;
  status.className = "status";
  status.textContent = "Scanning breach databases…";
  $("scanResults").hidden = true;
  try {
    const resp = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || "Scan failed");
    renderScan(data);
    status.hidden = true;
  } catch (err) {
    status.className = "status err";
    status.textContent = err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = btn.dataset.label || "Scan my data";
    $("password").value = "";
  }
});

function scoreLabel(score) {
  if (score === null || score === undefined) return "Scan incomplete — one source could not be reached.";
  if (score === 0) return "No exposure found in the databases checked. Still work through the Removal Centre — brokers can hold data that was never in a public breach.";
  if (score < 35) return "Some exposure. Change passwords for the breached sites below and start broker removals.";
  if (score < 70) return "Serious exposure. Change breached passwords today, turn on 2FA, and work the Removal Centre.";
  return "Critical exposure. Treat passwords as compromised: change them everywhere, turn on 2FA, and start removals now.";
}

function renderScan(d) {
  $("scanResults").hidden = false;
  if (d.exposure_score === null || d.exposure_score === undefined) {
    $("scoreNum").textContent = "–";
  } else {
    const target = d.exposure_score, numEl = $("scoreNum"), t0 = performance.now();
    const tick = (t) => {
      const p = Math.min(1, (t - t0) / 900);
      numEl.textContent = Math.round(target * (1 - Math.pow(1 - p, 3)));
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }
  const ring = $("scoreRing");
  if (ring) {
    const s = d.exposure_score;
    const C = 351.8;
    ring.style.strokeDashoffset = s === null ? C : String(C * (1 - s / 100));
    ring.style.stroke = s === null ? "#4f46e5" : s === 0 ? "#15803d" : s < 35 ? "#b45309" : s < 70 ? "#c2410c" : "#b91c1c";
    const num = $("scoreNum");
    num.className = s === null ? "" : s === 0 ? "sev-low" : s < 35 ? "sev-med" : s < 70 ? "sev-high" : "sev-crit";
  }
  $("scoreText").textContent = scoreLabel(d.exposure_score);
  $("sourceText").textContent = "Sources: " + d.sources.join(" · ");
  try {
    const key = "lg_last_scan";
    const prev = JSON.parse(localStorage.getItem(key) || "null");
    if (prev && prev.email === (d.email || "") && typeof d.breach_count === "number" && typeof prev.count === "number") {
      const diff = d.breach_count - prev.count;
      const when = new Date(prev.ts).toLocaleDateString();
      $("sourceText").textContent += " · Since your last scan (" + when + "): " + (diff > 0 ? "+" + diff + " new breach(es) ⚠️" : diff < 0 ? Math.abs(diff) + " fewer breach(es) ✅" : "no change ✅");
    }
    localStorage.setItem(key, JSON.stringify({ email: d.email || "", count: d.breach_count, score: d.exposure_score, ts: Date.now() }));
  } catch (e) { /* localStorage unavailable — skip delta */ }
  const list = $("breachList");
  list.innerHTML = "";
  if (d.breach_error) {
    list.innerHTML = "<p class='hint'>" + d.breach_error + "</p>";
  } else if (!d.breach_count) {
    list.innerHTML = "<p>✅ This email was not found in the breach database checked.</p>";
  } else {
    const p = document.createElement("p");
    p.textContent = "Found in " + d.breach_count + " breach(es):";
    list.appendChild(p);
    d.breaches.forEach((b, i) => {
      const s = document.createElement("span");
      s.className = "breachChip";
      s.style.animationDelay = Math.min(i * 35, 700) + "ms";
      s.textContent = b;
      list.appendChild(s);
    });
  }
  const types = d.analytics && d.analytics.exposed_data ? d.analytics.exposed_data : [];
  if (types.length) {
    $("exposedBox").hidden = false;
    const box = $("exposedTags");
    box.innerHTML = "";
    types.forEach((t) => {
      const s = document.createElement("span");
      s.className = "tag";
      s.textContent = t;
      box.appendChild(s);
    });
  } else {
    $("exposedBox").hidden = true;
  }
  if (d.password_pwned_count !== null && d.password_pwned_count !== undefined) {
    $("passwordBox").hidden = false;
    $("passwordText").textContent = d.password_pwned_count > 0
      ? "⚠️ This password has appeared " + d.password_pwned_count.toLocaleString() + " times in known breaches. Do not use it anywhere — change it now."
      : "✅ This password was not found in the Pwned Passwords database. (That is not a guarantee — use a unique password per site anyway.)";
  } else {
    $("passwordBox").hidden = true;
  }
  const steps = [];
  if (d.breach_count) steps.push("Change the password on every breached site above — and anywhere you reused the same password.");
  steps.push("Turn on two-factor authentication (authenticator app) on your email first, then banking and social accounts.");
  steps.push("Work through the Removal Centre below to delete your data from brokers selling it.");
  steps.push("Use Google “Results about you” (section 3) to hide your phone/address from Google Search.");
  const ol = $("nextSteps");
  ol.innerHTML = "";
  steps.forEach((s) => {
    const li = document.createElement("li");
    li.textContent = s;
    ol.appendChild(li);
  });
  if ($("lgEmail") && !$("lgEmail").value) $("lgEmail").value = d.email;
  if ($("agEmail") && !$("agEmail").value) $("agEmail").value = d.email;
}

/* ---------------- Letter generator ---------------- */
const LAWS = {
  dpdp: {
    cite: "Section 12 of India's Digital Personal Data Protection Act, 2023",
    ask: "erase my personal data, and cause any processor you shared it with to erase it as well, unless retention is required by law",
  },
  gdpr: {
    cite: "Article 17 of the General Data Protection Regulation (GDPR)",
    ask: "erase my personal data without undue delay, and inform any third parties you disclosed it to of this erasure request",
  },
  ccpa: {
    cite: "the California Consumer Privacy Act (CCPA), including my right to delete and to opt out of the sale of my personal information",
    ask: "delete my personal data, direct your service providers to delete it, and stop selling or sharing it",
  },
};

function makeLetter(brokerName) {
  const name = $("lgName").value.trim() || "[Your full name]";
  const email = $("lgEmail").value.trim() || "[Your email]";
  const city = $("lgCity").value.trim() || "[Your city, country]";
  const law = LAWS[$("lgLaw").value];
  const target = brokerName || "your company";
  return [
    "To: Data Protection / Privacy Team, " + target,
    "Subject: Request for erasure of my personal data",
    "",
    "Dear Sir/Madam,",
    "",
    "My name is " + name + ". I am writing to exercise my right under " + law.cite + ".",
    "",
    "I request that you " + law.ask + ". This includes, but is not limited to, any profile,",
    "listing or record associated with:",
    "",
    "  Name:  " + name,
    "  Email: " + email,
    "  Location: " + city,
    "",
    "Please also add my details to your suppression list so my data is not re-added",
    "from your data sources in the future.",
    "",
    "Please confirm in writing, to the email address above, once the erasure is",
    "complete, and tell me if you need any information from me to verify my identity.",
    "",
    "Thank you.",
    "",
    name,
    email,
  ].join("\n");
}

function showLetter(brokerName) {
  const out = $("letterOut");
  out.value = makeLetter(brokerName);
  out.hidden = false;
  $("letterBtns").hidden = false;
  out.scrollIntoView({ behavior: "smooth", block: "center" });
}
$("genericLetterBtn").addEventListener("click", () => showLetter(null));
$("copyLetterBtn").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("letterOut").value); $("copyLetterBtn").textContent = "Copied ✓"; }
  catch (e) { $("letterOut").select(); document.execCommand("copy"); }
  setTimeout(() => { $("copyLetterBtn").textContent = "Copy letter"; }, 1600);
});
$("downloadLetterBtn").addEventListener("click", () => {
  const blob = new Blob([$("letterOut").value], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "data-erasure-request.txt";
  a.click();
  URL.revokeObjectURL(a.href);
});

/* ---------------- Brokers ---------------- */
const LS_KEY = "leakguard-broker-status-v1";
function getStatuses() {
  try { return JSON.parse(localStorage.getItem(LS_KEY) || "{}"); } catch (e) { return {}; }
}
function setStatus(name, value) {
  const s = getStatuses();
  s[name] = value;
  localStorage.setItem(LS_KEY, JSON.stringify(s));
  renderProgress();
}
function renderProgress() {
  const s = getStatuses();
  const vals = Object.values(s);
  const done = vals.filter((v) => v === "removed").length;
  const sent = vals.filter((v) => v === "sent").length;
  $("brokerProgress").textContent = "Progress: " + done + " removed · " + sent + " requested · " + vals.filter((v) => v && v !== "removed" && v !== "sent").length + " other — out of the list below.";
  const bar = $("brokerBar");
  if (bar) {
    const total = (window.__brokerTotal || vals.length || 40);
    bar.style.width = Math.round(100 * done / Math.max(1, total)) + "%";
  }
}
async function loadBrokers() {
  try {
    const resp = await fetch("/api/brokers");
    const data = await resp.json();
    window.__brokerTotal = data.brokers.length;
    const statuses = getStatuses();
    const wrap = $("brokerList");
    data.brokers.forEach((b) => {
      const div = document.createElement("div");
      div.className = "broker";
      const head = document.createElement("div");
      head.className = "bhead";
      const title = document.createElement("div");
      title.innerHTML = "";
      const nm = document.createElement("span");
      nm.className = "bname";
      nm.textContent = b.name;
      const meta = document.createElement("span");
      meta.className = "bmeta";
      meta.textContent = " · " + b.type + " · " + b.region;
      title.appendChild(nm); title.appendChild(meta);
      const sel = document.createElement("select");
      [["", "Not started"], ["sent", "Request sent"], ["removed", "Removed ✓"], ["rejected", "Rejected"], ["notfound", "They didn't have me"]]
        .forEach(([v, t]) => {
          const o = document.createElement("option");
          o.value = v; o.textContent = t;
          sel.appendChild(o);
        });
      sel.value = statuses[b.name] || "";
      if (sel.value === "removed") div.classList.add("st-removed");
      sel.addEventListener("change", () => {
        setStatus(b.name, sel.value);
        div.classList.toggle("st-removed", sel.value === "removed");
      });
      head.appendChild(title); head.appendChild(sel);
      const method = document.createElement("p");
      method.className = "hint";
      method.textContent = b.method + (b.contact_email ? " · ✉ Or email your request: " + b.contact_email : "");
      const btns = document.createElement("div");
      btns.className = "bbtns";
      const a = document.createElement("a");
      a.className = "btnLink";
      a.href = b.optout_url; a.target = "_blank"; a.rel = "noopener";
      a.textContent = "Open opt-out →";
      const lb = document.createElement("button");
      lb.type = "button";
      lb.textContent = "Letter for this broker";
      lb.addEventListener("click", () => showLetter(b.name));
      btns.appendChild(a); btns.appendChild(lb);
      div.appendChild(head); div.appendChild(method); div.appendChild(btns);
      wrap.appendChild(div);
    });
    renderProgress();
  } catch (e) {
    $("brokerList").innerHTML = "<p class='hint'>Broker list failed to load.</p>";
  }
}
loadBrokers();

/* ---------------- Agent Mode (zero-token) ---------------- */
function agentProfile() {
  return {
    full_name: $("agName").value.trim(),
    email: $("agEmail").value.trim(),
    phone: $("agPhone").value.trim(),
    city: $("agCity").value.trim(),
  };
}
$("planBtn").addEventListener("click", async () => {
  const profile = agentProfile();
  const btn = $("planBtn");
  btn.disabled = true;
  btn.textContent = "Building plan…";
  try {
    const resp = await fetch("/api/agent/plan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(profile),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || "Plan failed");
    $("laneStatus").textContent = data.free_lane && data.free_lane.configured
      ? (data.free_lane.reachable ? "Free lane: connected (your gateway)" : "Free lane: configured but not reachable — script mode continues")
      : "Free lane: not configured — pure script mode (0 tokens)";
    const wrap = $("planList");
    wrap.innerHTML = "";
    window.__plan = data.plan;
    data.plan.forEach((item) => {
      const div = document.createElement("div");
      div.className = "broker";
      const head = document.createElement("div");
      head.className = "bhead";
      const nm = document.createElement("span");
      nm.className = "bname";
      nm.textContent = item.broker;
      const meta = document.createElement("span");
      meta.className = "bmeta";
      meta.textContent = item.automation.replace("_", " ") + (item.needs.length ? " · needs: " + item.needs.join(", ").replace(/_/g, " ") : "");
      head.appendChild(nm); head.appendChild(meta);
      const flow = document.createElement("p");
      flow.className = "hint";
      flow.textContent = item.flow.join(" → ") + (item.contact_email ? " · ✉ Email channel: " + item.contact_email : "");
      const btns = document.createElement("div");
      btns.className = "bbtns";
      const probe = document.createElement("button");
      probe.type = "button";
      probe.textContent = "Probe live form";
      probe.addEventListener("click", () => probeBroker(item.broker, probe));
      const open = document.createElement("a");
      open.className = "btnLink";
      open.href = item.optout_url; open.target = "_blank"; open.rel = "noopener";
      open.textContent = "Open opt-out →";
      const search = document.createElement("a");
      search.className = "btnLink";
      search.href = item.search_url; search.target = "_blank"; search.rel = "noopener";
      search.textContent = "Find my listing";
      btns.appendChild(probe); btns.appendChild(open); btns.appendChild(search);
      div.appendChild(head); div.appendChild(flow); div.appendChild(btns);
      wrap.appendChild(div);
    });
    $("planBox").hidden = false;
    if (profile.email && !$("lgEmail").value) $("lgEmail").value = profile.email;
    if (profile.full_name && !$("lgName").value) $("lgName").value = profile.full_name;
  } catch (err) {
    $("laneStatus").textContent = err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = "Build my removal plan";
  }
});

async function probeBroker(broker, btn) {
  btn.disabled = true;
  btn.textContent = "Probing…";
  try {
    const resp = await fetch("/api/agent/probe", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ broker, profile: agentProfile(), deep: true }),
    });
    const d = await resp.json();
    if (!resp.ok) throw new Error(d.error || "Probe failed");
    $("probeBox").hidden = false;
    $("probeTitle").textContent = "Probe: " + d.broker;
    const out = $("probeOut");
    out.innerHTML = "";
    const lines = [];
    lines.push(d.reachable ? "✅ Page reachable (HTTP " + d.status + ")" : "⚠️ Not directly reachable (HTTP " + (d.status || "—") + ")");
    if (d.forms && d.forms.length) {
      d.forms.forEach((f, i) => {
        lines.push("Form " + (i + 1) + ": " + f.method + " → " + f.action);
        lines.push("Fields: " + (f.fields.map((x) => x.name || x.type).join(", ") || "none readable"));
        if (f.unmapped_fields && f.unmapped_fields.length) lines.push("Unmapped fields: " + f.unmapped_fields.join(", "));
      });
    }
    if (d.payload_preview && Object.keys(d.payload_preview).length) {
      lines.push("Agent can pre-fill: " + Object.entries(d.payload_preview).map(([k, v]) => k + " = " + v).join(" · "));
      lines.push(d.fillable ? "✅ This form is script-fillable." : "Form found, but a blocker stops auto-fill.");
    }
    (d.blockers || []).forEach((b) => lines.push("🚧 " + b));
    if (d.alt_probe) {
      lines.push("🔀 Alternate official URL: " + (d.alt_probe.reachable ? "reachable via relay, " + d.alt_probe.forms + " form(s)" : d.alt_probe.challenge ? "Cloudflare challenge there too" : "not reachable either"));
    }
    if (d.contact_email) {
      lines.push("✉ Email channel (works from any network): " + d.contact_email + " — generate the letter in the Removal Centre and send it with your listing URL.");
    }
    if (d.relay) {
      lines.push("📡 Relay reader: " + (d.relay.reachable ? "fetched the real page (" + (d.relay.title || "untitled") + ")" : d.relay.challenge ? "Cloudflare challenge even via relay" : "could not fetch it either"));
    }
    if (d.browser && d.browser.available) {
      lines.push("🌐 Browser check: " + (d.browser.reachable ? "page rendered (" + (d.browser.title || "untitled") + ")" : "could not render either") + (d.browser.challenge ? " — bot-check challenge shown" : ""));
    } else if (d.browser) {
      lines.push("🌐 Browser check: not available on this server (HTTP probe only)");
    }
    if (d.free_lane_used) lines.push("Free lane (your gateway) classified the unknown fields — 0 Claude tokens used.");
    lines.forEach((t) => {
      const p = document.createElement("p");
      p.className = "hint";
      p.style.color = "#2c2f36";
      p.textContent = t;
      out.appendChild(p);
    });
    $("probeBox").scrollIntoView({ behavior: "smooth", block: "center" });
  } catch (err) {
    $("probeBox").hidden = false;
    $("probeTitle").textContent = "Probe: " + broker;
    $("probeOut").innerHTML = "";
    const p = document.createElement("p");
    p.textContent = err.message;
    $("probeOut").appendChild(p);
  } finally {
    btn.disabled = false;
    btn.textContent = "Probe live form";
  }
}

/* ---------------- Google searches ---------------- */
$("gSearchBtn").addEventListener("click", () => {
  const name = $("gName").value.trim();
  const phone = $("gPhone").value.trim();
  const email = $("email").value.trim();
  const box = $("gLinks");
  box.innerHTML = "";
  if (!name && !phone && !email) {
    box.innerHTML = "<span class='tag'>Enter your name first</span>";
    return;
  }
  const queries = [];
  if (name) queries.push('"' + name + '"');
  if (name && phone) queries.push('"' + name + '" "' + phone + '"');
  if (phone) queries.push('"' + phone + '"');
  if (email) queries.push('"' + email + '"');
  if (name) queries.push('"' + name + '" address OR phone OR email');
  queries.forEach((q) => {
    const a = document.createElement("a");
    a.className = "tag";
    a.target = "_blank"; a.rel = "noopener";
    a.href = "https://www.google.com/search?q=" + encodeURIComponent(q);
    a.textContent = "Google: " + q;
    box.appendChild(a);
  });
});

/* ---------------- One-tap removal run ---------------- */
let runProbes = {};   // broker -> probe result
let runGroups = { ready: [], email: [], manual: [] };
let runPlan = [];     // plan items by broker name lookup

function planItem(broker) { return runPlan.find((p) => p.broker === broker) || {}; }

async function probeFast(broker, profile) {
  const resp = await fetch("/api/agent/probe", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ broker, profile, deep: false }),
  });
  const d = await resp.json();
  if (!resp.ok) throw new Error(d.error || "Probe failed");
  return d;
}

function runRow(name, metaText) {
  const div = document.createElement("div");
  div.className = "broker";
  const row = document.createElement("div");
  row.className = "runRow";
  const left = document.createElement("div");
  const nm = document.createElement("span");
  nm.className = "bname"; nm.textContent = name;
  const meta = document.createElement("span");
  meta.className = "bmeta"; meta.textContent = metaText || "";
  left.appendChild(nm); left.appendChild(meta);
  row.appendChild(left);
  div.appendChild(row);
  return { div, row };
}

$("runAllBtn").addEventListener("click", async () => {
  const profile = agentProfile();
  const btn = $("runAllBtn");
  if (!profile.full_name || !profile.email) {
    $("runStatus").textContent = "Fill in your full name and email in Agent Mode above first — the agent needs them to probe and pre-fill.";
    return;
  }
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Running…';
  $("runStatus").textContent = "Building your plan…";
  $("runTrack").hidden = false;
  $("runBar").style.width = "0%";
  try {
    if (!window.__plan) {
      const resp = await fetch("/api/agent/plan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(profile),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Plan failed");
      window.__plan = data.plan;
    }
    runPlan = window.__plan;
    runProbes = {};
    runGroups = { ready: [], email: [], manual: [] };
    let done = 0;
    const total = runPlan.length;
    const queue = runPlan.slice();
    async function worker() {
      while (queue.length) {
        const item = queue.shift();
        try {
          const probe = await probeFast(item.broker, profile);
          runProbes[item.broker] = probe;
          if (probe.fillable && probe.forms && probe.forms.length) runGroups.ready.push(item.broker);
          else if (item.contact_email) runGroups.email.push(item.broker);
          else runGroups.manual.push(item.broker);
        } catch (e) {
          runGroups.manual.push(item.broker);
          runProbes[item.broker] = { blockers: ["Probe failed: " + e.message] };
        }
        done++;
        $("runBar").style.width = Math.round(100 * done / total) + "%";
        $("runStatus").textContent = "Probed " + done + " of " + total + " brokers…";
      }
    }
    await Promise.all([worker(), worker(), worker()]);
    renderRunGroups();
    $("runStatus").textContent = "Done — " + runGroups.ready.length + " ready to submit · " + runGroups.email.length + " email requests · " + runGroups.manual.length + " need you.";
    $("runBox").hidden = false;
    $("runBox").scrollIntoView({ behavior: "smooth", block: "center" });
  } catch (err) {
    $("runStatus").textContent = err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = "Run everything for me";
  }
});

function renderRunGroups() {
  const statuses = getStatuses();
  // READY
  $("readyCount").textContent = runGroups.ready.length;
  const rl = $("readyList"); rl.innerHTML = "";
  runGroups.ready.forEach((broker) => {
    const probe = runProbes[broker];
    const fields = Object.keys(probe.payload_preview || {}).length;
    const { div, row } = runRow(broker, "form found · " + fields + " field(s) pre-filled" + (statuses[broker] === "sent" ? " · already sent" : ""));
    const b = document.createElement("button");
    b.type = "button"; b.textContent = "Submit";
    b.addEventListener("click", () => submitOne(broker, b, div));
    const btns = document.createElement("div"); btns.className = "bbtns"; btns.appendChild(b);
    row.appendChild(btns);
    rl.appendChild(div);
  });
  // EMAIL
  $("emailCount").textContent = runGroups.email.length;
  const el = $("emailList"); el.innerHTML = "";
  runGroups.email.forEach((broker) => {
    const item = planItem(broker);
    const { div, row } = runRow(broker, "✉ " + (item.contact_email || "") + (statuses[broker] === "sent" ? " · already sent" : ""));
    const b = document.createElement("button");
    b.type = "button"; b.textContent = "Send email request";
    b.addEventListener("click", () => sendEmailRequest(broker));
    const btns = document.createElement("div"); btns.className = "bbtns"; btns.appendChild(b);
    row.appendChild(btns);
    el.appendChild(div);
  });
  // MANUAL
  $("manualCount").textContent = runGroups.manual.length;
  const ml = $("manualList"); ml.innerHTML = "";
  runGroups.manual.forEach((broker) => {
    const probe = runProbes[broker] || {};
    const item = planItem(broker);
    const why = (probe.blockers && probe.blockers[0]) || ("needs: " + ((item.needs || []).join(", ").replace(/_/g, " ") || "manual steps"));
    const { div, row } = runRow(broker, "");
    const p = document.createElement("p");
    p.className = "hint"; p.textContent = "🚧 " + why;
    const open = document.createElement("a");
    open.className = "btnLink"; open.href = item.optout_url || "#"; open.target = "_blank"; open.rel = "noopener";
    open.textContent = "Open opt-out →";
    const btns = document.createElement("div"); btns.className = "bbtns"; btns.appendChild(open);
    row.appendChild(btns);
    div.appendChild(p);
    ml.appendChild(div);
  });
}

async function submitOne(broker, btn, card) {
  const probe = runProbes[broker];
  if (!probe || !probe.forms || !probe.forms.length) return { ok: false };
  const form = probe.forms[probe.forms.length - 1];
  if (btn) { btn.disabled = true; btn.textContent = "Submitting…"; }
  try {
    const resp = await fetch("/api/agent/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: true, broker, form_action: form.action, method: form.method, payload: probe.payload_preview || {} }),
    });
    const d = await resp.json();
    if (!resp.ok) throw new Error(d.error || "Submit failed");
    if (d.ok) {
      setStatus(broker, "sent");
      if (card) card.classList.add("st-removed");
      if (btn) btn.textContent = "✓ Submitted (HTTP " + d.status + ")";
      return { ok: true };
    }
    if (btn) btn.textContent = "✗ Broker answered HTTP " + (d.status || "—");
    return { ok: false };
  } catch (e) {
    if (btn) btn.textContent = "✗ " + e.message;
    return { ok: false };
  } finally {
    if (btn) btn.disabled = false;
  }
}

$("submitAllBtn").addEventListener("click", async () => {
  const btn = $("submitAllBtn");
  if (!$("confirmAll").checked) {
    $("submitAllStatus").textContent = "Tick the confirm box first — submissions are real and go to the brokers.";
    return;
  }
  btn.disabled = true;
  let ok = 0;
  for (const broker of runGroups.ready) {
    $("submitAllStatus").textContent = "Submitting " + broker + "… (" + ok + " done)";
    const r = await submitOne(broker, null, null);
    if (r.ok) ok++;
  }
  $("submitAllStatus").textContent = "Finished: " + ok + " of " + runGroups.ready.length + " submitted. Brokers usually confirm by email — check your inbox and click their confirmation links.";
  btn.disabled = false;
  renderRunGroups();
});

function sendEmailRequest(broker) {
  const item = planItem(broker);
  const profile = agentProfile();
  if (!$("lgName").value && profile.full_name) $("lgName").value = profile.full_name;
  if (!$("lgEmail").value && profile.email) $("lgEmail").value = profile.email;
  if (!$("lgCity").value && profile.city) $("lgCity").value = profile.city;
  const letter = makeLetter(broker);
  const subject = "Request for erasure of my personal data — " + broker;
  const a = document.createElement("a");
  a.href = "mailto:" + (item.contact_email || "") + "?subject=" + encodeURIComponent(subject) + "&body=" + encodeURIComponent(letter);
  document.body.appendChild(a);
  a.click();
  a.remove();
  setStatus(broker, "sent");
  renderRunGroups();
}

/* Guided queue over the manual group */
let queueItems = [], queueIdx = 0;
function showQueueItem() {
  if (queueIdx >= queueItems.length) {
    $("queueBox").hidden = true;
    $("queueStatus").textContent = "🎉 Guided queue finished — everything else is submitted or emailed. Check your inbox for broker confirmation links.";
    renderProgress();
    return;
  }
  const broker = queueItems[queueIdx];
  const item = planItem(broker);
  const probe = runProbes[broker] || {};
  $("queueBox").hidden = false;
  $("queueTitle").textContent = "Guided queue — " + (queueIdx + 1) + " of " + queueItems.length + ": " + broker;
  $("queueWhy").textContent = (probe.blockers && probe.blockers[0]) || "This one needs your hands — the agent prepared everything else.";
  const p = agentProfile();
  $("queueProfile").textContent = [p.full_name, p.email, p.phone, p.city].filter(Boolean).join(" · ");
  $("queueOpen").href = item.optout_url || "#";
  $("queueStatus").textContent = "";
}
$("queueBtn").addEventListener("click", () => {
  const statuses = getStatuses();
  queueItems = runGroups.manual.filter((b) => statuses[b] !== "removed" && statuses[b] !== "sent");
  queueIdx = 0;
  if (!queueItems.length) {
    $("queueStatus").textContent = runGroups.manual.length ? "All manual brokers are already marked done 🎉" : "Run everything first — the queue is built from the 'Needs you' group.";
    return;
  }
  showQueueItem();
  $("queueBox").scrollIntoView({ behavior: "smooth", block: "center" });
});
$("queueCopy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("queueProfile").textContent); $("queueStatus").textContent = "Details copied — paste them into the broker's form."; }
  catch (e) { $("queueStatus").textContent = "Copy blocked by the browser — long-press the details text to copy."; }
});
$("queueDone").addEventListener("click", () => {
  const broker = queueItems[queueIdx];
  if (broker) setStatus(broker, "removed");
  queueIdx++;
  showQueueItem();
});
$("queueSkip").addEventListener("click", () => { queueIdx++; showQueueItem(); });

/* ---------------- Reveal on scroll ---------------- */
(function () {
  const cards = document.querySelectorAll(".card");
  if (!("IntersectionObserver" in window)) return;
  const io = new IntersectionObserver((entries) => {
    entries.forEach((en) => {
      if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); }
    });
  }, { threshold: 0.06 });
  cards.forEach((c) => { c.classList.add("reveal"); io.observe(c); });
})();

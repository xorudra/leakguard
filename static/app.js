"use strict";
const $ = (id) => document.getElementById(id);

/* API errors are structured: {error: {code, message, request_id}}.
   Pull the human message out (falling back gracefully). */
function errMsg(data, fallback) {
  const e = data && data.error;
  if (!e) return fallback;
  return typeof e === "string" ? e : (e.message || fallback);
}

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
    if (!resp.ok) throw new Error(errMsg(data, "Scan failed"));
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
    ring.style.stroke = s === null ? "#1ed760" : s === 0 ? "#1ed760" : s < 35 ? "#ffa42b" : s < 70 ? "#ff7a45" : "#ff4d6d";
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
  steps.push("Go to Agent Mode below and press \"Remove my data everywhere\" — the agent submits removal requests to the brokers for you.");
  steps.push("Use Google “Results about you” (section 4) to hide your phone/address from Google Search.");
  const ol = $("nextSteps");
  ol.innerHTML = "";
  steps.forEach((s) => {
    const li = document.createElement("li");
    li.textContent = s;
    ol.appendChild(li);
  });
  if ($("lgEmail") && !$("lgEmail").value) $("lgEmail").value = d.email;
  if ($("agEmail") && !$("agEmail").value) $("agEmail").value = d.email;
  lastScanEmail = d.email || "";
  refreshSaveScanBox();
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
      sel.setAttribute("aria-label", "Removal progress for " + b.name);
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
    if (!resp.ok) throw new Error(errMsg(data, "Plan failed"));
    $("planStatus").textContent = "Plan ready: " + data.plan.length + " brokers — press the green button below to run everything automatically.";
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
    $("planStatus").textContent = err.message;
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
    if (!resp.ok) throw new Error(errMsg(d, "Probe failed"));
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
    lines.forEach((t) => {
      const p = document.createElement("p");
      p.className = "hint";
      p.style.color = "#e8e8e8";
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

/* ---------------- Zero-touch automation ---------------- */
let autoPlan = [];
let autoResults = [];   // {broker, outcome, detail}
let autoDrafts = [];    // broker names with prepared email drafts

function planItem(broker) { return autoPlan.find((x) => x.broker === broker) || {}; }

function feed(icon, text) {
  const box = $("autoFeed");
  box.hidden = false;
  const line = document.createElement("p");
  line.className = "feedLine";
  line.textContent = icon + " " + text;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

async function fetchTimeout(url, opts, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try { return await fetch(url, Object.assign({}, opts, { signal: ctrl.signal })); }
  finally { clearTimeout(t); }
}

async function probeMode(broker, profile, deep) {
  const resp = await fetchTimeout("/api/agent/probe", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ broker, profile, deep: !!deep }),
  }, deep ? 120000 : 25000);
  const d = await resp.json();
  if (!resp.ok) throw new Error(errMsg(d, "Probe failed"));
  return d;
}

async function autoSubmit(broker, probe) {
  const form = probe.forms[probe.forms.length - 1];
  const resp = await fetchTimeout("/api/agent/submit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirm: true, broker, form_action: form.action, method: form.method, payload: probe.payload_preview || {} }),
  }, 30000);
  const d = await resp.json();
  if (!resp.ok) throw new Error(errMsg(d, "Submit failed"));
  return d;
}

function record(broker, outcome, detail) {
  autoResults.push({ broker, outcome, detail });
  if (outcome === "submitted") {
    feed("✅", broker + " — removal submitted automatically" + (detail ? " (" + detail + ")" : ""));
    setStatus(broker, "sent");
  } else if (outcome === "draft") {
    feed("✉️", broker + " — erasure letter written; opens in your mail app below");
    autoDrafts.push(broker);
  } else {
    feed("🚧", broker + " — " + detail);
  }
}

$("autoBtn").addEventListener("click", async () => {
  const profile = agentProfile();
  const btn = $("autoBtn");
  if (!profile.full_name || !profile.email) {
    $("runStatus").textContent = "Fill in your full name and email above first — the agent acts in your name.";
    return;
  }
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Working…';
  $("autoFeed").innerHTML = "";
  $("autoSummary").hidden = true;
  autoResults = []; autoDrafts = [];
  $("runTrack").hidden = false;
  $("runBar").style.width = "0%";
  let done = 0, total = 40;
  const bump = () => { done++; $("runBar").style.width = Math.round(100 * done / total) + "%"; $("runStatus").textContent = "Working… " + done + " of " + total + " brokers processed"; };
  try {
    if (!window.__plan) {
      const resp = await fetchTimeout("/api/agent/plan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(profile),
      }, 30000);
      const data = await resp.json();
      if (!resp.ok) throw new Error(errMsg(data, "Plan failed"));
      window.__plan = data.plan;
    }
    autoPlan = window.__plan;
    total = autoPlan.length;
    feed("🚀", "Starting — probing all " + total + " brokers…");
    const deepQueue = [];
    const queue = autoPlan.slice();
    async function fastWorker() {
      while (queue.length) {
        const item = queue.shift();
        try {
          const probe = await probeMode(item.broker, profile, false);
          if (probe.fillable && probe.forms && probe.forms.length) {
            const r = await autoSubmit(item.broker, probe);
            if (r.ok) record(item.broker, "submitted", "HTTP " + r.status);
            else record(item.broker, "blocked", "form found but the broker answered HTTP " + (r.status || "—") + " to the submission");
          } else if (item.contact_email) {
            record(item.broker, "draft", item.contact_email);
          } else {
            deepQueue.push(item);
          }
        } catch (e) { deepQueue.push(item); }
        bump();
      }
    }
    await Promise.all([fastWorker(), fastWorker(), fastWorker()]);
    if (deepQueue.length) {
      feed("🔎", "Deep pass — retrying " + deepQueue.length + " stubborn brokers with the relay and alternate routes (this pass is slow on purpose: walled brokers answer slowly, a few minutes is normal)…");
      const dq = deepQueue.slice();
      async function deepWorker() {
        while (dq.length) {
          const item = dq.shift();
          let outcome = null;
          try {
            const probe = await probeMode(item.broker, profile, true);
            if (probe.fillable && probe.forms && probe.forms.length) {
              const r = await autoSubmit(item.broker, probe);
              if (r.ok) outcome = ["submitted", "HTTP " + r.status + " via deep pass"];
              else outcome = ["blocked", "deep pass found the form but the broker answered HTTP " + (r.status || "—")];
            }
            if (!outcome) {
              const email = item.contact_email || probe.contact_email;
              if (email) outcome = ["draft", email];
              else {
                const why = (probe.blockers && probe.blockers[0]) || "no automatic channel found";
                outcome = ["blocked", why + " — no tool can pass this automatically"];
              }
            }
          } catch (e) {
            outcome = ["blocked", "unreachable from the server right now"];
          }
          record(item.broker, outcome[0], outcome[1]);
        }
      }
      await Promise.all([deepWorker(), deepWorker(), deepWorker()]);
    }
    const sub = autoResults.filter((r) => r.outcome === "submitted").length;
    const dr = autoResults.filter((r) => r.outcome === "draft").length;
    const bl = autoResults.filter((r) => r.outcome === "blocked").length;
    $("runStatus").textContent = "Run complete.";
    $("autoSummary").hidden = false;
    $("autoSummaryText").textContent = "✅ " + sub + " removals submitted automatically · ✉️ " + dr + " letters written for email brokers · 🚧 " + bl + " blocked by anti-bot walls (CAPTCHA / login / JavaScript) — those refuse every automated tool, including the paid ones; they're listed in the report with the exact reason each.";
    $("draftBtn").hidden = !autoDrafts.length;
    $("draftHint").hidden = !autoDrafts.length;
    $("lettersBtn").hidden = !autoDrafts.length;
    updateDraftBtn();
    $("autoSummary").scrollIntoView({ behavior: "smooth", block: "center" });
    renderProgress();
  } catch (err) {
    $("runStatus").textContent = err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = "Remove my data everywhere";
  }
});

function syncLetterFields() {
  const profile = agentProfile();
  if (!$("lgName").value && profile.full_name) $("lgName").value = profile.full_name;
  if (!$("lgEmail").value && profile.email) $("lgEmail").value = profile.email;
  if (!$("lgCity").value && profile.city) $("lgCity").value = profile.city;
}

function updateDraftBtn() {
  $("draftBtn").textContent = autoDrafts.length ? "Open email draft (" + autoDrafts.length + " left)" : "All drafts opened";
  $("draftBtn").disabled = !autoDrafts.length;
}

$("draftBtn").addEventListener("click", () => {
  const broker = autoDrafts.shift();
  if (!broker) return;
  const item = planItem(broker);
  syncLetterFields();
  const letter = makeLetter(broker);
  const a = document.createElement("a");
  a.href = "mailto:" + (item.contact_email || "") + "?subject=" + encodeURIComponent("Request for erasure of my personal data — " + broker) + "&body=" + encodeURIComponent(letter);
  document.body.appendChild(a);
  a.click();
  a.remove();
  setStatus(broker, "sent");
  updateDraftBtn();
  renderProgress();
});

$("lettersBtn").addEventListener("click", () => {
  syncLetterFields();
  const all = autoResults.filter((r) => r.outcome === "draft").map((r) => makeLetter(r.broker)).join("\n\n========================================\n\n");
  downloadText("leakguard-erasure-letters.txt", all || "No email drafts in this run.");
});

$("reportBtn").addEventListener("click", () => {
  const lines = ["LeakGuard removal report — " + new Date().toLocaleString(), ""];
  autoResults.forEach((r) => lines.push((r.outcome === "submitted" ? "[SUBMITTED] " : r.outcome === "draft" ? "[EMAIL LETTER] " : "[BLOCKED] ") + r.broker + " — " + (r.detail || "")));
  downloadText("leakguard-removal-report.txt", lines.join("\n"));
});

function downloadText(name, text) {
  const blob = new Blob([text], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}

/* ---------------- Account & Privacy Center ----------------
   Optional accounts: they exist to REMOVE effort (details entered
   once, stored encrypted, shown only masked) — the anonymous scan
   above never needs one. All state-changing calls send
   X-Requested-With (the server's CSRF guard requires it). */
const AH = { "Content-Type": "application/json", "X-Requested-With": "fetch" };
let meUser = null;
let lastScanEmail = "";
/* Password-reset landing (/reset?token=...): while this is on, the
   account panel shows ONLY the reset form — never the sign-in form
   or a previous session's Privacy Center. Set by the boot code at
   the bottom of this file, before any async load can resolve. */
let lgResetMode = false;
let lgResetToken = null;
/* Dedicated sign-in page (/signin): same idea as reset mode — set
   synchronously by the boot code at the bottom of this file. While
   it is on, the auth panel is the whole page, and a successful
   sign-in leaves for the app home (renderAccount honours this). */
let lgSigninMode = false;

async function apiJson(path, opts) {
  const resp = await fetch(path, opts || {});
  let data = null;
  try { data = await resp.json(); } catch (e) { /* non-JSON response */ }
  return { status: resp.status, ok: resp.ok, data };
}

function refreshSaveScanBox() {
  const box = $("saveScanBox");
  if (!box) return;
  const show = !!(meUser && lastScanEmail && !$("scanResults").hidden);
  box.hidden = !show;
  if (show) {
    $("saveScanBtn").disabled = false;
    $("saveScanMsg").textContent = "";
  }
}

function renderAccount() {
  if (lgSigninMode) {
    if (meUser) { location.replace("/"); return; }
    $("acctBtn").textContent = "← Back";
    $("authForms").hidden = false;
    $("privacyCenter").hidden = true;
    $("actionCenter").hidden = true;
    $("adminCard").hidden = true;
    return;
  }
  if (lgResetMode) {
    $("acctBtn").textContent = "Sign in";
    $("authForms").hidden = true;
    $("privacyCenter").hidden = true;
    $("actionCenter").hidden = true;
    $("adminCard").hidden = true;
    $("resetBox").hidden = false;
    return;
  }
  const signedIn = !!meUser;
  $("acctBtn").textContent = signedIn ? "My Privacy Center" : "Sign in";
  $("actionCenter").hidden = !signedIn;
  if (signedIn) loadActionCenter();
  $("acctLabel").hidden = !signedIn;
  if (signedIn) $("acctLabel").textContent = meUser.name || meUser.email_masked;
  $("authForms").hidden = signedIn;
  if (!signedIn && registerMode) setRegisterMode(false);
  $("privacyCenter").hidden = !signedIn;
  if (signedIn) {
    $("pcEmail").textContent = meUser.email_masked;
    $("pcSince").textContent = meUser.created_at
      ? "· member since " + new Date(meUser.created_at).toLocaleDateString() : "";
    renderTotp();
    loadPasskeys();
    loadHousehold().then(() => loadIdentifiers());
    loadDomains();
    loadConsents();
    loadRemoval();
    loadMonitoring();
    loadGraph();
    loadSearchExposure();
    loadApiTokens();
    if (renderAccount._fsUser !== meUser.id) {
      // Fresh sign-in (or a different account): clear the last
      // full-scan view so nobody sees a previous session's results.
      renderAccount._fsUser = meUser.id;
      stopFullScanPolling();
      $("fullScanResults").hidden = true;
      $("fullScanStatus").textContent = "";
      $("fullScanBtn").disabled = false;
      stopRemovalPolling();
      $("removalCounts").innerHTML = "";
      $("removalQueue").innerHTML = "";
      $("removalCases").innerHTML = "";
      $("removalStatus").textContent = "";
      $("removalBtn").disabled = false;
    }
  } else {
    renderAccount._fsUser = null;
  }
  // The Admin card exists only for the owner: /api/auth/me says so,
  // and the admin routes 404 for everyone else regardless.
  const showAdmin = !!(signedIn && meUser.is_admin);
  $("adminCard").hidden = !showAdmin;
  if (showAdmin) loadAdmin();
  refreshSaveScanBox();
}

async function loadMe() {
  try {
    const r = await apiJson("/api/auth/me");
    meUser = r.ok ? r.data : null;
  } catch (e) { meUser = null; }
  renderAccount();
}

$("acctBtn").addEventListener("click", () => {
  if (lgSigninMode) { location.href = "/"; return; }
  if (!meUser && !lgResetMode) { location.href = "/signin"; return; }
  const panel = $("account");
  panel.hidden = !panel.hidden;
  if (!panel.hidden) {
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
    if (meUser) renderAccount();
  }
});

$("authForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (registerMode) setRegisterMode(false);
  const email = $("acEmail").value.trim();
  const password = $("acPassword").value;
  const code = $("acTotp").value.trim();
  $("acStatus").textContent = "Signing in…";
  try {
    const payload = { email, password };
    if (code) payload.totp_code = code;
    const r = await apiJson("/api/auth/login", {
      method: "POST", headers: AH, body: JSON.stringify(payload),
    });
    if (!r.ok) throw new Error(errMsg(r.data, "Sign-in failed"));
    if (r.data.totp_required) {
      $("acTotpWrap").hidden = false;
      $("acStatus").textContent = "Two-factor is on for this account — enter the 6-digit code from your authenticator app, then press Sign in again.";
      $("acTotp").focus();
      return;
    }
    meUser = r.data.user;
    $("acPassword").value = "";
    $("acTotp").value = "";
    $("acTotpWrap").hidden = true;
    $("acStatus").textContent = "";
    renderAccount();
  } catch (err) {
    $("acStatus").textContent = err.message;
  }
});

let registerMode = false;
function setRegisterMode(on) {
  registerMode = on;
  $("acNameWrap").hidden = !on;
  $("acRegisterBtn").textContent = on ? "Create my account" : "Create free account";
  if (on) $("acName").focus();
}

$("acRegisterBtn").addEventListener("click", async () => {
  const email = $("acEmail").value.trim();
  const password = $("acPassword").value;
  if (!email || !password) {
    $("acStatus").textContent = "Enter an email and a password (at least 10 characters) first.";
    return;
  }
  if (!registerMode) {
    // First click only opens sign-up: ask for the name too (owner
    // request, 2026-10-08), second click creates the account.
    setRegisterMode(true);
    $("acStatus").textContent = "Almost there — add your name, then tap Create my account.";
    return;
  }
  const name = $("acName").value.trim();
  if (!name) {
    $("acStatus").textContent = "Add your name so we can greet you properly.";
    $("acName").focus();
    return;
  }
  $("acStatus").textContent = "Creating your account…";
  try {
    const r = await apiJson("/api/auth/register", {
      method: "POST", headers: AH,
      body: JSON.stringify({ email, password, name }),
    });
    if (!r.ok) throw new Error(errMsg(r.data, "Could not create the account"));
    meUser = r.data.user;
    $("acPassword").value = "";
    $("acStatus").textContent = "";
    renderAccount();
  } catch (err) {
    $("acStatus").textContent = err.message;
  }
});

/* ----- forgot / reset password ----- */
$("acForgotLink").addEventListener("click", (e) => {
  e.preventDefault();
  const box = $("forgotBox");
  box.hidden = !box.hidden;
  if (!box.hidden) {
    if (!$("fgEmail").value) $("fgEmail").value = $("acEmail").value.trim();
    $("fgEmail").focus();
  }
});

$("fgBtn").addEventListener("click", async () => {
  const email = $("fgEmail").value.trim();
  if (!email) { $("fgStatus").textContent = "Enter your email address first."; return; }
  $("fgBtn").disabled = true;
  $("fgStatus").textContent = "Sending…";
  try {
    const r = await apiJson("/api/auth/forgot-password", {
      method: "POST", headers: AH, body: JSON.stringify({ email }),
    });
    if (!r.ok) throw new Error(errMsg(r.data, "Could not send the reset email"));
    // Neutral on purpose: this exact sentence shows whether or not
    // the address has an account — anything else would leak who is
    // registered.
    $("fgStatus").textContent = "If that email has an account, a reset link is on its way — check your inbox.";
  } catch (err) {
    $("fgStatus").textContent = err.message;
  }
  $("fgBtn").disabled = false;
});

$("resetForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const pw = $("rsPassword").value;
  const pw2 = $("rsPassword2").value;
  if (!lgResetToken) {
    $("rsStatus").textContent = "This reset link is missing its token — request a new one from the sign-in form.";
    return;
  }
  if (pw.length < 10) { $("rsStatus").textContent = "Password must be at least 10 characters."; return; }
  if (pw !== pw2) { $("rsStatus").textContent = "The two passwords do not match."; return; }
  $("rsBtn").disabled = true;
  $("rsStatus").textContent = "Setting your new password…";
  try {
    const r = await apiJson("/api/auth/reset-password", {
      method: "POST", headers: AH,
      body: JSON.stringify({ token: lgResetToken, new_password: pw }),
    });
    if (!r.ok) throw new Error(errMsg(r.data, "Could not reset the password"));
    // Done: leave reset mode, scrub the token from the address bar,
    // and hand the user the normal sign-in form.
    lgResetMode = false;
    lgResetToken = null;
    history.replaceState(null, "", "/");
    $("resetBox").hidden = true;
    $("rsPassword").value = "";
    $("rsPassword2").value = "";
    renderAccount();
    $("acStatus").textContent = "Password changed — sign in with your new password.";
    $("account").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    $("rsStatus").textContent = err.message;
  }
  $("rsBtn").disabled = false;
});

$("pcLogoutBtn").addEventListener("click", async () => {
  stopFullScanPolling();
  try {
    await apiJson("/api/auth/logout", { method: "POST", headers: AH, body: "{}" });
  } catch (e) { /* cookie is cleared either way on next load */ }
  meUser = null;
  renderAccount();
  $("acStatus").textContent = "Signed out.";
});

/* ----- action center (Stage S9): the signed-in home -----
   One aggregate from the server: exposure, counts, recent
   activity, and next_action — the SINGLE most useful next step,
   computed server-side so this page stays one glance + one
   button. The button dispatches to the existing flows below
   (which re-check consent themselves); it never grants a
   permission or submits anything on its own. */
let actionCenterData = null;

async function loadActionCenter() {
  if (!meUser) return;
  try {
    const r = await apiJson("/api/action-center");
    if (!r.ok) { $("actionCenter").hidden = true; return; }
    $("actionCenter").hidden = false;
    renderActionCenter(r.data);
  } catch (e) {
    $("actionCenter").hidden = true;
  }
}

function renderActionCenter(d) {
  actionCenterData = d;
  const exp = d.exposure || {};
  const num = $("acScoreNum");
  const ring = $("acScoreRing");
  const C = 351.8;
  if (exp.score === null || exp.score === undefined) {
    num.textContent = "–";
    num.className = "";
    ring.style.strokeDashoffset = String(C);
    ring.style.stroke = "#1ed760";
    $("acScoreText").textContent =
      "Not scanned yet — run your first scan and your exposure score lands here.";
  } else {
    num.textContent = exp.score;
    num.className = exp.score === 0 ? "sev-low" : exp.score < 35
      ? "sev-med" : exp.score < 70 ? "sev-high" : "sev-crit";
    ring.style.strokeDashoffset = String(C * (1 - exp.score / 100));
    ring.style.stroke = exp.score === 0 ? "#1ed760" : exp.score < 35
      ? "#ffa42b" : exp.score < 70 ? "#ff7a45" : "#ff4d6d";
    let text = (exp.band || "Exposure") + " — score " + exp.score + " / 100";
    if (exp.delta !== null && exp.delta !== undefined) {
      text += exp.delta > 0
        ? " · up " + exp.delta + " since the scan before (worse)"
        : exp.delta < 0
          ? " · down " + Math.abs(exp.delta) + " since the scan before (better)"
          : " · unchanged since the scan before";
    }
    $("acScoreText").textContent = text + ".";
  }
  const counts = [
    d.counts.identifiers + (d.counts.identifiers === 1
      ? " saved detail" : " saved details"),
  ];
  if (exp.findings_total) {
    counts.push(exp.findings_total + (exp.findings_total === 1
      ? " exposure" : " exposures") + " in the latest scan");
  }
  $("acCounts").textContent = counts.join(" · ");

  const chips = $("acChips");
  chips.innerHTML = "";
  Object.keys(REMOVAL_LABELS).forEach((s) => {
    const n = (d.counts.cases || {})[s] || 0;
    if (!n) return;
    const chip = document.createElement("span");
    chip.className = "tag";
    chip.textContent = n + " · " + REMOVAL_LABELS[s];
    chips.appendChild(chip);
  });

  const na = d.next_action || {};
  const btn = $("acActionBtn");
  btn.textContent = na.label || "…";
  btn.disabled = na.kind === "scanning" || na.kind === "all_clear";
  $("acActionDetail").textContent = na.detail || "";

  const wrap = $("acRecent");
  wrap.innerHTML = "";
  const events = d.recent || [];
  if (!events.length) {
    wrap.innerHTML = "<p class='hint'>Nothing yet — your first scan will start the story.</p>";
  } else {
    events.forEach((ev) => {
      const row = document.createElement("div");
      row.className = "idRow";
      const left = document.createElement("span");
      left.textContent = ev.summary;
      const when = document.createElement("span");
      when.className = "hint";
      when.textContent = _fmtWhen(ev.at);
      row.appendChild(left); row.appendChild(when);
      wrap.appendChild(row);
    });
  }
}

function openAccountPanel() {
  $("account").hidden = false;
}

function focusConsentToggle(purpose) {
  const t = document.querySelector(
    "#consentList input[data-purpose='" + purpose + "']");
  if (t) {
    t.scrollIntoView({ behavior: "smooth", block: "center" });
    t.focus();
  }
}

$("acActionBtn").addEventListener("click", () => {
  const kind = (actionCenterData && actionCenterData.next_action
    && actionCenterData.next_action.kind) || "";
  if (kind === "add_details") {
    openAccountPanel();
    $("idValue").scrollIntoView({ behavior: "smooth", block: "center" });
    $("idValue").focus({ preventScroll: true });
  } else if (kind === "scan_now") {
    openAccountPanel();
    $("fullScanBtn").click();
  } else if (kind === "remove_all") {
    openAccountPanel();
    $("removalBtn").click();
  } else if (kind === "review_queue") {
    openAccountPanel();
    $("removalQueue").scrollIntoView({ behavior: "smooth", block: "start" });
  } else if (kind === "enable_removal") {
    openAccountPanel();
    focusConsentToggle("automated_remediation");
  } else if (kind === "enable_monitoring") {
    openAccountPanel();
    focusConsentToggle("monitoring");
  }
});

/* ----- exposure map (Stage S14) -----
   GET /api/graph: the caller's own details → where the latest
   scan found them → the removal case per broker, rendered as a
   dependency-free inline SVG in three columns. Deterministic
   layout (the server sorts; rows are evenly spaced), masked
   labels only. A column longer than 15 rows collapses its tail
   into one "+N more …" node so the map never becomes spaghetti —
   collapsed nodes draw no edges (their lines would be the mess
   we're avoiding); the full lists live in the sections above. */
const GRAPH_MAX_ROWS = 15;
const GRAPH_BROKER_DOT = {
  queued: "#a7a7a7", running: "#ffa42b", submitted: "#ff7a45",
  needs_human: "#ffa42b", blocked: "#ff4d6d",
  verified_removed: "#1ed760", reappeared: "#ff4d6d",
  failed: "#ff4d6d",
};

async function loadGraph() {
  if (!meUser) return;
  const wrap = $("graphWrap");
  try {
    const r = await apiJson("/api/graph");
    if (!r.ok || !r.data) {
      wrap.innerHTML = "<p class='hint'>The exposure map is unavailable right now.</p>";
      return;
    }
    renderGraph(r.data);
  } catch (e) {
    wrap.innerHTML = "<p class='hint'>The exposure map is unavailable right now.</p>";
  }
}

function _graphTruncate(text) {
  const s = String(text || "");
  return s.length > 26 ? s.slice(0, 25) + "…" : s;
}

function renderGraph(d) {
  const wrap = $("graphWrap");
  wrap.innerHTML = "";
  const nodes = d.nodes || [];
  const edges = d.edges || [];
  const byType = { identifier: [], source: [], broker: [] };
  nodes.forEach((n) => { if (byType[n.type]) byType[n.type].push(n); });
  if (!nodes.length) {
    wrap.innerHTML = "<p class='hint'>Nothing to map yet — once a scan finds your " +
      "details somewhere, the map appears here.</p>";
    return;
  }

  const NS = "http://www.w3.org/2000/svg";
  const COLS = [
    { key: "identifier", title: "Your details", x: 10, w: 200, more: "details" },
    { key: "source", title: "Where they appeared", x: 355, w: 190, more: "sources" },
    { key: "broker", title: "Removal", x: 700, w: 190, more: "removals" },
  ];
  // Collapse each column to at most GRAPH_MAX_ROWS visible rows;
  // the tail becomes one aggregate node (drawn, but edgeless).
  const visible = {};
  const collapsedCount = {};
  COLS.forEach((col) => {
    const all = byType[col.key];
    if (all.length > GRAPH_MAX_ROWS) {
      visible[col.key] = all.slice(0, GRAPH_MAX_ROWS - 1);
      collapsedCount[col.key] = all.length - (GRAPH_MAX_ROWS - 1);
    } else {
      visible[col.key] = all;
      collapsedCount[col.key] = 0;
    }
  });
  const rowCount = Math.max(1, ...COLS.map((c) =>
    visible[c.key].length + (collapsedCount[c.key] ? 1 : 0)));
  const ROW_H = 40, TOP = 34, NODE_H = 30;
  const height = TOP + rowCount * ROW_H + 8;

  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 900 " + height);
  svg.setAttribute("class", "graphSvg");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Exposure map: your details, where they appeared, and removal progress");

  const centers = {};  // node id -> {x1, x2, y} for edge drawing
  COLS.forEach((col) => {
    const head = document.createElementNS(NS, "text");
    head.setAttribute("x", col.x + col.w / 2);
    head.setAttribute("y", 20);
    head.setAttribute("class", "graphHead");
    head.setAttribute("text-anchor", "middle");
    head.textContent = col.title;
    svg.appendChild(head);

    const rows = visible[col.key].slice();
    if (collapsedCount[col.key]) {
      rows.push({ id: "__more_" + col.key, type: col.key,
        label: "+" + collapsedCount[col.key] + " more " + col.more,
        aggregate: true });
    }
    if (!rows.length) {
      const none = document.createElementNS(NS, "text");
      none.setAttribute("x", col.x + col.w / 2);
      none.setAttribute("y", TOP + ROW_H / 2 + 4);
      none.setAttribute("class", "graphNone");
      none.setAttribute("text-anchor", "middle");
      none.textContent = "— none —";
      svg.appendChild(none);
    }
    rows.forEach((node, i) => {
      const cy = TOP + i * ROW_H + ROW_H / 2;
      const g = document.createElementNS(NS, "g");
      const rect = document.createElementNS(NS, "rect");
      rect.setAttribute("x", col.x);
      rect.setAttribute("y", cy - NODE_H / 2);
      rect.setAttribute("width", col.w);
      rect.setAttribute("height", NODE_H);
      rect.setAttribute("rx", 9);
      rect.setAttribute("class", node.aggregate ? "graphNode graphMore" : "graphNode");
      g.appendChild(rect);
      let tx = col.x + 12;
      if (node.type === "broker" && !node.aggregate) {
        const dot = document.createElementNS(NS, "circle");
        dot.setAttribute("cx", col.x + 14);
        dot.setAttribute("cy", cy);
        dot.setAttribute("r", 5);
        dot.setAttribute("fill", GRAPH_BROKER_DOT[node.status] || "#a7a7a7");
        g.appendChild(dot);
        tx = col.x + 26;
      }
      const text = document.createElementNS(NS, "text");
      text.setAttribute("x", tx);
      text.setAttribute("y", cy + 4);
      text.setAttribute("class", "graphLabel");
      text.textContent = _graphTruncate(node.label);
      g.appendChild(text);
      svg.appendChild(g);
      if (!node.aggregate) {
        centers[node.id] = { x1: col.x, x2: col.x + col.w, y: cy };
      }
    });
  });

  // Edges are drawn UNDER the nodes (inserted as the first child).
  // Only edges whose BOTH endpoints are visible get a line.
  const edgeGroup = document.createElementNS(NS, "g");
  edges.forEach((e) => {
    const a = centers[e.from], b = centers[e.to];
    if (!a || !b) return;
    const line = document.createElementNS(NS, "line");
    line.setAttribute("x1", a.x2); line.setAttribute("y1", a.y);
    line.setAttribute("x2", b.x1); line.setAttribute("y2", b.y);
    line.setAttribute("class", "graphEdge");
    edgeGroup.appendChild(line);
  });
  svg.insertBefore(edgeGroup, svg.firstChild);

  wrap.appendChild(svg);
  const legend = document.createElement("p");
  legend.className = "hint";
  legend.textContent = "Broker dots: green = removed (verified gone) · " +
    "amber = waiting / needs you · orange = request sent · grey = queued · " +
    "red = blocked or reappeared.";
  wrap.appendChild(legend);
  renderPropagation(d.propagation);
}

const PROPAGATION_STATUS_LABEL = {
  verified_removed: "Verified removed",
  submitted: "Submitted",
  in_progress: "In progress",
  needs_human: "Needs you",
  blocked: "Blocked",
  not_started: "Not started",
};

function renderPropagation(propagation) {
  const wrap = $("propagationWrap");
  if (!wrap) return;
  wrap.innerHTML = "";
  const heading = document.createElement("h4");
  heading.textContent = "Brokers LeakGuard can act on for this source";
  wrap.appendChild(heading);
  const note = document.createElement("p");
  note.className = "hint";
  note.textContent = "Only brokers matched to a source by LeakGuard's removal matcher are listed. " +
    "A broker that is not listed has not been matched to that source.";
  wrap.appendChild(note);
  const entries = (propagation && propagation.entries) || [];
  if (!entries.length) {
    const empty = document.createElement("p");
    empty.className = "hint";
    empty.textContent = "No source-to-broker matches yet.";
    wrap.appendChild(empty);
    return;
  }
  const list = document.createElement("ul");
  list.className = "propagationList";
  entries.forEach((entry) => {
    if (!entry.brokers || !entry.brokers.length) {
      const item = document.createElement("li");
      item.textContent = entry.source.name + " → no matched broker";
      list.appendChild(item);
      return;
    }
    entry.brokers.forEach((broker) => {
      const item = document.createElement("li");
      item.textContent = entry.source.name + " → " + broker.name + " → " +
        (PROPAGATION_STATUS_LABEL[broker.status] || broker.status);
      list.appendChild(item);
    });
  });
  wrap.appendChild(list);
}

/* ----- privacy policy checker (Phase 102) ----- */
const POLICY_STATUS_LABEL = {
  found: "Found",
  not_found: "Not found",
  unclear: "Mentioned, but unclear",
};

function renderPolicyResults(data) {
  const wrap = $("policyResults");
  wrap.innerHTML = "";
  const disclaimer = document.createElement("p");
  disclaimer.className = "hint";
  disclaimer.textContent = data.disclaimer;
  wrap.appendChild(disclaimer);
  const stats = document.createElement("p");
  stats.textContent = data.stats.word_count.toLocaleString() + " words · average sentence: " +
    data.stats.average_sentence_words + " words";
  wrap.appendChild(stats);
  const list = document.createElement("ul");
  list.className = "policyChecks";
  (data.checks || []).forEach((check) => {
    const item = document.createElement("li");
    const label = document.createElement("strong");
    label.textContent = check.label + ": ";
    item.appendChild(label);
    item.appendChild(document.createTextNode(
      (POLICY_STATUS_LABEL[check.status] || check.status) + ". "));
    if (check.matched_phrase) {
      item.appendChild(document.createTextNode(
        "Matched phrase: “" + check.matched_phrase + "”. "));
    }
    item.appendChild(document.createTextNode(check.note));
    list.appendChild(item);
  });
  wrap.appendChild(list);
}

$("policyCheckBtn").addEventListener("click", async () => {
  const url = $("policyUrl").value.trim();
  const text = $("policyText").value.trim();
  const status = $("policyStatus");
  if ((url && text) || (!url && !text)) {
    status.textContent = "Give either a policy page address or pasted policy text — not both.";
    return;
  }
  const btn = $("policyCheckBtn");
  btn.disabled = true;
  status.textContent = "Checking the policy…";
  try {
    const r = await apiJson("/api/tools/policy-analyzer", {
      method: "POST", headers: AH,
      body: JSON.stringify(url ? { url } : { text }),
    });
    if (!r.ok) throw new Error(errMsg(r.data, "The policy could not be checked"));
    renderPolicyResults(r.data);
    status.textContent = "Check complete.";
  } catch (e) {
    status.textContent = e.message;
  } finally {
    btn.disabled = false;
  }
});

/* ----- my household (family profiles) -----
   A member is a grouping label only ("whose detail is this") — no
   account, no login, nothing stored beyond the label. The member
   list also feeds the little "whose" select on each saved detail. */
let householdMembers = [];
async function loadHousehold() {
  if (!meUser) return;
  const wrap = $("memberList");
  try {
    const r = await apiJson("/api/household");
    if (!r.ok) {
      householdMembers = [];
      wrap.innerHTML = "<p class='hint'>" + errMsg(r.data, "Could not load your household") + "</p>";
      return;
    }
    householdMembers = r.data.members || [];
    wrap.innerHTML = "";
    if (!householdMembers.length) {
      wrap.innerHTML = "<p class='hint'>Just you so far — your own details need no label.</p>";
      return;
    }
    householdMembers.forEach((m) => {
      const row = document.createElement("div");
      row.className = "idRow";
      const label = document.createElement("span");
      label.className = "idVal";
      label.textContent = m.label;
      const rm = document.createElement("button");
      rm.type = "button";
      rm.className = "btnGhost miniBtn";
      rm.textContent = "Remove";
      rm.addEventListener("click", async () => {
        rm.disabled = true;
        const d = await apiJson("/api/household/members/" + m.id, {
          method: "DELETE", headers: { "X-Requested-With": "fetch" },
        });
        if (d.ok) {
          $("memberStatus").textContent = "Removed — their details now count as yours.";
          await loadHousehold();
          loadIdentifiers();
        } else {
          $("memberStatus").textContent = errMsg(d.data, "Remove failed");
          rm.disabled = false;
        }
      });
      row.appendChild(label); row.appendChild(rm);
      wrap.appendChild(row);
    });
  } catch (e) {
    wrap.innerHTML = "<p class='hint'>Could not load your household.</p>";
  }
}

$("memberAddBtn").addEventListener("click", async () => {
  const label = $("memberLabel").value.trim();
  if (!label) { $("memberStatus").textContent = "Type a name first."; return; }
  const r = await apiJson("/api/household/members", {
    method: "POST", headers: AH, body: JSON.stringify({ label }),
  });
  if (r.ok) {
    $("memberLabel").value = "";
    $("memberStatus").textContent = "Added.";
    await loadHousehold();
    loadIdentifiers();
  } else {
    $("memberStatus").textContent = errMsg(r.data, "Could not add that person");
  }
});

/* ----- API access (personal tokens, Stage S13) -----
   Read-only Bearer tokens for the owner's own scripts. The raw
   value exists in this page exactly once — in the create response,
   in the box below — because the server stores only its hash. */
async function loadApiTokens() {
  if (!meUser) return;
  const wrap = $("apiTokenList");
  try {
    const r = await apiJson("/api/tokens");
    if (!r.ok) {
      wrap.innerHTML = "<p class='hint'>" + errMsg(r.data, "Could not load your API tokens") + "</p>";
      return;
    }
    const tokens = r.data.tokens || [];
    wrap.innerHTML = "";
    if (!tokens.length) {
      wrap.innerHTML = "<p class='hint'>No tokens yet — create one below.</p>";
      return;
    }
    tokens.forEach((t) => {
      const row = document.createElement("div");
      row.className = "idRow";
      const label = document.createElement("span");
      label.className = "idVal";
      let text = t.name + " · " + t.prefix + "…";
      if (t.revoked_at) text += " · revoked " + new Date(t.revoked_at).toLocaleDateString();
      else if (t.last_used_at) text += " · last used " + new Date(t.last_used_at).toLocaleString();
      else text += " · never used";
      label.textContent = text;
      row.appendChild(label);
      if (!t.revoked_at) {
        const rm = document.createElement("button");
        rm.type = "button";
        rm.className = "btnGhost miniBtn";
        rm.textContent = "Revoke";
        rm.addEventListener("click", async () => {
          rm.disabled = true;
          const d = await apiJson("/api/tokens/" + t.id, {
            method: "DELETE", headers: { "X-Requested-With": "fetch" },
          });
          if (d.ok) {
            $("apiTokenStatus").textContent = "Revoked — that token no longer works anywhere.";
            loadApiTokens();
          } else {
            $("apiTokenStatus").textContent = errMsg(d.data, "Revoke failed");
            rm.disabled = false;
          }
        });
        row.appendChild(rm);
      }
      wrap.appendChild(row);
    });
  } catch (e) {
    wrap.innerHTML = "<p class='hint'>Could not load your API tokens.</p>";
  }
}

$("apiTokenCreateBtn").addEventListener("click", async () => {
  const name = $("apiTokenName").value.trim();
  if (!name) { $("apiTokenStatus").textContent = "Give the token a name first."; return; }
  const r = await apiJson("/api/tokens", {
    method: "POST", headers: AH, body: JSON.stringify({ name }),
  });
  if (r.ok) {
    $("apiTokenName").value = "";
    $("apiTokenStatus").textContent = "Token created — copy it from the box above, it is shown only once.";
    $("apiTokenRaw").value = r.data.token;
    $("apiTokenOnce").hidden = false;
    loadApiTokens();
  } else {
    $("apiTokenStatus").textContent = errMsg(r.data, "Could not create the token");
  }
});

$("apiTokenCopyBtn").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("apiTokenRaw").value); $("apiTokenCopyBtn").textContent = "Copied ✓"; }
  catch (e) { $("apiTokenRaw").select(); }
  setTimeout(() => { $("apiTokenCopyBtn").textContent = "Copy token"; }, 1600);
});

/* ----- admin (owner only) -----
   The card stays hidden unless /api/auth/me reported is_admin; the
   server re-checks and 404s these routes for everyone else anyway.
   Everything rendered is counts and audit actions — never anyone's
   personal data. */
function fmtCounts(obj) {
  const keys = Object.keys(obj || {});
  if (!keys.length) return "none yet";
  return keys.map((k) => k + " " + obj[k]).join(", ");
}

async function loadAdmin() {
  if (!meUser || !meUser.is_admin) return;
  const ov = $("adminOverview");
  const au = $("adminAudit");
  try {
    const r = await apiJson("/api/admin/overview");
    if (!r.ok) {
      ov.innerHTML = "<p class='hint'>Could not load the overview.</p>";
      return;
    }
    const d = r.data;
    const lines = [
      ["Users", d.users.total + " total, " + d.users.registered_last_30d + " in the last 30 days"],
      ["Saved details", fmtCounts(d.identifiers_by_kind)],
      ["Scan jobs", fmtCounts(d.scan_jobs_by_status)],
      ["Removal cases", fmtCounts(d.remediation_cases_by_status)],
      ["Notifications", fmtCounts(d.notifications_by_status)],
      ["Brokers covered", String(d.brokers)],
      ["Database", d.db],
      ["Providers", (d.providers.providers || [])
        .map((p) => p.name + ": " + p.status).join(", ") || "—"],
    ];
    if (d.source_health) {
      const sh = d.source_health;
      let src = sh.ok + " ok, " + sh.changed + " changed, "
        + sh.unreachable + " unreachable";
      if (sh.changed_slugs && sh.changed_slugs.length) {
        src += " — changed: " + sh.changed_slugs.join(", ");
      }
      if (sh.last_checked_at) {
        src += " · last checked "
          + new Date(sh.last_checked_at).toLocaleString();
      }
      lines.push(["Broker opt-out pages", src]);
    }
    if (d.security_events) {
      const ev = d.security_events;
      lines.push(["Security events",
        ev.length ? ev.length + " recent — latest: " + ev[0].action
          + " (" + new Date(ev[0].created_at).toLocaleString() + ")"
          : "none yet"]);
    }
    if (d.metrics) {
      const m = d.metrics;
      const q = m.queue || {};
      let queueText = (q.active || 0) + " active (" + (q.queued || 0)
        + " queued, " + (q.running || 0) + " running)";
      if (q.oldest_queued_age_seconds != null) {
        queueText += ", oldest queued "
          + Math.round(q.oldest_queued_age_seconds / 60) + " min";
      }
      lines.push(["Queue", queueText]);
      const s24 = (m.scan_jobs && m.scan_jobs.last_24h) || {};
      let jobsText = (s24.completed || 0) + " completed, "
        + (s24.failed || 0) + " failed, " + (s24.dead || 0) + " dead";
      if (m.scan_jobs
          && m.scan_jobs.median_completed_duration_seconds_last_24h != null) {
        jobsText += ", median "
          + Math.round(m.scan_jobs.median_completed_duration_seconds_last_24h)
          + "s";
      }
      lines.push(["Scan jobs (24h)", jobsText]);
      lines.push(["Notifications (24h)",
        fmtCounts(m.notifications_by_status_last_24h)]);
      const bs = m.broker_sources || {};
      lines.push(["Broker sources",
        (bs.checked_last_24h || 0) + " checked in 24h, "
          + (bs.unreachable || 0) + " unreachable of " + (bs.total || 0)]);
      const er = m.errors_last_24h || {};
      let errText = (er.total_occurrences || 0) + " occurrences, "
        + (er.distinct_context_class_pairs || 0) + " distinct kinds";
      if (er.top && er.top.length) {
        errText += " — top: " + er.top[0].context + " ("
          + er.top[0].occurrences + ")";
      }
      lines.push(["Errors (24h)", errText]);
      lines.push(["Security events (24h)",
        fmtCounts(m.security_events_by_kind_last_24h)]);
      const pv = m.providers || [];
      if (pv.length) {
        const used = pv.filter((p) => p.calls > 0 || p.exhausted);
        const text = used.length ? used.map((p) =>
          p.provider + " " + p.calls
          + (p.budget ? "/" + p.budget + " calls" : "")
          + (p.exhausted ? " — BUDGET SPENT" : ""))
          .join(" · ") : "no provider calls yet today";
        lines.push(["Providers (today)", text]);
        const jt = (m.scan_jobs && m.scan_jobs.today) || {};
        if (jt.jobs != null) {
          lines.push(["Scan jobs (today)",
            jt.jobs + " jobs by " + jt.distinct_users
            + " user(s), max " + jt.max_jobs_per_user + " per user"]);
        }
      }
    }
    // Per-broker verification + workflow health (Phase 125): one
    // compact row per broker with removal activity — did its
    // listings actually go away, and is its workflow failing?
    (d.broker_health || []).forEach((b) => {
      const v = b.verification || {};
      let text = "verified gone " + (v.gone || 0) + " of "
        + ((v.gone || 0) + (v.still_present || 0)) + " checked listings";
      if (v.removed_rate != null) {
        text += " (" + Math.round(v.removed_rate * 100) + "%)";
      }
      if (v.unknown) text += ", " + v.unknown + " unclear";
      const cs = fmtCounts(b.cases);
      if (cs !== "none yet") text += " · cases: " + cs;
      const at = fmtCounts(b.attempts);
      if (at !== "none yet") text += " · attempts: " + at;
      lines.push(["Broker: " + b.name, text]);
    });
    ov.innerHTML = "";
    lines.forEach(([label, value]) => {
      const row = document.createElement("div");
      row.className = "idRow";
      const l = document.createElement("span");
      l.className = "kindTag";
      l.textContent = label;
      const v = document.createElement("span");
      v.className = "idVal";
      v.textContent = value;
      row.appendChild(l); row.appendChild(v);
      ov.appendChild(row);
    });
    const a = await apiJson("/api/admin/audit?limit=25");
    au.innerHTML = "";
    if (a.ok && a.data.audit && a.data.audit.length) {
      a.data.audit.forEach((entry) => {
        const row = document.createElement("div");
        row.className = "idRow";
        const l = document.createElement("span");
        l.className = "idVal";
        l.textContent = new Date(entry.created_at).toLocaleString()
          + " · " + entry.actor_kind + " · " + entry.action;
        const det = document.createElement("span");
        det.className = "hint";
        det.textContent = Object.keys(entry.detail || {})
          .map((k) => k + ": " + entry.detail[k]).join(", ");
        row.appendChild(l); row.appendChild(det);
        au.appendChild(row);
      });
    } else {
      au.innerHTML = "<p class='hint'>No audit activity yet.</p>";
    }
  } catch (e) {
    ov.innerHTML = "<p class='hint'>Could not load the overview.</p>";
  }
}

/* ----- search exposure (Phase 40) -----
   The signed-in user's public-web discovery findings, grouped by
   saved detail — what a search engine shows about them. Every
   entry is a weak-confidence candidate mention, never a
   confirmation (the section copy above the list says so, and
   the confidence word is rendered with each result). */
async function loadSearchExposure() {
  if (!meUser) return;
  const wrap = $("searchExposureList");
  try {
    const r = await apiJson("/api/search-exposure");
    wrap.innerHTML = "";
    if (!r.ok) {
      wrap.innerHTML = "<p class='hint'>Could not load your search exposure.</p>";
      return;
    }
    const groups = (r.data && r.data.identifiers) || [];
    if (!groups.length) {
      wrap.innerHTML = "<p class='hint'>No public web mentions found yet — "
        + "run a full scan and anything a search engine shows about your "
        + "saved details will appear here.</p>";
      return;
    }
    groups.forEach((g) => {
      const head = document.createElement("div");
      head.className = "idRow";
      const hl = document.createElement("span");
      const tag = document.createElement("span");
      tag.className = "kindTag";
      tag.textContent = g.identifier_kind;
      const val = document.createElement("span");
      val.className = "idVal";
      val.textContent = g.identifier_masked || "(detail removed)";
      hl.appendChild(tag); hl.appendChild(val);
      const n = document.createElement("span");
      n.className = "hint";
      n.textContent = g.findings.length + (g.findings.length === 1
        ? " mention" : " mentions");
      head.appendChild(hl); head.appendChild(n);
      wrap.appendChild(head);
      g.findings.forEach((f) => {
        const row = document.createElement("div");
        row.className = "idRow";
        const a = document.createElement("a");
        a.href = f.source_url || "#";
        a.target = "_blank"; a.rel = "noopener";
        a.textContent = f.source_name || f.source_url || "Public web page";
        const meta = document.createElement("span");
        meta.className = "hint";
        const when = f.source_date || f.discovered_at;
        meta.textContent = (f.confidence || "weak") + " confidence"
          + (when ? " · " + new Date(when).toLocaleDateString() : "");
        row.appendChild(a); row.appendChild(meta);
        wrap.appendChild(row);
      });
    });
  } catch (e) {
    wrap.innerHTML = "<p class='hint'>Could not load your search exposure.</p>";
  }
}

/* ----- saved details (identifiers) ----- */
async function loadIdentifiers() {
  if (!meUser) return;
  const wrap = $("idList");
  try {
    const r = await apiJson("/api/identifiers");
    wrap.innerHTML = "";
    if (!r.ok) {
      wrap.innerHTML = "<p class='hint'>" + errMsg(r.data, "Could not load your saved details") + "</p>";
      return;
    }
    if (!r.data.identifiers.length) {
      wrap.innerHTML = "<p class='hint'>Nothing saved yet.</p>";
      return;
    }
    r.data.identifiers.forEach((rec) => {
      const row = document.createElement("div");
      row.className = "idRow";
      const left = document.createElement("span");
      const tag = document.createElement("span");
      tag.className = "kindTag";
      tag.textContent = rec.kind;
      const val = document.createElement("span");
      val.className = "idVal";
      val.textContent = rec.masked;
      left.appendChild(tag); left.appendChild(val);
      const sel = document.createElement("select");
      sel.className = "memberSelect";
      sel.title = "Whose detail is this?";
      sel.setAttribute("aria-label",
        "Whose detail is this? (" + rec.kind + " " + rec.masked + ")");
      const mine = document.createElement("option");
      mine.value = "";
      mine.textContent = "Mine";
      sel.appendChild(mine);
      householdMembers.forEach((m) => {
        const o = document.createElement("option");
        o.value = m.id;
        o.textContent = m.label;
        sel.appendChild(o);
      });
      sel.value = rec.member_id || "";
      sel.addEventListener("change", async () => {
        sel.disabled = true;
        const d = await apiJson("/api/identifiers/" + rec.id, {
          method: "PATCH", headers: AH,
          body: JSON.stringify({ member_id: sel.value || null }),
        });
        if (d.ok) {
          rec.member_id = sel.value || null;
          $("idStatus").textContent = "Saved — whose detail updated.";
        } else {
          sel.value = rec.member_id || "";
          $("idStatus").textContent = errMsg(d.data, "Could not update whose detail this is");
        }
        sel.disabled = false;
      });
      const rm = document.createElement("button");
      rm.type = "button";
      rm.className = "btnGhost miniBtn";
      rm.textContent = "Remove";
      rm.addEventListener("click", async () => {
        rm.disabled = true;
        const d = await apiJson("/api/identifiers/" + rec.id, {
          method: "DELETE", headers: { "X-Requested-With": "fetch" },
        });
        if (d.ok) { loadIdentifiers(); loadActionCenter(); $("idStatus").textContent = "Removed."; }
        else { $("idStatus").textContent = errMsg(d.data, "Remove failed"); rm.disabled = false; }
      });
      row.appendChild(left); row.appendChild(sel); row.appendChild(rm);
      wrap.appendChild(row);
    });
  } catch (e) {
    wrap.innerHTML = "<p class='hint'>Could not load your saved details.</p>";
  }
}

$("idAddBtn").addEventListener("click", async () => {
  const kind = $("idKind").value;
  const value = $("idValue").value.trim();
  if (!value) { $("idStatus").textContent = "Type the value first."; return; }
  const r = await apiJson("/api/identifiers", {
    method: "POST", headers: AH, body: JSON.stringify({ kind, value }),
  });
  if (r.ok) {
    $("idValue").value = "";
    $("idStatus").textContent = "Saved ✓ (stored encrypted, shown masked).";
    loadIdentifiers();
    loadActionCenter();
  } else {
    $("idStatus").textContent = errMsg(r.data, "Could not save that detail");
  }
});

/* ----- my domains (verification-gated monitoring) ----- */
async function loadDomains() {
  if (!meUser) return;
  const wrap = $("domainList");
  try {
    const r = await apiJson("/api/domains");
    wrap.innerHTML = "";
    if (!r.ok) {
      wrap.innerHTML = "<p class='hint'>" + errMsg(r.data, "Could not load your domains") + "</p>";
      return;
    }
    if (!r.data.domains.length) {
      wrap.innerHTML = "<p class='hint'>No domains added yet.</p>";
      return;
    }
    r.data.domains.forEach((rec) => {
      const row = document.createElement("div");
      row.className = "idRow";
      const left = document.createElement("span");
      const val = document.createElement("span");
      val.className = "idVal";
      val.textContent = rec.domain;
      const badge = document.createElement("span");
      badge.className = "kindTag";
      badge.textContent = rec.verified ? "Verified" : "Pending";
      left.appendChild(val); left.appendChild(badge);
      row.appendChild(left);
      const btns = document.createElement("span");
      btns.className = "rowBtns";
      if (!rec.verified) {
        const verify = document.createElement("button");
        verify.type = "button";
        verify.className = "btnGhost miniBtn";
        verify.textContent = "Verify";
        verify.addEventListener("click", async () => {
          verify.disabled = true;
          $("domainStatus").textContent = "Checking your DNS record…";
          const v = await apiJson("/api/domains/" + rec.id + "/verify", {
            method: "POST", headers: AH, body: "{}",
          });
          if (v.ok && v.data.domain.verified) {
            $("domainStatus").textContent = "Verified ✓ — full scans now watch this domain.";
          } else if (v.ok) {
            $("domainStatus").textContent = "Record not found yet — double-check the TXT record below; DNS changes can take a while to spread.";
          } else {
            $("domainStatus").textContent = errMsg(v.data, "Verification check failed");
          }
          loadDomains();
        });
        btns.appendChild(verify);
      }
      const rm = document.createElement("button");
      rm.type = "button";
      rm.className = "btnGhost miniBtn";
      rm.textContent = "Remove";
      rm.addEventListener("click", async () => {
        rm.disabled = true;
        const d = await apiJson("/api/domains/" + rec.id, {
          method: "DELETE", headers: { "X-Requested-With": "fetch" },
        });
        if (d.ok) { loadDomains(); $("domainStatus").textContent = "Removed."; }
        else { $("domainStatus").textContent = errMsg(d.data, "Remove failed"); rm.disabled = false; }
      });
      btns.appendChild(rm);
      row.appendChild(btns);
      wrap.appendChild(row);
      if (!rec.verified) {
        const help = document.createElement("p");
        help.className = "hint";
        help.textContent = "Add this TXT record to " + rec.domain + "'s DNS, then press Verify:  " +
          rec.txt_name + "  →  " + rec.txt_value;
        const copy = document.createElement("button");
        copy.type = "button";
        copy.className = "btnGhost miniBtn";
        copy.textContent = "Copy record value";
        copy.addEventListener("click", () => {
          if (navigator.clipboard) navigator.clipboard.writeText(rec.txt_value);
          $("domainStatus").textContent = "Copied — paste it as the TXT record value.";
        });
        help.appendChild(copy);
        wrap.appendChild(help);
      }
    });
  } catch (e) {
    wrap.innerHTML = "<p class='hint'>Could not load your domains.</p>";
  }
}

$("domainAddBtn").addEventListener("click", async () => {
  const value = $("domainValue").value.trim();
  if (!value) { $("domainStatus").textContent = "Type the domain first."; return; }
  const r = await apiJson("/api/domains", {
    method: "POST", headers: AH, body: JSON.stringify({ domain: value }),
  });
  if (r.ok) {
    $("domainValue").value = "";
    $("domainStatus").textContent = r.data.domain.verified
      ? "Added — already verified."
      : "Added. Now add the TXT record shown next to it and press Verify.";
    loadDomains();
    loadIdentifiers();
  } else {
    $("domainStatus").textContent = errMsg(r.data, "Could not add that domain");
  }
});

$("saveScanBtn").addEventListener("click", async () => {
  if (!lastScanEmail) return;
  const btn = $("saveScanBtn");
  btn.disabled = true;
  const r = await apiJson("/api/identifiers", {
    method: "POST", headers: AH,
    body: JSON.stringify({ kind: "email", value: lastScanEmail }),
  });
  if (r.ok) {
    $("saveScanMsg").textContent = "Saved ✓ — find it under My saved details in your Privacy Center.";
    loadIdentifiers();
  } else {
    $("saveScanMsg").textContent = errMsg(r.data, "Could not save");
    btn.disabled = false;
  }
});

/* ----- consent ----- */
const CONSENT_INFO = [
  ["scanning", "Scanning", "Run breach scans for my saved details when I ask."],
  ["monitoring", "Monitoring", "Re-check my saved details regularly and tell me when a new leak appears."],
  ["automated_remediation", "Automatic removal", "Submit removal requests to data brokers for me, without asking me each time."],
  ["notifications", "Notifications", "Email me when something important changes — one summary email per check with any new leaks in it, and a note when a removal finishes."],
];

function renderConsents(state) {
  const wrap = $("consentList");
  wrap.innerHTML = "";
  const byPurpose = {};
  (state || []).forEach((c) => { byPurpose[c.purpose] = c; });
  CONSENT_INFO.forEach(([purpose, title, blurb]) => {
    const current = byPurpose[purpose] || { granted: false, version: 0 };
    const row = document.createElement("div");
    row.className = "consentRow";
    const text = document.createElement("div");
    text.className = "cText";
    const b = document.createElement("b");
    b.textContent = title;
    const s = document.createElement("span");
    s.textContent = blurb;
    text.appendChild(b); text.appendChild(s);
    const toggle = document.createElement("input");
    toggle.type = "checkbox";
    toggle.checked = !!current.granted;
    toggle.dataset.purpose = purpose;
    toggle.setAttribute("aria-label", title);
    toggle.addEventListener("change", async () => {
      toggle.disabled = true;
      const r = await apiJson("/api/consents", {
        method: "POST", headers: AH,
        body: JSON.stringify({ purpose, granted: toggle.checked }),
      });
      if (r.ok) {
        $("consentStatus").textContent = "Saved — " + title + (toggle.checked ? " is ON." : " is OFF.");
        renderConsents(r.data.consents);
        syncMonitoringConsent(r.data.consents);
        loadActionCenter();
      } else {
        toggle.checked = !toggle.checked;
        toggle.disabled = false;
        $("consentStatus").textContent = errMsg(r.data, "Could not save that change");
      }
    });
    row.appendChild(text); row.appendChild(toggle);
    wrap.appendChild(row);
  });
}

async function loadConsents() {
  if (!meUser) return;
  const r = await apiJson("/api/consents");
  if (r.ok) { renderConsents(r.data.consents); syncMonitoringConsent(r.data.consents); }
  else $("consentList").innerHTML = "<p class='hint'>" + errMsg(r.data, "Could not load permissions") + "</p>";
}

/* ----- monitoring (Stage S8): cadence, timeline, notifications ----- */
const NOTIF_KIND_LABELS = {
  new_finding: "New exposure found",
  finding_resolved: "Exposure no longer found",
  removal_verified: "Removal verified",
  reappeared: "Data reappeared",
  password_reset: "Password reset",
  scan_summary: "Scan summary",
};
const NOTIF_STATUS_WORDS = {
  sent: "Emailed to you",
  in_app_only: "In-app only (email alerts off)",
  unsent_no_lane: "Not emailed — email delivery is not set up",
  failed: "Email could not be sent",
  pending: "Sending…",
  suppressed: "Duplicate — not sent again",
};

function syncMonitoringConsent(state) {
  const entry = (state || []).find((c) => c.purpose === "monitoring");
  const on = !!(entry && entry.granted);
  const off = $("monitorOff");
  if (off) off.hidden = on;
  const sel = $("monCadence");
  if (sel) sel.disabled = !on;
  const btn = $("monSaveBtn");
  if (btn) btn.disabled = !on;
  const pauseBtn = $("monPauseBtn");
  if (pauseBtn) pauseBtn.disabled = !on;
}

/* The pause switch is a state of its own — NOT the consent. The
   button's label always names the action it will take next. */
let monPaused = false;

function renderMonPause() {
  const btn = $("monPauseBtn");
  if (btn) btn.textContent = monPaused ? "Resume monitoring" : "Pause monitoring";
  const state = $("monPauseState");
  if (state) {
    state.textContent = monPaused
      ? "Monitoring is paused — your permission stays on, re-checks are on hold."
      : "";
  }
}

function _fmtWhen(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? "" : d.toLocaleString();
}

async function loadMonitoring() {
  if (!meUser) return;
  try {
    const s = await apiJson("/api/monitoring/settings");
    if (s.ok) {
      $("monCadence").value = String(s.data.cadence_days || 7);
      monPaused = !!s.data.monitoring_paused;
      renderMonPause();
      const bits = [];
      bits.push(s.data.last_scan_at
        ? "Last full check: " + _fmtWhen(s.data.last_scan_at)
        : "No full check has completed yet");
      bits.push(s.data.next_scan_at
        ? "Next scheduled re-check: " + _fmtWhen(s.data.next_scan_at)
        : "The next scheduled re-check is due on the next scheduler pass");
      $("monLastNext").textContent = bits.join(" · ");
    }
  } catch (e) { /* the lists below still render what they can */ }
  try {
    const t = await apiJson("/api/monitoring/timeline");
    const wrap = $("timelineList");
    wrap.innerHTML = "";
    if (!t.ok) {
      wrap.innerHTML = "<p class='hint'>" + errMsg(t.data, "Could not load your timeline") + "</p>";
    } else if (!t.data.events.length) {
      wrap.innerHTML = "<p class='hint'>Nothing yet — your first scan will start the timeline.</p>";
    } else {
      t.data.events.slice(0, 20).forEach((ev) => {
        const row = document.createElement("div");
        row.className = "idRow";
        const left = document.createElement("span");
        left.textContent = ev.summary;
        const when = document.createElement("span");
        when.className = "hint";
        when.textContent = _fmtWhen(ev.at);
        row.appendChild(left); row.appendChild(when);
        wrap.appendChild(row);
      });
    }
  } catch (e) {
    $("timelineList").innerHTML = "<p class='hint'>Could not load your timeline.</p>";
  }
  try {
    const n = await apiJson("/api/notifications");
    const wrap = $("notifList");
    wrap.innerHTML = "";
    if (!n.ok) {
      wrap.innerHTML = "<p class='hint'>" + errMsg(n.data, "Could not load notifications") + "</p>";
    } else if (!n.data.notifications.length) {
      wrap.innerHTML = "<p class='hint'>No notifications yet.</p>";
    } else {
      n.data.notifications.slice(0, 20).forEach((item) => {
        const row = document.createElement("div");
        row.className = "idRow";
        const left = document.createElement("span");
        const tag = document.createElement("span");
        tag.className = "kindTag";
        tag.textContent = NOTIF_KIND_LABELS[item.kind] || item.kind;
        const detail = document.createElement("span");
        const p = item.payload || {};
        detail.textContent = p.source_name || p.broker_name || "";
        left.appendChild(tag); left.appendChild(detail);
        const right = document.createElement("span");
        right.className = "hint";
        right.textContent = (NOTIF_STATUS_WORDS[item.status] || item.status) +
          " · " + _fmtWhen(item.created_at);
        row.appendChild(left); row.appendChild(right);
        wrap.appendChild(row);
      });
    }
  } catch (e) {
    $("notifList").innerHTML = "<p class='hint'>Could not load notifications.</p>";
  }
}

$("monSaveBtn").addEventListener("click", async () => {
  const days = parseInt($("monCadence").value, 10);
  $("monSaveBtn").disabled = true;
  $("monStatus").textContent = "Saving…";
  try {
    const r = await apiJson("/api/monitoring/settings", {
      method: "PUT", headers: AH,
      body: JSON.stringify({ cadence_days: days }),
    });
    if (!r.ok) throw new Error(errMsg(r.data, "Could not save the schedule"));
    $("monStatus").textContent = "Saved — re-checks every " + r.data.cadence_days + " days.";
    loadMonitoring();
  } catch (err) {
    $("monStatus").textContent = err.message;
  }
  $("monSaveBtn").disabled = false;
});

$("monPauseBtn").addEventListener("click", async () => {
  const btn = $("monPauseBtn");
  btn.disabled = true;
  try {
    const r = await apiJson("/api/monitoring/settings", {
      method: "PUT", headers: AH,
      body: JSON.stringify({ monitoring_paused: !monPaused }),
    });
    if (!r.ok) throw new Error(errMsg(r.data, "Could not change the pause"));
    monPaused = !!r.data.monitoring_paused;
    renderMonPause();
    loadMonitoring();
  } catch (err) {
    $("monPauseState").textContent = err.message;
  }
  btn.disabled = false;
});

/* ----- full scan (Stage S5): one tap for the whole saved profile ----- */
let fullScanTimer = null;

function stopFullScanPolling() {
  if (fullScanTimer) { clearTimeout(fullScanTimer); fullScanTimer = null; }
}

function newIdempotencyKey() {
  if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
  return "scan-" + Date.now() + "-" + Math.random().toString(36).slice(2, 12);
}

$("fullScanBtn").addEventListener("click", async () => {
  if (!meUser) return;
  const btn = $("fullScanBtn");
  const status = $("fullScanStatus");
  btn.disabled = true;
  status.textContent = "Checking your permission…";
  try {
    // The scan never runs without the Scanning permission — and we
    // never switch it on for the user. Explain, point at the toggle.
    const c = await apiJson("/api/consents");
    const scanning = c.ok && (c.data.consents || [])
      .find((x) => x.purpose === "scanning");
    if (!scanning || !scanning.granted) {
      status.textContent = "The Scanning permission is off — turn it on above and press the button again. LeakGuard never scans your saved details without it.";
      const toggle = document.querySelector(
        "#consentList input[data-purpose='scanning']");
      if (toggle) {
        toggle.scrollIntoView({ behavior: "smooth", block: "center" });
        toggle.focus();
      }
      btn.disabled = false;
      return;
    }
    status.textContent = "Starting your scan…";
    const r = await apiJson("/api/scans", {
      method: "POST", headers: AH,
      body: JSON.stringify({ idempotency_key: newIdempotencyKey() }),
    });
    if (!r.ok) throw new Error(errMsg(r.data, "Could not start the scan"));
    status.textContent = "Scan queued — checking every saved detail…";
    pollFullScan(r.data.job.id, 0);
  } catch (err) {
    status.textContent = err.message;
    btn.disabled = false;
  }
});

function pollFullScan(jobId, tries) {
  stopFullScanPolling();
  fullScanTimer = setTimeout(async () => {
    fullScanTimer = null;
    if (!meUser) return;  // signed out meanwhile — stop quietly
    try {
      const r = await apiJson("/api/scans/" + jobId);
      if (!r.ok) throw new Error(errMsg(r.data, "Could not read the scan"));
      const job = r.data.job;
      if (job.status === "done") {
        $("fullScanStatus").textContent = "Scan complete.";
        $("fullScanBtn").disabled = false;
        renderFullScan(r.data);
        loadActionCenter();
        return;
      }
      if (job.status === "dead") {
        $("fullScanStatus").textContent = "The scan could not be completed — the sources stayed unreachable. Nothing was guessed or made up; please try again later.";
        $("fullScanBtn").disabled = false;
        return;
      }
      $("fullScanStatus").textContent = job.status === "failed"
        ? "A source hiccuped — retrying automatically…"
        : "Scanning… (" + job.status + ")";
      if (tries < 200) { pollFullScan(jobId, tries + 1); return; }
      $("fullScanStatus").textContent = "Still running — it will finish in the background. Press the button again later to see the result.";
      $("fullScanBtn").disabled = false;
    } catch (err) {
      $("fullScanStatus").textContent = err.message;
      $("fullScanBtn").disabled = false;
    }
  }, 3000);
}

/* False-positive feedback (Phase 156): the verdict buttons under a
   finding. 'not_me' dims the row and — server-side, via the one
   shared helper — also removes the exposure from Action Center
   counts and monitoring alerts. Undo posts verdict 'none'. */
async function postFindingFeedback(findingId, verdict, jobId, btn) {
  if (btn) btn.disabled = true;
  const d = await apiJson("/api/findings/feedback", {
    method: "POST",
    headers: { "X-Requested-With": "fetch",
               "Content-Type": "application/json" },
    body: JSON.stringify({ finding_id: findingId, verdict: verdict }),
  });
  if (d.ok) {
    const r = await apiJson("/api/scans/" + jobId);
    if (r.ok && r.data) renderFullScan(r.data);
    loadActionCenter();
  } else if (btn) {
    btn.disabled = false;
  }
}

function findingFeedbackRow(f, jobId) {
  const meta = document.createElement("div");
  meta.className = "findingMeta";
  const mkBtn = (label, verdict) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "btnGhost miniBtn";
    b.textContent = label;
    b.addEventListener("click", () =>
      postFindingFeedback(f.id, verdict, jobId, b));
    return b;
  };
  if (f.feedback === "not_me") {
    const note = document.createElement("span");
    note.className = "findingNote";
    note.textContent = "You marked this: not me — it no longer counts or alerts.";
    meta.appendChild(note);
    meta.appendChild(mkBtn("Undo", "none"));
  } else if (f.feedback === "confirmed") {
    const note = document.createElement("span");
    note.className = "findingNote";
    note.textContent = "You confirmed this is you.";
    meta.appendChild(note);
    meta.appendChild(mkBtn("Undo", "none"));
  } else {
    const note = document.createElement("span");
    note.className = "findingNote";
    note.textContent = "Is this about you?";
    meta.appendChild(note);
    meta.appendChild(mkBtn("Not me", "not_me"));
    meta.appendChild(mkBtn("This is me", "confirmed"));
  }
  return meta;
}

/* Dispute guidance (Phase 157): the server's per-source steps,
   shown on demand under the finding. Returns {toggle, box}: the
   toggle joins the finding's meta row, the box opens under it. */
function findingDisputeBox(f) {
  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.className = "btnGhost miniBtn";
  toggle.textContent = f.dispute.heading || "Dispute or correct this";
  toggle.setAttribute("aria-expanded", "false");
  const box = document.createElement("div");
  box.className = "disputeBox";
  box.hidden = true;
  const ol = document.createElement("ol");
  (f.dispute.steps || []).forEach((step) => {
    const li = document.createElement("li");
    li.textContent = step;
    ol.appendChild(li);
  });
  box.appendChild(ol);
  if (f.dispute.url) {
    const a = document.createElement("a");
    a.className = "btnLink";
    a.href = f.dispute.url;
    a.target = "_blank";
    a.rel = "noopener";
    a.textContent = (f.dispute.url_label || "Open") + " →";
    box.appendChild(a);
  }
  toggle.addEventListener("click", () => {
    box.hidden = !box.hidden;
    toggle.setAttribute("aria-expanded", box.hidden ? "false" : "true");
  });
  return { toggle: toggle, box: box };
}

function renderFullScan(data) {
  const job = data.job;
  const findings = data.findings || [];
  const summary = job.summary || {};
  $("fullScanResults").hidden = false;
  $("fsScore").innerHTML = job.score === null || job.score === undefined
    ? "" : "Exposure score for your saved profile: <b>" + job.score + " / 100</b>";
  const explain = $("fsExplain");
  explain.innerHTML = "";
  (job.score_explanation || []).forEach((line) => {
    const li = document.createElement("li");
    li.textContent = line;
    explain.appendChild(li);
  });

  const outcomes = $("fsOutcomes");
  outcomes.innerHTML = "";
  (summary.identifiers || []).forEach((o) => {
    const p = document.createElement("p");
    p.className = "hint";
    let text = o.masked + " (" + o.kind + ") — ";
    if (o.outcome === "scanned") {
      text += o.findings === 1 ? "1 finding" : o.findings + " findings";
    } else if (o.outcome === "no_provider_yet") {
      text += "no checks available for this kind of detail yet";
    } else if (o.outcome === "domain_unverified") {
      text += "not checked — verify this domain under My domains to start monitoring it";
    } else {
      text += "could not be checked this time (source unreachable)";
    }
    p.textContent = text;
    outcomes.appendChild(p);
  });
  if (summary.degraded) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "Some sources could not be reached, so these results may be incomplete — nothing was guessed to fill the gaps.";
    outcomes.appendChild(p);
  }

  const wrap = $("fsFindings");
  wrap.innerHTML = "";
  if (!findings.length) {
    const p = document.createElement("p");
    p.textContent = "No exposures found for your saved details in the sources we check.";
    wrap.appendChild(p);
  } else {
    const groups = {};
    findings.forEach((f) => {
      const key = f.identifier_id || "other";
      if (!groups[key]) {
        groups[key] = {
          label: (f.identifier_masked || "Saved detail") +
            " (" + f.identifier_kind + ")",
          items: [],
        };
      }
      groups[key].items.push(f);
    });
    Object.values(groups).forEach((group) => {
      const h = document.createElement("h4");
      h.textContent = group.label;
      wrap.appendChild(h);
      group.items.forEach((f) => {
        const block = document.createElement("div");
        const row = document.createElement("div");
        row.className = "idRow";
        if (f.feedback === "not_me") row.classList.add("dimmed");
        const left = document.createElement("span");
        const name = document.createElement("b");
        name.textContent = f.source_name;
        left.appendChild(name);
        const conf = document.createElement("span");
        conf.className = "hint";
        conf.textContent = " · " + f.confidence + " match · found " +
          new Date(f.discovered_at).toLocaleDateString();
        left.appendChild(conf);
        row.appendChild(left);
        const tags = document.createElement("span");
        tags.className = "tags";
        (f.exposed_fields || []).forEach((field) => {
          const chip = document.createElement("span");
          chip.className = "tag";
          chip.textContent = field;
          tags.appendChild(chip);
        });
        row.appendChild(tags);
        block.appendChild(row);
        const meta = findingFeedbackRow(f, job.id);
        block.appendChild(meta);
        if (f.dispute) {
          const parts = findingDisputeBox(f);
          meta.appendChild(parts.toggle);
          block.appendChild(parts.box);
        }
        wrap.appendChild(block);
      });
    });
  }

  const corr = $("fsCorrelations");
  corr.innerHTML = "";
  (summary.correlations || []).forEach((note) => {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "🔗 " + note.reason;
    corr.appendChild(p);
  });
}

/* ----- removal (Stage S7): one command for the whole registry ----- */
const REMOVAL_LABELS = {
  queued: "Waiting to run",
  running: "Working on it",
  submitted: "Request sent — waiting for the broker",
  needs_human: "Needs you",
  blocked: "Blocked by the broker's site",
  verified_removed: "Removed ✓ (checked — really gone)",
  reappeared: "Reappeared after removal",
  failed: "Could not complete",
};
let removalTimer = null;

function stopRemovalPolling() {
  if (removalTimer) { clearTimeout(removalTimer); removalTimer = null; }
}

function scheduleRemovalPoll() {
  stopRemovalPolling();
  removalTimer = setTimeout(async () => {
    removalTimer = null;
    if (!meUser) return;  // signed out meanwhile — stop quietly
    const again = await loadRemoval();
    if (again) scheduleRemovalPoll();
  }, 4000);
}

$("removalBtn").addEventListener("click", async () => {
  if (!meUser) return;
  const btn = $("removalBtn");
  const status = $("removalStatus");
  btn.disabled = true;
  status.textContent = "Checking your permission…";
  try {
    // Same rule as the full scan: never grant consent for the user —
    // explain and point at the toggle.
    const c = await apiJson("/api/consents");
    const removal = c.ok && (c.data.consents || [])
      .find((x) => x.purpose === "automated_remediation");
    if (!removal || !removal.granted) {
      status.textContent = "The Automatic removal permission is off — turn it on above and press the button again. LeakGuard never submits anything for you without it.";
      const toggle = document.querySelector(
        "#consentList input[data-purpose='automated_remediation']");
      if (toggle) {
        toggle.scrollIntoView({ behavior: "smooth", block: "center" });
        toggle.focus();
      }
      btn.disabled = false;
      return;
    }
    status.textContent = "Opening your removal cases…";
    const r = await apiJson("/api/remediation/run", {
      method: "POST", headers: AH, body: "{}",
    });
    if (!r.ok) throw new Error(errMsg(r.data, "Could not start removal"));
    status.textContent = r.data.cases_created
      ? "Started — " + r.data.cases_created + " new case(s) opened. LeakGuard is working through them now."
      : "Your cases are already open — LeakGuard is working through them.";
    await loadRemoval();
    scheduleRemovalPoll();
    loadActionCenter();
  } catch (err) {
    status.textContent = err.message;
  } finally {
    btn.disabled = false;
  }
});

async function loadRemoval() {
  if (!meUser) return false;
  const [casesR, queueR] = await Promise.all([
    apiJson("/api/remediation/cases"),
    apiJson("/api/remediation/queue"),
  ]);
  if (!casesR.ok) return false;
  const cases = casesR.data.cases || [];
  renderRemovalCounts(cases);
  renderRemovalQueue(queueR.ok ? (queueR.data.queue || []) : []);
  renderRemovalCases(cases);
  // Keep polling while anything is still queued or running.
  return cases.some((c) => c.status === "queued" || c.status === "running");
}

function renderRemovalCounts(cases) {
  const wrap = $("removalCounts");
  wrap.innerHTML = "";
  if (!cases.length) return;
  const counts = {};
  cases.forEach((c) => { counts[c.status] = (counts[c.status] || 0) + 1; });
  const p = document.createElement("p");
  p.className = "hint";
  p.textContent = "Your removal cases: " + Object.keys(REMOVAL_LABELS)
    .filter((s) => counts[s])
    .map((s) => counts[s] + " " + REMOVAL_LABELS[s].toLowerCase())
    .join(" · ");
  wrap.appendChild(p);
}

function renderRemovalQueue(queue) {
  const wrap = $("removalQueue");
  wrap.innerHTML = "";
  if (!queue.length) return;
  const h = document.createElement("p");
  h.innerHTML = "<b>Needs you:</b> these brokers would not accept an automatic request. Each one below has the exact step to finish it.";
  wrap.appendChild(h);
  queue.forEach((item) => {
    const card = document.createElement("div");
    card.className = "consentRow";
    const text = document.createElement("div");
    text.className = "cText";
    const b = document.createElement("b");
    b.textContent = item.broker_name;
    text.appendChild(b);
    const note = document.createElement("span");
    if (item.action === "send_email") {
      note.textContent = "This broker accepts removal requests by email — but only from YOUR email address. We wrote the letter for you; send it from your own mailbox and it becomes a legal erasure request.";
    } else {
      note.textContent = item.note || "";
    }
    text.appendChild(note);
    card.appendChild(text);
    const btns = document.createElement("div");
    btns.className = "rowBtns";
    if (item.action === "send_email") {
      const mail = document.createElement("button");
      mail.type = "button";
      mail.textContent = "Open the letter in my email app";
      mail.addEventListener("click", () => {
        window.location.href = "mailto:" + encodeURIComponent(item.to)
          + "?subject=" + encodeURIComponent(item.subject || "")
          + "&body=" + encodeURIComponent(item.body || "");
      });
      btns.appendChild(mail);
      const done = document.createElement("button");
      done.type = "button";
      done.className = "btnGhost";
      done.textContent = "I sent it";
      done.addEventListener("click", () => retryRemovalCase(item.id, done));
      btns.appendChild(done);
    } else {
      const open = document.createElement("button");
      open.type = "button";
      open.textContent = "Open opt-out page";
      open.addEventListener("click", () => {
        window.open(item.url, "_blank", "noopener");
      });
      btns.appendChild(open);
      const done = document.createElement("button");
      done.type = "button";
      done.className = "btnGhost";
      done.textContent = "I did it — try again";
      done.addEventListener("click", () => retryRemovalCase(item.id, done));
      btns.appendChild(done);
    }
    card.appendChild(btns);
    wrap.appendChild(card);
  });
}

async function retryRemovalCase(caseId, btn) {
  btn.disabled = true;
  const r = await apiJson("/api/remediation/cases/" + caseId + "/retry", {
    method: "POST", headers: AH, body: "{}",
  });
  if (r.ok) {
    $("removalStatus").textContent = "Queued again — LeakGuard will pick it up in a moment.";
    await loadRemoval();
    scheduleRemovalPoll();
  } else {
    $("removalStatus").textContent = errMsg(r.data, "Could not re-queue that case");
    btn.disabled = false;
  }
}

function renderRemovalCases(cases) {
  const wrap = $("removalCases");
  wrap.innerHTML = "";
  const checkable = cases.filter(
    (c) => c.status === "submitted" || c.status === "verified_removed");
  if (!checkable.length) return;
  const h = document.createElement("p");
  h.className = "hint";
  h.textContent = "Brokers who have your request — “Check now” goes back and looks for your listing. Only a check that finds nothing earns the word Removed.";
  wrap.appendChild(h);
  checkable.forEach((c) => {
    const row = document.createElement("div");
    row.className = "consentRow";
    const text = document.createElement("div");
    text.className = "cText";
    const b = document.createElement("b");
    b.textContent = c.broker_name;
    const s = document.createElement("span");
    s.textContent = REMOVAL_LABELS[c.status]
      + (c.reason === "still_listed" ? " — last check: still listed" : "");
    text.appendChild(b); text.appendChild(s);
    row.appendChild(text);
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btnGhost";
    btn.textContent = c.status === "verified_removed" ? "Re-check" : "Check now";
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      const r = await apiJson("/api/remediation/cases/" + c.id + "/verify", {
        method: "POST", headers: AH, body: "{}",
      });
      if (r.ok) {
        $("removalStatus").textContent = r.data.outcome === "gone"
          ? c.broker_name + ": checked — your listing is gone."
          : r.data.outcome === "still_present"
            ? c.broker_name + ": still listed. Brokers can take days — check again later."
            : c.broker_name + ": couldn't confirm either way this time — nothing was guessed.";
        await loadRemoval();
      } else {
        $("removalStatus").textContent = errMsg(r.data, "Could not check that case");
      }
      btn.disabled = false;
    });
    row.appendChild(btn);
    wrap.appendChild(row);
  });
}

/* ----- two-factor ----- */
function renderTotp() {
  const on = !!(meUser && meUser.totp_enabled);
  $("totpStatus").textContent = on ? "On" : "Off";
  $("totpEnrollBtn").style.display = on ? "none" : "";
  if (on) $("totpEnrollBox").hidden = true;
  $("totpDisableBox").hidden = !on;
}

$("totpEnrollBtn").addEventListener("click", async () => {
  const r = await apiJson("/api/auth/totp/enroll", {
    method: "POST", headers: AH, body: "{}",
  });
  if (r.ok) {
    $("totpUri").value = r.data.otpauth_uri;
    $("totpEnrollBox").hidden = false;
    $("totpMsg").textContent = "Setup text ready — it is shown only this once, copy it into your app now.";
  } else {
    $("totpMsg").textContent = errMsg(r.data, "Could not start two-factor setup");
  }
});

$("totpCopyBtn").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("totpUri").value); $("totpCopyBtn").textContent = "Copied ✓"; }
  catch (e) { $("totpUri").select(); document.execCommand("copy"); }
  setTimeout(() => { $("totpCopyBtn").textContent = "Copy setup text"; }, 1600);
});

$("totpActivateBtn").addEventListener("click", async () => {
  const r = await apiJson("/api/auth/totp/activate", {
    method: "POST", headers: AH,
    body: JSON.stringify({ code: $("totpCode").value.trim() }),
  });
  if (r.ok) {
    meUser.totp_enabled = true;
    $("totpCode").value = "";
    $("totpEnrollBox").hidden = true;
    $("totpMsg").textContent = "Two-factor is ON ✓ — from now on, signing in needs a code too.";
    renderTotp();
  } else {
    $("totpMsg").textContent = errMsg(r.data, "That code did not match");
  }
});

$("totpDisableBtn").addEventListener("click", async () => {
  const r = await apiJson("/api/auth/totp/disable", {
    method: "POST", headers: AH,
    body: JSON.stringify({
      password: $("totpDisablePw").value,
      code: $("totpDisableCode").value.trim(),
    }),
  });
  if (r.ok) {
    meUser.totp_enabled = false;
    $("totpDisablePw").value = "";
    $("totpDisableCode").value = "";
    $("totpMsg").textContent = "Two-factor is OFF.";
    renderTotp();
  } else {
    $("totpMsg").textContent = errMsg(r.data, "Could not switch two-factor off");
  }
});

/* ----- passkeys (WebAuthn) -----
   Feature-detected throughout: browsers/devices without the
   WebAuthn API simply never see the sign-in button, and the
   management section explains itself instead of offering an
   "Add" that cannot work. Listing and removing passkeys works
   everywhere — removing one from a borrowed device matters most
   exactly where passkeys cannot be created. */
const WEBAUTHN_AVAILABLE = !!(
  window.PublicKeyCredential && navigator.credentials
  && navigator.credentials.create && navigator.credentials.get);

function b64urlToBytes(text) {
  let s = String(text).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

if (WEBAUTHN_AVAILABLE) $("acPasskeyBtn").hidden = false;

$("acPasskeyBtn").addEventListener("click", async () => {
  $("acStatus").textContent = "Waiting for your device…";
  try {
    const opt = await apiJson("/api/auth/passkey/login/options", {
      method: "POST", headers: AH, body: "{}",
    });
    if (!opt.ok) throw new Error(errMsg(opt.data, "Passkey sign-in is not available right now"));
    const o = opt.data;
    let assertion;
    try {
      assertion = await navigator.credentials.get({
        publicKey: {
          challenge: b64urlToBytes(o.challenge),
          rpId: o.rpId,
          timeout: o.timeout,
          userVerification: o.userVerification,
          allowCredentials: [],
        },
      });
    } catch (e) {
      $("acStatus").textContent = "Passkey sign-in was cancelled — your password still works below.";
      return;
    }
    const r = await apiJson("/api/auth/passkey/login/verify", {
      method: "POST", headers: AH,
      body: JSON.stringify({
        id: assertion.id,
        rawId: bytesToB64url(assertion.rawId),
        type: assertion.type,
        response: {
          clientDataJSON: bytesToB64url(assertion.response.clientDataJSON),
          authenticatorData: bytesToB64url(assertion.response.authenticatorData),
          signature: bytesToB64url(assertion.response.signature),
        },
      }),
    });
    if (!r.ok) throw new Error(errMsg(r.data, "Passkey sign-in failed"));
    meUser = r.data.user;
    $("acPassword").value = "";
    $("acStatus").textContent = "";
    renderAccount();
  } catch (err) {
    $("acStatus").textContent = err.message;
  }
});

async function loadPasskeys() {
  const wrap = $("passkeyList");
  if (!wrap) return;
  $("pkAddBtn").disabled = !WEBAUTHN_AVAILABLE;
  $("pkUnsupported").hidden = WEBAUTHN_AVAILABLE;
  const r = await apiJson("/api/auth/passkeys");
  if (!r.ok) { wrap.innerHTML = ""; return; }
  const keys = r.data.passkeys || [];
  if (!keys.length) {
    wrap.innerHTML = '<p class="hint">No passkeys yet.</p>';
    return;
  }
  wrap.innerHTML = "";
  for (const key of keys) {
    const row = document.createElement("div");
    row.className = "rowBtns";
    const added = key.created_at ? new Date(key.created_at).toLocaleDateString() : "";
    const used = key.last_used_at
      ? "last used " + new Date(key.last_used_at).toLocaleDateString() : "never used yet";
    const label = document.createElement("span");
    label.textContent = key.nickname + " (" + key.id_prefix + "…) · added " + added + " · " + used;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btnGhost";
    btn.textContent = "Remove this passkey";
    btn.addEventListener("click", async () => {
      const password = $("pkPassword").value;
      if (!password) {
        $("pkMsg").textContent = "Type your password first — removing a passkey asks for it once more.";
        return;
      }
      const rr = await apiJson("/api/auth/passkeys/" + key.id + "/revoke", {
        method: "POST", headers: AH, body: JSON.stringify({ password }),
      });
      if (rr.ok) {
        $("pkMsg").textContent = "Passkey removed — it can no longer sign you in.";
        loadPasskeys();
      } else {
        $("pkMsg").textContent = errMsg(rr.data, "Could not remove that passkey");
      }
    });
    row.appendChild(label);
    row.appendChild(btn);
    wrap.appendChild(row);
  }
}

$("pkAddBtn").addEventListener("click", async () => {
  const nickname = $("pkNickname").value.trim();
  const password = $("pkPassword").value;
  if (!nickname) { $("pkMsg").textContent = "Give the passkey a name first (for example: My phone)."; return; }
  if (!password) { $("pkMsg").textContent = "Type your password first — adding a passkey asks for it once more."; return; }
  $("pkMsg").textContent = "Waiting for your device…";
  try {
    const opt = await apiJson("/api/auth/passkey/register/options", {
      method: "POST", headers: AH, body: JSON.stringify({ password }),
    });
    if (!opt.ok) throw new Error(errMsg(opt.data, "Could not start passkey setup"));
    const o = opt.data;
    let credential;
    try {
      credential = await navigator.credentials.create({
        publicKey: {
          challenge: b64urlToBytes(o.challenge),
          rp: o.rp,
          user: {
            id: b64urlToBytes(o.user.id),
            name: o.user.name,
            displayName: o.user.displayName,
          },
          pubKeyCredParams: o.pubKeyCredParams,
          excludeCredentials: (o.excludeCredentials || []).map((c) => ({
            type: c.type, id: b64urlToBytes(c.id),
          })),
          authenticatorSelection: o.authenticatorSelection,
          timeout: o.timeout,
          attestation: o.attestation,
        },
      });
    } catch (e) {
      $("pkMsg").textContent = "Passkey setup was cancelled on this device — nothing was added.";
      return;
    }
    const r = await apiJson("/api/auth/passkey/register/verify", {
      method: "POST", headers: AH,
      body: JSON.stringify({
        id: credential.id,
        rawId: bytesToB64url(credential.rawId),
        type: credential.type,
        nickname,
        transports: credential.response.getTransports
          ? credential.response.getTransports() : [],
        response: {
          clientDataJSON: bytesToB64url(credential.response.clientDataJSON),
          attestationObject: bytesToB64url(credential.response.attestationObject),
        },
      }),
    });
    if (!r.ok) throw new Error(errMsg(r.data, "Could not add that passkey"));
    $("pkNickname").value = "";
    $("pkPassword").value = "";
    $("pkMsg").textContent = "Passkey added ✓ — you can now sign in with it from the sign-in form.";
    loadPasskeys();
  } catch (err) {
    $("pkMsg").textContent = err.message;
  }
});

/* ----- export, password change, account deletion ----- */
$("exportBtn").addEventListener("click", async () => {
  const password = $("exportPassword").value;
  const format = $("exportFormat").value;
  if (!password) {
    $("exportMsg").textContent = "Type your password first — the download contains your details in full.";
    return;
  }
  $("exportMsg").textContent = "Preparing your file…";
  try {
    const resp = await fetch("/api/privacy/export", {
      method: "POST", headers: AH,
      body: JSON.stringify({ password, format }),
    });
    if (!resp.ok) {
      const d = await resp.json().catch(() => null);
      throw new Error(errMsg(d, "Export failed"));
    }
    const blob = await resp.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = format === "csv" ? "leakguard-export.csv" : "leakguard-export.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
    $("exportMsg").textContent = "Downloaded ✓ — keep the file somewhere private.";
  } catch (err) {
    $("exportMsg").textContent = err.message;
  }
  $("exportPassword").value = "";
});

$("cpBtn").addEventListener("click", async () => {
  const r = await apiJson("/api/auth/change-password", {
    method: "POST", headers: AH,
    body: JSON.stringify({
      current_password: $("cpCurrent").value,
      new_password: $("cpNew").value,
    }),
  });
  if (r.ok) {
    $("cpCurrent").value = "";
    $("cpNew").value = "";
    $("cpMsg").textContent = "Password changed ✓ — every other device was signed out.";
  } else {
    $("cpMsg").textContent = errMsg(r.data, "Could not change the password");
  }
});

$("delBtn").addEventListener("click", async () => {
  if (!$("delConfirm").checked) {
    $("delMsg").textContent = "Tick the “I understand” box first.";
    return;
  }
  const r = await apiJson("/api/auth/delete-account", {
    method: "POST", headers: AH,
    body: JSON.stringify({ password: $("delPassword").value }),
  });
  if (r.ok) {
    meUser = null;
    $("delPassword").value = "";
    $("delConfirm").checked = false;
    renderAccount();
    $("acStatus").textContent = "Your account and saved details were deleted.";
    $("account").scrollIntoView({ behavior: "smooth" });
  } else {
    $("delMsg").textContent = errMsg(r.data, "Could not delete the account");
  }
});

loadMe();

/* ---------------- Password-reset landing (/reset?token=...) ----------------
   Runs synchronously at script load — before loadMe()'s fetch can
   resolve — so the reset form is the only thing the account panel
   will show (renderAccount honours lgResetMode). */
(function () {
  if (location.pathname !== "/reset") return;
  lgResetMode = true;
  lgResetToken = new URLSearchParams(location.search).get("token");
  const panel = $("account");
  panel.hidden = false;
  $("authForms").hidden = true;
  $("privacyCenter").hidden = true;
  $("resetBox").hidden = false;
  if (!lgResetToken) {
    $("rsStatus").textContent = "This reset link is missing its token — request a new one from the sign-in form.";
    $("rsBtn").disabled = true;
  }
  panel.scrollIntoView();
})();

/* ---------------- Sign-in page (/signin) ----------------
   The dedicated sign-in page: the same landing pattern as /reset.
   body.signinPage (style.css) strips the page down to the auth
   panel alone; renderAccount handles the rest, including sending
   an already-signed-in visitor (or a fresh sign-in) home. */
(function () {
  if (location.pathname !== "/signin") return;
  lgSigninMode = true;
  document.body.classList.add("signinPage");
  const panel = $("account");
  panel.hidden = false;
  $("authForms").hidden = false;
  $("privacyCenter").hidden = true;
  window.scrollTo(0, 0);
})();

/* ---------------- Static information pages ----------------
   The Trust, Privacy, Terms and Support sections live in the same
   page (hidden); their URLs simply unhide and jump to the matching
   section. Everything else on the page keeps working — these
   sections are reading material, not modes. */
(function () {
  const pages = {
    "/trust": "trust",
    "/privacy": "privacyPolicy",
    "/terms": "terms",
    "/support": "supportPage",
  };
  const section = $(pages[location.pathname] || "");
  if (!section) return;
  section.hidden = false;
  section.scrollIntoView();
})();

/* ---------------- Service worker (Stage S14, PWA shell) ----------------
   Registers static/sw.js (served at /sw.js so its scope covers the
   app). The worker caches ONLY the static shell and never touches
   /api/* traffic. Registration is best-effort: any failure (old
   browser, non-secure context) leaves the app exactly as it was. */
(function () {
  try {
    if (!("serviceWorker" in navigator)) return;
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("/sw.js").catch(() => {});
    });
  } catch (e) { /* the app must never depend on the worker */ }
})();

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

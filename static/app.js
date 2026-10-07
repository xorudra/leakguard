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
  const signedIn = !!meUser;
  $("acctBtn").textContent = signedIn ? "My Privacy Center" : "Sign in";
  $("acctLabel").hidden = !signedIn;
  if (signedIn) $("acctLabel").textContent = meUser.email_masked;
  $("authForms").hidden = signedIn;
  $("privacyCenter").hidden = !signedIn;
  if (signedIn) {
    $("pcEmail").textContent = meUser.email_masked;
    $("pcSince").textContent = meUser.created_at
      ? "· member since " + new Date(meUser.created_at).toLocaleDateString() : "";
    renderTotp();
    loadIdentifiers();
    loadConsents();
  }
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
  const panel = $("account");
  panel.hidden = !panel.hidden;
  if (!panel.hidden) {
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
    if (meUser) renderAccount();
  }
});

$("authForm").addEventListener("submit", async (e) => {
  e.preventDefault();
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

$("acRegisterBtn").addEventListener("click", async () => {
  const email = $("acEmail").value.trim();
  const password = $("acPassword").value;
  if (!email || !password) {
    $("acStatus").textContent = "Enter an email and a password (at least 10 characters) first.";
    return;
  }
  $("acStatus").textContent = "Creating your account…";
  try {
    const r = await apiJson("/api/auth/register", {
      method: "POST", headers: AH,
      body: JSON.stringify({ email, password }),
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

$("pcLogoutBtn").addEventListener("click", async () => {
  try {
    await apiJson("/api/auth/logout", { method: "POST", headers: AH, body: "{}" });
  } catch (e) { /* cookie is cleared either way on next load */ }
  meUser = null;
  renderAccount();
  $("acStatus").textContent = "Signed out.";
});

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
      const rm = document.createElement("button");
      rm.type = "button";
      rm.className = "btnGhost miniBtn";
      rm.textContent = "Remove";
      rm.addEventListener("click", async () => {
        rm.disabled = true;
        const d = await apiJson("/api/identifiers/" + rec.id, {
          method: "DELETE", headers: { "X-Requested-With": "fetch" },
        });
        if (d.ok) { loadIdentifiers(); $("idStatus").textContent = "Removed."; }
        else { $("idStatus").textContent = errMsg(d.data, "Remove failed"); rm.disabled = false; }
      });
      row.appendChild(left); row.appendChild(rm);
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
  } else {
    $("idStatus").textContent = errMsg(r.data, "Could not save that detail");
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
  ["notifications", "Notifications", "Email me when something important changes — a new leak found, a removal finished."],
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
  if (r.ok) renderConsents(r.data.consents);
  else $("consentList").innerHTML = "<p class='hint'>" + errMsg(r.data, "Could not load permissions") + "</p>";
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

/* ----- export, password change, account deletion ----- */
$("exportBtn").addEventListener("click", async () => {
  try {
    const resp = await fetch("/api/privacy/export");
    if (!resp.ok) {
      const d = await resp.json().catch(() => null);
      throw new Error(errMsg(d, "Export failed"));
    }
    const blob = await resp.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "leakguard-export.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  } catch (err) {
    $("cpMsg").textContent = err.message;
  }
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

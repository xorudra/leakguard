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
  $("scoreNum").textContent = d.exposure_score === null ? "–" : d.exposure_score;
  $("scoreText").textContent = scoreLabel(d.exposure_score);
  $("sourceText").textContent = "Sources: " + d.sources.join(" · ");
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
    d.breaches.forEach((b) => {
      const s = document.createElement("span");
      s.className = "breachChip";
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
}
async function loadBrokers() {
  try {
    const resp = await fetch("/api/brokers");
    const data = await resp.json();
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
      method.textContent = b.method;
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

"use strict";
/* LeakGuard popup: one glance — score, counts, the server's one
   next action — and one button to the full site. Read-only: it
   GETs /api/v1/action-center with the stored token and changes
   nothing anywhere. */

const STATES = ["stateLoading", "stateSetup", "stateMain",
                "stateBadToken", "stateError"];

function show(id) {
  STATES.forEach((s) => { document.getElementById(s).hidden = s !== id; });
}

function openSite() {
  chrome.tabs.create({ url: LG_ORIGIN + "/" });
}

function openOptions() {
  if (chrome.runtime.openOptionsPage) {
    chrome.runtime.openOptionsPage();
  } else {
    chrome.tabs.create({ url: chrome.runtime.getURL("options.html") });
  }
}

document.getElementById("openBtn").addEventListener("click", openSite);
document.getElementById("openBtn2").addEventListener("click", openSite);
document.getElementById("setupBtn").addEventListener("click", openOptions);
document.getElementById("fixBtn").addEventListener("click", openOptions);

function scoreClass(score) {
  if (score === null || score === undefined) return "";
  if (score === 0) return "sev-low";
  if (score < 35) return "sev-med";
  if (score < 70) return "sev-high";
  return "sev-crit";
}

async function main() {
  show("stateLoading");
  const token = await lgGetToken();
  if (!token) { show("stateSetup"); return; }
  const r = await lgApi("/api/v1/action-center");
  if (r.status === 401) { show("stateBadToken"); return; }
  if (r.status !== 200 || !r.data) { show("stateError"); return; }
  const d = r.data;
  const exp = d.exposure || {};
  const num = document.getElementById("scoreNum");
  if (exp.score === null || exp.score === undefined) {
    num.textContent = "–";
    document.getElementById("scoreBand").textContent =
      "Not scanned yet";
  } else {
    num.textContent = exp.score;
    num.className = "scoreNum " + scoreClass(exp.score);
    document.getElementById("scoreBand").textContent =
      (exp.band || "Exposure") + " — score / 100";
  }
  const findings = exp.findings_total || 0;
  const needsYou = (d.counts && d.counts.cases
    && d.counts.cases.needs_human) || 0;
  const bits = [
    findings + (findings === 1 ? " exposure" : " exposures"),
    needsYou + (needsYou === 1 ? " case needs" : " cases need") + " you",
  ];
  document.getElementById("countsLine").textContent = bits.join(" · ");
  const na = d.next_action || {};
  document.getElementById("nextAction").textContent = na.label
    ? "Next: " + na.label : "";
  show("stateMain");
}

main();

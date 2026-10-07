"use strict";
/* LeakGuard extension options: store the API token locally, and
   prove it works against GET /api/v1/action-center before claiming
   success. The token is the ONLY credential this extension holds. */

const input = document.getElementById("tokenInput");
const status = document.getElementById("status");

function say(text) { status.textContent = text; }

async function load() {
  input.value = await lgGetToken();
}

document.getElementById("saveBtn").addEventListener("click", async () => {
  const token = input.value.trim();
  if (!token) { say("Paste a token first — it starts with lg_."); return; }
  await lgSetToken(token);
  say("Saved. Use Test connection to check it works.");
});

document.getElementById("clearBtn").addEventListener("click", async () => {
  await lgSetToken("");
  input.value = "";
  say("Token removed from this browser.");
});

document.getElementById("testBtn").addEventListener("click", async () => {
  const token = input.value.trim();
  if (token) await lgSetToken(token);
  say("Testing…");
  const r = await lgApi("/api/v1/action-center");
  if (r.noToken) {
    say("No token saved yet — paste one above first.");
  } else if (r.status === 200) {
    const exp = (r.data && r.data.exposure) || {};
    say("Connected ✓ — LeakGuard answered with your exposure data" +
      (exp.score === null || exp.score === undefined
        ? " (no scan yet)."
        : " (score " + exp.score + " / 100)."));
  } else if (r.status === 401) {
    say("That token doesn't work — it may have been revoked. " +
        "Create a fresh one in the Privacy Center and paste it here.");
  } else {
    say("Couldn't reach LeakGuard just now (the free server may be " +
        "waking up). Nothing was changed — try again in a few seconds.");
  }
});

load();

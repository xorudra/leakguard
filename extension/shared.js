"use strict";
/* LeakGuard extension — shared bits for the popup and options.

   The extension talks to exactly ONE origin (also the only host
   permission in the manifest) and only ever sends the user's own
   read-only API token, as a Bearer header. It never sees, asks for
   or stores the account's sign-in credentials: tokens are created
   in the LeakGuard Privacy Center, are read-only by construction
   on the server, and can be revoked there at any time. */
const LG_ORIGIN = "https://leakguard-hh8e.onrender.com";

function lgGetToken() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["lgApiToken"], (items) => {
      resolve((items && items.lgApiToken) || "");
    });
  });
}

function lgSetToken(token) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ lgApiToken: token }, () => resolve());
  });
}

/* GET a read-only API path with the stored token.
   Resolves {status, data}; status 0 means the request never
   completed (offline, server asleep) — callers word it honestly. */
async function lgApi(path) {
  const token = await lgGetToken();
  if (!token) return { status: 0, data: null, noToken: true };
  try {
    const resp = await fetch(LG_ORIGIN + path, {
      headers: { "Authorization": "Bearer " + token },
    });
    let data = null;
    try { data = await resp.json(); } catch (e) { /* non-JSON */ }
    return { status: resp.status, data };
  } catch (e) {
    return { status: 0, data: null };
  }
}

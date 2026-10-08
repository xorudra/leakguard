"use strict";
/* LeakGuard service worker (Stage S14) — deliberately minimal.

   Cache-first ONLY for the static app shell listed below, so the
   page chrome loads instantly (and offline). EVERYTHING else —
   above all every /api/* request — is network-only: API responses
   carry the user's own exposure data and are never stored in a
   cache, never served stale, never touched by this worker at all.

   If registration fails (old browser, non-secure context) the app
   simply runs without a worker — this file is an enhancement,
   never a dependency. Bump the cache name to retire old shells. */
const LG_CACHE = "leakguard-shell-v4";
const LG_SHELL = [
  "/",
  "/static/style.css",
  "/static/app.js",
  "/static/manifest.webmanifest",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(LG_CACHE)
      .then((cache) => cache.addAll(LG_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((names) => Promise.all(
        names.filter((name) => name !== LG_CACHE)
          .map((name) => caches.delete(name))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  // API traffic is network-only: never cached, never intercepted.
  if (url.pathname.startsWith("/api/")) return;
  if (event.request.method !== "GET") return;
  if (LG_SHELL.indexOf(url.pathname) === -1) return;
  event.respondWith(
    caches.match(event.request).then((hit) => hit || fetch(event.request))
  );
});

// Progressive enhancement for the portal. Every page works without this
// script; with it:
//   - links and forms load in place (fetch, then swap the body), with
//     pages prefetched while the pointer rests on a link, so moving around
//     doesn't flash a blank page;
//   - destructive forms ask first;
//   - IDs, secrets and configs get copy buttons;
//   - the file browser uploads by picker or drag and drop, several files
//     at a time, folders included.
"use strict";

// ---------------------------------------------------------------- navigation

const prefetched = new Map(); // url -> {at, page: Promise}
const PREFETCH_TTL = 10000;
let current = null; // AbortController of the navigation in flight

function sameOrigin(url) {
  return url.origin === location.origin;
}

// navigable says whether a link should load in place.
function navigable(a, ev) {
  if (!a || a.target || a.hasAttribute("download") || a.hasAttribute("data-full")) return false;
  if (ev && (ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey)) return false;
  const url = new URL(a.href, location.href);
  if (!sameOrigin(url) || url.pathname.startsWith("/auth/") || url.pathname === "/download") return false;
  return !(url.pathname === location.pathname && url.search === location.search && url.hash);
}

// load fetches a page and resolves to {url, redirected, html} or, for a
// response that isn't a page, {url, text, status}.
async function load(url, init) {
  const res = await fetch(url, Object.assign({ credentials: "same-origin" }, init));
  const type = res.headers.get("Content-Type") || "";
  if (type.startsWith("text/html")) {
    return { url: res.url, redirected: res.redirected, html: await res.text() };
  }
  return { url: res.url, status: res.status, text: await res.text() };
}

function prefetch(href) {
  const hit = prefetched.get(href);
  if (hit && Date.now() - hit.at < PREFETCH_TTL) return;
  const page = load(href).catch(() => null);
  prefetched.set(href, { at: Date.now(), page });
}

function setBusy(on) {
  clearTimeout(setBusy.timer);
  if (on) {
    setBusy.timer = setTimeout(() => document.documentElement.classList.add("busy"), 120);
  } else {
    document.documentElement.classList.remove("busy");
  }
}

function showError(msg) {
  const flash = document.getElementById("flash");
  if (!flash) return alert(msg);
  const p = document.createElement("p");
  p.className = "flash error";
  p.setAttribute("role", "alert");
  p.textContent = msg;
  flash.replaceChildren(p);
  scrollTo(0, 0);
}

// swap shows a fetched page in place of this one.
function swap(html) {
  const doc = new DOMParser().parseFromString(html, "text/html");
  // A page that redirects onward itself (the post-login step) gets a real load.
  if (doc.querySelector("meta[http-equiv=refresh]")) return false;
  document.title = doc.title;
  document.body.replaceWith(document.adoptNode(doc.body));
  enhance();
  const focus = document.querySelector("[autofocus]");
  if (focus) focus.focus();
  return true;
}

// navigate loads url (or submits a form to it) in place.
async function navigate(url, { method = "GET", body = null, push = true, keepScroll = false, scrollY = null } = {}) {
  if (current) current.abort();
  const ctl = new AbortController();
  current = ctl;
  setBusy(true);
  const before = location.pathname + location.search;
  try {
    let result;
    const hit = method === "GET" && prefetched.get(url);
    if (hit && Date.now() - hit.at < PREFETCH_TTL) {
      result = await hit.page;
    }
    prefetched.clear(); // anything else may be stale after this
    if (!result) {
      result = await load(url, { method, body, signal: ctl.signal });
    }
    if (ctl.signal.aborted) return;
    if (result.html === undefined) {
      if (method === "GET") {
        location.assign(url);
      } else {
        showError(result.text.trim() || "That didn't work.");
      }
      return;
    }
    if (!swap(result.html)) {
      location.assign(result.url);
      return;
    }
    // A POST that rendered a page (a form error, a new key) keeps the URL.
    const landed = new URL(result.url);
    const path = landed.pathname + landed.search;
    if (method === "GET" || result.redirected) {
      if (push && path !== before) {
        history.pushState({ y: 0 }, "", path);
      } else {
        history.replaceState(history.state, "", path);
      }
    }
    if (scrollY !== null) {
      scrollTo(0, scrollY);
    } else if (!keepScroll && path !== before) {
      scrollTo(0, 0);
    }
  } catch (err) {
    if (err.name === "AbortError") return;
    if (method === "GET") {
      location.assign(url);
    } else {
      showError("Couldn't reach the server. Check your connection and try again.");
    }
  } finally {
    if (current === ctl) {
      current = null;
      setBusy(false);
    }
  }
}

document.addEventListener("click", (ev) => {
  const a = ev.target.closest("a[href]");
  if (!navigable(a, ev)) return;
  ev.preventDefault();
  navigate(new URL(a.href, location.href).href);
});

let hoverTimer = null;
document.addEventListener("pointerover", (ev) => {
  const a = ev.target.closest("a[href]");
  clearTimeout(hoverTimer);
  if (!navigable(a)) return;
  hoverTimer = setTimeout(() => prefetch(new URL(a.href, location.href).href), 65);
});
document.addEventListener("pointerout", () => clearTimeout(hoverTimer));
document.addEventListener("touchstart", (ev) => {
  const a = ev.target.closest("a[href]");
  if (navigable(a)) prefetch(new URL(a.href, location.href).href);
}, { passive: true });

document.addEventListener("submit", (ev) => {
  const form = ev.target;
  const msg = form.dataset.confirm;
  if (msg && !window.confirm(msg)) {
    ev.preventDefault();
    return;
  }
  if (form.hasAttribute("data-full") || form.method.toLowerCase() !== "post") return;
  ev.preventDefault();
  const body = new URLSearchParams(new FormData(form, ev.submitter));
  const buttons = Array.from(form.querySelectorAll("button"));
  for (const b of buttons) b.disabled = true;
  // Actions on this page come back to it: keep the reader's place.
  navigate(form.action, { method: "POST", body, keepScroll: true })
    .finally(() => { for (const b of buttons) b.disabled = false; });
});

// Remember where the reader was on each page, for back and forward.
let scrollTimer = null;
window.addEventListener("scroll", () => {
  clearTimeout(scrollTimer);
  scrollTimer = setTimeout(() => history.replaceState({ y: window.scrollY }, ""), 100);
}, { passive: true });

window.addEventListener("popstate", (ev) => {
  navigate(location.href, { push: false, scrollY: ev.state && ev.state.y || 0 });
});

// ------------------------------------------------------------------ enhance

function markCurrentNav() {
  const here = location.pathname === "/admin" ? "/admin" : "/";
  for (const a of document.querySelectorAll("nav.links a")) {
    if (a.getAttribute("href") === here) a.setAttribute("aria-current", "page");
  }
}

function addCopyButtons() {
  if (!navigator.clipboard) return;
  for (const el of document.querySelectorAll(".copy")) {
    if (el.dataset.copyReady) continue;
    el.dataset.copyReady = "1";
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy-btn";
    btn.textContent = "Copy";
    btn.setAttribute("aria-label", "Copy to clipboard");
    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(el.textContent);
        btn.textContent = "Copied";
        btn.classList.add("done");
        setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("done"); }, 1500);
      } catch {
        btn.textContent = "Select and copy";
      }
    });
    if (el.tagName === "PRE") {
      el.append(btn);
    } else {
      const wrap = document.createElement("span");
      wrap.className = "copyable";
      el.replaceWith(wrap);
      wrap.append(el, btn);
    }
  }
}

function enhance() {
  markCurrentNav();
  addCopyButtons();
}

// Close an open menu when clicking elsewhere.
document.addEventListener("click", (ev) => {
  for (const d of document.querySelectorAll("details.menu[open]")) {
    if (!d.contains(ev.target)) d.open = false;
  }
});

// Buttons that are labels for hidden file inputs need the keyboard too.
document.addEventListener("keydown", (ev) => {
  const label = ev.target.closest && ev.target.closest("label.button");
  if (label && (ev.key === "Enter" || ev.key === " ")) {
    ev.preventDefault();
    label.querySelector("input").click();
  }
});

// ------------------------------------------------------------------ uploads

const PARALLEL_UPLOADS = 3;

function putFile(box, key, file, progress) {
  return new Promise((resolve, reject) => {
    const q = new URLSearchParams({ bucket: box.dataset.bucket, key });
    const x = new XMLHttpRequest();
    x.open("PUT", "/upload?" + q.toString());
    x.setRequestHeader("X-CSRF-Token", box.dataset.csrf);
    x.setRequestHeader("Content-Type", file.type || "application/octet-stream");
    x.upload.addEventListener("progress", (ev) => {
      if (ev.lengthComputable) progress.value = ev.loaded / ev.total;
    });
    x.addEventListener("load", () => {
      if (x.status >= 200 && x.status < 300) {
        resolve();
      } else {
        reject(new Error(x.responseText.trim() || x.statusText));
      }
    });
    x.addEventListener("error", () => reject(new Error("The connection dropped.")));
    x.send(file);
  });
}

// upload sends [{file, path}] into the folder being browsed, a few at a time.
async function upload(box, items) {
  if (!items.length) return;
  const status = box.querySelector("#upload-status");
  const queue = items.map(({ file, path }) => {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.className = "fname";
    name.textContent = path;
    name.title = path;
    const progress = document.createElement("progress");
    progress.max = 1;
    progress.value = 0;
    li.append(name, progress);
    status.append(li);
    return { file, key: box.dataset.prefix + path, li, progress };
  });
  let failed = 0;
  const work = async () => {
    for (let job = queue.shift(); job; job = queue.shift()) {
      try {
        await putFile(box, job.key, job.file, job.progress);
        job.progress.value = 1;
        job.li.remove();
      } catch (err) {
        failed++;
        job.progress.remove();
        const msg = document.createElement("span");
        msg.className = "error-text";
        msg.textContent = err.message;
        job.li.append(msg);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(PARALLEL_UPLOADS, items.length) }, work));
  if (failed === 0) {
    navigate(location.href, { push: false, keepScroll: true });
  }
}

document.addEventListener("change", (ev) => {
  const input = ev.target;
  if (!input.classList.contains("pick")) return;
  const box = input.closest("#files");
  const items = Array.from(input.files, (file) => ({ file, path: file.webkitRelativePath || file.name }));
  input.value = "";
  upload(box, items);
});

// Dropped folders arrive as entries to walk.
async function walk(entry, path, out) {
  if (entry.isFile) {
    const file = await new Promise((res, rej) => entry.file(res, rej));
    out.push({ file, path: path + file.name });
  } else if (entry.isDirectory) {
    const reader = entry.createReader();
    for (;;) {
      const batch = await new Promise((res, rej) => reader.readEntries(res, rej));
      if (!batch.length) break;
      for (const child of batch) await walk(child, path + entry.name + "/", out);
    }
  }
}

let dragDepth = 0;
document.addEventListener("dragenter", (ev) => {
  const box = document.getElementById("files");
  if (!box || !ev.dataTransfer.types.includes("Files")) return;
  dragDepth++;
  box.classList.add("dragging");
});
document.addEventListener("dragleave", () => {
  const box = document.getElementById("files");
  if (box && --dragDepth <= 0) {
    dragDepth = 0;
    box.classList.remove("dragging");
  }
});
document.addEventListener("dragover", (ev) => {
  if (document.getElementById("files")) ev.preventDefault();
});
document.addEventListener("drop", async (ev) => {
  const box = document.getElementById("files");
  if (!box) return;
  ev.preventDefault();
  dragDepth = 0;
  box.classList.remove("dragging");
  const entries = Array.from(ev.dataTransfer.items || [])
    .map((i) => i.webkitGetAsEntry && i.webkitGetAsEntry())
    .filter(Boolean);
  const items = [];
  if (entries.length) {
    for (const e of entries) await walk(e, "", items);
  } else {
    for (const file of ev.dataTransfer.files) items.push({ file, path: file.name });
  }
  upload(box, items);
});

enhance();

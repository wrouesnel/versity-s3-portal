// Progressive enhancement for the portal. Every page works without this
// script; with it:
//   - links and forms load in place (fetch, then swap the body), with
//     pages prefetched while the pointer rests on a link, so moving around
//     doesn't flash a blank page;
//   - destructive forms ask first;
//   - IDs, secrets and configs get copy buttons;
//   - the file browser uploads by picker or drag and drop, several files
//     at a time, folders included, and unpacks .zip and .tar archives;
//   - the bucket list can be filtered, resized, hidden, and on a phone is
//     a drawer.
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
  const side = document.querySelector(".sidebar");
  const kept = side && { top: side.scrollTop, filter: document.getElementById("bucket-filter").value };
  document.body.replaceWith(document.adoptNode(doc.body));
  const newSide = document.querySelector(".sidebar");
  if (kept && newSide) {
    document.getElementById("bucket-filter").value = kept.filter;
    newSide.scrollTop = kept.top;
    newSide.dataset.placed = "1";
  }
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
  const sub = ev.submitter;
  let msg = form.dataset.confirm;
  if (sub && sub.hasAttribute("data-confirm-selection")) msg = selectionQuestion();
  if (msg && !window.confirm(msg)) {
    ev.preventDefault();
    return;
  }
  // Downloads are plain posts: the browser saves the response.
  const action = sub && sub.hasAttribute("formaction") ? sub.formAction : form.action;
  if ((form.hasAttribute("data-full") && !(sub && sub.hasAttribute("formaction"))) || form.method.toLowerCase() !== "post") {
    for (const d of document.querySelectorAll("details.menu[open]")) d.open = false;
    return;
  }
  ev.preventDefault();
  const body = new URLSearchParams(new FormData(form, ev.submitter));
  const buttons = Array.from(form.querySelectorAll("button"));
  for (const b of buttons) b.disabled = true;
  // Actions on this page come back to it: keep the reader's place.
  navigate(action, { method: "POST", body, keepScroll: true })
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

// ------------------------------------------------------------------ buckets

// filterBuckets shows only the buckets, in the sidebar and the all-buckets
// table, whose names contain every word typed in the filter.
function filterBuckets() {
  const input = document.getElementById("bucket-filter");
  if (!input) return;
  const words = input.value.toLowerCase().split(/\s+/).filter(Boolean);
  const match = (name) => words.every((w) => name.includes(w));
  let any = false;
  for (const ul of document.querySelectorAll(".bucket-nav ul")) {
    let shown = 0;
    for (const li of ul.children) {
      const ok = match(li.dataset.name);
      li.hidden = !ok;
      if (ok) shown++;
    }
    const h = ul.previousElementSibling;
    if (h && h.tagName === "H2") {
      h.hidden = shown === 0 && words.length > 0;
      const count = h.querySelector(".count");
      if (count) count.textContent = words.length ? `${shown} of ${ul.children.length}` : ul.children.length;
    }
    if (shown) any = true;
  }
  const none = document.querySelector(".bucket-nav .no-match");
  if (none) none.hidden = any || !words.length;
  for (const tr of document.querySelectorAll(".bucket-table tbody tr")) {
    tr.hidden = !match(tr.dataset.bucket);
  }
}

document.addEventListener("input", (ev) => {
  if (ev.target.id === "bucket-filter") filterBuckets();
});

document.addEventListener("keydown", (ev) => {
  const input = document.getElementById("bucket-filter");
  if (!input) return;
  // "/" jumps to the filter, as in most file and code browsers.
  if (ev.key === "/" && !ev.target.closest("input, textarea, select, [contenteditable]")) {
    ev.preventDefault();
    input.focus();
    input.select();
    return;
  }
  if (ev.target !== input) return;
  if (ev.key === "Escape") {
    input.value = "";
    filterBuckets();
    input.blur();
  } else if (ev.key === "Enter") {
    // Opens the first bucket that matches.
    const first = [...document.querySelectorAll(".bucket-nav li")].find((li) => !li.hidden);
    if (first) first.querySelector("a").click();
  }
});

// Clicking a header with data-sort sorts its table by that column; again
// reverses it. Cells may carry data-v to sort by instead of their text.
document.addEventListener("click", (ev) => {
  const th = ev.target.closest && ev.target.closest("th[data-sort]");
  if (!th) return;
  const table = th.closest("table");
  const col = [...th.parentElement.children].indexOf(th);
  const dir = th.getAttribute("aria-sort") === "ascending" ? -1 : 1;
  for (const h of th.parentElement.children) h.removeAttribute("aria-sort");
  th.setAttribute("aria-sort", dir === 1 ? "ascending" : "descending");
  const num = th.dataset.sort === "num";
  const key = (tr) => {
    const td = tr.children[col];
    const v = td.dataset.v ?? td.textContent.trim();
    return num ? Number(v) || 0 : v.toLowerCase();
  };
  const body = table.tBodies[0];
  const rows = [...body.rows].sort((a, b) => {
    const x = key(a), y = key(b);
    return (x < y ? -1 : x > y ? 1 : 0) * dir;
  });
  body.append(...rows);
});

// A search box with data-table filters that table's rows by their text.
document.addEventListener("input", (ev) => {
  const input = ev.target.closest && ev.target.closest("input.table-filter");
  if (!input) return;
  const table = document.querySelector(input.dataset.table);
  if (!table) return;
  const words = input.value.toLowerCase().split(/\s+/).filter(Boolean);
  for (const tr of table.tBodies[0].rows) {
    const text = tr.textContent.toLowerCase();
    tr.hidden = !words.every((w) => text.includes(w));
  }
});

// --------------------------------------------------------------- key form

// The key form lists only the buckets the key reaches; others are added
// from a search box, at the most the person can give.
const MAX_MATCHES = 50;

function grantRows(ed) {
  return [...ed.querySelectorAll("tbody tr[data-bucket]")];
}

function syncGrants(ed) {
  const any = grantRows(ed).some((tr) => tr.classList.contains("granted"));
  ed.querySelector("table.grants").hidden = !any;
  const empty = ed.querySelector(".grants-empty");
  if (empty) empty.hidden = any;
}

function showMatches(ed) {
  const input = ed.querySelector(".grant-search");
  const list = ed.querySelector(".grant-matches");
  const words = input.value.toLowerCase().split(/\s+/).filter(Boolean);
  const free = grantRows(ed).filter((tr) => !tr.classList.contains("granted") && words.every((w) => tr.dataset.bucket.toLowerCase().includes(w)));
  list.replaceChildren();
  for (const tr of free.slice(0, MAX_MATCHES)) {
    const li = document.createElement("li");
    li.setAttribute("role", "option");
    li.dataset.bucket = tr.dataset.bucket;
    const name = document.createElement("span");
    name.textContent = tr.dataset.bucket;
    const owner = document.createElement("span");
    owner.className = "muted small";
    owner.textContent = tr.children[1].textContent.trim();
    li.append(name, owner);
    list.append(li);
  }
  if (free.length > MAX_MATCHES) {
    const more = document.createElement("li");
    more.className = "more muted small";
    more.textContent = `…and ${free.length - MAX_MATCHES} more: keep typing`;
    list.append(more);
  } else if (!free.length) {
    const none = document.createElement("li");
    none.className = "more muted small";
    none.textContent = words.length ? "No other buckets match." : "Every bucket you have is on this key.";
    list.append(none);
  }
  const first = list.querySelector("li[data-bucket]");
  if (first) first.classList.add("active");
  list.hidden = false;
  input.setAttribute("aria-expanded", "true");
}

function hideMatches(ed) {
  ed.querySelector(".grant-matches").hidden = true;
  ed.querySelector(".grant-search").setAttribute("aria-expanded", "false");
}

function addGrant(ed, bucket) {
  const tr = grantRows(ed).find((r) => r.dataset.bucket === bucket);
  if (!tr) return;
  const sel = tr.querySelector("select");
  if (!sel.value) sel.selectedIndex = 1; // the most this person can give
  tr.classList.add("granted", "just-added");
  setTimeout(() => tr.classList.remove("just-added"), 1200);
  syncGrants(ed);
  const input = ed.querySelector(".grant-search");
  input.value = "";
  showMatches(ed);
  input.focus();
}

document.addEventListener("focusin", (ev) => {
  const input = ev.target.closest && ev.target.closest(".grant-search");
  if (input) showMatches(input.closest("[data-grants]"));
});
document.addEventListener("input", (ev) => {
  const input = ev.target.closest && ev.target.closest(".grant-search");
  if (input) showMatches(input.closest("[data-grants]"));
});
document.addEventListener("keydown", (ev) => {
  const input = ev.target.closest && ev.target.closest(".grant-search");
  if (!input) return;
  const ed = input.closest("[data-grants]");
  const items = [...ed.querySelectorAll(".grant-matches li[data-bucket]")];
  const at = items.findIndex((li) => li.classList.contains("active"));
  if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
    ev.preventDefault();
    if (!items.length) return;
    const next = items[(at + (ev.key === "ArrowDown" ? 1 : items.length - 1)) % items.length];
    items.forEach((li) => li.classList.toggle("active", li === next));
    next.scrollIntoView({ block: "nearest" });
  } else if (ev.key === "Enter") {
    // Adds the highlighted bucket rather than submitting the form.
    ev.preventDefault();
    if (at >= 0) addGrant(ed, items[at].dataset.bucket);
  } else if (ev.key === "Escape") {
    input.value = "";
    hideMatches(ed);
  }
});
document.addEventListener("mousedown", (ev) => {
  const li = ev.target.closest && ev.target.closest(".grant-matches li[data-bucket]");
  if (li) {
    ev.preventDefault(); // keep focus in the search box
    addGrant(li.closest("[data-grants]"), li.dataset.bucket);
    return;
  }
  for (const ed of document.querySelectorAll("[data-grants]")) {
    if (!ed.querySelector(".grant-add").contains(ev.target)) hideMatches(ed);
  }
});
document.addEventListener("click", (ev) => {
  const rm = ev.target.closest && ev.target.closest(".grant-remove");
  if (!rm) return;
  const tr = rm.closest("tr");
  tr.querySelector("select").value = "";
  tr.classList.remove("granted");
  syncGrants(tr.closest("[data-grants]"));
});

// placeCurrentBucket scrolls the sidebar to the open bucket on a fresh load.
function placeCurrentBucket() {
  const side = document.querySelector(".sidebar");
  if (!side || side.dataset.placed) return;
  side.dataset.placed = "1";
  const cur = side.querySelector("a[aria-current]");
  if (!cur) return;
  const s = side.getBoundingClientRect(), c = cur.getBoundingClientRect();
  if (c.top < s.top + 60 || c.bottom > s.bottom) side.scrollTop += c.top - s.top - s.height / 3;
}

// ------------------------------------------------------------- bucket list

// On a wide screen the bucket list sits beside the files: the hamburger
// shows and hides it, and the divider resizes it, both remembered. On a
// narrow one it's a drawer over the files, closed until asked for.
const narrow = matchMedia("(max-width: 800px)");
const SIDE_MIN = 160, SIDE_DEFAULT = 280;

function remember(key, value) {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    // Storage blocked: it just won't be remembered.
  }
}

function sideShown() {
  const h = document.documentElement;
  return narrow.matches ? h.classList.contains("drawer-open") : !h.classList.contains("side-closed");
}

function syncHamburger() {
  const b = document.querySelector(".hamburger");
  if (b) b.setAttribute("aria-expanded", sideShown());
}

function setDrawer(open) {
  document.documentElement.classList.toggle("drawer-open", open);
  syncHamburger();
}

function setSideClosed(closed) {
  document.documentElement.classList.toggle("side-closed", closed);
  remember("side", closed ? "closed" : null);
  syncHamburger();
}

function setSideWidth(px) {
  const max = Math.max(SIDE_MIN, Math.min(640, innerWidth * 0.6));
  const w = Math.round(Math.min(max, Math.max(SIDE_MIN, px)));
  document.documentElement.style.setProperty("--side", w + "px");
  return w;
}

document.addEventListener("click", (ev) => {
  if (ev.target.closest(".hamburger")) {
    if (narrow.matches) setDrawer(!sideShown());
    else setSideClosed(sideShown());
  } else if (ev.target.closest(".side-backdrop")) {
    setDrawer(false);
  } else if (narrow.matches && ev.target.closest(".bucket-nav a")) {
    setDrawer(false);
  }
});

document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape" && document.documentElement.classList.contains("drawer-open")) setDrawer(false);
});

narrow.addEventListener("change", () => {
  document.documentElement.classList.remove("drawer-open");
  syncHamburger();
});

// Dragging the divider; dragging it nearly shut hides the list.
document.addEventListener("pointerdown", (ev) => {
  const grip = ev.target.closest(".side-resize");
  if (!grip || ev.button !== 0 || narrow.matches) return;
  ev.preventDefault();
  grip.setPointerCapture(ev.pointerId);
  const h = document.documentElement;
  h.classList.add("resizing");
  const left = document.querySelector(".split").getBoundingClientRect().left;
  let width = null;
  const move = (e) => {
    const x = e.clientX - left;
    h.classList.toggle("side-closing", x < SIDE_MIN / 2);
    width = setSideWidth(x);
  };
  const up = (e) => {
    grip.removeEventListener("pointermove", move);
    grip.removeEventListener("pointerup", up);
    grip.removeEventListener("pointercancel", up);
    h.classList.remove("resizing", "side-closing");
    if (e.clientX - left < SIDE_MIN / 2) {
      setSideClosed(true);
      setSideWidth(SIDE_DEFAULT);
      remember("sideWidth", null);
    } else if (width !== null) {
      remember("sideWidth", width);
    }
  };
  grip.addEventListener("pointermove", move);
  grip.addEventListener("pointerup", up);
  grip.addEventListener("pointercancel", up);
});

document.addEventListener("dblclick", (ev) => {
  if (!ev.target.closest(".side-resize")) return;
  setSideWidth(SIDE_DEFAULT);
  remember("sideWidth", null);
});

document.addEventListener("keydown", (ev) => {
  if (!ev.target.closest || !ev.target.closest(".side-resize")) return;
  if (ev.key !== "ArrowLeft" && ev.key !== "ArrowRight") return;
  ev.preventDefault();
  const now = document.querySelector(".sidebar").getBoundingClientRect().width;
  remember("sideWidth", setSideWidth(now + (ev.key === "ArrowLeft" ? -20 : 20)));
});

function enhance() {
  addCopyButtons();
  for (const ed of document.querySelectorAll("[data-grants]")) if (ed.querySelector("table.grants")) syncGrants(ed);
  for (const f of document.querySelectorAll("input.table-filter")) if (f.value) f.dispatchEvent(new Event("input", { bubbles: true }));
  syncSelection();
  filterBuckets();
  placeCurrentBucket();
  syncHamburger();
}

// A level picker saves as soon as it changes.
document.addEventListener("change", (ev) => {
  const form = ev.target.closest && ev.target.closest("form.autosubmit");
  if (form && ev.target.tagName === "SELECT") form.requestSubmit();
});

// Esc closes an open menu, and puts focus back on its button.
document.addEventListener("keydown", (ev) => {
  if (ev.key !== "Escape") return;
  for (const d of document.querySelectorAll("details.menu[open]")) {
    d.open = false;
    d.querySelector("summary").focus();
  }
});

// Close an open menu when clicking elsewhere.
document.addEventListener("click", (ev) => {
  for (const d of document.querySelectorAll("details.menu[open]")) {
    if (!d.contains(ev.target)) d.open = false;
  }
});

// Buttons that are labels for hidden file inputs need the keyboard too.
document.addEventListener("keydown", (ev) => {
  const label = ev.target.closest && ev.target.closest("label.button, label.menu-item");
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
  busyUploads++;
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
  try {
    await Promise.all(Array.from({ length: Math.min(PARALLEL_UPLOADS, items.length) }, work));
  } finally {
    busyUploads--;
  }
  if (failed === 0) {
    navigate(location.href, { push: false, keepScroll: true });
  }
}

// ---------------------------------------------------------------- selection

// Ticking files in the table shows the bar of things to do with them.
// Shift-click ticks a run of rows.
let lastTicked = null;

function selected() {
  return [...document.querySelectorAll('table.selectable tbody input[type=checkbox]')].filter((c) => c.checked);
}

function syncSelection() {
  const bar = document.getElementById("sel");
  if (!bar) return;
  const boxes = [...document.querySelectorAll("table.selectable tbody input[type=checkbox]")];
  const picked = boxes.filter((c) => c.checked);
  for (const c of boxes) c.closest("tr").classList.toggle("selected", c.checked);
  const all = document.querySelector("table.selectable .sel-all");
  if (all) {
    all.checked = picked.length > 0 && picked.length === boxes.length;
    all.indeterminate = picked.length > 0 && picked.length < boxes.length;
  }
  bar.classList.toggle("active", picked.length > 0);
  const count = bar.querySelector(".selcount");
  if (!count.dataset.idle) count.dataset.idle = count.textContent;
  const folders = picked.filter((c) => c.name === "folder").length;
  const files = picked.length - folders;
  const parts = [];
  if (files) parts.push(`${files} file${files === 1 ? "" : "s"}`);
  if (folders) parts.push(`${folders} folder${folders === 1 ? "" : "s"}`);
  count.textContent = picked.length ? parts.join(" and ") + " selected" : count.dataset.idle;
}

function selectionQuestion() {
  const picked = selected();
  const folders = picked.filter((c) => c.name === "folder").length;
  const files = picked.length - folders;
  if (picked.length === 1) {
    const name = picked[0].closest("tr").querySelector("td:nth-child(2)").textContent.trim();
    return folders ? `Delete the folder ${name} and everything in it?` : `Delete ${name}?`;
  }
  const parts = [];
  if (files) parts.push(`${files} file${files === 1 ? "" : "s"}`);
  if (folders) parts.push(`${folders} folder${folders === 1 ? "" : "s"} and everything in ${folders === 1 ? "it" : "them"}`);
  return `Delete ${parts.join(" and ")}?`;
}

document.addEventListener("click", (ev) => {
  const box = ev.target.closest && ev.target.closest("table.selectable tbody input[type=checkbox]");
  if (box) {
    const boxes = [...document.querySelectorAll("table.selectable tbody input[type=checkbox]")];
    if (ev.shiftKey && lastTicked && boxes.includes(lastTicked)) {
      const [a, b] = [boxes.indexOf(lastTicked), boxes.indexOf(box)].sort((x, y) => x - y);
      for (let i = a; i <= b; i++) boxes[i].checked = box.checked;
    }
    lastTicked = box;
    syncSelection();
    return;
  }
  if (ev.target.closest && ev.target.closest(".sel-all")) {
    const on = ev.target.checked;
    for (const c of document.querySelectorAll("table.selectable tbody input[type=checkbox]")) c.checked = on;
    syncSelection();
    return;
  }
  if (ev.target.closest && ev.target.closest(".sel-clear")) {
    for (const c of selected()) c.checked = false;
    syncSelection();
    return;
  }
  const dl = ev.target.closest && ev.target.closest(".dl-files");
  if (dl) downloadFiles(dl.closest("form"));
});

document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape" && selected().length && !ev.target.closest("input[type=search], input[type=text]") && !document.querySelector("details.menu[open]")) {
    for (const c of selected()) c.checked = false;
    syncSelection();
  }
});

// downloadFiles saves the selection as separate files. A few plain files
// are just downloaded; folders, or many files, go into a folder picked on
// this computer where the browser allows it.
async function downloadFiles(form) {
  const picked = selected();
  const folders = picked.filter((c) => c.name === "folder");
  const keys = picked.filter((c) => c.name === "key").map((c) => c.value);
  const data = new FormData(form);
  const bucket = data.get("bucket"), snap = data.get("snap"), prefix = data.get("prefix");
  const fileURL = (key) => "/download?" + new URLSearchParams(snap ? { bucket, snap, key } : { bucket, key });
  const status = ensureStatus(form);
  if (!folders.length && keys.length <= 10) {
    // Browsers may ask once whether this site may download several files.
    for (const key of keys) {
      const a = document.createElement("a");
      a.href = fileURL(key);
      a.download = "";
      document.body.append(a);
      a.click();
      a.remove();
      await new Promise((r) => setTimeout(r, 350));
    }
    return;
  }
  if (!window.showDirectoryPicker) {
    status.textContent = folders.length
      ? "This browser can't save folders as they are: download them as a .zip or .tar instead."
      : "That's a lot of separate downloads: download them as a .zip or .tar instead.";
    return;
  }
  let dir;
  try {
    dir = await window.showDirectoryPicker({ mode: "readwrite", id: "s3-downloads" });
  } catch {
    return; // cancelled
  }
  const body = new URLSearchParams(data);
  for (const c of picked) body.append(c.name, c.value);
  status.textContent = "Finding the files…";
  const res = await fetch("/selection/list", { method: "POST", body });
  if (!res.ok) {
    status.textContent = (await res.text()).trim() || "Couldn't list the files.";
    return;
  }
  const files = await res.json();
  let done = 0, failed = 0;
  busyUploads++;
  try {
    for (const f of files) {
      status.textContent = `Saving ${done + 1} of ${files.length}: ${f.key.slice(prefix.length)}`;
      try {
        const parts = f.key.slice(prefix.length).split("/");
        let d = dir;
        for (const p of parts.slice(0, -1)) d = await d.getDirectoryHandle(p, { create: true });
        const r = await fetch(fileURL(f.key));
        if (!r.ok) throw new Error(r.statusText);
        const out = await (await d.getFileHandle(parts.at(-1), { create: true })).createWritable();
        await r.body.pipeTo(out);
        done++;
      } catch {
        failed++;
      }
    }
  } finally {
    busyUploads--;
  }
  status.textContent = `Saved ${done} file${done === 1 ? "" : "s"} to ${dir.name}` + (failed ? `; ${failed} failed.` : ".");
}

function ensureStatus(form) {
  let s = form.querySelector(".sel-status");
  if (!s) {
    s = document.createElement("span");
    s.className = "sel-status small muted";
    s.setAttribute("aria-live", "polite");
    form.append(s);
  }
  return s;
}

// ---------------------------------------------------------------- archives

// Where app.js came from, so archive.js loads from the same release.
const ASSET_BASE = document.currentScript ? document.currentScript.src.replace(/[^/]*$/, "") : "/static/";

// Content types for extracted files, which arrive without one.
const TYPES = {
  txt: "text/plain", md: "text/markdown", csv: "text/csv", html: "text/html", htm: "text/html", css: "text/css",
  js: "text/javascript", json: "application/json", xml: "application/xml", pdf: "application/pdf",
  png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp", svg: "image/svg+xml",
  mp4: "video/mp4", webm: "video/webm", mov: "video/quicktime", mp3: "audio/mpeg", wav: "audio/wav",
  zip: "application/zip", gz: "application/gzip", tar: "application/x-tar",
};
const typeOf = (path) => TYPES[path.slice(path.lastIndexOf(".") + 1).toLowerCase()] || "application/octet-stream";

let busyUploads = 0;
window.addEventListener("beforeunload", (ev) => {
  if (busyUploads) ev.preventDefault();
});

// extract unpacks an archive into the folder being browsed: one status
// row for the whole archive, the files sent a few at a time.
async function extract(box, file) {
  const status = box.querySelector("#upload-status");
  const li = document.createElement("li");
  li.className = "archive";
  const name = document.createElement("span");
  name.className = "fname";
  name.textContent = `Extracting ${file.name}`;
  const progress = document.createElement("progress");
  progress.max = 1;
  progress.value = 0;
  const detail = document.createElement("span");
  detail.className = "detail small";
  detail.textContent = "Reading the archive…";
  li.append(name, progress, detail);
  status.append(li);
  const problems = (title, lines) => {
    if (!lines.length) return;
    const d = document.createElement("details");
    const sum = document.createElement("summary");
    sum.textContent = title;
    const ul = document.createElement("ul");
    for (const l of lines.slice(0, 500)) {
      const item = document.createElement("li");
      item.textContent = l;
      ul.append(item);
    }
    if (lines.length > 500) ul.append(Object.assign(document.createElement("li"), { textContent: `…and ${lines.length - 500} more` }));
    d.append(sum, ul);
    li.append(d);
  };

  let archive;
  try {
    const mod = await import(ASSET_BASE + "archive.js");
    archive = await mod.open(file);
  } catch (err) {
    progress.remove();
    detail.className = "detail small error-text";
    detail.textContent = err.message || "Couldn't read the archive.";
    return;
  }
  busyUploads++;
  let done = 0, sent = 0, streak = 0, stopped = false;
  const failed = [];
  const show = () => {
    progress.value = archive.total ? done / archive.total : archive.progress ? archive.progress() : 0;
    detail.textContent = `${sent} of ${archive.total ?? "?"} files${failed.length ? `, ${failed.length} failed` : ""}`;
  };
  show();
  const work = async () => {
    for (;;) {
      if (stopped) return;
      let next;
      try {
        next = await archive.entries.next();
      } catch (err) {
        failed.push(`${file.name}: ${err.message}`);
        stopped = true;
        return;
      }
      if (next.done) return;
      const e = next.value;
      try {
        const blob = await e.blob();
        await putFile(box, box.dataset.prefix + e.path, new Blob([blob], { type: typeOf(e.path) }), { value: 0 });
        sent++;
        streak = 0;
      } catch (err) {
        failed.push(err.message.includes(e.path) ? err.message : `${e.path}: ${err.message}`);
        // Every file refused in a row (no access, a full quota): stop.
        if (++streak >= 10) stopped = true;
      }
      done++;
      show();
    }
  };
  try {
    await Promise.all(Array.from({ length: PARALLEL_UPLOADS }, work));
  } finally {
    busyUploads--;
  }
  progress.remove();
  name.textContent = file.name;
  detail.textContent = `Extracted ${sent} file${sent === 1 ? "" : "s"}` +
    (failed.length ? `; ${failed.length} failed${stopped ? ", so the rest were not tried" : ""}` : "") +
    (archive.skipped.length ? `; skipped ${archive.skipped.length}` : "") + ".";
  if (failed.length) detail.classList.add("error-text");
  problems("Failed", failed);
  problems("Skipped", archive.skipped);
  if (sent) {
    // Show the new files, keeping this summary if there's more to say.
    await navigate(location.href, { push: false, keepScroll: true });
    const again = document.querySelector("#upload-status");
    if (again && (failed.length || archive.skipped.length)) again.append(li);
  }
}

document.addEventListener("change", (ev) => {
  const input = ev.target;
  if (input.classList.contains("pick-archive")) {
    const box = input.closest("#files");
    const file = input.files[0];
    input.value = "";
    const menu = input.closest("details");
    if (menu) menu.open = false;
    if (file) extract(box, file);
    return;
  }
  if (!input.classList.contains("pick")) return;
  const menu = input.closest("details.menu");
  if (menu) menu.open = false;
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
function dropBox() {
  const box = document.getElementById("files");
  return box && box.hasAttribute("data-upload") ? box : null;
}

document.addEventListener("dragenter", (ev) => {
  const box = dropBox();
  if (!box || !ev.dataTransfer.types.includes("Files")) return;
  dragDepth++;
  box.classList.add("dragging");
});
document.addEventListener("dragleave", () => {
  const box = dropBox();
  if (box && --dragDepth <= 0) {
    dragDepth = 0;
    box.classList.remove("dragging");
  }
});
document.addEventListener("dragover", (ev) => {
  if (dropBox()) ev.preventDefault();
});
document.addEventListener("drop", async (ev) => {
  const box = dropBox();
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

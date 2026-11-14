// Runs before the page is drawn, so the bucket list starts at the size and
// state it was left in instead of jumping there once app.js loads.
"use strict";
(() => {
  const h = document.documentElement;
  h.classList.add("js");
  try {
    if (localStorage.getItem("side") === "closed") h.classList.add("side-closed");
    const w = Number(localStorage.getItem("sideWidth"));
    if (w) h.style.setProperty("--side", w + "px");
  } catch {
    // Storage blocked: the defaults are fine.
  }
})();

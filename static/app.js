// Confirmation for destructive forms, and uploads with progress.
"use strict";

document.addEventListener("submit", (e) => {
  const msg = e.target.dataset.confirm;
  if (msg && !window.confirm(msg)) {
    e.preventDefault();
  }
});

function putFile(form, file, progress) {
  return new Promise((resolve, reject) => {
    const q = new URLSearchParams({ bucket: form.dataset.bucket, key: form.dataset.prefix + file.name });
    const x = new XMLHttpRequest();
    x.open("PUT", "/upload?" + q.toString());
    x.setRequestHeader("X-CSRF-Token", form.dataset.csrf);
    x.setRequestHeader("Content-Type", file.type || "application/octet-stream");
    x.upload.addEventListener("progress", (ev) => {
      if (ev.lengthComputable) {
        progress.value = ev.loaded / ev.total;
      }
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

const upload = document.getElementById("upload");
if (upload) {
  upload.addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = upload.querySelector("input[type=file]");
    const button = upload.querySelector("button");
    const status = document.getElementById("upload-status");
    const files = Array.from(input.files);
    button.disabled = true;
    let failed = 0;
    for (const file of files) {
      const li = document.createElement("li");
      const name = document.createElement("span");
      name.textContent = file.name;
      const progress = document.createElement("progress");
      progress.max = 1;
      progress.value = 0;
      li.append(name, progress);
      status.append(li);
      try {
        await putFile(upload, file, progress);
        progress.value = 1;
      } catch (err) {
        failed++;
        progress.remove();
        const msg = document.createElement("span");
        msg.className = "error-text";
        msg.textContent = err.message;
        li.append(msg);
      }
    }
    button.disabled = false;
    if (failed === 0) {
      window.location.reload();
    }
  });
}

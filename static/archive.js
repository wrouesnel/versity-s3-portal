// Reads .zip, .tar and .tar.gz archives in the browser, one file at a time,
// for "Extract archive". Loaded by app.js only when it's used.
//
// Each entry is {path, size, blob: () => Promise<Blob>}. Zip and plain tar
// entries are slices of the archive file itself, so nothing is held in
// memory; a gzipped tar is read front to back, one file at a time.
// Directories, links and devices are skipped; names are cleaned so nothing
// lands outside the folder being extracted into.
"use strict";

export class ArchiveError extends Error {}

// cleanPath turns an archive's name for a file into a relative path, or
// null if it would climb out of the folder.
export function cleanPath(name) {
  const parts = [];
  for (const p of name.replace(/\\/g, "/").split("/")) {
    if (p === "" || p === ".") continue;
    if (p === "..") return null;
    parts.push(p);
  }
  return parts.length ? parts.join("/") : null;
}

export function kind(file) {
  const n = file.name.toLowerCase();
  if (n.endsWith(".zip")) return "zip";
  if (n.endsWith(".tar")) return "tar";
  if (n.endsWith(".tar.gz") || n.endsWith(".tgz")) return "tgz";
  return null;
}

// open returns {total, entries, skipped}: total is the number of files when
// it's known up front (zip), entries an async iterator, and skipped a
// running list of names left out and why.
export async function open(file) {
  switch (kind(file)) {
    case "zip": return openZip(file);
    case "tar": return openTar(file);
    case "tgz": return openTarGz(file);
  }
  throw new ArchiveError("Only .zip, .tar, .tar.gz and .tgz archives can be extracted.");
}

const bytes = async (blob) => new DataView(await blob.arrayBuffer());
const utf8 = new TextDecoder("utf-8", { fatal: true });
const latin1 = new TextDecoder("latin1");
function text(u8, utf) {
  if (utf) { try { return utf8.decode(u8); } catch { /* fall through */ } }
  try { return utf8.decode(u8); } catch { return latin1.decode(u8); }
}

// ---------------------------------------------------------------------- zip

async function openZip(file) {
  // The end of central directory record is in the last 64 KiB + 22 bytes.
  const tailStart = Math.max(0, file.size - 65557);
  const tail = await bytes(file.slice(tailStart));
  let eocd = -1;
  for (let i = tail.byteLength - 22; i >= 0; i--) {
    if (tail.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new ArchiveError("This isn't a zip file, or it's damaged.");
  let count = tail.getUint16(eocd + 10, true);
  let cdSize = tail.getUint32(eocd + 12, true);
  let cdOffset = tail.getUint32(eocd + 16, true);
  // Zip64: the locator sits just before the end record.
  if (eocd >= 20 && tail.getUint32(eocd - 20, true) === 0x07064b50) {
    const at = Number(tail.getBigUint64(eocd - 12, true));
    const z = await bytes(file.slice(at, at + 56));
    if (z.getUint32(0, true) !== 0x06064b50) throw new ArchiveError("The zip file's index is damaged.");
    count = Number(z.getBigUint64(32, true));
    cdSize = Number(z.getBigUint64(40, true));
    cdOffset = Number(z.getBigUint64(48, true));
  }
  const cd = await bytes(file.slice(cdOffset, cdOffset + cdSize));
  const list = [];
  const skipped = [];
  for (let p = 0, i = 0; i < count; i++) {
    if (p + 46 > cd.byteLength || cd.getUint32(p, true) !== 0x02014b50) throw new ArchiveError("The zip file's index is damaged.");
    const flags = cd.getUint16(p + 8, true);
    const method = cd.getUint16(p + 10, true);
    let csize = cd.getUint32(p + 20, true);
    let usize = cd.getUint32(p + 24, true);
    const nameLen = cd.getUint16(p + 28, true);
    const extraLen = cd.getUint16(p + 30, true);
    const commentLen = cd.getUint16(p + 32, true);
    const madeBy = cd.getUint16(p + 4, true) >> 8;
    const attrs = cd.getUint32(p + 38, true);
    let local = cd.getUint32(p + 42, true);
    const raw = new Uint8Array(cd.buffer, cd.byteOffset + p + 46, nameLen);
    const name = text(raw, flags & 0x800);
    // Zip64 sizes and offset live in an extra field when the 32-bit ones are full.
    for (let e = p + 46 + nameLen; e + 4 <= p + 46 + nameLen + extraLen;) {
      const id = cd.getUint16(e, true), len = cd.getUint16(e + 2, true);
      if (id === 0x0001) {
        let f = e + 4;
        if (usize === 0xffffffff) { usize = Number(cd.getBigUint64(f, true)); f += 8; }
        if (csize === 0xffffffff) { csize = Number(cd.getBigUint64(f, true)); f += 8; }
        if (local === 0xffffffff) { local = Number(cd.getBigUint64(f, true)); }
      }
      e += 4 + len;
    }
    p += 46 + nameLen + extraLen + commentLen;
    const isDir = name.endsWith("/") || name.endsWith("\\");
    const unixMode = madeBy === 3 ? attrs >>> 16 : 0;
    if (isDir) continue;
    if ((unixMode & 0o170000) === 0o120000) { skipped.push(`${name} (a link)`); continue; }
    if (flags & 1) { skipped.push(`${name} (encrypted)`); continue; }
    if (method !== 0 && method !== 8) { skipped.push(`${name} (unsupported compression)`); continue; }
    const path = cleanPath(name);
    if (!path) { skipped.push(`${name} (outside the folder)`); continue; }
    list.push({ path, size: usize, method, csize, local });
  }
  async function* entries() {
    for (const e of list) {
      yield {
        path: e.path, size: e.size,
        blob: async () => {
          const h = await bytes(file.slice(e.local, e.local + 30));
          if (h.getUint32(0, true) !== 0x04034b50) throw new ArchiveError("damaged in the zip file");
          const start = e.local + 30 + h.getUint16(26, true) + h.getUint16(28, true);
          const data = file.slice(start, start + e.csize);
          if (e.method === 0) return data;
          return new Response(data.stream().pipeThrough(new DecompressionStream("deflate-raw"))).blob();
        },
      };
    }
  }
  return { total: list.length, entries: entries(), skipped };
}

// ---------------------------------------------------------------------- tar

// parseHeader reads one 512-byte tar header block.
function parseHeader(b) {
  const str = (off, len) => {
    let end = off;
    while (end < off + len && b[end] !== 0) end++;
    return text(b.subarray(off, end), true);
  };
  if (b.every((x) => x === 0)) return null; // end of archive
  let size;
  if (b[124] & 0x80) {
    // GNU base-256 for files over 8 GiB.
    size = 0;
    for (let i = 125; i < 136; i++) size = size * 256 + b[i];
  } else {
    size = parseInt(str(124, 12).trim() || "0", 8);
  }
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : b[i];
  if (sum !== parseInt(str(148, 8).trim(), 8)) throw new ArchiveError("This isn't a tar file, or it's damaged.");
  const type = String.fromCharCode(b[156] || 48);
  let name = str(0, 100);
  if (str(257, 5) === "ustar") {
    const prefix = str(345, 155);
    if (prefix) name = prefix + "/" + name;
  }
  return { name, size, type };
}

function paxPath(data) {
  // Records are "<len> key=value\n", with len counting bytes.
  for (let i = 0; i < data.length;) {
    const sp = data.indexOf(32, i);
    if (sp < 0) break;
    const len = parseInt(latin1.decode(data.subarray(i, sp)), 10);
    if (!len) break;
    const rec = data.subarray(sp + 1, i + len - 1);
    const eq = rec.indexOf(61);
    if (latin1.decode(rec.subarray(0, eq)) === "path") return text(rec.subarray(eq + 1), true);
    i += len;
  }
  return null;
}

// tarEntries turns a stream of header/data reads into entries. read(n)
// returns the next n bytes as a Uint8Array; take(n) returns the next n
// bytes as a Blob, read lazily where it can be.
async function* tarEntries(read, take, skip, skipped) {
  let longName = null;
  for (;;) {
    const block = await read(512);
    if (!block || block.length < 512) return;
    const h = parseHeader(block);
    if (!h) return;
    const padded = Math.ceil(h.size / 512) * 512;
    if (h.type === "L" || h.type === "x") {
      const data = await read(padded);
      let v;
      if (h.type === "L") {
        const d = data.subarray(0, h.size);
        const nul = d.indexOf(0);
        v = text(nul < 0 ? d : d.subarray(0, nul), true);
      } else {
        v = paxPath(data.subarray(0, h.size));
      }
      if (v) longName = v;
      continue;
    }
    if (h.type === "g") { await skip(padded); continue; }
    const name = longName || h.name;
    longName = null;
    if (h.type !== "0" && h.type !== "7") {
      if (h.type !== "5") skipped.push(`${name} (${h.type === "2" ? "a link" : h.type === "1" ? "a hard link" : "not a regular file"})`);
      await skip(padded);
      continue;
    }
    const path = cleanPath(name);
    if (!path) { skipped.push(`${name} (outside the folder)`); await skip(padded); continue; }
    const blob = await take(h.size);
    await skip(padded - h.size);
    yield { path, size: h.size, blob: async () => blob };
  }
}

async function openTar(file) {
  let pos = 0;
  const skipped = [];
  const read = async (n) => { const u = new Uint8Array(await file.slice(pos, pos + n).arrayBuffer()); pos += n; return u; };
  const take = async (n) => { const b = file.slice(pos, pos + n); pos += n; return b; };
  const skip = async (n) => { pos += n; };
  return { total: null, entries: tarEntries(read, take, skip, skipped), skipped, progress: () => Math.min(1, pos / file.size) };
}

async function openTarGz(file) {
  // Counts compressed bytes read, for progress.
  let done = 0;
  const counted = file.stream().pipeThrough(new TransformStream({ transform(c, ctl) { done += c.length; ctl.enqueue(c); } }));
  const reader = counted.pipeThrough(new DecompressionStream("gzip")).getReader();
  let buf = new Uint8Array(0);
  let ended = false;
  async function fill(n) {
    const parts = [buf];
    let have = buf.length;
    while (have < n && !ended) {
      const { value, done: d } = await reader.read();
      if (d) { ended = true; break; }
      parts.push(value);
      have += value.length;
    }
    if (parts.length > 1) {
      buf = new Uint8Array(have);
      let o = 0;
      for (const p of parts) { buf.set(p, o); o += p.length; }
    }
  }
  const read = async (n) => {
    await fill(n);
    const out = buf.subarray(0, Math.min(n, buf.length));
    buf = buf.subarray(out.length);
    return out;
  };
  // Large files are gathered in chunks so no single buffer gets huge; the
  // browser may keep a big Blob on disk.
  const take = async (n) => {
    const parts = [];
    while (n > 0) {
      const chunk = await read(Math.min(n, 8 << 20));
      if (!chunk.length) throw new ArchiveError("The archive ends in the middle of a file.");
      parts.push(chunk.slice());
      n -= chunk.length;
    }
    return new Blob(parts);
  };
  const skip = async (n) => { while (n > 0) { const c = await read(Math.min(n, 8 << 20)); if (!c.length) return; n -= c.length; } };
  const skipped = [];
  return { total: null, entries: tarEntries(read, take, skip, skipped), skipped, progress: () => Math.min(1, done / file.size) };
}

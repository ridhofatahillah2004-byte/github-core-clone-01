// main.ts — a standalone GitHub-compatible git forge (Node 22, stdlib only).
// One process: git smart HTTP (upload-pack v2, receive-pack v0), REST v3,
// GraphQL v4 and MCP, all served from an in-memory store with a deterministic
// logical clock, so two runs on the same instance leave identical state.
// No git binary, no outside service, no UI.
import http from "node:http";
import { createHash } from "node:crypto";
import { deflateSync, inflateSync } from "node:zlib";

// ===========================================================================
// pkt-line framing (git wire protocol)
// ===========================================================================
function pktLine(data: string | Buffer): Buffer {
  const payload = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  const head = Buffer.alloc(4);
  head.write((payload.length + 4).toString(16).padStart(4, "0"), "ascii");
  return Buffer.concat([head, payload]);
}
const FLUSH_PKT = Buffer.from("0000", "ascii");
const DELIM_PKT = Buffer.from("0001", "ascii");

type PktItem =
  | { kind: "data"; data: Buffer; start: number; end: number }
  | { kind: "flush"; start: number; end: number }
  | { kind: "delim"; start: number; end: number };

function readPktLines(buf: Buffer): PktItem[] {
  const out: PktItem[] = [];
  let pos = 0;
  while (pos + 4 <= buf.length) {
    const len = parseInt(buf.toString("ascii", pos, pos + 4), 16);
    if (!Number.isFinite(len) || len < 0) break;
    if (len === 0) {
      out.push({ kind: "flush", start: pos, end: pos + 4 });
      pos += 4;
      continue;
    }
    if (len === 1) {
      out.push({ kind: "delim", start: pos, end: pos + 4 });
      pos += 4;
      continue;
    }
    if (pos + len > buf.length) break;
    // A view, not a copy: no caller mutates an item's payload.
    out.push({ kind: "data", data: buf.subarray(pos + 4, pos + len), start: pos, end: pos + len });
    pos += len;
  }
  return out;
}

/** Wrap a payload in a sideband (channel 1) pkt-line. */
function sideband(data: string | Buffer): Buffer {
  const payload = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return pktLine(Buffer.concat([Buffer.from([1]), payload]));
}

/**
 * Unwrap stateless-RPC transport framing. Over HTTP, git sends fetch and
 * receive-pack requests via send_sideband(band=-1): the body is a sequence
 * of pkt-lines whose data payloads concatenate to the inner request
 * (command pkt-lines + flush + raw pack), plus a trailing flush. A raw
 * (unwrapped) request is returned unchanged: it is detected because its
 * first payload is a single line that does not parse as pkt-line framing.
 */
function unwrapStatelessRpc(body: Buffer): Buffer {
  const items = readPktLines(body);
  let consumed = 0;
  for (const item of items) {
    consumed += item.kind === "data" ? 4 + item.data.length : 4;
  }
  if (consumed !== body.length || items.length === 0) return body;
  const first = items[0];
  if (first.kind !== "data") return body;
  const inner = readPktLines(first.data);
  if (inner.length === 0 || inner[0].kind !== "data") return body;
  const firstInner = inner[0].data.toString("utf8");
  if (
    !firstInner.startsWith("command=") &&
    !firstInner.startsWith("want ") &&
    !/^[0-9a-f]{40} [0-9a-f]{40} \S+/.test(firstInner)
  ) {
    return body;
  }
  return Buffer.concat(items.filter((i) => i.kind === "data").map((i) => (i as { data: Buffer }).data));
}

// ===========================================================================
// sha1 + zlib
// ===========================================================================
function sha1Buf(data: Buffer): Buffer {
  return createHash("sha1").update(data).digest();
}

/** Adler-32, the checksum a zlib stream ends with; chunked so big buffers stay fast. */
function adler32(buf: Buffer): number {
  let a = 1;
  let b = 0;
  const NMAX = 5552;
  for (let off = 0; off < buf.length; off += NMAX) {
    const end = Math.min(buf.length, off + NMAX);
    for (let i = off; i < end; i++) {
      a += buf[i];
      b += a;
    }
    a %= 65521;
    b %= 65521;
  }
  return ((b << 16) | a) >>> 0;
}

/**
 * Inflate the zlib stream starting at `start`; returns the data and the offset
 * just past the stream. inflateSync ignores trailing bytes, so one call yields
 * the data; the stream's end is the 4-byte Adler-32 checksum that follows the
 * deflate data, found by scanning for it and verified with one exact-prefix
 * inflate (a coincidental match inside the deflate data is ~1e-7 per object).
 * Falls back to the old binary search when no candidate verifies (never on a
 * well-formed pack). Throws on a corrupt stream, exactly as before — but the
 * common path throws nothing, where the binary search threw ~log2(n) times
 * per object (each throw pays a full stack capture).
 */
function inflateExact(buf: Buffer, start: number): { data: Buffer; next: number } {
  const data = inflateSync(buf.subarray(start));
  const adler = adler32(data);
  // The earliest the Adler-32 can start: 2-byte zlib header + deflate data.
  for (let pos = start + 2; pos + 4 <= buf.length; pos++) {
    if (buf.readUInt32BE(pos) !== adler) continue;
    const end = pos + 4;
    try {
      const check = inflateSync(buf.subarray(start, end));
      if (check.length === data.length && check.equals(data)) return { data, next: end };
    } catch {
      // Not the real end (a coincidental match inside the deflate data); keep scanning.
    }
  }
  let lo = start + 1;
  let hi = buf.length;
  let ans = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    try {
      inflateSync(buf.subarray(start, mid));
      ans = mid;
      hi = mid - 1;
    } catch {
      lo = mid + 1;
    }
  }
  if (ans === -1) throw new Error("bad zlib stream in packfile");
  return { data: inflateSync(buf.subarray(start, ans)), next: ans };
}

// ===========================================================================
// git objects
// ===========================================================================
type ObjType = "commit" | "tree" | "blob" | "tag";
const OBJ_TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const OBJ_CODE_TYPE: Record<number, ObjType> = { 1: "commit", 2: "tree", 3: "blob", 4: "tag" };

function hashObject(type: ObjType, data: Buffer): string {
  // Two updates instead of Buffer.concat: the same SHA-1 without copying data.
  return createHash("sha1").update(`${type} ${data.length}\0`, "utf8").update(data).digest("hex");
}

interface GitObject {
  type: ObjType;
  data: Buffer;
  /** The object's id, set by readPack (the pack reader hashes every object once). */
  oid?: string;
}

interface ParsedCommit {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): ParsedCommit {
  const text = data.toString("utf8");
  const headEnd = text.indexOf("\n\n");
  const head = headEnd === -1 ? text : text.slice(0, headEnd);
  const message = headEnd === -1 ? "" : text.slice(headEnd + 2);
  let tree = "";
  const parents: string[] = [];
  let author = "";
  let committer = "";
  for (const line of head.split("\n")) {
    if (line.startsWith("tree ")) tree = line.slice(5).trim();
    else if (line.startsWith("parent ")) parents.push(line.slice(7).trim());
    else if (line.startsWith("author ")) author = line.slice(7);
    else if (line.startsWith("committer ")) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(
  tree: string,
  parents: string[],
  author: string,
  committer: string,
  message: string,
): Buffer {
  let s = `tree ${tree}\n`;
  for (const p of parents) s += `parent ${p}\n`;
  s += `author ${author}\ncommitter ${committer}\n\n${message}`;
  return Buffer.from(s, "utf8");
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let pos = 0;
  while (pos < data.length) {
    const sp = data.indexOf(0x20, pos);
    const nul = data.indexOf(0x00, sp);
    if (sp === -1 || nul === -1 || nul + 21 > data.length) break;
    entries.push({
      mode: data.toString("ascii", pos, sp),
      name: data.toString("utf8", sp + 1, nul),
      oid: data.subarray(nul + 1, nul + 21).toString("hex"),
    });
    pos = nul + 21;
  }
  return entries;
}

function buildTree(entries: TreeEntry[]): Buffer {
  const parts: Buffer[] = [];
  for (const e of entries) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, "utf8"));
    parts.push(Buffer.from(e.oid, "hex"));
  }
  return Buffer.concat(parts);
}

/** Apply a git delta (copy/insert ops) to a base buffer. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let pos = 0;
  const readVarint = (): number => {
    let v = 0;
    let shift = 0;
    for (;;) {
      const b = delta[pos++];
      v += (b & 0x7f) * 2 ** shift;
      shift += 7;
      if ((b & 0x80) === 0) break;
    }
    return v;
  };
  const srcSize = readVarint();
  const tgtSize = readVarint();
  if (srcSize !== base.length) throw new Error("delta base size mismatch");
  const out: Buffer[] = [];
  while (pos < delta.length) {
    const op = delta[pos++];
    if (op & 0x80) {
      let off = 0;
      let size = 0;
      if (op & 0x01) off = delta[pos++];
      if (op & 0x02) off |= delta[pos++] << 8;
      if (op & 0x04) off |= delta[pos++] << 16;
      if (op & 0x08) off |= delta[pos++] << 24;
      if (op & 0x10) size = delta[pos++];
      if (op & 0x20) size |= delta[pos++] << 8;
      if (op & 0x40) size |= delta[pos++] << 16;
      if (size === 0) size = 0x10000;
      if (off + size > base.length) throw new Error("delta copy out of range");
      out.push(base.subarray(off, off + size));
    } else if (op !== 0) {
      out.push(delta.subarray(pos, pos + op));
      pos += op;
    } else {
      throw new Error("delta opcode 0");
    }
  }
  const result = Buffer.concat(out);
  if (result.length !== tgtSize) throw new Error("delta target size mismatch");
  return result;
}

// ===========================================================================
// packfiles
// ===========================================================================
function readPack(buf: Buffer): GitObject[] {
  if (buf.length < 12 || buf.toString("ascii", 0, 4) !== "PACK") {
    throw new Error("not a packfile");
  }
  const version = buf.readUInt32BE(4);
  const count = buf.readUInt32BE(8);
  if (version !== 2 && version !== 3) throw new Error("unsupported pack version");
  const objects: GitObject[] = [];
  const byOffset = new Map<number, GitObject>();
  const byOid = new Map<string, GitObject>();
  let pos = 12;
  for (let i = 0; i < count; i++) {
    const objStart = pos;
    const b0 = buf[pos++];
    let typeCode = (b0 >> 4) & 0x7;
    let size = b0 & 0x0f;
    let shift = 4;
    let b = b0;
    while (b & 0x80) {
      b = buf[pos++];
      size += (b & 0x7f) * 2 ** shift;
      shift += 7;
    }
    let base: GitObject | undefined;
    if (typeCode === 6) {
      // OFS_DELTA: offset back from this object's header start
      let c = buf[pos++];
      let offset = c & 0x7f;
      while (c & 0x80) {
        c = buf[pos++];
        offset = ((offset + 1) << 7) | (c & 0x7f);
      }
      base = byOffset.get(objStart - offset);
      if (!base) throw new Error("ofs-delta base not found");
    } else if (typeCode === 7) {
      const baseOid = buf.subarray(pos, pos + 20).toString("hex");
      pos += 20;
      base = byOid.get(baseOid);
      if (!base) throw new Error("ref-delta base not found");
    }
    const { data, next } = inflateExact(buf, pos);
    pos = next;
    let obj: GitObject;
    if (typeCode === 6 || typeCode === 7) {
      if (!base) throw new Error("delta without base");
      const full = applyDelta(base.data, data);
      obj = { type: base.type, data: full };
    } else {
      const type = OBJ_CODE_TYPE[typeCode];
      if (!type) throw new Error(`unknown pack object type ${typeCode}`);
      if (data.length !== size) throw new Error("pack object size mismatch");
      obj = { type, data };
    }
    const oid = hashObject(obj.type, obj.data);
    obj.oid = oid;
    objects.push(obj);
    byOffset.set(objStart, obj);
    byOid.set(oid, obj);
  }
  return objects;
}

function writePack(objects: GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write("PACK", 0, "ascii");
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const obj of objects) {
    const code = OBJ_TYPE_CODE[obj.type];
    let size = obj.data.length;
    const bytes: number[] = [];
    let first = (code << 4) | (size & 0x0f);
    size >>= 4;
    if (size > 0) first |= 0x80;
    bytes.push(first);
    while (size > 0) {
      let b = size & 0x7f;
      size >>= 7;
      if (size > 0) b |= 0x80;
      bytes.push(b);
    }
    parts.push(Buffer.from(bytes));
    parts.push(deflateSync(obj.data, { level: 6 }));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, sha1Buf(body)]);
}

// ===========================================================================
// commit graph helpers (operate on a repo's object map)
// ===========================================================================
type ObjectMap = Map<string, GitObject>;

function collectReachable(
  objects: ObjectMap,
  starts: string[],
  stopAt: ReadonlySet<string>,
  shallow: boolean,
): Map<string, GitObject> {
  const out = new Map<string, GitObject>();
  const seen = new Set<string>();
  const stack: string[] = [...starts];
  while (stack.length > 0) {
    const oid = stack.pop()!;
    if (seen.has(oid) || stopAt.has(oid)) continue;
    seen.add(oid);
    const obj = objects.get(oid);
    if (!obj) continue;
    out.set(oid, obj);
    if (obj.type === "commit") {
      const c = parseCommit(obj.data);
      if (!shallow) for (const p of c.parents) stack.push(p);
      stack.push(c.tree);
    } else if (obj.type === "tree") {
      for (const e of parseTree(obj.data)) stack.push(e.oid);
    } else if (obj.type === "tag") {
      const m = obj.data.toString("utf8").match(/^object ([0-9a-f]{40})/m);
      if (m) stack.push(m[1]);
    }
  }
  return out;
}

function isAncestor(objects: ObjectMap, ancestor: string, descendant: string): boolean {
  const seen = new Set<string>();
  const stack = [descendant];
  while (stack.length > 0) {
    const oid = stack.pop()!;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = objects.get(oid);
    if (obj && obj.type === "commit") {
      for (const p of parseCommit(obj.data).parents) stack.push(p);
    }
  }
  return false;
}

function mergeBase(objects: ObjectMap, a: string, b: string): string | null {
  const ancA = new Set<string>();
  const stackA = [a];
  while (stackA.length > 0) {
    const oid = stackA.pop()!;
    if (ancA.has(oid)) continue;
    ancA.add(oid);
    const obj = objects.get(oid);
    if (obj && obj.type === "commit") {
      for (const p of parseCommit(obj.data).parents) stackA.push(p);
    }
  }
  const seenB = new Set<string>();
  const stackB = [b];
  while (stackB.length > 0) {
    const oid = stackB.pop()!;
    if (ancA.has(oid)) return oid;
    if (seenB.has(oid)) continue;
    seenB.add(oid);
    const obj = objects.get(oid);
    if (obj && obj.type === "commit") {
      for (const p of parseCommit(obj.data).parents) stackB.push(p);
    }
  }
  return null;
}

/** Build a tree object from a flat path -> {oid, mode} map, storing subtrees. */
function buildTreeFromFiles(
  objects: ObjectMap,
  files: Map<string, { oid: string; mode: string }>,
): string {
  const build = (prefix: string): string => {
    const entries: TreeEntry[] = [];
    const dirs = new Map<string, Map<string, { oid: string; mode: string }>>();
    for (const [path, f] of files) {
      if (!path.startsWith(prefix)) continue;
      const rest = path.slice(prefix.length);
      const slash = rest.indexOf("/");
      if (slash === -1) {
        entries.push({ mode: f.mode, name: rest, oid: f.oid });
      } else {
        const dir = rest.slice(0, slash);
        if (!dirs.has(dir)) dirs.set(dir, new Map());
        dirs.get(dir)!.set(path, f);
      }
    }
    for (const [dir, sub] of dirs) {
      entries.push({ mode: "40000", name: dir, oid: build(prefix + dir + "/") });
    }
    entries.sort((x, y) => {
      const xn = x.mode === "40000" ? x.name + "/" : x.name;
      const yn = y.mode === "40000" ? y.name + "/" : y.name;
      return xn < yn ? -1 : xn > yn ? 1 : 0;
    });
    const data = buildTree(entries);
    const oid = hashObject("tree", data);
    objects.set(oid, { type: "tree", data });
    return oid;
  };
  return build("");
}

/** Flatten a tree object into a path -> {oid, mode} map. */
function treeToFiles(
  objects: ObjectMap,
  treeOid: string,
  prefix = "",
  out: Map<string, { oid: string; mode: string }> = new Map(),
): Map<string, { oid: string; mode: string }> {
  const obj = objects.get(treeOid);
  if (!obj || obj.type !== "tree") return out;
  for (const e of parseTree(obj.data)) {
    const path = prefix + e.name;
    if (e.mode === "40000") treeToFiles(objects, e.oid, path + "/", out);
    else out.set(path, { oid: e.oid, mode: e.mode });
  }
  return out;
}

// ===========================================================================
// store
// ===========================================================================
const ZERO_OID = "0000000000000000000000000000000000000000";
// Single-tenant forge: the bearer token names exactly one login (the viewer).
// The harness never tells the entry that login out of band, so the first
// owner-scoped request names it: learn it there and re-owner every repo
// created before that moment. Any other owner is a 404, never a 403.
let LOGIN = "octocat";
let viewerKnown = false;
function isViewer(owner: string): boolean {
  if (!viewerKnown) {
    viewerKnown = true;
    LOGIN = owner;
    for (const r of repos.values()) r.owner = owner;
  }
  return owner === LOGIN;
}
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN || "test-token";
const AGENT = "forge/1.0";

interface Label {
  name: string;
  color: string;
  description: string;
}

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string | null;
  state: "open" | "closed";
  labels: string[];
  user: string;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  comments: { id: number; body: string; user: string; createdAt: string }[];
  /** Cached JSON.stringify(issueJson(...)) for this issue; cleared on any mutation. */
  _json?: string;
}

interface Pull {
  id: number;
  number: number;
  title: string;
  body: string | null;
  state: "open" | "closed";
  head: string;
  base: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergeCommitSha: string | null;
  user: string;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  mergedAt: string | null;
}

interface Repo {
  id: number;
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  refs: Map<string, string>;
  objects: ObjectMap;
  issues: Map<number, Issue>;
  labels: Map<string, Label>;
  pulls: Map<number, Pull>;
  nextNumber: number;
  createdAt: string;
  updatedAt: string;
}

const repos = new Map<string, Repo>(); // key: owner + "/" + name
let nextRepoId = 1;

/** Deterministic logical clock: every timestamp comes from here, never Date.now(). */
let clockBase = 1700000000;
{
  const nowEnv = process.env.MAKEFUN_TRIAL_NOW;
  if (nowEnv) {
    const parsed = Date.parse(nowEnv);
    if (Number.isFinite(parsed)) clockBase = Math.floor(parsed / 1000);
  }
}
let clockTick = 0;
function nextTimeSec(): number {
  return clockBase + clockTick++;
}
function isoNow(): string {
  return new Date(nextTimeSec() * 1000).toISOString();
}
function gitIdent(name: string): string {
  return `${name} <${name}@forge.local> ${nextTimeSec()} +0000`;
}

function repoKey(_owner: string, name: string): string {
  // Single tenant: repository names are unique; the owner is the viewer.
  return name;
}
function getRepo(owner: string, name: string): Repo | undefined {
  if (!isViewer(owner)) return undefined;
  return repos.get(repoKey(owner, name));
}
function openIssueCount(r: Repo): number {
  let n = 0;
  for (const i of r.issues.values()) if (i.state === "open") n++;
  for (const p of r.pulls.values()) if (p.state === "open") n++;
  return n;
}

// ===========================================================================
// HTTP helpers
// ===========================================================================
let requestCounter = 0;

function sendJson(
  res: http.ServerResponse,
  status: number,
  obj: unknown,
  extra: Record<string, string> = {},
): void {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "content-type": "application/json",
    "x-github-request-id": `req-${++requestCounter}`,
    ...extra,
  });
  res.end(body);
}

/** Like sendJson, but the body is already a JSON string (no second stringify). */
function sendJsonText(
  res: http.ServerResponse,
  status: number,
  json: string,
  extra: Record<string, string> = {},
): void {
  res.writeHead(status, {
    "content-type": "application/json",
    "x-github-request-id": `req-${++requestCounter}`,
    ...extra,
  });
  res.end(json);
}

function sendError(res: http.ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function sendRaw(
  res: http.ServerResponse,
  status: number,
  contentType: string,
  buf: Buffer,
  extra: Record<string, string> = {},
): void {
  res.writeHead(status, {
    "content-type": contentType,
    "x-github-request-id": `req-${++requestCounter}`,
    ...extra,
  });
  res.end(buf);
}

function authed(req: http.IncomingMessage): boolean {
  const h = req.headers.authorization ?? "";
  return h === `Bearer ${TOKEN}`;
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(chunks.length === 1 ? chunks[0] : Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function parseJsonBody(buf: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (buf.length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(buf.toString("utf8")) };
  } catch {
    return { ok: false };
  }
}

function ownerOf(req: http.IncomingMessage): string {
  return LOGIN;
}

// ===========================================================================
// git smart HTTP
// ===========================================================================
function refLinesV0(repo: Repo): Buffer[] {
  const lines: Buffer[] = [];
  const headRef = `refs/heads/${repo.defaultBranch}`;
  const headOid = repo.refs.get(headRef) ?? ZERO_OID;
  const caps = [
    "multi_ack",
    "thin-pack",
    "side-band",
    "side-band-64k",
    "ofs-delta",
    "shallow",
    "deepen-since",
    "deepen-not",
    "deepen-relative",
    "no-progress",
    "include-tag",
    "multi_ack_detailed",
    "allow-tip-sha1-in-want",
    "allow-reachable-sha1-in-want",
    "no-done",
    `symref=HEAD:${headRef}`,
    `agent=${AGENT}`,
  ].join(" ");
  lines.push(pktLine(`${headOid} HEAD\0${caps}\n`));
  const names = [...repo.refs.keys()].sort();
  for (const name of names) {
    lines.push(pktLine(`${repo.refs.get(name)} ${name}\n`));
  }
  return lines;
}

function handleInfoRefs(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  owner: string,
  name: string,
  service: string,
): void {
  const repo = getRepo(owner, name);
  if (!repo || owner !== LOGIN) {
    sendError(res, 404, "Not Found");
    return;
  }
  if (service === "git-upload-pack") {
    const proto = req.headers["git-protocol"] ?? "";
    if (typeof proto === "string" && proto.includes("version=2")) {
      const parts: Buffer[] = [
        pktLine("version 2\n"),
        pktLine(`agent=${AGENT}\n`),
        pktLine("ls-refs=unborn\n"),
        pktLine("fetch=shallow wait-for-done\n"),
        pktLine("server-option\n"),
        pktLine("object-format=sha1\n"),
        FLUSH_PKT,
      ];
      sendRaw(res, 200, "application/x-git-upload-pack-advertisement", Buffer.concat(parts));
      return;
    }
    const parts: Buffer[] = [
      pktLine("# service=git-upload-pack\n"),
      FLUSH_PKT,
      ...refLinesV0(repo),
      FLUSH_PKT,
    ];
    sendRaw(res, 200, "application/x-git-upload-pack-advertisement", Buffer.concat(parts));
    return;
  }
  if (service === "git-receive-pack") {
    const caps = [
      "report-status",
      "side-band-64k",
      "delete-refs",
      "ofs-delta",
      `agent=${AGENT}`,
    ].join(" ");
    const headRef = `refs/heads/${repo.defaultBranch}`;
    const headOid = repo.refs.get(headRef) ?? ZERO_OID;
    const parts: Buffer[] = [
      pktLine("# service=git-receive-pack\n"),
      FLUSH_PKT,
      pktLine(`${headOid} HEAD\0${caps}\n`),
    ];
    const names = [...repo.refs.keys()].sort();
    for (const n of names) parts.push(pktLine(`${repo.refs.get(n)} ${n}\n`));
    parts.push(FLUSH_PKT);
    sendRaw(res, 200, "application/x-git-receive-pack-advertisement", Buffer.concat(parts));
    return;
  }
  sendError(res, 404, "Not Found");
}

function lsRefsResponse(repo: Repo, args: string[]): Buffer {
  // Real git ls-refs format (see ls-refs.c send_ref): lines are space
  // separated, no NUL: "<oid> <ref>[ symref-target:<t>][ peeled:<oid>]"
  // and unborn refs are "unborn <ref>[ symref-target:<t>]".
  const peel = args.includes("peel");
  const unborn = args.includes("unborn");
  const symrefs = args.includes("symrefs");
  const prefixes = args.filter((a) => a.startsWith("ref-prefix ")).map((a) => a.slice(11));
  const headRef = `refs/heads/${repo.defaultBranch}`;
  const headOid = repo.refs.get(headRef);
  const lines: Buffer[] = [];
  const match = (ref: string): boolean =>
    prefixes.length === 0 || prefixes.some((p) => ref.startsWith(p));
  // HEAD: sent when it resolves to a real oid, or (when unborn) only if the
  // client asked for both unborn and symrefs.
  if (match("HEAD")) {
    if (headOid) {
      let line = `${headOid} HEAD`;
      if (symrefs) line += ` symref-target:${headRef}`;
      lines.push(pktLine(line + "\n"));
    } else if (unborn && symrefs) {
      lines.push(pktLine(`unborn HEAD symref-target:${headRef}\n`));
    }
  }
  const names = [...repo.refs.keys()].sort();
  for (const name of names) {
    if (!match(name)) continue;
    const oid = repo.refs.get(name)!;
    let line = `${oid} ${name}`;
    if (peel) {
      const obj = repo.objects.get(oid);
      if (obj && obj.type === "tag") {
        const m = obj.data.toString("utf8").match(/^object ([0-9a-f]{40})/m);
        if (m) line += ` peeled:${m[1]}`;
      }
    }
    lines.push(pktLine(line + "\n"));
  }
  lines.push(FLUSH_PKT);
  return Buffer.concat(lines);
}

/**
 * Build the pack for a fetch. Without a depth, the pack holds everything
 * reachable from the wants that the client does not already have (a have
 * implies its whole closure). With deepen N, the walk is depth-limited
 * from the wants: commits closer than N generations are sent (unless the
 * client has them), commits at distance N-1 are the new shallow boundary,
 * and nothing deeper is sent. The client's haves then name only the tip
 * objects it holds — their parents are NOT implied — so the exclusion set
 * is each have plus its tree, not its commit closure. `clientShallow` is
 * the boundary the client reported; entries whose parents are all now
 * present stop being shallow and are reported as unshallow.
 */
function fetchPack(
  repo: Repo,
  wants: string[],
  haves: string[],
  deepen: number,
  clientShallow: string[] = [],
): { pack: Buffer; shallows: string[]; unshallows: string[] } {
  if (deepen > 0) {
    const haveSet = new Set(haves);
    const held = new Set<string>();
    for (const h of haves) {
      const o = repo.objects.get(h);
      if (!o) continue;
      held.add(h);
      if (o.type === "commit") {
        const tree = parseCommit(o.data).tree;
        for (const oid of collectReachable(repo.objects, [tree], new Set(), false).keys()) held.add(oid);
      }
    }
    const dist = new Map<string, number>();
    const queue: string[] = [];
    for (const w of wants) {
      if (!dist.has(w)) {
        dist.set(w, 0);
        queue.push(w);
      }
    }
    const sendCommits = new Set<string>();
    const boundary = new Set<string>();
    while (queue.length > 0) {
      const oid = queue.shift()!;
      const d = dist.get(oid)!;
      if (d >= deepen) continue;
      const obj = repo.objects.get(oid);
      if (!obj || obj.type !== "commit") continue;
      if (!haveSet.has(oid)) sendCommits.add(oid);
      if (d === deepen - 1) boundary.add(oid);
      for (const p of parseCommit(obj.data).parents) {
        if (!dist.has(p)) {
          dist.set(p, d + 1);
          queue.push(p);
        }
      }
    }
    const objects = new Map<string, GitObject>();
    for (const oid of sendCommits) {
      const obj = repo.objects.get(oid)!;
      objects.set(oid, obj);
      const tree = parseCommit(obj.data).tree;
      for (const [toid, tobj] of collectReachable(repo.objects, [tree], held, false)) {
        if (!objects.has(toid)) objects.set(toid, tobj);
      }
    }
    const unshallows: string[] = [];
    for (const s of clientShallow) {
      const obj = repo.objects.get(s);
      if (!obj || obj.type !== "commit") continue;
      const parents = parseCommit(obj.data).parents;
      if (parents.every((p) => sendCommits.has(p) || held.has(p))) unshallows.push(s);
    }
    const sorted = [...objects.entries()]
      .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
      .map(([, obj]) => obj);
    return { pack: writePack(sorted), shallows: [...boundary].sort(), unshallows };
  }
  const haveSet = new Set<string>();
  if (haves.length > 0) {
    const reached = collectReachable(repo.objects, haves, new Set(), false);
    for (const oid of reached.keys()) haveSet.add(oid);
  }
  const wanted = collectReachable(repo.objects, wants, haveSet, false);
  // The map is keyed by oid, so sorting by key is sorting by oid — the same
  // order the old comparator produced by re-hashing every object per compare.
  const objects = [...wanted.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([, obj]) => obj);
  return { pack: writePack(objects), shallows: [], unshallows: [] };
}

function packAsPktLines(pack: Buffer): Buffer[] {
  // Protocol v2 packfile section: each chunk is a sideband pkt-line whose
  // payload starts with channel byte 0x01 (pack data), then the pack bytes.
  const parts: Buffer[] = [];
  const CHUNK = 65515; // max pkt-line 65520 = 4 length + 1 channel + 65515 data
  for (let i = 0; i < pack.length; i += CHUNK) {
    parts.push(sideband(pack.subarray(i, Math.min(pack.length, i + CHUNK))));
  }
  parts.push(FLUSH_PKT);
  return parts;
}

function handleUploadPackV2(repo: Repo, body: Buffer): Buffer {
  const stream = unwrapStatelessRpc(body);
  const items = readPktLines(stream);
  let command = "";
  const args: string[] = [];
  let seenDelim = false;
  for (const item of items) {
    if (item.kind === "delim") {
      seenDelim = true;
      continue;
    }
    if (item.kind === "flush") break;
    const line = item.data.toString("utf8").replace(/\n$/, "");
    if (!seenDelim) {
      const eq = line.indexOf("=");
      const key = eq === -1 ? line : line.slice(0, eq);
      const value = eq === -1 ? "" : line.slice(eq + 1);
      if (key === "command") command = value;
    } else {
      args.push(line);
    }
  }
  if (command === "ls-refs") {
    return lsRefsResponse(repo, args);
  }
  if (command === "fetch") {
    const wants: string[] = [];
    const haves: string[] = [];
    const clientShallow: string[] = [];
    let deepen = 0;
    let done = false;
    let waitForDone = false;
    for (const a of args) {
      if (a.startsWith("want ")) wants.push(a.slice(5).trim());
      else if (a.startsWith("have ")) haves.push(a.slice(5).trim());
      else if (a.startsWith("shallow ")) clientShallow.push(a.slice(8).trim());
      else if (a.startsWith("deepen ")) deepen = parseInt(a.slice(7).trim(), 10) || 0;
      else if (a === "done") done = true;
      else if (a === "wait-for-done") waitForDone = true;
    }
    const { pack, shallows, unshallows } = fetchPack(repo, wants, haves, deepen, clientShallow);
    const parts: Buffer[] = [];
    // Acknowledgement section: only when the client sent haves AND has not
    // sent "done" yet (with "done", the server skips straight to the pack).
    // Section header is "acknowledgments" (with an 's').
    if (haves.length > 0 && !done) {
      const common = haves.filter((h) => wants.some((w) => isAncestor(repo.objects, h, w)));
      parts.push(pktLine("acknowledgments\n"));
      if (common.length === 0) {
        parts.push(pktLine("NAK\n"));
      } else {
        for (const c of common) parts.push(pktLine(`ACK ${c}\n`));
      }
      const ready = common.length > 0 && !waitForDone;
      if (ready) parts.push(pktLine("ready\n"));
      if (!ready) {
        parts.push(FLUSH_PKT);
        return Buffer.concat(parts);
      }
      parts.push(DELIM_PKT);
    }
    // Shallow-info section (only when a depth was requested).
    if (shallows.length > 0 || unshallows.length > 0) {
      parts.push(pktLine("shallow-info\n"));
      for (const s of shallows) parts.push(pktLine(`shallow ${s}\n`));
      for (const s of unshallows) parts.push(pktLine(`unshallow ${s}\n`));
      parts.push(DELIM_PKT);
    }
    // Packfile section.
    parts.push(pktLine("packfile\n"));
    parts.push(...packAsPktLines(pack));
    return Buffer.concat(parts);
  }
  // Unknown command: empty acknowledgement.
  return Buffer.concat([pktLine("acknowledgments\n"), pktLine("NAK\n"), FLUSH_PKT]);
}

function handleUploadPackV0(repo: Repo, body: Buffer): Buffer {
  const stream = unwrapStatelessRpc(body);
  const items = readPktLines(stream);
  const wants: string[] = [];
  const haves: string[] = [];
  const clientShallow: string[] = [];
  let deepen = 0;
  let useSideband = false;
  for (const item of items) {
    if (item.kind !== "data") continue;
    const line = item.data.toString("utf8").replace(/\n$/, "");
    if (line.startsWith("want ")) {
      // v0 want line: "want <oid>[ <capability> ...]" (space-separated caps,
      // no NUL). Split off the oid and scan the caps for side-band-64k.
      const rest = line.slice(5);
      const [head, ...nulCaps] = rest.split("\0");
      const tokens = head!.trim().split(/\s+/);
      wants.push(tokens[0]!);
      const caps = [...tokens.slice(1), ...nulCaps.join(" ").split(/\s+/)];
      if (caps.includes("side-band-64k")) useSideband = true;
    } else if (line.startsWith("have ")) {
      haves.push(line.slice(5).trim());
    } else if (line.startsWith("shallow ")) {
      clientShallow.push(line.slice(8).trim());
    } else if (line.startsWith("deepen ")) {
      deepen = parseInt(line.slice(7).trim(), 10) || 0;
    }
  }
  const { pack, shallows, unshallows } = fetchPack(repo, wants, haves, deepen, clientShallow);
  const parts: Buffer[] = [];
  for (const s of shallows) parts.push(pktLine(`shallow ${s}\n`));
  for (const s of unshallows) parts.push(pktLine(`unshallow ${s}\n`));
  // ACK when any have is an ancestor of a want, else NAK.
  let ack: string | null = null;
  for (const h of haves) {
    if (wants.some((w) => isAncestor(repo.objects, h, w))) {
      ack = h;
      break;
    }
  }
  parts.push(pktLine(ack ? `ACK ${ack}\n` : "NAK\n"));
  if (useSideband) {
    const CHUNK = 65515; // max pkt-line 65520 = 4 length + 1 channel + 65515 data
    for (let i = 0; i < pack.length; i += CHUNK) {
      parts.push(sideband(pack.subarray(i, Math.min(pack.length, i + CHUNK))));
    }
    parts.push(FLUSH_PKT);
  } else {
    parts.push(pack);
  }
  return Buffer.concat(parts);
}

function handleReceivePack(repo: Repo, body: Buffer): Buffer {
  const stream = unwrapStatelessRpc(body);
  const items = readPktLines(stream);
  interface Cmd {
    oldOid: string;
    newOid: string;
    ref: string;
  }
  const cmds: Cmd[] = [];
  let useSideband = false;
  let reportStatus = false;
  // One pass over the parsed lines: the commands and caps come from the items
  // themselves, and the pack starts just past the flush pkt-line that ends
  // the command section (the item's recorded end offset). With no flush at
  // all packStart stays 0, as the old re-walk left it.
  let packStart = 0;
  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    if (item.kind === "flush") {
      packStart = item.end;
      break;
    }
    if (item.kind !== "data") continue;
    const payload = item.data.toString("utf8").replace(/\n$/, "");
    if (i === 0) {
      const nul = payload.indexOf("\0");
      const caps = nul === -1 ? "" : payload.slice(nul + 1);
      if (caps.includes("side-band-64k")) useSideband = true;
      if (caps.includes("report-status")) reportStatus = true;
    }
    const first = payload.split("\0")[0];
    const m = first.match(/^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/);
    if (m) cmds.push({ oldOid: m[1], newOid: m[2], ref: m[3] });
  }
  // Extract the packfile. In stateless RPC the pack arrives as plain
  // pkt-lines (send_sideband band=-1) after the command flush, or as raw
  // bytes when the client did not wrap it.
  let packBuf: Buffer;
  const rest = stream.subarray(packStart);
  if (rest.length === 0) {
    packBuf = Buffer.alloc(0);
  } else if (rest.subarray(0, 4).toString("ascii") === "PACK") {
    packBuf = Buffer.from(rest);
  } else {
    // Transport pkt-lines: concatenate payloads until a flush.
    const chunks: Buffer[] = [];
    for (const item of readPktLines(rest)) {
      if (item.kind === "flush" || item.kind === "delim") break;
      chunks.push(Buffer.from(item.data));
    }
    const joined = Buffer.concat(chunks);
    packBuf = joined.subarray(0, 4).toString("ascii") === "PACK" ? joined : Buffer.from(rest);
  }
  const results: { ref: string; ok: boolean; reason: string }[] = [];
  let unpackOk = true;
  let newObjects: GitObject[] = [];
  if (packBuf.length === 0) {
    // No pack data (e.g. delete-only push): nothing to unpack.
    newObjects = [];
  } else {
    try {
      newObjects = readPack(packBuf);
    } catch {
      unpackOk = false;
    }
  }
  if (unpackOk) {
    for (const o of newObjects) {
      // readPack already hashed each object once; reuse its oid.
      repo.objects.set(o.oid ?? hashObject(o.type, o.data), o);
    }
    for (const cmd of cmds) {
      const current = repo.refs.get(cmd.ref);
      if (cmd.newOid === ZERO_OID) {
        // delete
        if (current === undefined || current !== cmd.oldOid) {
          results.push({ ref: cmd.ref, ok: false, reason: "remote ref does not exist" });
        } else {
          repo.refs.delete(cmd.ref);
          results.push({ ref: cmd.ref, ok: true, reason: "" });
        }
        continue;
      }
      if (cmd.oldOid === ZERO_OID) {
        // create
        if (current !== undefined) {
          results.push({ ref: cmd.ref, ok: false, reason: "already exists" });
        } else if (!repo.objects.has(cmd.newOid)) {
          results.push({ ref: cmd.ref, ok: false, reason: "object not found" });
        } else {
          repo.refs.set(cmd.ref, cmd.newOid);
          results.push({ ref: cmd.ref, ok: true, reason: "" });
        }
        continue;
      }
      if (current === undefined || current !== cmd.oldOid) {
        results.push({ ref: cmd.ref, ok: false, reason: "non-fast-forward" });
        continue;
      }
      if (!repo.objects.has(cmd.newOid)) {
        results.push({ ref: cmd.ref, ok: false, reason: "object not found" });
        continue;
      }
      if (!isAncestor(repo.objects, cmd.oldOid, cmd.newOid)) {
        results.push({ ref: cmd.ref, ok: false, reason: "non-fast-forward" });
        continue;
      }
      repo.refs.set(cmd.ref, cmd.newOid);
      results.push({ ref: cmd.ref, ok: true, reason: "" });
    }
    repo.updatedAt = new Date(nextTimeSec() * 1000).toISOString();
  }
  const parts: Buffer[] = [];
  if (reportStatus) {
    // Real receive-pack report(): the status lines are pkt-lines first
    // ("unpack ok", "ok <ref>"/"ng <ref> ...", flush), and the whole buffer
    // is then wrapped in sideband channel-1 packets when sideband was
    // negotiated. A plain flush terminates the sideband stream.
    const report = Buffer.concat([
      pktLine(unpackOk ? "unpack ok\n" : "unpack failed\n"),
      ...results.map((r) => pktLine(r.ok ? `ok ${r.ref}\n` : `ng ${r.ref} ${r.reason}\n`)),
      FLUSH_PKT,
    ]);
    if (useSideband) {
      const CHUNK = 65515; // max pkt-line 65520 = 4 length + 1 channel + 65515 data
      for (let i = 0; i < report.length; i += CHUNK) {
        parts.push(sideband(report.subarray(i, Math.min(report.length, i + CHUNK))));
      }
    } else {
      parts.push(report);
    }
    parts.push(FLUSH_PKT);
  }
  return Buffer.concat(parts);
}

// ===========================================================================
// REST v3
// ===========================================================================
function repoJson(r: Repo): Record<string, unknown> {
  return {
    id: r.id,
    node_id: `R_${r.id}`,
    name: r.name,
    full_name: `${r.owner}/${r.name}`,
    owner: { login: r.owner, id: 1, type: "User" },
    private: r.isPrivate,
    html_url: `https://github.com/${r.owner}/${r.name}`,
    description: r.description,
    fork: false,
    url: `/api/v3/repos/${r.owner}/${r.name}`,
    created_at: r.createdAt,
    updated_at: r.updatedAt,
    pushed_at: r.updatedAt,
    homepage: null,
    size: 0,
    stargazers_count: 0,
    watchers_count: 0,
    language: null,
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: true,
    has_pages: false,
    forks_count: 0,
    archived: false,
    disabled: false,
    open_issues_count: openIssueCount(r),
    license: null,
    allow_forking: true,
    is_template: false,
    topics: [],
    visibility: r.isPrivate ? "private" : "public",
    forks: 0,
    open_issues: openIssueCount(r),
    watchers: 0,
    default_branch: r.defaultBranch,
    permissions: { admin: true, push: true, pull: true },
  };
}

function issueJson(r: Repo, i: Issue): Record<string, unknown> {
  return {
    id: i.id,
    node_id: `I_${i.id}`,
    url: `/api/v3/repos/${r.owner}/${r.name}/issues/${i.number}`,
    repository_url: `/api/v3/repos/${r.owner}/${r.name}`,
    labels_url: `/api/v3/repos/${r.owner}/${r.name}/issues/${i.number}/labels{/name}`,
    comments_url: `/api/v3/repos/${r.owner}/${r.name}/issues/${i.number}/comments`,
    events_url: `/api/v3/repos/${r.owner}/${r.name}/issues/${i.number}/events`,
    html_url: `https://github.com/${r.owner}/${r.name}/issues/${i.number}`,
    number: i.number,
    state: i.state,
    title: i.title,
    body: i.body,
    user: { login: i.user, id: 1, type: "User" },
    labels: i.labels.map((name) => {
      const l = r.labels.get(name);
      return {
        id: 0,
        node_id: "",
        url: `/api/v3/repos/${r.owner}/${r.name}/labels/${encodeURIComponent(name)}`,
        name,
        color: l ? l.color : "000000",
        default: false,
        description: l ? l.description : "",
      };
    }),
    assignee: null,
    assignees: [],
    milestone: null,
    locked: false,
    comments: i.comments.length,
    created_at: i.createdAt,
    updated_at: i.updatedAt,
    closed_at: i.closedAt,
    author_association: "OWNER",
  };
}

/**
 * The issue's JSON body as a string, cached on the issue: the read workload
 * GETs one unchanged issue thousands of times, and rebuilding + stringifying
 * the same object every time is pure waste. The string is byte-identical to
 * JSON.stringify(issueJson(r, i)) — it is built by exactly that — so a
 * cached read answers what a fresh build would. Every mutation of the issue
 * (REST PATCH, comment add, label add, GraphQL close/addComment) clears it,
 * and any change to the repo's label definitions clears every issue's (the
 * labels' color/description are embedded in the JSON).
 */
function issueJsonString(r: Repo, i: Issue): string {
  if (i._json === undefined) i._json = JSON.stringify(issueJson(r, i));
  return i._json;
}
function invalidateIssueJson(i: Issue): void {
  i._json = undefined;
}
function invalidateRepoIssueJson(r: Repo): void {
  for (const i of r.issues.values()) i._json = undefined;
}

function pullJson(r: Repo, p: Pull): Record<string, unknown> {
  return {
    id: p.id,
    node_id: `PR_${p.id}`,
    url: `/api/v3/repos/${r.owner}/${r.name}/pulls/${p.number}`,
    html_url: `https://github.com/${r.owner}/${r.name}/pull/${p.number}`,
    number: p.number,
    state: p.state,
    title: p.title,
    body: p.body,
    user: { login: p.user, id: 1, type: "User" },
    created_at: p.createdAt,
    updated_at: p.updatedAt,
    closed_at: p.closedAt,
    merged_at: p.mergedAt,
    merge_commit_sha: p.mergeCommitSha,
    head: {
      label: `${r.owner}:${p.head}`,
      ref: p.head,
      sha: p.headSha,
      user: { login: r.owner, id: 1, type: "User" },
      repo: repoJson(r),
    },
    base: {
      label: `${r.owner}:${p.base}`,
      ref: p.base,
      sha: p.baseSha,
      user: { login: r.owner, id: 1, type: "User" },
      repo: repoJson(r),
    },
    merged: p.merged,
    mergeable: p.state === "open",
    mergeable_state: p.state === "open" ? "clean" : "unknown",
    merged_by: null,
    commits: 1,
    additions: 0,
    deletions: 0,
    changed_files: 0,
    draft: false,
    labels: [],
    assignee: null,
    assignees: [],
    milestone: null,
  };
}

function parseQuery(url: string): URLSearchParams {
  return new URL(url, "http://x").searchParams;
}

function paginate<T>(items: T[], q: URLSearchParams, res: http.ServerResponse, path: string, origin = ""): T[] {
  const perPage = Math.max(1, Math.min(100, parseInt(q.get("per_page") ?? "30", 10) || 30));
  const page = Math.max(1, parseInt(q.get("page") ?? "1", 10) || 1);
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  if (page < totalPages) {
    const base = `${origin}${path}?per_page=${perPage}&page=${page + 1}`;
    res.setHeader("Link", `<${base}>; rel="next"`);
  }
  const start = (page - 1) * perPage;
  return items.slice(start, start + perPage);
}

interface RestCtx {
  req: http.IncomingMessage;
  res: http.ServerResponse;
  body: unknown;
  path: string;
  q: URLSearchParams;
}

/** Parse a git ident line ("Name <email> 1700000000 +0000") for REST output. */
function parseIdent(ident: string): { name: string; email: string; date: string } {
  const m = ident.match(/^(.*?) <([^>]*)> (\d+) ([+-]\d{4})$/);
  if (!m) return { name: ident, email: "", date: new Date(clockBase * 1000).toISOString() };
  return { name: m[1], email: m[2], date: new Date(parseInt(m[3], 10) * 1000).toISOString() };
}

/** Commits reachable from a tip, newest first (depth-first from the tip). */
function commitList(repo: Repo, tipOid: string, limit = 100): { sha: string; message: string; author: { name: string; email: string; date: string }; committer: { name: string; email: string; date: string }; parents: string[]; tree: string }[] {
  const out: { sha: string; message: string; author: { name: string; email: string; date: string }; committer: { name: string; email: string; date: string }; parents: string[]; tree: string }[] = [];
  const seen = new Set<string>();
  const stack = [tipOid];
  while (stack.length > 0 && out.length < limit) {
    const oid = stack.pop()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== "commit") continue;
    const c = parseCommit(obj.data);
    // GitHub's API view strips the trailing newline git stores in the object.
    out.push({ sha: oid, message: c.message.replace(/\n+$/, ""), author: parseIdent(c.author), committer: parseIdent(c.committer), parents: c.parents, tree: c.tree });
    for (const p of c.parents) stack.push(p);
  }
  return out;
}

function countLines(content: Buffer): string[] {
  const s = content.toString("utf8");
  if (s === "") return [];
  const lines = s.split("\n");
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return lines;
}

/** Line additions/deletions between two blob contents (multiset difference). */
function lineDiff(oldBuf: Buffer | null, newBuf: Buffer | null): { additions: number; deletions: number } {
  if (!oldBuf) return { additions: countLines(newBuf ?? Buffer.alloc(0)).length, deletions: 0 };
  if (!newBuf) return { additions: 0, deletions: countLines(oldBuf).length };
  const remaining = new Map<string, number>();
  for (const l of countLines(oldBuf)) remaining.set(l, (remaining.get(l) ?? 0) + 1);
  let additions = 0;
  for (const l of countLines(newBuf)) {
    const c = remaining.get(l) ?? 0;
    if (c > 0) remaining.set(l, c - 1);
    else additions++;
  }
  let deletions = 0;
  for (const c of remaining.values()) deletions += c;
  return { additions, deletions };
}

/** Files changed between a pull request's base and head tips. */
function pullFiles(repo: Repo, p: Pull): { filename: string; status: string; additions: number; deletions: number; changes: number }[] {
  const treeOf = (oid: string | undefined): Map<string, { oid: string; mode: string }> => {
    if (!oid) return new Map();
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== "commit") return new Map();
    return treeToFiles(repo.objects, parseCommit(obj.data).tree);
  };
  const baseFiles = treeOf(p.baseSha);
  const headFiles = treeOf(p.headSha);
  const out: { filename: string; status: string; additions: number; deletions: number; changes: number }[] = [];
  for (const name of [...new Set([...baseFiles.keys(), ...headFiles.keys()])].sort()) {
    const bf = baseFiles.get(name);
    const hf = headFiles.get(name);
    if (bf && hf && bf.oid === hf.oid) continue;
    const status = !bf ? "added" : !hf ? "removed" : "modified";
    const { additions, deletions } = lineDiff(
      bf ? repo.objects.get(bf.oid)?.data ?? null : null,
      hf ? repo.objects.get(hf.oid)?.data ?? null : null,
    );
    out.push({ filename: name, status, additions, deletions, changes: additions + deletions });
  }
  return out;
}

/** 3-way merge of the head tip onto the base tip; merged is null on conflict. */
function tryMergeFiles(repo: Repo, baseOid: string, headOid: string): { conflict: boolean; merged: Map<string, { oid: string; mode: string }> | null } {
  const base = mergeBase(repo.objects, baseOid, headOid);
  if (!base) return { conflict: true, merged: null };
  const baseCommit = repo.objects.get(base);
  const headCommit = repo.objects.get(headOid);
  const baseCommitObj = repo.objects.get(baseOid);
  if (!baseCommit || !headCommit || !baseCommitObj || baseCommit.type !== "commit" || headCommit.type !== "commit" || baseCommitObj.type !== "commit") {
    return { conflict: true, merged: null };
  }
  const ancestor = treeToFiles(repo.objects, parseCommit(baseCommit.data).tree);
  const headFiles = treeToFiles(repo.objects, parseCommit(headCommit.data).tree);
  const curFiles = treeToFiles(repo.objects, parseCommit(baseCommitObj.data).tree);
  const merged = new Map(curFiles);
  for (const [path, hf] of headFiles) {
    const af = ancestor.get(path);
    const cf = curFiles.get(path);
    if (af && af.oid === hf.oid) continue;
    if (cf && af && cf.oid !== af.oid && cf.oid !== hf.oid) return { conflict: true, merged: null };
    merged.set(path, hf);
  }
  for (const [path, af] of ancestor) {
    if (headFiles.has(path)) continue;
    const cf = curFiles.get(path);
    if (cf && cf.oid !== af.oid) return { conflict: true, merged: null };
    merged.delete(path);
  }
  return { conflict: false, merged };
}

function handleRest(ctx: RestCtx): boolean {
  const { req, res, body, path, q } = ctx;
  const method = req.method ?? "GET";
  const owner = ownerOf(req);
  const origin = `http://${req.headers.host ?? "127.0.0.1"}`;

  if (method === "GET" && path === "/api/v3/") {
    sendJson(res, 200, { current_user_url: "/api/v3/user", current_user_repos_url: "/api/v3/user/repos" }, {
      "x-oauth-scopes": "repo",
    });
    return true;
  }
  if (method === "GET" && path === "/api/v3/meta") {
    sendJson(res, 200, {
      installed_version: "1.0.0",
      verifiable_password_authentication: false,
      github_services_sha: "0000000000000000000000000000000000000000",
      hooks: [],
      git: [],
      pages: [],
      importer: [],
      api: [],
      domains: { website: [".github.com"], codespaces: [".github.dev"], copilot: [".githubcopilot.com"], packages: [".pkg.github.com"], actions: [".actions.githubusercontent.com"] },
    });
    return true;
  }
  if (method === "GET" && path === "/api/v3/user") {
    sendJson(res, 200, {
      login: LOGIN,
      id: 1,
      node_id: "U_1",
      avatar_url: "",
      html_url: `https://github.com/${LOGIN}`,
      type: "User",
      site_admin: false,
      name: LOGIN,
      company: null,
      blog: "",
      location: null,
      email: `${LOGIN}@forge.local`,
      bio: null,
      public_repos: repos.size,
      public_gists: 0,
      followers: 0,
      following: 0,
      created_at: new Date(clockBase * 1000).toISOString(),
      updated_at: new Date(clockBase * 1000).toISOString(),
    });
    return true;
  }
  if (method === "GET" && path === "/api/v3/user/repos") {
    const mine = [...repos.values()]
      .filter((r) => r.owner === LOGIN)
      .sort((a, b) => a.id - b.id)
      .map((r) => repoJson(r));
    sendJson(res, 200, paginate(mine, q, res, path, origin));
    return true;
  }
  if (method === "POST" && path === "/api/v3/user/repos") {
    const b = (body ?? {}) as Record<string, unknown>;
    const name = typeof b.name === "string" && b.name.length > 0 ? b.name : null;
    if (!name) {
      sendError(res, 422, "name is required");
      return true;
    }
    if (repos.has(repoKey(LOGIN, name))) {
      sendError(res, 422, "Repository creation failed: name already exists.");
      return true;
    }
    const now = isoNow();
    const repo: Repo = {
      id: nextRepoId++,
      name,
      owner: LOGIN,
      description: typeof b.description === "string" ? b.description : "",
      isPrivate: b.private === true,
      defaultBranch: typeof b.default_branch === "string" ? b.default_branch : "main",
      refs: new Map(),
      objects: new Map(),
      issues: new Map(),
      labels: new Map(),
      pulls: new Map(),
      nextNumber: 1,
      createdAt: now,
      updatedAt: now,
    };
    repos.set(repoKey(LOGIN, name), repo);
    sendJson(res, 201, repoJson(repo));
    return true;
  }

  // /api/v3/repos/{owner}/{repo}[...]
  const repoMatch = path.match(/^\/api\/v3\/repos\/([^/]+)\/([^/]+)(?:\/(.*))?$/);
  if (repoMatch) {
    const rOwner = decodeURIComponent(repoMatch[1]);
    const rName = decodeURIComponent(repoMatch[2]);
    const rest = repoMatch[3] ?? "";
    const repo = getRepo(rOwner, rName);
    if (!repo) {
      sendError(res, 404, "Not Found");
      return true;
    }
    if (method === "GET" && rest === "") {
      sendJson(res, 200, repoJson(repo));
      return true;
    }
    if (method === "PATCH" && rest === "") {
      const b = (body ?? {}) as Record<string, unknown>;
      if (typeof b.description === "string") repo.description = b.description;
      if (typeof b.default_branch === "string") repo.defaultBranch = b.default_branch;
      repo.updatedAt = isoNow();
      sendJson(res, 200, repoJson(repo));
      return true;
    }
    if (method === "DELETE" && rest === "") {
      repos.delete(repoKey(rOwner, rName));
      res.writeHead(204, { "x-github-request-id": `req-${++requestCounter}` });
      res.end();
      return true;
    }
    // contents
    const contentsMatch = rest.match(/^contents\/(.+)$/);
    if (contentsMatch) {
      const filePath = decodeURIComponent(contentsMatch[1]);
      return handleContents(ctx, repo, filePath);
    }
    // labels
    if (rest === "labels") {
      if (method === "GET") {
        const list = [...repo.labels.values()]
          .sort((a, b) => (a.name < b.name ? -1 : 1))
          .map((l) => ({
            id: 0,
            node_id: "",
            url: `/api/v3/repos/${repo.owner}/${repo.name}/labels/${encodeURIComponent(l.name)}`,
            name: l.name,
            color: l.color,
            default: false,
            description: l.description,
          }));
        sendJson(res, 200, list);
        return true;
      }
      if (method === "POST") {
        const b = (body ?? {}) as Record<string, unknown>;
        const name = typeof b.name === "string" ? b.name : "";
        if (!name) {
          sendError(res, 422, "name is required");
          return true;
        }
        const label: Label = {
          name,
          color: typeof b.color === "string" ? b.color : "000000",
          description: typeof b.description === "string" ? b.description : "",
        };
        repo.labels.set(name, label);
        // A label definition changed: every cached issue JSON embeds it.
        invalidateRepoIssueJson(repo);
        sendJson(res, 201, {
          id: 0,
          node_id: "",
          url: `/api/v3/repos/${repo.owner}/${repo.name}/labels/${encodeURIComponent(name)}`,
          name: label.name,
          color: label.color,
          default: false,
          description: label.description,
        });
        return true;
      }
    }
    // issues
    if (rest === "issues") {
      if (method === "GET") {
        const state = q.get("state") ?? "open";
        const labels = q.get("labels");
        let list = [...repo.issues.values()];
        if (state !== "all") list = list.filter((i) => i.state === state);
        if (labels) {
          const wanted = labels.split(",").map((s) => s.trim());
          list = list.filter((i) => wanted.every((w) => i.labels.includes(w)));
        }
        const sort = (q.get("sort") ?? "").toLowerCase();
        const direction = (q.get("direction") ?? "desc").toLowerCase();
        if (sort === "created" || sort === "updated") {
          const key = sort === "updated" ? "updatedAt" : "createdAt";
          list.sort((a, b) => {
            const cmp = Date.parse(a[key]) - Date.parse(b[key]) || a.number - b.number;
            return direction === "desc" ? -cmp : cmp;
          });
        } else {
          list.sort((a, b) => a.number - b.number);
        }
        sendJson(res, 200, paginate(list.map((i) => issueJson(repo, i)), q, res, path, origin));
        return true;
      }
      if (method === "POST") {
        const b = (body ?? {}) as Record<string, unknown>;
        const title = typeof b.title === "string" ? b.title : "";
        if (!title) {
          sendError(res, 422, "title is required");
          return true;
        }
        const labels: string[] = Array.isArray(b.labels)
          ? (b.labels as unknown[]).filter((x) => typeof x === "string") as string[]
          : [];
        for (const l of labels) {
          if (!repo.labels.has(l)) {
            sendError(res, 422, `Label does not exist: ${l}`);
            return true;
          }
        }
        const now = isoNow();
        const number = repo.nextNumber++;
        const issue: Issue = {
          id: number,
          number,
          title,
          body: typeof b.body === "string" ? b.body : null,
          state: "open",
          labels,
          user: LOGIN,
          createdAt: now,
          updatedAt: now,
          closedAt: null,
          comments: [],
        };
        repo.issues.set(number, issue);
        sendJson(res, 201, issueJson(repo, issue));
        return true;
      }
    }
    const issueMatch = rest.match(/^issues\/(\d+)(?:\/(comments|labels))?$/);
    if (issueMatch) {
      const number = parseInt(issueMatch[1], 10);
      const issue = repo.issues.get(number);
      if (!issue) {
        sendError(res, 404, "Not Found");
        return true;
      }
      const sub = issueMatch[2] ?? "";
      if (method === "GET" && sub === "") {
        sendJsonText(res, 200, issueJsonString(repo, issue));
        return true;
      }
      if (method === "PATCH" && sub === "") {
        const b = (body ?? {}) as Record<string, unknown>;
        if (typeof b.title === "string") issue.title = b.title;
        if (typeof b.body === "string" || b.body === null) issue.body = b.body as string | null;
        if (typeof b.state === "string" && (b.state === "open" || b.state === "closed")) {
          issue.state = b.state;
          issue.closedAt = b.state === "closed" ? isoNow() : null;
        }
        if (Array.isArray(b.labels)) {
          const labels = (b.labels as unknown[]).filter((x) => typeof x === "string") as string[];
          for (const l of labels) {
            if (!repo.labels.has(l)) {
              sendError(res, 422, `Label does not exist: ${l}`);
              return true;
            }
          }
          issue.labels = labels;
        }
        issue.updatedAt = isoNow();
        invalidateIssueJson(issue);
        sendJson(res, 200, issueJson(repo, issue));
        return true;
      }
      if (sub === "comments") {
        if (method === "GET") {
          sendJson(
            res,
            200,
            issue.comments.map((c) => ({
              id: c.id,
              node_id: `C_${c.id}`,
              url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${number}/comments/${c.id}`,
              html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${number}#issuecomment-${c.id}`,
              body: c.body,
              user: { login: c.user, id: 1, type: "User" },
              created_at: c.createdAt,
              updated_at: c.createdAt,
            })),
          );
          return true;
        }
        if (method === "POST") {
          const b = (body ?? {}) as Record<string, unknown>;
          const cBody = typeof b.body === "string" ? b.body : "";
          const comment = {
            id: issue.comments.length + 1,
            body: cBody,
            user: LOGIN,
            createdAt: isoNow(),
          };
          issue.comments.push(comment);
          issue.updatedAt = isoNow();
          invalidateIssueJson(issue);
          sendJson(res, 201, {
            id: comment.id,
            node_id: `C_${comment.id}`,
            url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${number}/comments/${comment.id}`,
            html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${number}#issuecomment-${comment.id}`,
            body: comment.body,
            user: { login: comment.user, id: 1, type: "User" },
            created_at: comment.createdAt,
            updated_at: comment.createdAt,
          });
          return true;
        }
      }
      if (sub === "labels" && method === "POST") {
        const b = (body ?? {}) as Record<string, unknown>;
        const names: string[] = Array.isArray(b.labels)
          ? (b.labels as unknown[]).filter((x) => typeof x === "string") as string[]
          : [];
        for (const l of names) {
          if (!repo.labels.has(l)) {
            sendError(res, 422, `Label does not exist: ${l}`);
            return true;
          }
          if (!issue.labels.includes(l)) issue.labels.push(l);
        }
        issue.updatedAt = isoNow();
        invalidateIssueJson(issue);
        sendJson(
          res,
          200,
          issue.labels.map((name) => {
            const l = repo.labels.get(name)!;
            return { name, color: l.color, description: l.description };
          }),
        );
        return true;
      }
    }
    // pulls
    if (rest === "pulls") {
      if (method === "GET") {
        const state = q.get("state") ?? "open";
        let list = [...repo.pulls.values()].sort((a, b) => a.number - b.number);
        if (state !== "all") list = list.filter((p) => p.state === state);
        sendJson(res, 200, paginate(list.map((p) => pullJson(repo, p)), q, res, path, origin));
        return true;
      }
      if (method === "POST") {
        const b = (body ?? {}) as Record<string, unknown>;
        const title = typeof b.title === "string" ? b.title : "";
        const head = typeof b.head === "string" ? b.head : "";
        const base = typeof b.base === "string" ? b.base : repo.defaultBranch;
        if (!title || !head) {
          sendError(res, 422, "title and head are required");
          return true;
        }
        const headRef = `refs/heads/${head}`;
        const baseRef = `refs/heads/${base}`;
        const headSha = repo.refs.get(headRef);
        const baseSha = repo.refs.get(baseRef);
        if (!headSha || !baseSha) {
          sendError(res, 422, "head or base branch not found");
          return true;
        }
        const now = isoNow();
        const number = repo.nextNumber++;
        const pull: Pull = {
          id: number,
          number,
          title,
          body: typeof b.body === "string" ? b.body : null,
          state: "open",
          head,
          base,
          headSha,
          baseSha,
          merged: false,
          mergeCommitSha: null,
          user: LOGIN,
          createdAt: now,
          updatedAt: now,
          closedAt: null,
          mergedAt: null,
        };
        repo.pulls.set(number, pull);
        sendJson(res, 201, pullJson(repo, pull));
        return true;
      }
    }
    const pullMatch = rest.match(/^pulls\/(\d+)(?:\/(merge))?$/);
    if (pullMatch) {
      const number = parseInt(pullMatch[1], 10);
      const pull = repo.pulls.get(number);
      if (!pull) {
        sendError(res, 404, "Not Found");
        return true;
      }
      const sub = pullMatch[2] ?? "";
      if (method === "GET" && sub === "") {
        sendJson(res, 200, pullJson(repo, pull));
        return true;
      }
      if (method === "PUT" && sub === "merge") {
        return handleMerge(ctx, repo, pull);
      }
      if (method === "PATCH" && sub === "") {
        const b = (body ?? {}) as Record<string, unknown>;
        if (typeof b.title === "string") pull.title = b.title;
        if (typeof b.body === "string" || b.body === null) pull.body = b.body as string | null;
        if (typeof b.state === "string" && b.state === "closed") {
          pull.state = "closed";
          pull.closedAt = isoNow();
        }
        pull.updatedAt = isoNow();
        sendJson(res, 200, pullJson(repo, pull));
        return true;
      }
    }
    const pullFilesMatch = rest.match(/^pulls\/(\d+)\/files$/);
    if (pullFilesMatch) {
      const number = parseInt(pullFilesMatch[1], 10);
      const pull = repo.pulls.get(number);
      if (!pull) {
        sendError(res, 404, "Not Found");
        return true;
      }
      if (method === "GET") {
        sendJson(
          res,
          200,
          pullFiles(repo, pull).map((f) => ({
            sha: "",
            filename: f.filename,
            status: f.status,
            additions: f.additions,
            deletions: f.deletions,
            changes: f.changes,
            blob_url: "",
            raw_url: "",
            contents_url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${f.filename}`,
            patch: "",
          })),
        );
        return true;
      }
    }
    // branches
    if (rest === "branches") {
      if (method === "GET") {
        const list = [...repo.refs.keys()]
          .filter((n) => n.startsWith("refs/heads/"))
          .map((n) => n.slice("refs/heads/".length))
          .sort()
          .map((name) => ({
            name,
            commit: { sha: repo.refs.get(`refs/heads/${name}`), url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${repo.refs.get(`refs/heads/${name}`)}` },
            protected: false,
          }));
        sendJson(res, 200, list);
        return true;
      }
    }
    const branchMatch = rest.match(/^branches\/(.+)$/);
    if (branchMatch) {
      const name = decodeURIComponent(branchMatch[1]);
      const sha = repo.refs.get(`refs/heads/${name}`);
      if (!sha) {
        sendError(res, 404, "Not Found");
        return true;
      }
      if (method === "GET") {
        sendJson(res, 200, {
          name,
          commit: { sha, url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${sha}` },
          protected: false,
        });
        return true;
      }
    }
    // commits
    if (rest === "commits") {
      if (method === "GET") {
        const shaParam = q.get("sha");
        let tip: string | undefined;
        if (shaParam) {
          tip = repo.refs.get(`refs/heads/${shaParam}`) ?? (repo.objects.has(shaParam) ? shaParam : undefined);
        } else {
          tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
        }
        if (!tip) {
          sendError(res, 404, "Not Found");
          return true;
        }
        sendJson(
          res,
          200,
          commitList(repo, tip).map((c) => ({
            sha: c.sha,
            commit: {
              message: c.message,
              author: c.author,
              committer: c.committer,
              tree: { sha: c.tree },
            },
            parents: c.parents.map((p) => ({ sha: p })),
            url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${c.sha}`,
            html_url: `https://github.com/${repo.owner}/${repo.name}/commit/${c.sha}`,
          })),
        );
        return true;
      }
    }
    // git refs (Git Data API)
    if (rest === "git/refs") {
      if (method === "GET") {
        const list = [...repo.refs.entries()]
          .sort((a, b) => (a[0] < b[0] ? -1 : 1))
          .map(([ref, sha]) => ({
            ref,
            url: `/api/v3/repos/${repo.owner}/${repo.name}/git/refs/${ref.slice(5)}`,
            object: { sha, type: repo.objects.get(sha)?.type ?? "commit", url: "" },
          }));
        sendJson(res, 200, list);
        return true;
      }
      if (method === "POST") {
        const b = (body ?? {}) as Record<string, unknown>;
        const ref = typeof b.ref === "string" ? b.ref : "";
        const sha = typeof b.sha === "string" ? b.sha : "";
        if (!ref.startsWith("refs/") || !sha || !repo.objects.has(sha)) {
          sendError(res, 422, "ref and sha are required and sha must exist");
          return true;
        }
        if (repo.refs.has(ref)) {
          sendError(res, 422, "Reference already exists");
          return true;
        }
        repo.refs.set(ref, sha);
        repo.updatedAt = isoNow();
        sendJson(res, 201, {
          ref,
          url: `/api/v3/repos/${repo.owner}/${repo.name}/git/refs/${ref.slice(5)}`,
          object: { sha, type: repo.objects.get(sha)?.type ?? "commit", url: "" },
        });
        return true;
      }
    }
    const gitRefMatch = rest.match(/^git\/refs\/(.+)$/);
    if (gitRefMatch) {
      const ref = `refs/${decodeURIComponent(gitRefMatch[1])}`;
      const sha = repo.refs.get(ref);
      if (!sha) {
        sendError(res, 404, "Not Found");
        return true;
      }
      if (method === "GET") {
        sendJson(res, 200, {
          ref,
          url: `/api/v3/repos/${repo.owner}/${repo.name}/git/refs/${ref.slice(5)}`,
          object: { sha, type: repo.objects.get(sha)?.type ?? "commit", url: "" },
        });
        return true;
      }
      if (method === "PATCH") {
        const b = (body ?? {}) as Record<string, unknown>;
        const newSha = typeof b.sha === "string" ? b.sha : "";
        if (!newSha || !repo.objects.has(newSha)) {
          sendError(res, 422, "sha must exist");
          return true;
        }
        repo.refs.set(ref, newSha);
        repo.updatedAt = isoNow();
        sendJson(res, 200, {
          ref,
          url: `/api/v3/repos/${repo.owner}/${repo.name}/git/refs/${ref.slice(5)}`,
          object: { sha: newSha, type: repo.objects.get(newSha)?.type ?? "commit", url: "" },
        });
        return true;
      }
      if (method === "DELETE") {
        repo.refs.delete(ref);
        res.writeHead(204, { "x-github-request-id": `req-${++requestCounter}` });
        res.end();
        return true;
      }
    }
    sendError(res, 404, "Not Found");
    return true;
  }
  return false;
}

/** Immediate children of a directory path inside a tree (null when absent). */
function listTreeDir(
  objects: ObjectMap,
  treeOid: string,
  dirPath: string,
): { name: string; oid: string; mode: string; type: "file" | "dir" }[] | null {
  let cur = treeOid;
  for (const part of dirPath.split("/").filter((p) => p !== "")) {
    const obj = objects.get(cur);
    if (!obj || obj.type !== "tree") return null;
    const entry = parseTree(obj.data).find((e) => e.name === part && (e.mode === "40000" || e.mode === "040000"));
    if (!entry) return null;
    cur = entry.oid;
  }
  const obj = objects.get(cur);
  if (!obj || obj.type !== "tree") return null;
  return parseTree(obj.data).map((e) => ({
    name: e.name,
    oid: e.oid,
    mode: e.mode,
    type: e.mode === "40000" || e.mode === "040000" ? "dir" as const : "file" as const,
  }));
}

function handleContents(ctx: RestCtx, repo: Repo, filePath: string): boolean {
  const { req, res, body } = ctx;
  const method = req.method ?? "GET";
  const b = (body ?? {}) as Record<string, unknown>;
  // Writes name the branch in the JSON body; reads name it with ?ref=.
  const branch =
    method === "GET"
      ? ctx.q.get("ref") ?? repo.defaultBranch
      : typeof b.branch === "string" && b.branch !== ""
        ? b.branch
        : ctx.q.get("ref") ?? repo.defaultBranch;
  const headOid = repo.refs.get(`refs/heads/${branch}`);
  const commitObj = headOid ? repo.objects.get(headOid) : undefined;
  const treeOid = commitObj && commitObj.type === "commit" ? parseCommit(commitObj.data).tree : "";
  const files = treeOid ? treeToFiles(repo.objects, treeOid) : new Map<string, { oid: string; mode: string }>();

  if (method === "GET") {
    const f = files.get(filePath);
    if (!f) {
      // A directory lists its immediate children.
      const dir = treeOid ? listTreeDir(repo.objects, treeOid, filePath) : null;
      if (!dir) {
        sendError(res, 404, "Not Found");
        return true;
      }
      sendJson(
        res,
        200,
        dir
          .sort((a, c) => (a.name < c.name ? -1 : 1))
          .map((e) => ({
            type: e.type,
            name: e.name,
            path: `${filePath}/${e.name}`,
            sha: e.oid,
            size: e.type === "file" ? (repo.objects.get(e.oid)?.data.length ?? 0) : 0,
            url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${filePath}/${e.name}`,
            html_url: `https://github.com/${repo.owner}/${repo.name}/blob/${branch}/${filePath}/${e.name}`,
            git_url: "",
            download_url: "",
            _links: { self: "", git: "", html: "" },
          })),
      );
      return true;
    }
    const blob = repo.objects.get(f.oid);
    if (!blob) {
      sendError(res, 404, "Not Found");
      return true;
    }
    sendJson(res, 200, {
      type: "file",
      encoding: "base64",
      size: blob.data.length,
      name: filePath.split("/").pop(),
      path: filePath,
      content: blob.data.toString("base64"),
      sha: f.oid,
      url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${filePath}`,
      html_url: `https://github.com/${repo.owner}/${repo.name}/blob/${branch}/${filePath}`,
      git_url: "",
      download_url: "",
      _links: { self: "", git: "", html: "" },
    });
    return true;
  }

  if (method === "PUT") {
    const contentB64 = typeof b.content === "string" ? b.content : "";
    const sha = typeof b.sha === "string" ? b.sha : undefined;
    const message = typeof b.message === "string" ? b.message : "Update file";
    let content: Buffer;
    try {
      content = Buffer.from(contentB64.replace(/\n/g, ""), "base64");
    } catch {
      sendError(res, 422, "content must be base64");
      return true;
    }
    const existing = files.get(filePath);
    if (existing) {
      if (!sha) {
        sendError(res, 422, "sha is required to update a file");
        return true;
      }
      if (sha !== existing.oid) {
        sendError(res, 409, "sha does not match");
        return true;
      }
    } else if (sha) {
      sendError(res, 409, "file does not exist");
      return true;
    }
    const blobOid = hashObject("blob", content);
    repo.objects.set(blobOid, { type: "blob", data: content });
    const newFiles = new Map(files);
    newFiles.set(filePath, { oid: blobOid, mode: "100644" });
    const newTree = buildTreeFromFiles(repo.objects, newFiles);
    const author = gitIdent(LOGIN);
    const commitData = buildCommit(newTree, headOid ? [headOid] : [], author, author, message + "\n");
    const commitOid = hashObject("commit", commitData);
    repo.objects.set(commitOid, { type: "commit", data: commitData });
    repo.refs.set(`refs/heads/${branch}`, commitOid);
    repo.updatedAt = isoNow();
    sendJson(res, existing ? 200 : 201, {
      content: {
        type: "file",
        encoding: "base64",
        size: content.length,
        name: filePath.split("/").pop(),
        path: filePath,
        content: content.toString("base64"),
        sha: blobOid,
      },
      commit: { sha: commitOid, message: message + "\n" },
    });
    return true;
  }

  if (method === "DELETE") {
    const sha = typeof b.sha === "string" ? b.sha : undefined;
    const message = typeof b.message === "string" ? b.message : "Delete file";
    const existing = files.get(filePath);
    if (!existing) {
      sendError(res, 404, "Not Found");
      return true;
    }
    if (!sha || sha !== existing.oid) {
      sendError(res, 409, "sha does not match");
      return true;
    }
    const newFiles = new Map(files);
    newFiles.delete(filePath);
    const newTree = buildTreeFromFiles(repo.objects, newFiles);
    const author = gitIdent(LOGIN);
    const commitData = buildCommit(newTree, headOid ? [headOid] : [], author, author, message + "\n");
    const commitOid = hashObject("commit", commitData);
    repo.objects.set(commitOid, { type: "commit", data: commitData });
    repo.refs.set(`refs/heads/${branch}`, commitOid);
    repo.updatedAt = isoNow();
    sendJson(res, 200, { commit: { sha: commitOid, message: message + "\n" } });
    return true;
  }

  sendError(res, 404, "Not Found");
  return true;
}

/** Squash-merge a pull request (shared by REST PUT /merge and the GraphQL mergePullRequest mutation). */
function doMergePull(repo: Repo, pull: Pull): { status: "ok" | "not-open" | "not-found" | "conflict"; sha: string | null } {
  if (pull.state !== "open") return { status: "not-open", sha: null };
  const headOid = repo.refs.get(`refs/heads/${pull.head}`);
  const baseOid = repo.refs.get(`refs/heads/${pull.base}`);
  if (!headOid || !baseOid || headOid !== pull.headSha) return { status: "not-found", sha: null };
  const { conflict, merged } = tryMergeFiles(repo, baseOid, headOid);
  if (conflict || !merged) return { status: "conflict", sha: null };
  const newTree = buildTreeFromFiles(repo.objects, merged);
  const author = gitIdent(LOGIN);
  const message = `Merge pull request #${pull.number} from ${pull.head}\n\n${pull.title}\n`;
  const commitData = buildCommit(newTree, [baseOid], author, author, message);
  const commitOid = hashObject("commit", commitData);
  repo.objects.set(commitOid, { type: "commit", data: commitData });
  repo.refs.set(`refs/heads/${pull.base}`, commitOid);
  pull.state = "closed";
  pull.merged = true;
  pull.mergeCommitSha = commitOid;
  const now = isoNow();
  pull.mergedAt = now;
  pull.closedAt = now;
  pull.updatedAt = now;
  pull.baseSha = commitOid;
  return { status: "ok", sha: commitOid };
}

/** Squash-merge a pull request; 3-way merge of the file trees. */
function handleMerge(ctx: RestCtx, repo: Repo, pull: Pull): boolean {
  const { res } = ctx;
  const result = doMergePull(repo, pull);
  if (result.status === "not-open") {
    sendError(res, 405, "Pull request is not open");
    return true;
  }
  if (result.status === "not-found") {
    sendError(res, 404, "Head or base not found");
    return true;
  }
  if (result.status === "conflict") {
    sendError(res, 405, "Merge conflict");
    return true;
  }
  sendJson(res, 200, {
    sha: result.sha,
    merged: true,
    message: "Pull Request successfully merged",
  });
  return true;
}

// ===========================================================================
// GraphQL v4
// ===========================================================================
type GqlValue =
  | string
  | number
  | boolean
  | null
  | GqlValue[]
  | { [key: string]: GqlValue };

interface GqlField {
  name: string;
  alias: string | null;
  args: Record<string, GqlValue>;
  selection: GqlField[];
  fragmentSpreads: string[];
  inlineFragments: { typeCondition: string | null; selection: GqlField[] }[];
}

interface GqlOp {
  operation: "query" | "mutation";
  fields: GqlField[];
  fragments: Record<string, { typeCondition: string | null; selection: GqlField[] }>;
  variables: Record<string, { type: string; defaultValue?: GqlValue }>;
}

function gqlTokenize(src: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s|,/.test(c)) {
      i++;
      continue;
    }
    if (c === "#") {
      while (i < src.length && src[i] !== "\n") i++;
      continue;
    }
    if ("{}()[]:!$=@".includes(c) || c === ".") {
      if (c === "." && src.slice(i, i + 3) === "...") {
        tokens.push("...");
        i += 3;
        continue;
      }
      tokens.push(c);
      i++;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let out = "";
      while (j < src.length && src[j] !== '"') {
        if (src[j] === "\\" && j + 1 < src.length) {
          const e = src[j + 1];
          if (e === "n") out += "\n";
          else if (e === "t") out += "\t";
          else if (e === "r") out += "\r";
          else out += e;
          j += 2;
        } else {
          out += src[j];
          j++;
        }
      }
      tokens.push(JSON.stringify(out));
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i;
      while (j < src.length && /[0-9.eE+-]/.test(src[j])) j++;
      tokens.push(src.slice(i, j));
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++;
      tokens.push(src.slice(i, j));
      i = j;
      continue;
    }
    i++;
  }
  return tokens;
}

class GqlParser {
  private pos = 0;
  private tokens: string[];
  private variables: Record<string, GqlValue>;
  constructor(tokens: string[], variables: Record<string, GqlValue>) {
    this.tokens = tokens;
    this.variables = variables;
  }

  private peek(): string | undefined {
    return this.tokens[this.pos];
  }
  private next(): string {
    return this.tokens[this.pos++]!;
  }
  private expect(t: string): void {
    if (this.peek() !== t) throw new Error(`expected ${t}, got ${this.peek()}`);
    this.pos++;
  }

  parseDocument(): GqlOp[] {
    const ops: GqlOp[] = [];
    const fragments: Record<string, { typeCondition: string | null; selection: GqlField[] }> = {};
    while (this.pos < this.tokens.length) {
      const tok = this.peek();
      if (tok === "fragment") {
        this.next();
        const name = this.next();
        this.expect("on");
        const typeCond = this.next();
        const sel = this.parseSelectionSet();
        fragments[name] = { typeCondition: typeCond, selection: sel };
        continue;
      }
      let operation: "query" | "mutation" = "query";
      if (tok === "query" || tok === "mutation") {
        operation = tok;
        this.next();
        // optional operation name
        if (this.peek() && !["(", "{"].includes(this.peek()!)) this.next();
        if (this.peek() === "(") this.parseVariableDefinitions();
      }
      const fields = this.parseSelectionSet();
      ops.push({ operation, fields, fragments, variables: {} });
    }
    return ops;
  }

  private parseVariableDefinitions(): void {
    this.expect("(");
    while (this.peek() !== ")") {
      const t = this.next();
      if (t === "$") {
        const name = this.next();
        this.expect(":");
        let type = this.next();
        if (this.peek() === "!") {
          this.next();
          type += "!";
        }
        if (this.peek() === "=") {
          this.next();
          this.parseValue();
        }
        void name;
      } else {
        // skip type token sequences we don't model
        continue;
      }
    }
    this.expect(")");
  }

  private parseSelectionSet(): GqlField[] {
    this.expect("{");
    const fields: GqlField[] = [];
    while (this.peek() !== "}") {
      if (this.pos >= this.tokens.length) throw new Error("unterminated selection set");
      fields.push(this.parseField());
    }
    this.expect("}");
    return fields;
  }

  private parseField(): GqlField {
    const tok = this.peek();
    if (tok === "...") {
      this.next();
      const nextTok = this.peek();
      if (nextTok === "on") {
        this.next();
        const typeCond = this.next();
        const sel = this.parseSelectionSet();
        return {
          name: "__inline",
          alias: null,
          args: {},
          selection: [],
          fragmentSpreads: [],
          inlineFragments: [{ typeCondition: typeCond, selection: sel }],
        };
      }
      const fragName = this.next();
      return {
        name: "__spread",
        alias: null,
        args: {},
        selection: [],
        fragmentSpreads: [fragName],
        inlineFragments: [],
      };
    }
    let name = this.next();
    let alias: string | null = null;
    if (this.peek() === ":") {
      this.next();
      alias = name;
      name = this.next();
    }
    const args: Record<string, GqlValue> = {};
    if (this.peek() === "(") {
      this.next();
      while (this.peek() !== ")") {
        const argName = this.next();
        this.expect(":");
        args[argName] = this.parseValue();
      }
      this.expect(")");
    }
    let selection: GqlField[] = [];
    if (this.peek() === "{") {
      selection = this.parseSelectionSet();
    }
    return { name, alias, args, selection, fragmentSpreads: [], inlineFragments: [] };
  }

  private parseValue(): GqlValue {
    const t = this.next();
    if (t === "$") {
      const name = this.next();
      return this.variables[name] ?? null;
    }
    if (t === "[") {
      const arr: GqlValue[] = [];
      while (this.peek() !== "]") arr.push(this.parseValue());
      this.expect("]");
      return arr;
    }
    if (t === "{") {
      const obj: { [key: string]: GqlValue } = {};
      while (this.peek() !== "}") {
        const key = this.next();
        this.expect(":");
        obj[key] = this.parseValue();
      }
      this.expect("}");
      return obj;
    }
    if (t.startsWith('"')) return JSON.parse(t) as string;
    if (t === "true") return true;
    if (t === "false") return false;
    if (t === "null") return null;
    const num = Number(t);
    if (Number.isFinite(num) && /^[0-9-]+$/.test(t)) return num;
    if (Number.isFinite(num)) return num;
    return t; // enum value
  }
}

function gqlString(v: GqlValue): string {
  return typeof v === "string" ? v : v === null ? "" : String(v);
}

function gqlInt(v: GqlValue): number {
  const n = typeof v === "number" ? v : parseInt(String(v), 10);
  return Number.isFinite(n) ? n : 0;
}

/** Decode a Relay global id back to its object: R_<repoId>, I_<repoId>_<number>, PR_<repoId>_<number>. */
function decodeGlobalId(id: string): { repo: Repo; issue?: Issue; pull?: Pull } | null {
  let m = id.match(/^R_(\d+)$/);
  if (m) {
    const repo = [...repos.values()].find((r) => r.id === parseInt(m[1], 10));
    return repo ? { repo } : null;
  }
  m = id.match(/^I_(\d+)_(\d+)$/);
  if (m) {
    const repo = [...repos.values()].find((r) => r.id === parseInt(m[1], 10));
    const issue = repo?.issues.get(parseInt(m[2], 10));
    return repo && issue ? { repo, issue } : null;
  }
  m = id.match(/^PR_(\d+)_(\d+)$/);
  if (m) {
    const repo = [...repos.values()].find((r) => r.id === parseInt(m[1], 10));
    const pull = repo?.pulls.get(parseInt(m[2], 10));
    return repo && pull ? { repo, pull } : null;
  }
  return null;
}

function gqlRepoNode(r: Repo): { [key: string]: GqlValue } {
  return {
    id: `R_${r.id}`,
    databaseId: r.id,
    name: r.name,
    nameWithOwner: `${r.owner}/${r.name}`,
    owner: { login: r.owner },
    defaultBranchRef: { name: r.defaultBranch },
    viewerPermission: "ADMIN",
    hasIssuesEnabled: true,
  };
}

function gqlIssueNode(r: Repo, i: Issue): { [key: string]: GqlValue } {
  return {
    id: `I_${r.id}_${i.number}`,
    number: i.number,
    title: i.title,
    state: i.state.toUpperCase(),
    body: i.body,
  };
}

function gqlPullNode(r: Repo, p: Pull): { [key: string]: GqlValue } {
  let mergeable = "UNKNOWN";
  if (p.state === "open") {
    const headOid = r.refs.get(`refs/heads/${p.head}`) ?? p.headSha;
    const baseOid = r.refs.get(`refs/heads/${p.base}`) ?? p.baseSha;
    mergeable = tryMergeFiles(r, baseOid, headOid).conflict ? "CONFLICTING" : "MERGEABLE";
  }
  return {
    id: `PR_${r.id}_${p.number}`,
    number: p.number,
    headRefName: p.head,
    baseRefName: p.base,
    mergeable,
    state: p.state.toUpperCase(),
    merged: p.merged,
  };
}

const GQL_TYPE_FIELDS: Record<string, Record<string, string>> = {
  Issue: {
    id: "ID",
    number: "Int",
    title: "String",
    state: "IssueState",
    body: "String",
  },
  PullRequest: {
    id: "ID",
    number: "Int",
    headRefName: "String",
    baseRefName: "String",
    mergeable: "Boolean",
    state: "PullRequestState",
    merged: "Boolean",
    files: "PullRequestChangedFileConnection",
  },
  Repository: {
    id: "ID",
    databaseId: "Int",
    name: "String",
    nameWithOwner: "String",
    owner: "RepositoryOwner",
    defaultBranchRef: "Ref",
    viewerPermission: "RepositoryPermission",
    hasIssuesEnabled: "Boolean",
    issue: "Issue",
    issues: "IssueConnection",
    pullRequests: "PullRequestConnection",
    pullRequest: "PullRequest",
  },
};

function expandSelection(
  fields: GqlField[],
  fragments: Record<string, { typeCondition: string | null; selection: GqlField[] }>,
): GqlField[] {
  const out: GqlField[] = [];
  for (const f of fields) {
    if (f.name === "__spread") {
      for (const name of f.fragmentSpreads) {
        const frag = fragments[name];
        if (frag) out.push(...expandSelection(frag.selection, fragments));
      }
      continue;
    }
    if (f.name === "__inline") {
      for (const frag of f.inlineFragments) {
        out.push(...expandSelection(frag.selection, fragments));
      }
      continue;
    }
    out.push({
      ...f,
      selection: expandSelection(f.selection, fragments),
    });
  }
  return out;
}

function execFields(
  node: { [key: string]: GqlValue } | null,
  fields: GqlField[],
  fragments: Record<string, { typeCondition: string | null; selection: GqlField[] }>,
  repo: Repo | null,
  errors: { message: string }[],
): { [key: string]: GqlValue } {
  const out: { [key: string]: GqlValue } = {};
  if (!node) return out;
  for (const f of expandSelection(fields, fragments)) {
    const key = f.alias ?? f.name;
    out[key] = execField(node, f, fragments, repo, errors);
  }
  return out;
}

function execField(
  node: { [key: string]: GqlValue },
  f: GqlField,
  fragments: Record<string, { typeCondition: string | null; selection: GqlField[] }>,
  repo: Repo | null,
  errors: { message: string }[],
): GqlValue {
  const name = f.name;
  if (name === "__typename") return (node.__typename as string) ?? "Repository";
  // connection fields
  if (name === "issues" && repo) {
    const issues = [...repo.issues.values()].sort((a, b) => a.number - b.number);
    const filtered = filterIssuesForGql(issues, f.args);
    return execIssueConnection(repo, filtered, f, fragments, errors);
  }
  if (name === "pullRequests" && repo) {
    const pulls = [...repo.pulls.values()].sort((a, b) => a.number - b.number);
    return execPullConnection(repo, pulls, f, fragments, errors);
  }
  if (name === "issue" && repo) {
    const number = gqlInt(f.args.number);
    const issue = repo.issues.get(number);
    if (!issue) return null;
    return execFields(gqlIssueNode(repo, issue), f.selection, fragments, repo, errors);
  }
  if (name === "pullRequest" && repo) {
    const number = gqlInt(f.args.number);
    const pull = repo.pulls.get(number);
    if (!pull) return null;
    return execFields(gqlPullNode(repo, pull), f.selection, fragments, repo, errors);
  }
  if (name === "owner" && node.owner && typeof node.owner === "object") {
    const ownerNode = node.owner as { [key: string]: GqlValue };
    return execFields(ownerNode, f.selection, fragments, repo, errors);
  }
  if (name === "defaultBranchRef" && node.defaultBranchRef && typeof node.defaultBranchRef === "object") {
    const refNode = node.defaultBranchRef as { [key: string]: GqlValue };
    return execFields(refNode, f.selection, fragments, repo, errors);
  }
  if (name === "files" && repo) {
    const pull = repo.pulls.get(gqlInt(node.number));
    if (!pull) return { nodes: [], totalCount: 0 };
    const files = pullFiles(repo, pull).map((f) => ({ path: f.filename, status: f.status, additions: f.additions, deletions: f.deletions, changes: f.changes }));
    return execConnectionNodes(files, (f) => f as unknown as { [key: string]: GqlValue }, f, fragments, repo, errors);
  }
  const v = node[name];
  if (v === undefined) {
    errors.push({ message: `Field '${name}' doesn't exist on type` });
    return null;
  }
  if (v !== null && typeof v === "object" && !Array.isArray(v) && f.selection.length > 0) {
    return execFields(v as { [key: string]: GqlValue }, f.selection, fragments, repo, errors);
  }
  return v;
}

function execConnectionNodes<T>(
  items: T[],
  nodeOf: (item: T) => { [key: string]: GqlValue },
  f: GqlField,
  fragments: Record<string, { typeCondition: string | null; selection: GqlField[] }>,
  repo: Repo | null,
  errors: { message: string }[],
): { [key: string]: GqlValue } {
  // Cursor pagination: `first` caps the window, `after` resumes past the
  // cursor (the item's number) of the previous page. totalCount is the
  // full filtered size, not the window size.
  const totalCount = items.length;
  const firstArg = f.args.first;
  const first = firstArg === undefined || firstArg === null ? 0 : Math.max(0, gqlInt(firstArg));
  const after = gqlString(f.args.after ?? "");
  let start = 0;
  if (after !== "") {
    const idx = items.findIndex((it) => String((nodeOf(it).number as number) ?? 0) === after);
    start = idx >= 0 ? idx + 1 : items.length;
  }
  const window = first > 0 ? items.slice(start, start + first) : items.slice(start);
  const hasNextPage = start + window.length < totalCount;
  const hasPreviousPage = start > 0;
  const out: { [key: string]: GqlValue } = {};
  for (const sub of expandSelection(f.selection, fragments)) {
    if (sub.name === "totalCount") {
      out.totalCount = totalCount;
    } else if (sub.name === "nodes") {
      out.nodes = window.map((it) => execFields(nodeOf(it), sub.selection, fragments, repo, errors));
    } else if (sub.name === "edges") {
      out.edges = window.map((it) => {
        const edgeOut: { [key: string]: GqlValue } = {};
        for (const eSub of expandSelection(sub.selection, fragments)) {
          if (eSub.name === "node") {
            edgeOut.node = execFields(nodeOf(it), eSub.selection, fragments, repo, errors);
          } else if (eSub.name === "cursor") {
            edgeOut.cursor = String((nodeOf(it).number as number) ?? 0);
          } else {
            edgeOut[eSub.alias ?? eSub.name] = null;
          }
        }
        return edgeOut;
      });
    } else if (sub.name === "pageInfo") {
      const pageOut: { [key: string]: GqlValue } = {};
      for (const pSub of expandSelection(sub.selection, fragments)) {
        if (pSub.name === "hasNextPage") pageOut.hasNextPage = hasNextPage;
        else if (pSub.name === "hasPreviousPage") pageOut.hasPreviousPage = hasPreviousPage;
        else if (pSub.name === "startCursor") {
          pageOut.startCursor = window.length > 0 ? String((nodeOf(window[0]!).number as number) ?? 0) : null;
        } else if (pSub.name === "endCursor") {
          pageOut.endCursor = window.length > 0 ? String((nodeOf(window[window.length - 1]!).number as number) ?? 0) : null;
        } else pageOut[pSub.alias ?? pSub.name] = null;
      }
      out.pageInfo = pageOut;
    } else {
      out[sub.alias ?? sub.name] = null;
    }
  }
  return out;
}

function execIssueConnection(
  repo: Repo,
  issues: Issue[],
  f: GqlField,
  fragments: Record<string, { typeCondition: string | null; selection: GqlField[] }>,
  errors: { message: string }[],
): { [key: string]: GqlValue } {
  return execConnectionNodes(issues, (i) => gqlIssueNode(repo, i), f, fragments, repo, errors);
}

function execPullConnection(
  repo: Repo,
  pulls: Pull[],
  f: GqlField,
  fragments: Record<string, { typeCondition: string | null; selection: GqlField[] }>,
  errors: { message: string }[],
): { [key: string]: GqlValue } {
  return execConnectionNodes(pulls, (p) => gqlPullNode(repo, p), f, fragments, repo, errors);
}

function filterIssuesForGql(issues: Issue[], args: Record<string, GqlValue>): Issue[] {
  let list = [...issues].sort((a, b) => {
    const ta = Date.parse(a.createdAt);
    const tb = Date.parse(b.createdAt);
    if (tb !== ta) return tb - ta;
    return b.number - a.number;
  });
  // Default ordering: CREATED_AT DESC, ties by number DESC.
  const orderBy = args.orderBy as { direction?: string; field?: string } | undefined;
  if (orderBy) {
    const dir = (orderBy.direction ?? "DESC").toString().toUpperCase();
    const field = (orderBy.field ?? "CREATED_AT").toString().toUpperCase();
    list.sort((a, b) => {
      let cmp = 0;
      if (field === "CREATED_AT") cmp = Date.parse(a.createdAt) - Date.parse(b.createdAt);
      else cmp = a.number - b.number;
      if (cmp === 0) cmp = a.number - b.number;
      return dir === "DESC" ? -cmp : cmp;
    });
  }
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const wanted = new Set(states.map((s) => gqlString(s).toUpperCase()));
    list = list.filter((i) => wanted.has(i.state.toUpperCase()));
  }
  return list;
}

function gqlIntrospectionField(
  f: GqlField,
  fragments: Record<string, { typeCondition: string | null; selection: GqlField[] }>,
  errors: { message: string }[],
): GqlValue {
  if (f.name === "__type") {
    const typeName = gqlString(f.args.name);
    const fields = GQL_TYPE_FIELDS[typeName];
    // SearchType is an enum: gh's SearchFeatures probe reads its values.
    const enumValues =
      typeName === "SearchType"
        ? ["ISSUE", "PULL_REQUEST", "REPOSITORY", "USER", "DISCUSSION", "CODE", "COMMIT"]
        : null;
    if (!fields && !enumValues) return null;
    const typeNode: { [key: string]: GqlValue } = {
      name: typeName,
      kind: enumValues ? "ENUM" : "OBJECT",
      fields: fields
        ? Object.entries(fields).map(([n, t]) => ({
            name: n,
            type: { name: t, kind: t === "Int" || t === "String" || t === "Boolean" || t === "ID" ? "SCALAR" : "OBJECT" },
          }))
        : [],
      enumValues: (enumValues ?? []).map((n) => ({ name: n })),
    };
    const out: { [key: string]: GqlValue } = {};
    for (const sub of expandSelection(f.selection, fragments)) {
      if (sub.name === "name") out.name = typeName;
      else if (sub.name === "kind") out.kind = typeNode.kind;
      else if (sub.name === "enumValues") {
        out.enumValues = (typeNode.enumValues as { [key: string]: GqlValue }[]).map((ev) => {
          const evo: { [key: string]: GqlValue } = {};
          for (const s2 of expandSelection(sub.selection, fragments)) {
            if (s2.name === "name") evo.name = ev.name;
            else evo[s2.alias ?? s2.name] = null;
          }
          return evo;
        });
      } else if (sub.name === "fields") {
        const fieldNodes = typeNode.fields as { [key: string]: GqlValue }[];
        out.fields = fieldNodes.map((fn) => {
          const fo: { [key: string]: GqlValue } = {};
          for (const s2 of expandSelection(sub.selection, fragments)) {
            if (s2.name === "name") fo.name = fn.name;
            else if (s2.name === "type") {
              const tNode = fn.type as { [key: string]: GqlValue };
              const to: { [key: string]: GqlValue } = {};
              for (const s3 of expandSelection(s2.selection, fragments)) {
                if (s3.name === "name") to.name = tNode.name;
                else if (s3.name === "kind") to.kind = tNode.kind;
                else to[s3.alias ?? s3.name] = null;
              }
              fo.type = to;
            } else fo[s2.alias ?? s2.name] = null;
          }
          return fo;
        });
      } else out[sub.alias ?? sub.name] = null;
    }
    return out;
  }
  if (f.name === "__schema") {
    const out: { [key: string]: GqlValue } = {};
    for (const sub of expandSelection(f.selection, fragments)) {
      if (sub.name === "queryType") out.queryType = { name: "Query" };
      else if (sub.name === "mutationType") out.mutationType = { name: "Mutation" };
      else out[sub.alias ?? sub.name] = null;
    }
    return out;
  }
  if (f.name === "__typename") return "Query";
  errors.push({ message: `Field '${f.name}' doesn't exist on type 'Query'` });
  return null;
}

/** Execute one GraphQL document ({query, variables}) and answer its result. */
function runGraphQLDoc(query: string, variables: Record<string, GqlValue>): { data: { [key: string]: GqlValue } | null; errors?: { message: string }[] } | { data: { [key: string]: GqlValue } | null; errors?: { message: string }[] }[] {
  let ops: GqlOp[];
  try {
    const parser = new GqlParser(gqlTokenize(query), variables);
    ops = parser.parseDocument();
  } catch (e) {
    return { data: null, errors: [{ message: (e as Error).message }] };
  }
  const results: { data: { [key: string]: GqlValue } | null; errors?: { message: string }[] }[] = [];
  for (const op of ops) {
    const opErrors: { message: string }[] = [];
    const data: { [key: string]: GqlValue } = {};
    for (const f of op.fields) {
      const key = f.alias ?? f.name;
      if (op.operation === "mutation") {
        data[key] = execMutation(f, op.fragments, opErrors);
      } else {
        data[key] = execRootQuery(f, op.fragments, opErrors);
      }
    }
    const result: { data: { [key: string]: GqlValue } | null; errors?: { message: string }[] } = { data };
    if (opErrors.length > 0) result.errors = opErrors;
    results.push(result);
  }
  return results.length === 1 ? results[0]! : results;
}

function handleGraphQL(ctx: RestCtx): boolean {
  const { req, res, body } = ctx;
  // A batched body is an array of {query, variables} documents; answer an
  // array of results in order. A single document answers one result.
  const docs = Array.isArray(body)
    ? (body as unknown[])
    : [body];
  const results = docs.map((doc) => {
    const b = (doc ?? {}) as Record<string, unknown>;
    const query = typeof b.query === "string" ? b.query : "";
    const variables = (b.variables ?? {}) as Record<string, GqlValue>;
    return runGraphQLDoc(query, variables);
  });
  sendJson(res, 200, Array.isArray(body) ? results : results[0]);
  return true;
}

function execRootQuery(
  f: GqlField,
  fragments: Record<string, { typeCondition: string | null; selection: GqlField[] }>,
  errors: { message: string }[],
): GqlValue {
  if (f.name === "__type" || f.name === "__schema" || f.name === "__typename") {
    return gqlIntrospectionField(f, fragments, errors);
  }
  if (f.name === "repository") {
    const owner = gqlString(f.args.owner);
    const name = gqlString(f.args.name);
    const repo = getRepo(owner, name);
    if (!repo) return null;
    const node = gqlRepoNode(repo);
    node.__typename = "Repository";
    return execFields(node, f.selection, fragments, repo, errors);
  }
  if (f.name === "viewer") {
    const node: { [key: string]: GqlValue } = {
      login: LOGIN,
      id: "U_1",
      viewerPermission: "ADMIN",
      hasIssuesEnabled: true,
      __typename: "User",
    };
    return execFields(node, f.selection, fragments, null, errors);
  }
  if (f.name === "node") {
    const decoded = decodeGlobalId(gqlString(f.args.id));
    if (!decoded) return null;
    if (decoded.issue) {
      const node = gqlIssueNode(decoded.repo, decoded.issue);
      node.__typename = "Issue";
      return execFields(node, f.selection, fragments, decoded.repo, errors);
    }
    if (decoded.pull) {
      const node = gqlPullNode(decoded.repo, decoded.pull);
      node.__typename = "PullRequest";
      return execFields(node, f.selection, fragments, decoded.repo, errors);
    }
    const node = gqlRepoNode(decoded.repo);
    node.__typename = "Repository";
    return execFields(node, f.selection, fragments, decoded.repo, errors);
  }
  if (f.name === "search") {
    errors.push({ message: "Field 'search' doesn't exist on type 'Query'" });
    return null;
  }
  errors.push({ message: `Field '${f.name}' doesn't exist on type 'Query'` });
  return null;
}

function execMutation(
  f: GqlField,
  fragments: Record<string, { typeCondition: string | null; selection: GqlField[] }>,
  errors: { message: string }[],
): GqlValue {
  if (f.name === "createIssue") {
    const input = (f.args.input ?? {}) as Record<string, GqlValue>;
    const repoId = gqlString(input.repositoryId);
    const repo = [...repos.values()].find((r) => `R_${r.id}` === repoId);
    if (!repo) return null;
    const title = gqlString(input.title);
    if (!title) {
      errors.push({ message: "createIssue requires a title" });
      return null;
    }
    const now = isoNow();
    const number = repo.nextNumber++;
    const issue: Issue = {
      id: number,
      number,
      title,
      body: input.body === undefined ? null : gqlString(input.body),
      state: "open",
      labels: [],
      user: LOGIN,
      createdAt: now,
      updatedAt: now,
      closedAt: null,
      comments: [],
    };
    repo.issues.set(number, issue);
    const out: { [key: string]: GqlValue } = {};
    for (const sub of expandSelection(f.selection, fragments)) {
      if (sub.name === "issue") {
        out.issue = execFields(gqlIssueNode(repo, issue), sub.selection, fragments, repo, errors);
      } else out[sub.alias ?? sub.name] = null;
    }
    return out;
  }
  if (f.name === "closeIssue") {
    const input = (f.args.input ?? {}) as Record<string, GqlValue>;
    const decoded = decodeGlobalId(gqlString(input.issueId));
    if (!decoded?.issue) return null;
    const { repo, issue } = decoded;
    issue.state = "closed";
    issue.closedAt = isoNow();
    issue.updatedAt = isoNow();
    invalidateIssueJson(issue);
    const out: { [key: string]: GqlValue } = {};
    for (const sub of expandSelection(f.selection, fragments)) {
      if (sub.name === "issue") {
        out.issue = execFields(gqlIssueNode(repo, issue), sub.selection, fragments, repo, errors);
      } else out[sub.alias ?? sub.name] = null;
    }
    return out;
  }
  if (f.name === "addComment") {
    const input = (f.args.input ?? {}) as Record<string, GqlValue>;
    const decoded = decodeGlobalId(gqlString(input.subjectId));
    if (!decoded?.issue) return null;
    const { repo, issue } = decoded;
    const comment = {
      id: issue.comments.length + 1,
      body: gqlString(input.body),
      user: LOGIN,
      createdAt: isoNow(),
    };
    issue.comments.push(comment);
    issue.updatedAt = isoNow();
    invalidateIssueJson(issue);
    const out: { [key: string]: GqlValue } = {};
    for (const sub of expandSelection(f.selection, fragments)) {
      if (sub.name === "commentEdge") {
        const edgeOut: { [key: string]: GqlValue } = {};
        for (const eSub of expandSelection(sub.selection, fragments)) {
          if (eSub.name === "node") {
            edgeOut.node = execFields(
              { id: `C_${repo.id}_${issue.number}_${comment.id}`, body: comment.body },
              eSub.selection,
              fragments,
              repo,
              errors,
            );
          } else edgeOut[eSub.alias ?? eSub.name] = null;
        }
        out.commentEdge = edgeOut;
      } else out[sub.alias ?? sub.name] = null;
    }
    return out;
  }
  if (f.name === "mergePullRequest") {
    const input = (f.args.input ?? {}) as Record<string, GqlValue>;
    const decoded = decodeGlobalId(gqlString(input.pullRequestId));
    if (!decoded?.pull) return null;
    const { repo, pull } = decoded;
    const result = doMergePull(repo, pull);
    if (result.status !== "ok") {
      errors.push({ message: `mergePullRequest failed: ${result.status}` });
      return null;
    }
    const out: { [key: string]: GqlValue } = {};
    for (const sub of expandSelection(f.selection, fragments)) {
      if (sub.name === "pullRequest") {
        out.pullRequest = execFields(gqlPullNode(repo, pull), sub.selection, fragments, repo, errors);
      } else out[sub.alias ?? sub.name] = null;
    }
    return out;
  }
  if (f.name === "createPullRequest") {
    const input = (f.args.input ?? {}) as Record<string, GqlValue>;
    const repoId = gqlString(input.repositoryId);
    const repo = [...repos.values()].find((r) => `R_${r.id}` === repoId);
    if (!repo) return null;
    const head = gqlString(input.headRefName);
    const base = gqlString(input.baseRefName);
    const headSha = repo.refs.get(`refs/heads/${head}`);
    const baseSha = repo.refs.get(`refs/heads/${base}`);
    if (!headSha || !baseSha) return null;
    const now = isoNow();
    const number = repo.nextNumber++;
    const pull: Pull = {
      id: number,
      number,
      title: gqlString(input.title),
      body: input.body === undefined ? null : gqlString(input.body),
      state: "open",
      head,
      base,
      headSha,
      baseSha,
      merged: false,
      mergeCommitSha: null,
      user: LOGIN,
      createdAt: now,
      updatedAt: now,
      closedAt: null,
      mergedAt: null,
    };
    repo.pulls.set(number, pull);
    const out: { [key: string]: GqlValue } = {};
    for (const sub of expandSelection(f.selection, fragments)) {
      if (sub.name === "pullRequest") {
        out.pullRequest = execFields(gqlPullNode(repo, pull), sub.selection, fragments, repo, errors);
      } else out[sub.alias ?? sub.name] = null;
    }
    return out;
  }
  errors.push({ message: `Field '${f.name}' doesn't exist on type 'Mutation'` });
  return null;
}

// ===========================================================================
// MCP
// ===========================================================================
const MCP_TOOLS: {
  name: string;
  description: string;
  inputSchema: { type: "object"; properties: Record<string, { type: string; description: string }>; required: string[] };
}[] = [
  {
    name: "create_repo",
    description: "Create a new repository.",
    inputSchema: {
      type: "object",
      properties: { name: { type: "string", description: "Repository name" } },
      required: ["name"],
    },
  },
  {
    name: "get_repo",
    description: "Get a repository by owner and name.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "create_issue",
    description: "Create an issue in a repository.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        title: { type: "string", description: "Issue title" },
        body: { type: "string", description: "Issue body" },
      },
      required: ["owner", "repo", "title"],
    },
  },
  {
    name: "list_issues",
    description: "List issues in a repository.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        state: { type: "string", description: "Issue state filter" },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "create_pull_request",
    description: "Create a pull request in a repository.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        title: { type: "string", description: "Pull request title" },
        head: { type: "string", description: "Head branch" },
        base: { type: "string", description: "Base branch" },
      },
      required: ["owner", "repo", "title", "head", "base"],
    },
  },
  {
    name: "merge_pull_request",
    description: "Merge a pull request.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        pull_number: { type: "number", description: "Pull request number" },
      },
      required: ["owner", "repo", "pull_number"],
    },
  },
];

function mcpToolNameMatch(toolName: string): string | null {
  const suffix = toolName.split("__").pop()!.toLowerCase();
  for (const t of MCP_TOOLS) {
    if (t.name.toLowerCase() === suffix) return t.name;
  }
  return null;
}

function mcpCallTool(
  name: string,
  args: Record<string, unknown>,
): { content: { type: "text"; text: string }[]; isError?: boolean } {
  const tool = mcpToolNameMatch(name);
  if (!tool) {
    return {
      content: [{ type: "text", text: `unknown tool: ${name}` }],
      isError: true,
    };
  }
  const def = MCP_TOOLS.find((t) => t.name === tool)!;
  const norm: Record<string, unknown> = {};
  for (const key of Object.keys(args)) {
    const lower = key.toLowerCase();
    const match = Object.keys(def.inputSchema.properties).find((p) => p.toLowerCase() === lower)
      ?? (lower === "repository" ? "repo" : lower === "number" ? "pull_number" : null);
    if (match) norm[match] = args[key];
    else norm[key] = args[key];
  }
  for (const reqField of def.inputSchema.required) {
    if (norm[reqField] === undefined || norm[reqField] === null) {
      return {
        content: [{ type: "text", text: `missing required argument: ${reqField}` }],
        isError: true,
      };
    }
  }
  const owner = String(norm.owner ?? LOGIN);
  const repoName = String(norm.repo ?? "");
  if (tool === "create_repo") {
    const rName = String(norm.name ?? "");
    if (!rName) return { content: [{ type: "text", text: "name is required" }], isError: true };
    if (norm.owner !== undefined && norm.owner !== null && !isViewer(owner)) {
      return { content: [{ type: "text", text: "Not Found" }], isError: true };
    }
    if (repos.has(repoKey(LOGIN, rName))) {
      return { content: [{ type: "text", text: "Repository creation failed: name already exists." }], isError: true };
    }
    const now = isoNow();
    const repo: Repo = {
      id: nextRepoId++,
      name: rName,
      owner,
      description: "",
      isPrivate: false,
      defaultBranch: "main",
      refs: new Map(),
      objects: new Map(),
      issues: new Map(),
      labels: new Map(),
      pulls: new Map(),
      nextNumber: 1,
      createdAt: now,
      updatedAt: now,
    };
    repos.set(repoKey(LOGIN, rName), repo);
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ id: repo.id, name: repo.name, full_name: `${repo.owner}/${repo.name}`, owner: repo.owner, description: "", default_branch: "main" }),
      }],
    };
  }
  const repo = getRepo(owner, repoName);
  if (!repo) {
    return { content: [{ type: "text", text: "Not Found" }], isError: true };
  }
  if (tool === "get_repo") {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ id: repo.id, name: repo.name, full_name: `${repo.owner}/${repo.name}`, owner: repo.owner, description: repo.description, default_branch: repo.defaultBranch, created_at: repo.createdAt, updated_at: repo.updatedAt }),
      }],
    };
  }
  if (tool === "create_issue") {
    const title = String(norm.title ?? "");
    const number = repo.nextNumber++;
    const now = isoNow();
    const issue: Issue = {
      id: number,
      number,
      title,
      body: norm.body === undefined ? null : String(norm.body),
      state: "open",
      labels: [],
      user: LOGIN,
      createdAt: now,
      updatedAt: now,
      closedAt: null,
      comments: [],
    };
    repo.issues.set(number, issue);
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ id: issue.id, number, title, body: issue.body, state: "open", user: LOGIN, created_at: now, updated_at: now }),
      }],
    };
  }
  if (tool === "list_issues") {
    const state = norm.state ? String(norm.state) : "open";
    let list = [...repo.issues.values()].sort((a, b) => a.number - b.number);
    if (state !== "all") list = list.filter((i) => i.state === state);
    return {
      content: [{
        type: "text",
        text: JSON.stringify(list.map((i) => ({ id: i.id, number: i.number, title: i.title, body: i.body, state: i.state, user: i.user, created_at: i.createdAt, updated_at: i.updatedAt }))),
      }],
    };
  }
  if (tool === "create_pull_request") {
    const head = String(norm.head ?? "");
    const base = String(norm.base ?? repo.defaultBranch);
    const headSha = repo.refs.get(`refs/heads/${head}`);
    const baseSha = repo.refs.get(`refs/heads/${base}`);
    if (!headSha || !baseSha) {
      return { content: [{ type: "text", text: "head or base branch not found" }], isError: true };
    }
    const number = repo.nextNumber++;
    const now = isoNow();
    const pull: Pull = {
      id: number,
      number,
      title: String(norm.title ?? ""),
      body: norm.body === undefined ? null : String(norm.body),
      state: "open",
      head,
      base,
      headSha,
      baseSha,
      merged: false,
      mergeCommitSha: null,
      user: LOGIN,
      createdAt: now,
      updatedAt: now,
      closedAt: null,
      mergedAt: null,
    };
    repo.pulls.set(number, pull);
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ id: pull.id, number, title: pull.title, body: pull.body, state: "open", head, base, head_sha: headSha, base_sha: baseSha }),
      }],
    };
  }
  if (tool === "merge_pull_request") {
    const pullNumber = typeof norm.pull_number === "number" ? norm.pull_number : parseInt(String(norm.pull_number), 10);
    const pull = repo.pulls.get(pullNumber);
    if (!pull) {
      return { content: [{ type: "text", text: "Not Found" }], isError: true };
    }
    const result = doMergePull(repo, pull);
    if (result.status === "not-open") {
      return { content: [{ type: "text", text: "Pull request is not open" }], isError: true };
    }
    if (result.status === "not-found") {
      return { content: [{ type: "text", text: "Head or base not found" }], isError: true };
    }
    if (result.status === "conflict") {
      return { content: [{ type: "text", text: "Merge conflict" }], isError: true };
    }
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ sha: result.sha, merged: true, message: "Pull Request successfully merged" }),
      }],
    };
  }
  return { content: [{ type: "text", text: "unhandled tool" }], isError: true };
}

function handleMcp(ctx: RestCtx): boolean {
  const { req, res, body } = ctx;
  const parsed = parseJsonBody(Buffer.from(JSON.stringify(body ?? {})));
  void parsed;
  const b = (body ?? {}) as Record<string, unknown>;
  const id = b.id ?? null;
  const method = typeof b.method === "string" ? b.method : "";
  const params = (b.params ?? {}) as Record<string, unknown>;
  const respond = (result: unknown): void => {
    sendJson(res, 200, { jsonrpc: "2.0", id, result });
  };
  const respondError = (code: number, message: string): void => {
    sendJson(res, 200, { jsonrpc: "2.0", id, error: { code, message } });
  };
  if (method === "initialize") {
    const proto = (params.protocolVersion as string) ?? "";
    const supported = ["2026-07-28", "2025-11-25"];
    const version = supported.includes(proto) ? proto : "2026-07-28";
    respond({
      protocolVersion: version,
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: "forge", version: "1.0.0" },
      supportedVersions: supported,
    });
    return true;
  }
  if (method === "notifications/initialized") {
    res.writeHead(202, { "x-github-request-id": `req-${++requestCounter}` });
    res.end();
    return true;
  }
  if (method === "tools/list") {
    respond({
      tools: MCP_TOOLS.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      })),
    });
    return true;
  }
  if (method === "tools/call") {
    const name = String(params.name ?? "");
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    const out = mcpCallTool(name, args);
    if (out.isError) {
      // Tool-level error: return isError content, not a JSON-RPC error, for
      // known tools; unknown tools get -32602.
      if (mcpToolNameMatch(name)) {
        respond(out);
      } else {
        respondError(-32602, `unknown tool: ${name}`);
      }
      return true;
    }
    respond(out);
    return true;
  }
  if (method === "ping") {
    respond({});
    return true;
  }
  respondError(-32601, `Method not found: ${method}`);
  return true;
}

// ===========================================================================
// server + lifecycle
// ===========================================================================
async function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", "http://x");
  const path = url.pathname;
  const q = url.searchParams;
  const method = req.method ?? "GET";

  // /healthz is unauthenticated.
  if (method === "GET" && path === "/healthz") {
    sendJson(res, 200, { ok: true });
    return;
  }
  if (method === "GET" && path === "/") {
    sendJson(res, 200, { ok: true, service: "forge", version: "1.0.0" });
    return;
  }

  if (!authed(req)) {
    sendError(res, 401, "Requires authentication");
    return;
  }

  const bodyBuf = await readBody(req);
  const isJsonPath =
    path.startsWith("/api/v3") || path.startsWith("/api/graphql") || path === "/mcp";
  let body: unknown = {};
  if (isJsonPath) {
    const parsed = parseJsonBody(bodyBuf);
    if (!parsed.ok) {
      if (path === "/mcp") {
        sendJson(res, 400, { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
        return;
      }
      sendError(res, 400, "Problems parsing JSON");
      return;
    }
    body = parsed.value;
  }

  // Git smart HTTP.
  const gitMatch = path.match(/^\/(?:api\/v3\/)?([^/]+)\/([^/]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/);
  const gitMatch2 = path.match(/^\/([^/]+)\/([^/]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/);
  const gm = gitMatch ?? gitMatch2;
  if (gm) {
    const owner = decodeURIComponent(gm[1]);
    const name = decodeURIComponent(gm[2]);
    const action = gm[3];
    if (action === "info/refs") {
      handleInfoRefs(req, res, owner, name, q.get("service") ?? "");
      return;
    }
    const repo = getRepo(owner, name);
    if (!repo) {
      sendError(res, 404, "Not Found");
      return;
    }
    if (action === "git-upload-pack") {
      const proto = req.headers["git-protocol"] ?? "";
      const result =
        typeof proto === "string" && proto.includes("version=2")
          ? handleUploadPackV2(repo, bodyBuf)
          : handleUploadPackV0(repo, bodyBuf);
      sendRaw(res, 200, "application/x-git-upload-pack-result", result);
      return;
    }
    if (action === "git-receive-pack") {
      const result = handleReceivePack(repo, bodyBuf);
      sendRaw(res, 200, "application/x-git-receive-pack-result", result);
      return;
    }
  }

  if (path === "/api/graphql") {
    handleGraphQL({ req, res, body, path, q });
    return;
  }
  if (path === "/mcp") {
    handleMcp({ req, res, body, path, q });
    return;
  }
  if (path.startsWith("/api/v3")) {
    const handled = handleRest({ req, res, body, path, q });
    if (handled) return;
    sendError(res, 404, "Not Found");
    return;
  }
  sendError(res, 404, "Not Found");
}

async function main(): Promise<void> {
  const envUrl = process.env.MAKEFUN_ENV_URL;
  const server = http.createServer((req, res) => {
    handleRequest(req, res).catch((err) => {
      console.error("request error:", err);
      if (!res.headersSent) {
        try {
          sendError(res, 500, (err as Error).message);
        } catch {
          res.end();
        }
      }
    });
  });
  server.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;

  if (envUrl) {
    const base = envUrl.replace(/\/$/, "");
    try {
      const reg = await fetch(`${base}/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ port }),
      });
      void reg;
    } catch {
      // Registration failed; the harness will still probe /healthz.
    }
    // Long-poll for the done signal, then exit 0. The env answers
    // {"done": false} at once while the suite runs; re-poll until it
    // answers {"done": true}.
    for (;;) {
      try {
        const res = await fetch(`${base}/done`);
        const body: unknown = await res.json().catch(() => ({}));
        if ((body as { done?: unknown }).done === true) break;
      } catch {
        // If the poll fails, keep serving and retry.
      }
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  server.close();
  process.exit(0);
}

main();





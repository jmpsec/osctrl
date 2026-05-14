// Copies monaco-editor's min/vs runtime into public/monaco/vs so the SPA
// can load it from its own origin under CSP `script-src 'self' blob:`.
// Without this, @monaco-editor/loader default fetches from
// cdn.jsdelivr.net which the CSP blocks, breaking every page that mounts
// <CodeEditor>.
//
// Supply-chain hardening: we compute a deterministic SHA-256 over the
// recursive contents of the source directory and compare it against
// monaco-runtime.sha256 (committed). Any drift — npm registry compromise,
// MITM during npm install, accidental local tampering — fails the build
// before bytes ever ship. To intentionally bump monaco-editor: update
// package.json + monaco-runtime.sha256 in the same commit. The script
// prints the observed hash on mismatch so the new value is easy to commit.
//
// Runs automatically before `npm run dev` / `npm run build` via the
// predev / prebuild npm scripts. The destination directory is gitignored.

import { copyFile, mkdir, readdir, stat, rm, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, '..', 'node_modules', 'monaco-editor', 'min', 'vs');
const dst = join(here, '..', 'public', 'monaco', 'vs');
const expectedHashFile = join(here, '..', 'monaco-runtime.sha256');

// ── Discovery ─────────────────────────────────────────────────────────
try {
  await stat(src);
} catch {
  console.error(`error: monaco-editor not installed at ${src}`);
  console.error(`run \`npm install\` and retry`);
  process.exit(1);
}

// Collect (relativePath, absolutePath) for every file under src, sorted.
async function listFiles(root) {
  const out = [];
  async function walk(dir) {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      const abs = join(dir, e.name);
      if (e.isDirectory()) await walk(abs);
      else if (e.isFile()) {
        // POSIX path separators in the hash input so the hash is
        // identical on macOS / Linux / Windows.
        out.push([relative(root, abs).split(sep).join('/'), abs]);
      }
    }
  }
  await walk(root);
  out.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return out;
}

async function hashFile(p) {
  const h = createHash('sha256');
  h.update(await readFile(p));
  return h.digest('hex');
}

async function dirHash(root) {
  const files = await listFiles(root);
  const h = createHash('sha256');
  for (const [rel, abs] of files) {
    h.update(rel);
    h.update('\0');
    h.update(await hashFile(abs));
    h.update('\n');
  }
  return h.digest('hex');
}

// ── Supply-chain integrity check ──────────────────────────────────────
const observed = await dirHash(src);
let expected = null;
try {
  expected = (await readFile(expectedHashFile, 'utf8')).trim();
} catch {
  // First run — no committed expected hash. Write one and ask the
  // operator to commit it so subsequent builds enforce the value.
  await writeFile(expectedHashFile, observed + '\n');
  console.warn(
    `WARNING: no committed monaco-runtime.sha256 found. Wrote ${observed}.\n` +
    `         Inspect the tree at ${src}, then \`git add monaco-runtime.sha256\` ` +
    `to lock the hash. Subsequent builds will fail on drift.`,
  );
}

if (expected && observed !== expected) {
  console.error(
    `error: monaco-editor integrity check FAILED.\n` +
    `       expected ${expected}\n` +
    `       got      ${observed}\n` +
    `       at       ${src}\n` +
    `\n` +
    `This means the monaco-editor bytes on disk do not match the\n` +
    `committed monaco-runtime.sha256. Either:\n` +
    `  (a) monaco-editor was intentionally bumped — update package.json\n` +
    `      and monaco-runtime.sha256 in the same commit; or\n` +
    `  (b) the npm registry / local cache was tampered with — DO NOT\n` +
    `      build. Investigate before proceeding.\n`,
  );
  process.exit(2);
}

// ── Stage into public/monaco/vs ───────────────────────────────────────
async function copyRecursive(s, d) {
  const entries = await readdir(s, { withFileTypes: true });
  await mkdir(d, { recursive: true });
  for (const e of entries) {
    const sp = join(s, e.name);
    const dp = join(d, e.name);
    if (e.isDirectory()) {
      await copyRecursive(sp, dp);
    } else if (e.isFile()) {
      await copyFile(sp, dp);
    }
  }
}

await rm(dst, { recursive: true, force: true });
await copyRecursive(src, dst);
console.log(
  `staged monaco runtime: ${src} -> ${dst}\n` +
  `integrity: ${observed} ✓`,
);

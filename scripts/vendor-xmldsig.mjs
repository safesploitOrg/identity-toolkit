import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const VERSION = '2.8.8';
const UPSTREAM_TAG = 'xmldsigjs@2.8.8';
const UPSTREAM_COMMIT = '47d5d3e8df98facc3738ebd476b38e98108b7306';
const EXTERNAL_DIR = resolve(ROOT, 'public/assets/js/external');
const OUT_FILE = resolve(EXTERNAL_DIR, `xmldsigjs-${VERSION}.bundle.js`);
const LICENSE_FILE = resolve(EXTERNAL_DIR, `xmldsigjs-${VERSION}.LICENSE.txt`);
const MANIFEST_FILE = resolve(EXTERNAL_DIR, 'vendor-manifest.json');
const INDEX_FILE = resolve(ROOT, 'public/index.html');

const PINNED_RUNTIME = [
  'xmldsigjs',
  'asn1js',
  'pkijs',
  'pvtsutils',
  'pvutils',
  'tslib',
  'xml-core',
  'xpath',
  '@noble/hashes',
  'bytestreamjs',
];

async function packageVersion(name) {
  const packagePath = resolve(ROOT, 'node_modules', ...name.split('/'), 'package.json');
  try {
    const pkg = JSON.parse(await readFile(packagePath, 'utf8'));
    return pkg.version ?? 'unknown';
  } catch {
    return 'not-installed';
  }
}

await mkdir(dirname(OUT_FILE), { recursive: true });
const xmldsigPackage = JSON.parse(await readFile(resolve(ROOT, 'node_modules/xmldsigjs/package.json'), 'utf8'));
if (xmldsigPackage.version !== VERSION) {
  throw new Error(`Expected xmldsigjs ${VERSION}; installed ${xmldsigPackage.version ?? 'unknown'}`);
}

await build({
  entryPoints: [resolve(ROOT, 'node_modules/xmldsigjs/build/esm/index.js')],
  outfile: OUT_FILE,
  bundle: true,
  format: 'iife',
  globalName: 'XmlDsigJs',
  platform: 'browser',
  target: ['es2020'],
  minify: false,
  sourcemap: false,
  legalComments: 'inline',
  banner: {
    js: `/* xmldsigjs ${VERSION} - locally vendored browser bundle. Upstream licence: MIT. */`,
  },
});

await copyFile(resolve(ROOT, 'node_modules/xmldsigjs/LICENSE'), LICENSE_FILE);

const bundle = await readFile(OUT_FILE);
const digest = createHash('sha384').update(bundle).digest('base64');
const integrity = `sha384-${digest}`;
const sha384Hex = createHash('sha384').update(bundle).digest('hex');
const installedRuntime = Object.fromEntries(await Promise.all(PINNED_RUNTIME.map(async (name) => [name, await packageVersion(name)])));

const manifest = {
  schemaVersion: 1,
  generatedBy: 'scripts/vendor-xmldsig.mjs',
  dependency: {
    name: 'xmldsigjs',
    version: VERSION,
    file: `xmldsigjs-${VERSION}.bundle.js`,
    integrity,
    sha384: sha384Hex,
    upstream: 'https://github.com/PeculiarVentures/xmldsigjs',
    upstreamTag: UPSTREAM_TAG,
    upstreamCommit: UPSTREAM_COMMIT,
    source: `npm:xmldsigjs@${VERSION}`,
    licence: 'MIT',
    installedRuntime,
    note: 'Bundle contains xmldsigjs and its browser runtime dependency graph. Runtime loading is local only.',
  },
};
await writeFile(MANIFEST_FILE, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');

let html = await readFile(INDEX_FILE, 'utf8');
const vendorPattern = /(data-vendor="xmldsigjs"[^>]*integrity=")[^"]*(")/;
if (!vendorPattern.test(html)) throw new Error('Cannot locate xmldsigjs SRI attribute in public/index.html');
html = html.replace(vendorPattern, `$1${integrity}$2`);
await writeFile(INDEX_FILE, html, 'utf8');

console.log(`Vendored xmldsigjs ${VERSION}`);
console.log(`Upstream tag: ${UPSTREAM_TAG}`);
console.log(`Upstream commit: ${UPSTREAM_COMMIT}`);
console.log(`SRI: ${integrity}`);

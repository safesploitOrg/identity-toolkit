import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const MANIFEST = resolve(ROOT, 'public/assets/js/external/vendor-manifest.json');

let manifest;
try {
  manifest = JSON.parse(await readFile(MANIFEST, 'utf8'));
} catch (error) {
  throw new Error(`Vendor manifest missing/unreadable. Run npm run vendor:xmldsig first. ${error.message}`);
}

const dep = manifest.dependency;
if (!dep || dep.name !== 'xmldsigjs' || dep.version !== '2.8.8') {
  throw new Error('xmldsigjs vendor manifest is missing or not pinned to 2.8.8');
}
if (dep.upstreamCommit !== '47d5d3e8df98facc3738ebd476b38e98108b7306') {
  throw new Error('xmldsigjs upstream commit provenance does not match the approved 2.8.8 tag commit');
}

const bundlePath = resolve(ROOT, 'public/assets/js/external', dep.file);
const bundle = await readFile(bundlePath);
const integrity = `sha384-${createHash('sha384').update(bundle).digest('base64')}`;
const sha384 = createHash('sha384').update(bundle).digest('hex');
if (integrity !== dep.integrity || sha384 !== dep.sha384) {
  throw new Error(`Vendor integrity mismatch for ${dep.file}`);
}

const html = await readFile(resolve(ROOT, 'public/index.html'), 'utf8');
const sriMatch = html.match(/data-vendor="xmldsigjs"[^>]*integrity="([^"]+)"/);
if (!sriMatch) throw new Error('index.html does not declare SRI for xmldsigjs');
if (sriMatch[1] !== dep.integrity) throw new Error('index.html SRI does not match vendor manifest');
if (/PLACEHOLDER/.test(sriMatch[1])) throw new Error('index.html still contains the vendor SRI placeholder');
if (/https?:\/\/[^"']+\.(?:js|css)(?:[?"'])/i.test(html)) {
  throw new Error('Remote runtime JavaScript/CSS dependency found in index.html');
}

console.log(`Verified ${dep.file}`);
console.log(dep.integrity);

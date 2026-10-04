import { readFile, readdir, stat } from 'node:fs/promises';
import { resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const INDEX = resolve(ROOT, 'public/index.html');
const APP_ROOT = resolve(ROOT, 'public/assets/js');
const CSS = resolve(ROOT, 'public/assets/css/app.css');

async function filesUnder(dir) {
  const output = [];
  for (const name of await readdir(dir)) {
    const path = resolve(dir, name);
    const info = await stat(path);
    if (info.isDirectory()) {
      if (name === 'external') continue;
      output.push(...await filesUnder(path));
    } else if (name.endsWith('.js') || name.endsWith('.mjs')) {
      output.push(path);
    }
  }
  return output;
}

function requireMatch(text, regex, message) {
  if (!regex.test(text)) throw new Error(message);
}

function rejectMatch(text, regex, message) {
  const match = text.match(regex);
  if (match) throw new Error(`${message}: ${match[0]}`);
}

const html = await readFile(INDEX, 'utf8');
const css = await readFile(CSS, 'utf8');

requireMatch(html, /connect-src 'none'/, "CSP must retain connect-src 'none'");
requireMatch(html, /data-vendor="xmldsigjs"[^>]+src="\.\/assets\/js\/external\/xmldsigjs-2\.8\.8\.bundle\.js"[^>]+integrity="sha384-[^"]+"/, 'xmldsigjs must load locally with an SRI attribute');
requireMatch(html, /© 2026 identity-toolkit · <a[^>]*>GitHub ↗<\/a>/, 'Expected footer text is missing');
requireMatch(css, /\.centered-footer\s*\{[^}]*text-align:\s*center/s, 'Footer centring rule is missing');
rejectMatch(html, /<(?:script|link)\b[^>]+(?:src|href)="https?:\/\//i, 'Remote runtime JavaScript/CSS dependency found');

const networkApi = /\b(?:fetch|XMLHttpRequest|WebSocket|EventSource)\b/;
const persistenceApi = /\b(?:localStorage|sessionStorage|indexedDB)\b|document\.cookie/;
for (const file of await filesUnder(APP_ROOT)) {
  const source = await readFile(file, 'utf8');
  rejectMatch(source, networkApi, `Unexpected first-party runtime network API in ${file}`);
  rejectMatch(source, persistenceApi, `Unexpected browser persistence API in ${file}`);
}

console.log('Static security/UI assertions verified.');

import { finding, SEVERITY } from '../validation/findings.js';

function expectedKty(alg = '') {
  if (/^(RS|PS)\d+$/.test(alg)) return 'RSA';
  if (/^ES\d+$/.test(alg)) return 'EC';
  if (alg === 'EdDSA') return 'OKP';
  return '';
}

function keyCompatible(key, header) {
  if (!key || typeof key !== 'object') return false;
  if (key.use && key.use !== 'sig') return false;
  if (Array.isArray(key.key_ops) && !key.key_ops.includes('verify')) return false;
  const requiredKty = expectedKty(header?.alg ?? '');
  if (requiredKty && key.kty !== requiredKty) return false;
  if (header?.alg && key.alg && key.alg !== header.alg) return false;
  return true;
}

function hasPrivateMaterial(key) {
  return ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some((name) => key?.[name] !== undefined);
}

export function parseJwkMaterial(text) {
  if (!String(text ?? '').trim()) return { keys: [], source: 'none' };
  const data = JSON.parse(text);
  if (Array.isArray(data?.keys)) return { keys: data.keys, source: 'jwks' };
  if (data && typeof data === 'object' && data.kty) return { keys: [data], source: 'jwk' };
  throw new Error('Verification material must be a JWK or JWKS JSON document.');
}

export function selectJwk(keys, header) {
  if (!Array.isArray(keys) || keys.length === 0) return { key: null, reason: 'No keys supplied.' };
  const kid = header?.kid;
  let candidates = keys.filter((key) => keyCompatible(key, header));
  if (kid) candidates = candidates.filter((key) => key.kid === kid);
  if (candidates.length === 1) return { key: candidates[0], reason: kid ? `Matched kid ${kid}.` : 'Single compatible verification key supplied.' };
  if (candidates.length === 0) {
    return {
      key: null,
      reason: kid
        ? `No supplied signing/verification key is compatible with alg ${header?.alg ?? '(unspecified)'} and kid ${kid}.`
        : `No supplied signing/verification key is compatible with alg ${header?.alg ?? '(unspecified)'}.`,
    };
  }
  return { key: null, reason: `Multiple compatible candidate keys (${candidates.length}) remain; a unique signing key cannot be selected.` };
}

export function inspectJwks(data) {
  const keys = Array.isArray(data?.keys) ? data.keys : [];
  const kids = new Map();
  for (const key of keys) {
    if (!key?.kid) continue;
    kids.set(key.kid, (kids.get(key.kid) ?? 0) + 1);
  }
  return {
    keyCount: keys.length,
    keys: keys.map((key, index) => ({
      index,
      kid: key.kid ?? '',
      kty: key.kty ?? '',
      use: key.use ?? '',
      keyOps: key.key_ops ?? [],
      alg: key.alg ?? '',
      crv: key.crv ?? '',
      hasX5c: Array.isArray(key.x5c) && key.x5c.length > 0,
      x5cCount: Array.isArray(key.x5c) ? key.x5c.length : 0,
      hasPrivateMaterial: hasPrivateMaterial(key),
    })),
    duplicateKids: [...kids.entries()].filter(([, count]) => count > 1).map(([kid, count]) => ({ kid, count })),
    missingKidCount: keys.filter((key) => !key?.kid).length,
    privateMaterialCount: keys.filter(hasPrivateMaterial).length,
  };
}

export function analyseJwks(data) {
  const summary = inspectJwks(data);
  const findings = [finding('jwks.parsed', SEVERITY.INFO, `${summary.keyCount} JSON Web Key(s)`, 'Key material was inspected locally and no jku/x5u/jwks_uri URL was contacted.')];
  if (!summary.keyCount) findings.push(finding('jwks.empty', SEVERITY.WARNING, 'JWKS contains no keys', 'A published JWKS with no keys cannot verify signatures until key material is added.'));
  if (summary.duplicateKids.length) findings.push(finding('jwks.kid.duplicate', SEVERITY.ERROR, 'Duplicate kid values detected', JSON.stringify(summary.duplicateKids)));
  if (summary.missingKidCount && summary.keyCount > 1) findings.push(finding('jwks.kid.missing', SEVERITY.WARNING, `${summary.missingKidCount} key(s) have no kid`, 'Multiple signing keys without kid values can make deterministic key selection difficult.'));
  if (summary.privateMaterialCount) findings.push(finding('jwks.private', SEVERITY.ERROR, 'Private/symmetric key material detected', 'Public verification JWKS documents should not expose private RSA/EC parameters or symmetric k values.'));

  for (const key of summary.keys) {
    if (!['RSA', 'EC', 'OKP', 'oct'].includes(key.kty)) findings.push(finding(`jwks.kty.${key.index}`, SEVERITY.WARNING, `Unrecognised JWK type: ${key.kty || '(missing)'}`, `Key ${key.kid || `#${key.index + 1}`} uses an unrecognised kty.`));
    if (key.use && !['sig', 'enc'].includes(key.use)) findings.push(finding(`jwks.use.${key.index}`, SEVERITY.WARNING, `Unrecognised JWK use: ${key.use}`, 'Standard public key use values are sig and enc.'));
    if (key.kty === 'oct') findings.push(finding(`jwks.symmetric.${key.index}`, SEVERITY.WARNING, 'Symmetric JWK present', 'Symmetric keys require especially careful distribution boundaries; a public JWKS must not disclose the k value.'));
  }

  return { summary, findings };
}

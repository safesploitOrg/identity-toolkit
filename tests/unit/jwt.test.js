import test from 'node:test';
import assert from 'node:assert/strict';
import { bytesToBase64Url } from '../../public/assets/js/modules/encoding/base64url.js';
import { parseJwt } from '../../public/assets/js/modules/jwt/jwt-parser.js';
import { validateJwt } from '../../public/assets/js/modules/jwt/jwt-validator.js';
import { selectJwk } from '../../public/assets/js/modules/jwt/jwk.js';

function enc(value) { return bytesToBase64Url(new TextEncoder().encode(JSON.stringify(value))); }
function token(header, claims, signature = '') { return `${enc(header)}.${enc(claims)}.${signature}`; }

test('parses a compact JWT and preserves claims', () => {
  const parsed = parseJwt(token({ alg: 'none', typ: 'JWT' }, { sub: 'alice', aud: 'app' }));
  assert.equal(parsed.header.typ, 'JWT');
  assert.equal(parsed.claims.sub, 'alice');
  assert.equal(parsed.signature.length, 0);
});

test('rejects compact values with wrong segment count', () => {
  assert.throws(() => parseJwt('one.two'), /exactly three/);
});

test('OIDC profile reports missing required claims', () => {
  const parsed = parseJwt(token({ alg: 'RS256' }, { sub: 'alice' }, 'AA'));
  const findings = validateJwt(parsed, { profile: 'oidc-id-token', now: new Date('2026-10-02T00:00:00Z') });
  assert.ok(findings.some((item) => item.id === 'oidc.required.iss' && item.severity === 'error'));
  assert.ok(findings.some((item) => item.id === 'oidc.required.exp' && item.severity === 'error'));
});

test('expected audience accepts aud arrays', () => {
  const now = Math.floor(Date.parse('2026-10-02T00:00:00Z') / 1000);
  const parsed = parseJwt(token({ alg: 'RS256' }, { aud: ['api-a', 'api-b'], exp: now + 3600 }, 'AA'));
  const findings = validateJwt(parsed, { profile: 'generic-jwt', expectedAudience: 'api-b', now: new Date(now * 1000) });
  assert.ok(findings.some((item) => item.id === 'jwt.aud.expected'));
});

test('critical b64 semantics remain indeterminate until implemented', () => {
  const parsed = parseJwt(token({ alg: 'RS256', crit: ['b64'], b64: false }, { sub: 'alice' }, 'AA'));
  const findings = validateJwt(parsed, { profile: 'generic-jwt', now: new Date('2026-10-02T00:00:00Z') });
  assert.ok(findings.some((item) => item.id === 'jwt.crit.unknown' && item.severity === 'indeterminate'));
  assert.ok(findings.some((item) => item.id === 'jwt.b64.unsupported' && item.severity === 'indeterminate'));
});


test('JWK selection excludes encryption-only and incompatible key types', () => {
  const keys = [
    { kty: 'RSA', kid: 'enc', use: 'enc', n: 'x', e: 'AQAB' },
    { kty: 'EC', kid: 'sig', use: 'sig', crv: 'P-256', x: 'x', y: 'y' },
    { kty: 'RSA', kid: 'sig', use: 'sig', key_ops: ['verify'], n: 'x', e: 'AQAB' },
  ];
  const selected = selectJwk(keys, { alg: 'RS256', kid: 'sig' });
  assert.equal(selected.key?.kty, 'RSA');
  assert.equal(selected.key?.kid, 'sig');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { bytesToBase64Url } from '../../public/assets/js/modules/encoding/base64url.js';
import { analyseOidcIdToken } from '../../public/assets/js/modules/oidc/id-token.js';
import { analyseOidcDiscovery } from '../../public/assets/js/modules/oidc/discovery.js';

globalThis.crypto ??= webcrypto;

async function halfHash(value, alg = 'RS256') {
  const hash = alg.endsWith('384') ? 'SHA-384' : alg.endsWith('512') ? 'SHA-512' : 'SHA-256';
  const digest = new Uint8Array(await webcrypto.subtle.digest(hash, new TextEncoder().encode(value)));
  return bytesToBase64Url(digest.slice(0, digest.length / 2));
}

test('OIDC ID Token checks azp, nonce and at_hash', async () => {
  const accessToken = 'access-token-value';
  const parsed = {
    header: { alg: 'RS256' },
    claims: {
      iss: 'https://idp.example', sub: 'alice', aud: ['client-a', 'client-b'], azp: 'client-b',
      exp: 2000000000, iat: 1900000000, nonce: 'n-123', at_hash: await halfHash(accessToken),
      acr: 'urn:mfa', amr: ['pwd', 'otp'],
    },
  };
  const result = await analyseOidcIdToken(parsed, { expectedAudience: 'client-b', expectedNonce: 'n-123', relatedAccessToken: accessToken, now: new Date('2026-10-02T00:00:00Z') });
  assert.ok(result.findings.some((item) => item.id === 'oidc.nonce.expected' && item.severity === 'pass'));
  assert.ok(result.findings.some((item) => item.id === 'oidc.at_hash.result' && item.severity === 'pass'));
  assert.ok(result.findings.some((item) => item.id === 'oidc.azp.expected' && item.severity === 'pass'));
});

test('OIDC ID Token reports additional-audience trust without inventing an azp requirement', async () => {
  const result = await analyseOidcIdToken({ header: { alg: 'RS256' }, claims: { aud: ['a', 'b'] } });
  assert.ok(result.findings.some((item) => item.id === 'oidc.aud.additional-trust' && item.severity === 'warning'));
  assert.ok(result.findings.some((item) => item.id === 'oidc.azp.absent' && item.severity === 'info'));
  assert.ok(!result.findings.some((item) => item.id === 'oidc.azp.required'));
});

test('OIDC discovery checks required capability arrays and PKCE S256', () => {
  const result = analyseOidcDiscovery({
    issuer: 'https://idp.example',
    authorization_endpoint: 'https://idp.example/authorize',
    token_endpoint: 'https://idp.example/token',
    jwks_uri: 'https://idp.example/jwks',
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile'],
    code_challenge_methods_supported: ['S256'],
  });
  assert.ok(result.findings.some((item) => item.id === 'oidc.discovery.pkce.s256' && item.severity === 'pass'));
  assert.equal(result.summary.issuer, 'https://idp.example');
});


test('OIDC max authentication age requires auth_time context', async () => {
  const parsed = { header: { alg: 'RS256' }, claims: { iss: 'https://issuer.example', sub: 'u', aud: 'client', iat: 1000, exp: 2000 } };
  const result = await analyseOidcIdToken(parsed, { now: new Date(1_500_000), maxAuthenticationAgeSeconds: 300 });
  assert.ok(result.findings.some((item) => item.id === 'oidc.auth_time.missing' && item.severity === 'error'));
});


test('OIDC discovery requires token endpoint when code response type is advertised', () => {
  const result = analyseOidcDiscovery({
    issuer: 'https://idp.example',
    authorization_endpoint: 'https://idp.example/authorize',
    jwks_uri: 'https://idp.example/jwks',
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
  });
  assert.ok(result.findings.some((item) => item.id === 'oidc.discovery.token.missing' && item.severity === 'error'));
});

test('OIDC discovery flags front-channel access-token response types', () => {
  const result = analyseOidcDiscovery({
    issuer: 'https://idp.example',
    authorization_endpoint: 'https://idp.example/authorize',
    jwks_uri: 'https://idp.example/jwks',
    response_types_supported: ['id_token token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
  });
  assert.ok(result.findings.some((item) => item.id === 'oidc.discovery.implicit' && item.severity === 'warning'));
});

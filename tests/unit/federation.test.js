import test from 'node:test';
import assert from 'node:assert/strict';
import { analyseOidcDiscovery } from '../../public/assets/js/modules/oidc/discovery.js';
import { compareFederation } from '../../public/assets/js/modules/federation/federation-compare.js';
import { analyseJwks, inspectJwks } from '../../public/assets/js/modules/jwt/jwk.js';

test('analyses OIDC discovery endpoints without fetching them', () => {
  const result = analyseOidcDiscovery({
    issuer: 'https://idp.example',
    authorization_endpoint: 'https://idp.example/auth',
    token_endpoint: 'https://idp.example/token',
    jwks_uri: 'https://idp.example/jwks',
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
  });
  assert.equal(result.summary.issuer, 'https://idp.example');
  assert.ok(result.findings.every((item) => !item.id.endsWith('.scheme')));
});

test('finds duplicate JWKS kid values', () => {
  const result = inspectJwks({ keys: [{ kty: 'RSA', kid: 'same' }, { kty: 'EC', kid: 'same' }] });
  assert.deepEqual(result.duplicateKids, [{ kid: 'same', count: 2 }]);
});

test('flags private key material in a JWKS', () => {
  const result = analyseJwks({ keys: [{ kty: 'RSA', kid: 'bad', n: 'x', e: 'AQAB', d: 'private' }] });
  assert.ok(result.findings.some((item) => item.id === 'jwks.private' && item.severity === 'error'));
});

test('compares OIDC configuration fields', async () => {
  const base = { response_types_supported: ['code'], subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256'] };
  const left = analyseOidcDiscovery({ ...base, issuer: 'https://a', authorization_endpoint: 'https://a/auth', token_endpoint: 'https://a/token', jwks_uri: 'https://a/jwks' });
  const right = analyseOidcDiscovery({ ...base, issuer: 'https://b', authorization_endpoint: 'https://b/auth', token_endpoint: 'https://b/token', jwks_uri: 'https://b/jwks' });
  const diff = await compareFederation(left, right);
  assert.ok(diff.rows.some((item) => item.name === 'issuer' && item.status === 'changed'));
  assert.equal(diff.issuerMigration.classification, 'issuer-host-change');
});

test('detects overlap JWKS key rotation', async () => {
  const leftAnalysis = analyseJwks({ keys: [{ kty: 'RSA', kid: 'old', use: 'sig' }] });
  const rightAnalysis = analyseJwks({ keys: [{ kty: 'RSA', kid: 'old', use: 'sig' }, { kty: 'RSA', kid: 'new', use: 'sig' }] });
  const left = { kind: 'jwks', summary: leftAnalysis.summary };
  const right = { kind: 'jwks', summary: rightAnalysis.summary };
  const comparison = await compareFederation(left, right);
  assert.equal(comparison.keyRotation.classification, 'overlap-addition');
  assert.deepEqual(comparison.keyRotation.added, ['new']);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { analyseOpenIdFederationStatement } from '../../public/assets/js/modules/federation/openid-federation.js';

test('validates final OpenID Federation Entity Statement shape', () => {
  const now = 1790899200;
  const result = analyseOpenIdFederationStatement({
    header: { typ: 'entity-statement+jwt', alg: 'RS256', kid: 'k1' },
    claims: {
      iss: 'https://entity.example', sub: 'https://entity.example', iat: now - 60, exp: now + 3600,
      jwks: { keys: [{ kty: 'RSA', kid: 'k1', n: 'x', e: 'AQAB' }] },
      authority_hints: ['https://ta.example'],
      metadata: { openid_provider: { issuer: 'https://entity.example' } },
    },
  }, { now: new Date(now * 1000), clockSkewSeconds: 0 });
  assert.equal(result.summary.statementType, 'Entity Configuration');
  assert.ok(result.findings.some((item) => item.id === 'federation.typ' && item.severity === 'pass'));
  assert.ok(result.findings.some((item) => item.id === 'federation.jwks.header-kid' && item.severity === 'pass'));
});

test('flags metadata_policy on an Entity Configuration', () => {
  const result = analyseOpenIdFederationStatement({
    header: { typ: 'entity-statement+jwt', alg: 'RS256', kid: 'k1' },
    claims: { iss: 'https://entity.example', sub: 'https://entity.example', iat: 1, exp: 2, jwks: { keys: [{ kty: 'RSA', kid: 'k1' }] }, metadata_policy: { openid_provider: {} } },
  }, { now: new Date(1500) });
  assert.ok(result.findings.some((item) => item.id === 'federation.metadata_policy.statement' && item.severity === 'error'));
});

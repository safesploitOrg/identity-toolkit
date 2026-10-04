import test from 'node:test';
import assert from 'node:assert/strict';
import { analyseOAuthAccessToken } from '../../public/assets/js/modules/oauth/oauth-token.js';

test('RFC 9068 access token requires standard claims and at+jwt type', () => {
  const parsed = {
    header: { alg: 'RS256', typ: 'at+jwt' },
    claims: { iss: 'https://as.example', exp: 2000000000, aud: 'api', sub: 'alice', client_id: 'client', iat: 1900000000, jti: '1', scope: 'read write' },
  };
  const result = analyseOAuthAccessToken(parsed, { oauthProfile: 'rfc9068' });
  assert.equal(result.rfc9068, true);
  assert.deepEqual(result.permissions.scopes, ['read', 'write']);
  assert.ok(!result.findings.some((item) => item.id.startsWith('oauth.rfc9068.required.') && item.severity === 'error'));
});

test('RFC 9068 access token flags missing client_id and wrong typ', () => {
  const parsed = { header: { alg: 'RS256', typ: 'JWT' }, claims: { iss: 'x', exp: 1, aud: 'api', sub: 'alice', iat: 1, jti: '1' } };
  const result = analyseOAuthAccessToken(parsed, { oauthProfile: 'rfc9068' });
  assert.ok(result.findings.some((item) => item.id === 'oauth.rfc9068.required.client_id' && item.severity === 'error'));
  assert.ok(result.findings.some((item) => item.id === 'oauth.rfc9068.typ' && item.severity === 'error'));
});


test('RFC 9068 reports symmetric signing as permitted but not preferred', () => {
  const parsed = {
    header: { alg: 'HS256', typ: 'at+jwt' },
    claims: { iss: 'https://as.example', exp: 2000000000, aud: 'api', sub: 'alice', client_id: 'client', iat: 1900000000, jti: '1' },
  };
  const result = analyseOAuthAccessToken(parsed, { oauthProfile: 'rfc9068' });
  assert.ok(result.findings.some((item) => item.id === 'oauth.rfc9068.alg.symmetric' && item.severity === 'warning'));
});

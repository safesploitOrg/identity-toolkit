import test from 'node:test';
import assert from 'node:assert/strict';
import { claimsFromJwt, normaliseClaimEntries } from '../../public/assets/js/modules/claims/claims.js';
import { compareClaims } from '../../public/assets/js/modules/claims/claim-diff.js';

const roleUri = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role';

test('normalises common SAML/WS-Fed role claims', () => {
  const claims = normaliseClaimEntries([{ name: roleUri, value: 'Admin' }], 'saml');
  assert.equal(claims[0].canonical, 'roles');
});

test('compares scp and scope through canonical name', () => {
  const left = normaliseClaimEntries([{ name: 'scp', value: 'read write' }], 'jwt');
  const right = normaliseClaimEntries([{ name: 'scope', value: 'read write' }], 'jwt');
  const diff = compareClaims(left, right);
  assert.equal(diff.length, 1);
  assert.equal(diff[0].name, 'scope');
  assert.equal(diff[0].status, 'mapped');
});


test('custom claim mapping can align provider-specific names', () => {
  const left = normaliseClaimEntries([{ name: 'legacy-role', value: ['Admin'] }], 'saml');
  const right = normaliseClaimEntries([{ name: 'roles', value: ['Admin'] }], 'jwt');
  const diff = compareClaims(left, right, { 'legacy-role': 'roles' });
  assert.equal(diff[0].name, 'roles');
  assert.equal(diff[0].status, 'mapped');
});

test('set-like claim comparison ignores ordering', () => {
  const left = normaliseClaimEntries([{ name: 'groups', value: ['b', 'a'] }], 'jwt');
  const right = normaliseClaimEntries([{ name: 'groups', value: ['a', 'b'] }], 'jwt');
  const diff = compareClaims(left, right);
  assert.equal(diff[0].status, 'same');
});

test('scope comparison treats OAuth space-delimited scope as a set', () => {
  const left = claimsFromJwt({ scope: 'openid profile email' });
  const right = claimsFromJwt({ scope: ['email', 'openid', 'profile'] });
  const item = compareClaims(left, right).find((entry) => entry.name === 'scope');
  assert.equal(item.status, 'same');
});

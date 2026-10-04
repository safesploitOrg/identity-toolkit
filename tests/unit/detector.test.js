import test from 'node:test';
import assert from 'node:assert/strict';
import { detectInput } from '../../public/assets/js/modules/input-detector.js';

const cases = [
  ['eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.', 'jwt'],
  ['{"keys":[]}', 'jwks'],
  ['{"kty":"RSA","n":"x","e":"AQAB"}', 'jwk'],
  ['{"issuer":"https://idp.example","authorization_endpoint":"https://idp.example/auth","jwks_uri":"https://idp.example/jwks"}', 'oidc-discovery'],
  ['<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>', 'saml'],
  ['<t:RequestSecurityTokenResponse xmlns:t="urn:test"/>', 'wsfed'],
  ['<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"/>', 'saml-metadata'],
];

for (const [input, expected] of cases) {
  test(`detects ${expected}`, () => assert.equal(detectInput(input).type, expected));
}

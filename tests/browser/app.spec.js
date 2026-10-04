import { test, expect } from '@playwright/test';

function b64url(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function compactJwt(header, claims) {
  return `${b64url(header)}.${b64url(claims)}.`;
}

test('loads local xmldsigjs bundle and analyses a JWT', async ({ page }) => {
  await page.goto('/#inspect');
  await expect(page.getByRole('heading', { name: 'Inspect tokens and federation assertions locally' })).toBeVisible();
  const libraryLoaded = await page.evaluate(() => typeof globalThis.XmlDsigJs?.SignedXml === 'function');
  expect(libraryLoaded).toBe(true);

  const now = Math.floor(Date.now() / 1000);
  const token = compactJwt({ alg: 'none', typ: 'JWT' }, { sub: 'browser-test', aud: 'app', exp: now + 3600 });
  await page.locator('#artifact-input').fill(token);
  await page.getByRole('button', { name: 'Analyse artefact' }).click();
  await expect(page.locator('#detected-type')).toContainText('JWT');
  await expect(page.getByText('Unsecured JWT')).toBeVisible();
});

test('OIDC ID-token context validates nonce, azp and auth context', async ({ page }) => {
  await page.goto('/#inspect');
  const now = Math.floor(Date.now() / 1000);
  const token = compactJwt(
    { alg: 'RS256', typ: 'JWT' },
    {
      iss: 'https://idp.example/',
      sub: 'user-123',
      aud: ['client-a', 'api-a'],
      azp: 'client-a',
      nonce: 'nonce-123',
      iat: now - 30,
      auth_time: now - 60,
      exp: now + 3600,
      acr: 'urn:example:mfa',
      amr: ['pwd', 'otp'],
    },
  );
  await page.locator('#artifact-input').fill(token);
  await page.locator('#profile').selectOption('oidc-id-token');
  await page.locator('details.advanced-block').evaluate((node) => { node.open = true; });
  await page.locator('#expected-audience').fill('client-a');
  await page.locator('#expected-nonce').fill('nonce-123');
  await page.locator('#max-auth-age').fill('300');
  await page.getByRole('button', { name: 'Analyse artefact' }).click();
  await expect(page.getByText('Nonce matches authentication request')).toBeVisible();
  await expect(page.getByText('Authorised party present')).toBeVisible();
  await expect(page.getByText('Authentication methods reported')).toBeVisible();
});

test('RFC 9068 access-token analysis exposes scopes and profile findings', async ({ page }) => {
  await page.goto('/#inspect');
  const now = Math.floor(Date.now() / 1000);
  const token = compactJwt(
    { alg: 'RS256', typ: 'at+jwt' },
    {
      iss: 'https://as.example/',
      sub: 'user-123',
      aud: 'https://api.example/',
      client_id: 'client-a',
      iat: now,
      exp: now + 600,
      jti: 'token-1',
      scope: 'read write',
      roles: ['Operator'],
    },
  );
  await page.locator('#artifact-input').fill(token);
  await page.locator('#profile').selectOption('oauth-access-token');
  await page.locator('details.advanced-block').evaluate((node) => { node.open = true; });
  await page.locator('#oauth-profile').selectOption('rfc9068');
  await page.getByRole('button', { name: 'Analyse artefact' }).click();
  await expect(page.getByText('JWT access-token media type is explicit')).toBeVisible();
  await expect(page.getByText('2 OAuth scope(s)')).toBeVisible();
  await expect(page.getByText('1 role value(s)')).toBeVisible();
});

test('SAML 2.0 checks recipient, InResponseTo, audience and AuthnContext', async ({ page }) => {
  await page.goto('/#inspect');
  const future = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  const past = new Date(Date.now() - 60 * 1000).toISOString();
  const saml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" Destination="https://sp.example/saml/acs" InResponseTo="_request-1"><saml:Issuer>https://idp.example/</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_a1" Version="2.0"><saml:Issuer>https://idp.example/</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.test</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="https://sp.example/saml/acs" InResponseTo="_request-1" NotOnOrAfter="${future}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${past}" NotOnOrAfter="${future}"><saml:AudienceRestriction><saml:Audience>https://sp.example/</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${past}" SessionIndex="session-1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:example:mfa</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="roles"><saml:AttributeValue>Admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`;
  await page.locator('#artifact-input').fill(saml);
  await page.locator('#expected-audience').fill('https://sp.example/');
  await page.locator('details.advanced-block').evaluate((node) => { node.open = true; });
  await page.locator('#expected-recipient').fill('https://sp.example/saml/acs');
  await page.locator('#expected-in-response-to').fill('_request-1');
  await page.getByRole('button', { name: 'Analyse artefact' }).click();
  await expect(page.locator('#detected-type')).toContainText('SAML Response');
  await expect(page.getByText('Response Destination matches')).toBeVisible();
  await expect(page.getByText('SubjectConfirmation recipient matches')).toBeVisible();
  await expect(page.getByText('Every AudienceRestriction contains https://sp.example/')).toBeVisible();
  await expect(page.locator('#summary-grid')).toContainText('urn:example:mfa');
});

test('claims compare works across JWT/SAML and custom mapping', async ({ page }) => {
  await page.goto('/#compare');
  const token = compactJwt({ alg: 'none' }, { roles: ['Admin'], preferred_username: 'user@example.test' });
  const saml = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a"><saml:Issuer>https://idp.example</saml:Issuer><saml:AttributeStatement><saml:Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/role"><saml:AttributeValue>Admin</saml:AttributeValue></saml:Attribute><saml:Attribute Name="legacy-upn"><saml:AttributeValue>user@example.test</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`;
  await page.locator('#compare-left').fill(saml);
  await page.locator('#compare-right').fill(token);
  await page.locator('#claim-mapping').fill('{"legacy-upn":"preferred_username"}');
  await page.getByRole('button', { name: 'Compare claims' }).click();
  await expect(page.locator('#claim-diff-results')).toContainText('roles');
  await expect(page.locator('#claim-diff-results')).toContainText('preferred_username');
  await expect(page.locator('#migration-report-output')).toContainText('IDENTITY TOOLKIT CLAIMS MIGRATION REPORT');
});

test('federation comparison identifies overlapping JWKS key rotation', async ({ page }) => {
  await page.goto('/#federation');
  const left = JSON.stringify({ keys: [
    { kty: 'RSA', kid: 'old', use: 'sig', n: 'AQAB', e: 'AQAB' },
    { kty: 'RSA', kid: 'shared', use: 'sig', n: 'AQAB', e: 'AQAB' },
  ] });
  const right = JSON.stringify({ keys: [
    { kty: 'RSA', kid: 'shared', use: 'sig', n: 'AQAB', e: 'AQAB' },
    { kty: 'RSA', kid: 'new', use: 'sig', n: 'AQAB', e: 'AQAB' },
  ] });
  await page.locator('#federation-left').fill(left);
  await page.locator('#federation-right').fill(right);
  await page.getByRole('button', { name: 'Analyse federation configuration' }).click();
  await expect(page.locator('#federation-migration-summary')).toContainText('overlap-rotation');
  await expect(page.locator('#federation-report-output')).toContainText('SIGNING KEY ROTATION');
  await expect(page.locator('#federation-report-output')).toContainText('Added: new');
  await expect(page.locator('#federation-report-output')).toContainText('Removed: old');
});


test('OpenID Federation structural analysis is exposed in the browser', async ({ page }) => {
  await page.goto('/#inspect');
  const now = Math.floor(Date.now() / 1000);
  const entityId = 'https://federation.example/entity';
  const statement = compactJwt(
    { alg: 'RS256', typ: 'entity-statement+jwt', kid: 'fed-key-1' },
    {
      iss: entityId,
      sub: entityId,
      iat: now,
      exp: now + 3600,
      jwks: { keys: [{ kty: 'RSA', kid: 'fed-key-1', use: 'sig', alg: 'RS256', n: 'AQAB', e: 'AQAB' }] },
      authority_hints: ['https://federation.example/authority'],
      metadata: { openid_relying_party: { client_registration_types: ['automatic'] } },
    },
  );
  await page.locator('#artifact-input').fill(statement);
  await page.locator('#profile').selectOption('openid-federation');
  await page.getByRole('button', { name: 'Analyse artefact' }).click();
  await expect(page.locator('#summary-grid')).toContainText('Entity Configuration');
  await expect(page.getByText('Entity Configuration', { exact: true })).toBeVisible();
  await expect(page.getByText('1 authority hint(s)')).toBeVisible();
});

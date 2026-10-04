const DICTIONARY = {
  iss: ['Issuer', 'Identifies the authority that issued the token or assertion.'],
  sub: ['Subject', 'Identifies the principal that is the subject of the token.'],
  aud: ['Audience', 'Identifies the intended recipient or resource.'],
  exp: ['Expiration Time', 'Time after which the token must no longer be accepted.'],
  nbf: ['Not Before', 'Time before which the token must not be accepted.'],
  iat: ['Issued At', 'Time at which the token was issued.'],
  jti: ['JWT ID', 'Identifier for this JWT.'],
  nonce: ['Nonce', 'Value used to bind an ID Token to an authentication request.'],
  auth_time: ['Authentication Time', 'Time at which end-user authentication occurred, as reported by the issuer.'],
  acr: ['Authentication Context Class', 'Authentication context or assurance class asserted by the issuer.'],
  amr: ['Authentication Methods References', 'Methods the issuer reports as having participated in authentication.'],
  azp: ['Authorised Party', 'Client to which an ID Token was issued when relevant.'],
  client_id: ['OAuth Client ID', 'Identifies the OAuth client associated with the token.'],
  scope: ['OAuth Scopes', 'Space-delimited or structured permissions associated with an access token.'],
  roles: ['Roles', 'Application or directory roles asserted for the subject/client.'],
  groups: ['Groups', 'Group identifiers or names asserted for the subject.'],
  entitlements: ['Entitlements', 'Authorisation entitlements asserted for the subject/client.'],
  email: ['Email', 'Email address claim.'],
  email_verified: ['Email Verified', 'Issuer statement about whether the email address has been verified.'],
  name: ['Display Name', 'Human-readable name claim.'],
  given_name: ['Given Name', 'Given/first name.'],
  family_name: ['Family Name', 'Family/surname.'],
  preferred_username: ['Preferred Username', 'Human-readable preferred username.'],
  oid: ['Object ID', 'Provider-specific object identifier commonly used by Microsoft identity systems.'],
  tid: ['Tenant ID', 'Provider-specific tenant identifier commonly used by Microsoft identity systems.'],
  idp: ['Identity Provider', 'Provider-specific identity-provider identifier.'],
};

const URI_ALIASES = {
  'http://schemas.microsoft.com/ws/2008/06/identity/claims/role': 'roles',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role': 'roles',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'email',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'name',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier': 'sub',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn': 'preferred_username',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': 'given_name',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': 'family_name',
  'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups': 'groups',
  'http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod': 'amr',
  'http://schemas.microsoft.com/identity/claims/objectidentifier': 'oid',
  'http://schemas.microsoft.com/identity/claims/tenantid': 'tid',
  'http://schemas.microsoft.com/identity/claims/identityprovider': 'idp',
};

const SIMPLE_ALIASES = {
  scp: 'scope',
  role: 'roles',
  upn: 'preferred_username',
};

export function canonicalClaimName(name, customMapping = {}) {
  const value = String(name ?? '');
  if (customMapping && typeof customMapping === 'object' && typeof customMapping[value] === 'string' && customMapping[value]) return customMapping[value];
  if (URI_ALIASES[value]) return URI_ALIASES[value];
  if (SIMPLE_ALIASES[value]) return SIMPLE_ALIASES[value];
  return value;
}

export function claimInfo(name, customMapping = {}) {
  const canonical = canonicalClaimName(name, customMapping);
  const entry = DICTIONARY[canonical];
  return {
    canonical,
    title: entry?.[0] ?? canonical,
    description: entry?.[1] ?? 'No built-in semantic description is available for this claim.',
  };
}

export function parseClaimMapping(text) {
  if (!String(text ?? '').trim()) return {};
  const parsed = JSON.parse(text);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Claim mapping must be a JSON object of source-name to canonical-name strings.');
  for (const [from, to] of Object.entries(parsed)) {
    if (!from || typeof to !== 'string' || !to.trim()) throw new Error('Each claim mapping entry must map a non-empty source name to a non-empty string.');
  }
  return Object.fromEntries(Object.entries(parsed).map(([from, to]) => [from, to.trim()]));
}

export const SET_LIKE_CLAIMS = new Set(['aud', 'scope', 'roles', 'groups', 'entitlements', 'amr']);

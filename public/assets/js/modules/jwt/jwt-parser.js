import { base64UrlToBytes, base64UrlToText } from '../encoding/base64url.js';

function parseObject(segment, label) {
  let text;
  try {
    text = base64UrlToText(segment);
  } catch (error) {
    throw new Error(`${label} is not valid Base64URL UTF-8: ${error.message}`);
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`);
  }
  if (!value || Array.isArray(value) || typeof value !== 'object') {
    throw new Error(`${label} must decode to a JSON object.`);
  }
  return { value, text };
}

export function parseJwt(token) {
  const compact = String(token ?? '').trim();
  const parts = compact.split('.');
  if (parts.length !== 3) throw new Error('A compact JWS/JWT must contain exactly three segments.');
  if (parts.some((part) => !/^[A-Za-z0-9_-]*$/.test(part))) throw new Error('JWT contains characters outside Base64URL encoding.');

  const header = parseObject(parts[0], 'JOSE header');
  const payload = parseObject(parts[1], 'JWT payload');
  const signature = base64UrlToBytes(parts[2]);

  return {
    kind: 'jwt',
    compact,
    encoded: { header: parts[0], payload: parts[1], signature: parts[2] },
    signingInput: new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    header: header.value,
    claims: payload.value,
    raw: { header: header.text, payload: payload.text },
    signature,
  };
}

export function looksLikeOpenIdFederationEntityStatement(claims) {
  return Boolean(claims && typeof claims === 'object' && claims.iss && claims.sub && (claims.metadata || claims.authority_hints || claims.jwks));
}

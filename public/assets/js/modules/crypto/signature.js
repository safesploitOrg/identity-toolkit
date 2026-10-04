function algorithmForJws(alg) {
  const map = {
    RS256: { import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, verify: { name: 'RSASSA-PKCS1-v1_5' } },
    RS384: { import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }, verify: { name: 'RSASSA-PKCS1-v1_5' } },
    RS512: { import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }, verify: { name: 'RSASSA-PKCS1-v1_5' } },
    PS256: { import: { name: 'RSA-PSS', hash: 'SHA-256' }, verify: { name: 'RSA-PSS', saltLength: 32 } },
    PS384: { import: { name: 'RSA-PSS', hash: 'SHA-384' }, verify: { name: 'RSA-PSS', saltLength: 48 } },
    PS512: { import: { name: 'RSA-PSS', hash: 'SHA-512' }, verify: { name: 'RSA-PSS', saltLength: 64 } },
    ES256: { import: { name: 'ECDSA', namedCurve: 'P-256' }, verify: { name: 'ECDSA', hash: 'SHA-256' } },
    ES384: { import: { name: 'ECDSA', namedCurve: 'P-384' }, verify: { name: 'ECDSA', hash: 'SHA-384' } },
    ES512: { import: { name: 'ECDSA', namedCurve: 'P-521' }, verify: { name: 'ECDSA', hash: 'SHA-512' } },
    EdDSA: { import: { name: 'Ed25519' }, verify: { name: 'Ed25519' } },
  };
  return map[alg] ?? null;
}

export async function verifyCompactJws(parsedJwt, jwk) {
  const alg = parsedJwt?.header?.alg;
  if (!alg) return { supported: false, valid: null, detail: 'No alg header is present.' };
  if (alg === 'none') return { supported: false, valid: false, detail: 'Unsecured JWS alg=none is not verified.' };
  if (alg.startsWith('HS')) return { supported: false, valid: null, detail: 'HMAC verification is intentionally not supported in this public-key troubleshooting workflow.' };

  const spec = algorithmForJws(alg);
  if (!spec) return { supported: false, valid: null, detail: `Algorithm ${alg} is not supported by this version.` };
  if (!globalThis.crypto?.subtle) return { supported: false, valid: null, detail: 'Web Crypto is not available in this environment.' };

  try {
    const key = await globalThis.crypto.subtle.importKey('jwk', jwk, spec.import, false, ['verify']);
    const valid = await globalThis.crypto.subtle.verify(spec.verify, key, parsedJwt.signature, parsedJwt.signingInput);
    return { supported: true, valid, detail: valid ? 'Signature verified with the supplied JWK.' : 'Signature verification failed with the supplied JWK.' };
  } catch (error) {
    return { supported: false, valid: null, detail: `Key import or signature verification failed: ${error.message}` };
  }
}

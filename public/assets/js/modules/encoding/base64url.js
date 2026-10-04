export function base64UrlToBytes(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error('Invalid Base64URL input.');
  }
  const pad = value.length % 4;
  if (pad === 1) throw new Error('Invalid Base64URL length.');
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/') + (pad === 2 ? '==' : pad === 3 ? '=' : '');
  if (typeof atob === 'function') {
    const binary = atob(base64);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  }
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

export function base64UrlToText(value) {
  return new TextDecoder('utf-8', { fatal: true }).decode(base64UrlToBytes(value));
}

export function bytesToBase64Url(bytes) {
  let base64;
  if (typeof btoa === 'function') {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    base64 = btoa(binary);
  } else {
    base64 = Buffer.from(bytes).toString('base64');
  }
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

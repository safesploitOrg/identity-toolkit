import { finding, SEVERITY } from './findings.js';

export function numericDateToDate(value) {
  return Number.isFinite(value) ? new Date(value * 1000) : null;
}

export function analyseJwtTimes(claims, now = new Date(), clockSkewSeconds = 300) {
  const findings = [];
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const skew = Math.max(0, Number(clockSkewSeconds) || 0);

  if (Number.isFinite(claims.exp)) {
    if (nowSeconds - skew >= claims.exp) {
      findings.push(finding('jwt.expired', SEVERITY.ERROR, 'Token has expired', 'The exp claim is earlier than the current time outside the configured clock-skew allowance.', { exp: claims.exp }));
    } else {
      findings.push(finding('jwt.exp.valid', SEVERITY.PASS, 'Token is not expired', 'The exp claim is later than the current time.', { exp: claims.exp }));
    }
  } else {
    findings.push(finding('jwt.exp.missing', SEVERITY.WARNING, 'No expiration claim', 'No numeric exp claim is present. Whether exp is mandatory depends on the token profile.'));
  }

  if (Number.isFinite(claims.nbf)) {
    if (nowSeconds + skew < claims.nbf) {
      findings.push(finding('jwt.nbf.future', SEVERITY.ERROR, 'Token is not valid yet', 'The nbf claim is later than the current time outside the configured clock-skew allowance.', { nbf: claims.nbf }));
    } else {
      findings.push(finding('jwt.nbf.valid', SEVERITY.PASS, 'Not-before condition satisfied', 'The current time is on or after nbf within the configured clock-skew allowance.', { nbf: claims.nbf }));
    }
  }

  if (Number.isFinite(claims.iat) && claims.iat > nowSeconds + skew) {
    findings.push(finding('jwt.iat.future', SEVERITY.WARNING, 'Issued-at time is in the future', 'The iat claim is later than the current time outside the configured clock-skew allowance.', { iat: claims.iat }));
  }

  return findings;
}

export function analyseXmlWindow(notBefore, notOnOrAfter, now = new Date(), clockSkewSeconds = 300) {
  const findings = [];
  const skewMs = Math.max(0, Number(clockSkewSeconds) || 0) * 1000;
  const current = now.getTime();
  const start = notBefore ? Date.parse(notBefore) : NaN;
  const end = notOnOrAfter ? Date.parse(notOnOrAfter) : NaN;

  if (notBefore && Number.isNaN(start)) findings.push(finding('xml.time.notbefore.invalid', SEVERITY.WARNING, 'Invalid NotBefore value', 'The NotBefore value is not a valid date-time.'));
  if (notOnOrAfter && Number.isNaN(end)) findings.push(finding('xml.time.notonorafter.invalid', SEVERITY.WARNING, 'Invalid NotOnOrAfter value', 'The NotOnOrAfter value is not a valid date-time.'));
  if (Number.isFinite(start) && current + skewMs < start) findings.push(finding('xml.time.future', SEVERITY.ERROR, 'Assertion is not valid yet', 'The current time is before NotBefore outside the clock-skew allowance.'));
  if (Number.isFinite(end) && current - skewMs >= end) findings.push(finding('xml.time.expired', SEVERITY.ERROR, 'Assertion has expired', 'The current time is on or after NotOnOrAfter outside the clock-skew allowance.'));
  if (Number.isFinite(start) && Number.isFinite(end) && current + skewMs >= start && current - skewMs < end) findings.push(finding('xml.time.valid', SEVERITY.PASS, 'Assertion time window is current', 'The current time is within the supplied Conditions window.'));
  return findings;
}

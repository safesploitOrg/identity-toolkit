export const SEVERITY = Object.freeze({
  PASS: 'pass',
  INFO: 'info',
  WARNING: 'warning',
  ERROR: 'error',
  INDETERMINATE: 'indeterminate',
});

export function finding(id, severity, title, detail, evidence = undefined) {
  return { id, severity, title, detail, ...(evidence === undefined ? {} : { evidence }) };
}

export function overallFromFindings(findings) {
  if (findings.some((item) => item.severity === SEVERITY.ERROR)) return 'error';
  if (findings.some((item) => item.severity === SEVERITY.WARNING)) return 'warning';
  if (findings.some((item) => item.severity === SEVERITY.INDETERMINATE)) return 'indeterminate';
  return 'pass';
}

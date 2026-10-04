function display(value) {
  if (value === null || value === undefined || value === '') return '(not present)';
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}

export function buildDiagnosticReport(result) {
  const lines = [
    'IDENTITY TOOLKIT DIAGNOSTIC REPORT',
    '==================================',
    '',
    `Detected type: ${result.detected?.label ?? result.kind}`,
    `Analysis profile: ${result.profile ?? 'automatic'}`,
    `Generated: ${new Date().toISOString()}`,
    '',
    'Summary',
    '-------',
  ];
  for (const [name, value] of Object.entries(result.summary ?? {})) lines.push(`${name}: ${display(value)}`);
  lines.push('', 'Findings', '--------');
  for (const item of result.findings ?? []) lines.push(`${item.severity.toUpperCase().padEnd(13)} ${item.title} - ${item.detail}`);
  if (result.claims?.length) {
    lines.push('', 'Claims', '------');
    for (const claim of result.claims) lines.push(`${claim.canonical}${claim.name !== claim.canonical ? ` [source: ${claim.name}]` : ''}: ${display(claim.value)}`);
  }
  if (result.signature) {
    lines.push('', 'Signature', '---------', `valid: ${display(result.signature.valid)}`, `provenance: ${display(result.signature.provenance)}`, `detail: ${display(result.signature.detail)}`);
  }
  lines.push('', 'Privacy', '-------', 'Raw bearer tokens/assertions are intentionally excluded from this report.', '', 'Identity Toolkit v0.6.0-alpha.1');
  return lines.join('\n');
}

function element(tag, className = '', text = '') {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== '') node.textContent = text;
  return node;
}

export function clearNode(node) {
  node.replaceChildren();
}

function stringify(value) {
  if (value === null || value === undefined || value === '') return '—';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isFinite(value) && value > 946684800 && value < 4102444800) {
    return `${value} (${new Date(value * 1000).toISOString()})`;
  }
  return JSON.stringify(value, null, Array.isArray(value) || typeof value === 'object' ? 2 : 0);
}

export function renderSummary(container, summary) {
  clearNode(container);
  for (const [name, value] of Object.entries(summary ?? {})) {
    const card = element('article', 'summary-item');
    card.append(element('span', 'summary-label', name.replace(/([A-Z])/g, ' $1').replace(/^./, (char) => char.toUpperCase())));
    card.append(element('strong', 'summary-value', stringify(value)));
    container.append(card);
  }
}

export function renderFindings(container, findings) {
  clearNode(container);
  for (const item of findings ?? []) {
    const article = element('article', `finding finding-${item.severity}`);
    const badge = element('span', `finding-badge ${item.severity}`, item.severity.toUpperCase());
    const body = element('div', 'finding-body');
    body.append(element('strong', '', item.title));
    body.append(element('p', '', item.detail));
    if (item.evidence !== undefined) {
      const details = element('details', 'finding-evidence');
      details.append(element('summary', '', 'Evidence'));
      details.append(element('pre', 'code-output compact', stringify(item.evidence)));
      body.append(details);
    }
    article.append(badge, body);
    container.append(article);
  }
}

export function renderClaims(container, claims) {
  clearNode(container);
  if (!claims?.length) {
    container.append(element('p', 'muted', 'No claim/attribute set was extracted from this artefact.'));
    return;
  }
  const table = element('table', 'data-table');
  const thead = element('thead');
  const header = element('tr');
  for (const title of ['Claim', 'Value', 'Meaning']) header.append(element('th', '', title));
  thead.append(header);
  const tbody = element('tbody');
  for (const claim of claims) {
    const row = element('tr');
    const name = element('td');
    name.append(element('strong', '', claim.canonical));
    if (claim.name !== claim.canonical) name.append(element('small', 'muted block', `Source: ${claim.name}`));
    row.append(name, element('td', 'mono-cell', stringify(claim.value)), element('td', '', claim.description));
    tbody.append(row);
  }
  table.append(thead, tbody);
  container.append(table);
}

function appendJsonDetails(container, title, value) {
  const details = element('details');
  details.append(element('summary', '', title), element('pre', 'code-output', JSON.stringify(value, null, 2)));
  container.append(details);
}

export function renderRaw(container, result) {
  clearNode(container);
  if (result.kind === 'jwt' || result.kind === 'openid-federation') {
    appendJsonDetails(container, 'Decoded JOSE header', result.parsed.header);
    appendJsonDetails(container, 'Decoded payload', result.parsed.claims);
    if (result.signature) appendJsonDetails(container, 'Signature verification result', result.signature);
    return;
  }
  if (result.kind === 'oidc-discovery') {
    appendJsonDetails(container, 'Provider metadata', result.raw);
    appendJsonDetails(container, 'Normalised capabilities', result.capabilities ?? {});
    return;
  }
  if (result.kind === 'jwks') {
    appendJsonDetails(container, 'JWKS/JWK inspection', result.summary);
    appendJsonDetails(container, 'Parsed JSON', result.raw);
    return;
  }
  if (result.kind === 'saml') {
    appendJsonDetails(container, 'Parsed SAML Response / Assertion', {
      summary: result.parsed?.summary,
      assertions: result.parsed?.assertions,
      signatures: result.parsed?.signatures,
      duplicateIds: result.parsed?.duplicateIds,
      xmlSignatureVerification: result.verification?.results,
    });
  } else if (result.kind === 'saml-metadata') {
    appendJsonDetails(container, 'Parsed SAML metadata', { entities: result.entities, xmlSignatureVerification: result.verification?.results });
  } else if (result.kind === 'wsfed') {
    appendJsonDetails(container, 'Parsed WS-Federation / WS-Trust response', {
      summary: result.parsed?.summary,
      responses: (result.parsed?.responses ?? []).map((response) => ({
        summary: response.summary,
        claims: response.claims,
        saml2: response.saml?.assertions ?? null,
        saml11: response.saml11?.assertion ?? null,
      })),
    });
  }
  const details = element('details');
  details.append(element('summary', '', 'Raw XML input'), element('pre', 'code-output', String(result.raw ?? '')));
  container.append(details);
}

export function renderStatusPill(node, status) {
  node.className = `status-pill ${status}`;
  node.textContent = status === 'pass' ? 'No blocking findings' : status === 'error' ? 'Errors found' : status === 'warning' ? 'Warnings found' : 'Indeterminate';
}

export function renderDiff(container, diff, leftLabel = 'Left', rightLabel = 'Right') {
  clearNode(container);
  const table = element('table', 'data-table diff-table');
  const thead = element('thead');
  const header = element('tr');
  for (const title of ['Field / claim', leftLabel, rightLabel, 'Status']) header.append(element('th', '', title));
  thead.append(header);
  const tbody = element('tbody');
  for (const item of diff) {
    const row = element('tr', `diff-${item.status}`);
    const label = item.title && item.title !== item.name ? `${item.name}\n${item.title}` : item.name;
    row.append(
      element('td', '', label),
      element('td', 'mono-cell', stringify(item.left)),
      element('td', 'mono-cell', stringify(item.right)),
      element('td', '', item.status.toUpperCase()),
    );
    tbody.append(row);
  }
  table.append(thead, tbody);
  container.append(table);
}

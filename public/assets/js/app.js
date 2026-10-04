import { analyseArtifact } from './modules/analyse.js';
import { buildMigrationReport, compareClaims } from './modules/claims/claim-diff.js';
import { parseClaimMapping } from './modules/claims/claim-dictionary.js';
import { buildFederationMigrationReport, compareFederation } from './modules/federation/federation-compare.js';
import { buildDiagnosticReport } from './modules/report.js';
import { clearNode, renderClaims, renderDiff, renderFindings, renderRaw, renderStatusPill, renderSummary } from './modules/render.js';

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

function currentRoute() {
  const route = location.hash.replace(/^#/, '') || 'inspect';
  return ['inspect', 'compare', 'federation', 'security'].includes(route) ? route : 'inspect';
}

function renderRoute() {
  const route = currentRoute();
  $$('.route').forEach((section) => section.classList.toggle('hidden', section.dataset.route !== route));
  $$('[data-route-link]').forEach((link) => link.classList.toggle('active', link.dataset.routeLink === route));
}

function setError(selector, message = '') {
  const node = $(selector);
  node.textContent = message;
  node.classList.toggle('hidden', !message);
}

function analysisOptions(prefix = '') {
  const id = (name) => $(`#${prefix}${name}`);
  const maxAgeValue = id('max-auth-age')?.value;
  return {
    profile: id('profile')?.value ?? 'auto',
    oauthProfile: id('oauth-profile')?.value ?? 'auto',
    verificationMaterial: id('verification')?.value ?? '',
    expectedIssuer: id('expected-issuer')?.value.trim() ?? '',
    expectedAudience: id('expected-audience')?.value.trim() ?? '',
    expectedNonce: id('expected-nonce')?.value ?? '',
    relatedAccessToken: id('related-access-token')?.value ?? '',
    relatedAuthorizationCode: id('related-authorization-code')?.value ?? '',
    maxAuthenticationAgeSeconds: maxAgeValue === '' || maxAgeValue === undefined ? undefined : Number(maxAgeValue),
    expectedRecipient: id('expected-recipient')?.value.trim() ?? '',
    expectedInResponseTo: id('expected-in-response-to')?.value.trim() ?? '',
    clockSkewSeconds: Number(id('clock-skew')?.value ?? 300),
  };
}

async function analyseMain(event) {
  event.preventDefault();
  setError('#inspect-error');
  const input = $('#artifact-input').value;
  if (!input.trim()) return setError('#inspect-error', 'Paste an identity artefact first.');
  $('#analyse-button').disabled = true;
  try {
    const result = await analyseArtifact(input, analysisOptions());
    $('#detected-type').textContent = result.detected.label;
    renderStatusPill($('#overall-status'), result.overall);
    renderSummary($('#summary-grid'), result.summary);
    renderFindings($('#finding-list'), result.findings);
    renderClaims($('#claim-results'), result.claims);
    renderRaw($('#raw-results'), result);
    const report = buildDiagnosticReport(result);
    $('#report-output').textContent = report;
    $('#results').classList.remove('hidden');
    $('#results').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) {
    $('#results').classList.add('hidden');
    setError('#inspect-error', error.message);
  } finally {
    $('#analyse-button').disabled = false;
  }
}

function clearInspect() {
  for (const id of ['artifact-input', 'verification', 'expected-issuer', 'expected-audience', 'expected-nonce', 'related-access-token', 'related-authorization-code', 'max-auth-age', 'expected-recipient', 'expected-in-response-to']) {
    const node = $(`#${id}`);
    if (node) node.value = '';
  }
  $('#profile').value = 'auto';
  $('#oauth-profile').value = 'auto';
  $('#clock-skew').value = '300';
  $('#results').classList.add('hidden');
  $('#detected-type').textContent = 'Not analysed';
  setError('#inspect-error');
}

async function compareClaimSets(event) {
  event.preventDefault();
  setError('#compare-error');
  try {
    const leftText = $('#compare-left').value.trim();
    const rightText = $('#compare-right').value.trim();
    if (!leftText || !rightText) throw new Error('Paste both source and target identity artefacts.');
    const mapping = parseClaimMapping($('#claim-mapping').value);
    const [left, right] = await Promise.all([
      analyseArtifact(leftText, { profile: 'auto' }),
      analyseArtifact(rightText, { profile: 'auto' }),
    ]);
    if (!left.claims?.length && !right.claims?.length) throw new Error('Neither artefact exposed a claim/attribute set suitable for comparison.');
    const diff = compareClaims(left.claims ?? [], right.claims ?? [], mapping);
    const migration = buildMigrationReport(left, right, diff, mapping);
    renderDiff($('#claim-diff-results'), diff, left.detected.label, right.detected.label);
    renderSummary($('#migration-summary'), migration.counts);
    $('#migration-report-output').textContent = migration.text;
    $('#compare-result').classList.remove('hidden');
  } catch (error) {
    $('#compare-result').classList.add('hidden');
    setError('#compare-error', error.message);
  }
}

async function compareFederationInputs(event) {
  event.preventDefault();
  setError('#federation-error');
  try {
    const leftText = $('#federation-left').value.trim();
    const rightText = $('#federation-right').value.trim();
    if (!leftText) throw new Error('Paste at least one federation configuration document.');
    const left = await analyseArtifact(leftText, { profile: 'auto' });
    renderSummary($('#federation-left-summary'), left.summary ?? {});
    renderFindings($('#federation-left-findings'), left.findings ?? []);
    if (rightText) {
      const right = await analyseArtifact(rightText, { profile: 'auto' });
      renderSummary($('#federation-right-summary'), right.summary ?? {});
      renderFindings($('#federation-right-findings'), right.findings ?? []);
      const comparison = await compareFederation(left, right);
      renderDiff($('#federation-diff'), comparison.rows, left.detected.label, right.detected.label);
      const migrationSummary = {
        changedFields: comparison.changedFields.length,
        issuerMigration: comparison.issuerMigration?.classification ?? 'none',
        keyRotation: comparison.keyRotation?.classification ?? 'not applicable',
        retainedKeys: comparison.keyRotation?.retained ?? [],
        addedKeys: comparison.keyRotation?.added ?? [],
        removedKeys: comparison.keyRotation?.removed ?? [],
      };
      renderSummary($('#federation-migration-summary'), migrationSummary);
      $('#federation-report-output').textContent = buildFederationMigrationReport(left, right, comparison);
      $('#federation-right-result').classList.remove('hidden');
      $('#federation-diff-panel').classList.remove('hidden');
      $('#federation-migration-panel').classList.remove('hidden');
    } else {
      clearNode($('#federation-right-summary'));
      clearNode($('#federation-right-findings'));
      $('#federation-right-result').classList.add('hidden');
      $('#federation-diff-panel').classList.add('hidden');
      $('#federation-migration-panel').classList.add('hidden');
    }
    $('#federation-result').classList.remove('hidden');
  } catch (error) {
    $('#federation-result').classList.add('hidden');
    setError('#federation-error', error.message);
  }
}

async function copyText(text, button) {
  await navigator.clipboard.writeText(text);
  const original = button.textContent;
  button.textContent = 'Copied';
  setTimeout(() => { button.textContent = original; }, 1200);
}

function downloadText(filename, text) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

window.addEventListener('hashchange', renderRoute);
$('#inspect-form').addEventListener('submit', analyseMain);
$('#clear-button').addEventListener('click', clearInspect);
$('#compare-form').addEventListener('submit', compareClaimSets);
$('#federation-form').addEventListener('submit', compareFederationInputs);
$('#copy-report').addEventListener('click', () => copyText($('#report-output').textContent, $('#copy-report')));
$('#download-report').addEventListener('click', () => downloadText('identity-toolkit-report.txt', $('#report-output').textContent));
$('#copy-migration-report').addEventListener('click', () => copyText($('#migration-report-output').textContent, $('#copy-migration-report')));
$('#download-migration-report').addEventListener('click', () => downloadText('identity-toolkit-claims-migration-report.txt', $('#migration-report-output').textContent));
$('#copy-federation-report').addEventListener('click', () => copyText($('#federation-report-output').textContent, $('#copy-federation-report')));
$('#download-federation-report').addEventListener('click', () => downloadText('identity-toolkit-federation-migration-report.txt', $('#federation-report-output').textContent));

renderRoute();

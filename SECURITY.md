# Security

## Objective

Identity Toolkit is designed for troubleshooting artefacts that may contain personal data, internal tenant/application identifiers and live bearer credentials. The public application therefore minimises network, persistence and implicit-trust paths by design.

## Runtime boundary

The deployed application is static HTML/CSS/JavaScript under `public/`.

It intentionally has:

- no backend;
- no analytics or telemetry;
- no CDN-hosted runtime JavaScript;
- CSP `connect-src 'none'`;
- no first-party fetch/XHR/WebSocket/EventSource path;
- no localStorage/sessionStorage/IndexedDB use;
- no raw bearer token/assertion in generated reports.

The GitHub Actions security assertion rejects new first-party browser network APIs and remote runtime script/stylesheet dependencies.

## Untrusted URLs

JWT/OIDC/SAML/federation material may contain attacker-controlled URLs such as:

- `jku` / `x5u`;
- issuer/discovery locations;
- `jwks_uri`;
- authorization/token/userinfo endpoints;
- SAML SSO/SLO/ACS endpoints;
- OpenID Federation authority hints, trust-anchor hints and source endpoints.

These values are parsed and reported but never automatically contacted. This avoids CORS dependence, SSRF-like browser side effects, metadata leakage and attacker-directed key retrieval.

## JWT / JOSE

JWT signature verification uses Web Crypto and explicitly supplied JWK/JWKS material.

A positive signature result establishes only that the compact JWS signing input verifies with the selected key. It does not establish that:

- the key belongs to the claimed issuer;
- the issuer is trusted;
- the token is the right token type for the receiving endpoint;
- issuer/audience/nonce/time semantics are correct;
- the token is currently acceptable under application policy.

Additional protections include:

- `alg=none` is never treated as verified;
- unsupported JOSE `crit` parameters produce an indeterminate result;
- `b64=false` is not signature-verified until its altered signing semantics are explicitly implemented;
- JWK candidates are filtered by key type, `use`, `key_ops`, `kid` and algorithm family;
- `jku`, `x5u`, embedded JWK and embedded certificate material do not become trusted merely because they appear in the token.

Symmetric HMAC verification is intentionally excluded from the public troubleshooting workflow to avoid encouraging users to paste shared signing secrets.

## OIDC / OAuth

Request-side context is required for several meaningful OIDC checks. Identity Toolkit therefore accepts explicit expected values rather than inventing them:

- expected issuer;
- expected audience/client;
- expected nonce;
- maximum authentication age;
- related access token for `at_hash`;
- related authorisation code for `c_hash`.

`acr` and `amr` are issuer assertions. The UI reports them without claiming the browser independently observed the authentication event.

OAuth bearer tokens may themselves be live credentials. The tool deliberately does not attempt to call APIs with them. Refresh-token workflows are outside the public-app scope.

## XML / SAML / WS-Federation

XML input is untrusted.

Current protections include:

- `DOCTYPE` and `ENTITY` declarations are rejected;
- parsing is namespace-aware for SAML 2.0 and XMLDSig elements;
- duplicate `ID` / `Id` / `id` values are errors;
- XMLDSig `Reference` URIs pointing outside the current document are rejected;
- external XML resources are never fetched;
- signed-parent and Response/Assertion reference coverage is reported separately from cryptographic verification;
- multiple and encrypted assertions are surfaced rather than silently selecting/decrypting them;
- explicit expected Destination/Recipient/InResponseTo values are compared when supplied;
- dynamic output uses DOM `textContent` rather than injecting untrusted identity strings as HTML.

XMLDSig remains a high-risk parser/validation area. A cryptographically valid signature does not establish certificate trust or prove that a relying party will consume exactly the intended signed element. The code therefore keeps signature validity, reference coverage, SAML semantic checks and signer trust separate. A larger signature-wrapping/adversarial corpus remains required before stable 1.0.

WS-Fed/WS-Trust embeds older XML/SAML structures in some deployments. Its parser reuses the SAML 2.0 implementation where possible and has a separate narrow SAML 1.x parser for enterprise migration diagnostics; it does not claim complete WS-Trust conformance.

## OpenID Federation

OpenID Federation Entity Statements are signed JWTs but trust is transitive and policy-driven.

For an Entity Configuration, Identity Toolkit can verify self-consistency using the Entity's own published `jwks` claim. A successful result means only that the statement is self-signed consistently with those keys.

It does **not** establish a trusted federation path. Full trust-chain construction, Trust Anchor selection, metadata-policy application and Trust Mark issuer trust remain separate/future validation dimensions.

`authority_hints`, `trust_anchor_hints`, `source_endpoint` and embedded chain hints are never automatically dereferenced.

## Claims / migration reports

Claim comparison can normalise names and values, but equivalent-looking claim values do not prove equivalent authorisation behaviour in an application.

User-defined mappings are applied only to the current in-memory comparison. They are not persisted.

Diagnostic and migration reports exclude the original raw token/assertion. Individual claims can still contain sensitive personal or organisational information, so reports must be reviewed before external sharing.

## xmldsigjs supply chain

Identity Toolkit uses `xmldsigjs` **2.8.8** from Peculiar Ventures under the MIT licence.

Runtime policy:

- the package and known runtime dependencies are exactly pinned in `package.json` / overrides;
- the browser bundle is generated locally under `public/assets/js/external/` during the build;
- the upstream licence is included alongside it;
- `vendor-manifest.json` records package/upstream provenance plus SHA-384 in Base64/SRI and hexadecimal form;
- `index.html` loads the local bundle with the same SRI value;
- CI recalculates SHA-384 from the exact deployment bytes and fails if bundle, manifest and HTML SRI disagree.

SRI is deliberately used for the same-origin local resource as an additional immutability assertion. It does not replace source review, exact pinning, upstream provenance review or dependency vulnerability monitoring.

## Clipboard / downloads

Clipboard writes and report downloads occur only after explicit user actions.

Generated reports do not contain raw credential artefacts by default.

## Browser memory

Identity Toolkit makes no claim of secure zeroisation of JavaScript memory. Garbage-collected browser environments cannot guarantee immediate forensic erasure of every temporary string/buffer.

The security claim is **no deliberate persistence or transmission**, not guaranteed physical memory sanitisation.

## Reporting vulnerabilities

Do not paste production bearer tokens, refresh tokens, private keys or shared signing secrets into public GitHub issues. Reproduce problems with disposable fixtures wherever possible.

# Identity Toolkit

Browser-only identity, claims and federation diagnostics for JWT/JOSE, OpenID Connect, OAuth 2.0, SAML 2.0, WS-Federation / WS-Trust and OpenID Federation.

> **Status:** `v0.6.0-alpha.2` — the planned v0.2–v0.6 analysis surfaces are implemented. The project remains pre-1.0 while adversarial corpora, complete profile conformance and trust-chain workflows are hardened.

## Principles

- Static HTML/CSS/JavaScript deployable on GitHub Pages.
- Identity artefacts remain in the current browser tab.
- No backend, analytics or telemetry.
- `connect-src 'none'`; URLs embedded in artefacts are never automatically contacted.
- **Decoded ≠ semantically valid ≠ cryptographically verified ≠ trusted.** These dimensions are reported separately.
- Cryptographic primitives use Web Crypto or mature libraries rather than home-grown implementations.
- SAML XML Digital Signature verification uses a locally generated/vendored `xmldsigjs` 2.8.8 browser bundle.
- Cross-protocol comparison operates on normalised claims rather than provider-specific UI logic.

## Implemented capability

### v0.1 — JWT / JOSE foundation

- Compact JWS/JWT parsing and Base64URL handling.
- JOSE header and claims inspection.
- `exp`, `nbf`, `iat`, expected issuer and expected audience checks.
- Critical-header and `b64=false` conservative handling.
- Local JWK/JWKS signature verification for supported asymmetric algorithms.
- `jku`, `x5u`, embedded `jwk` and `x5c` security observations without network access.
- Explicit indeterminate state when signing material is missing, ambiguous or incompatible.

### v0.2 — OIDC / OAuth

- OIDC ID-token validation profile.
- Required OIDC claim checks.
- Multi-audience / `azp` semantics.
- Expected `nonce` validation.
- `auth_time` and maximum-authentication-age checks.
- `acr` / `amr` interpretation without pretending to observe the authentication event.
- Optional `at_hash` and `c_hash` verification from supplied related artefacts.
- OAuth access-token analysis for scopes, roles, groups, entitlements and client identity.
- RFC 9068 JWT access-token profile mode, including `at+jwt` typing, required claims, `alg=none` rejection and asymmetric-signing guidance.
- `cnf`, `act` and `may_act` observations.
- OIDC Discovery inspection: issuer/endpoints, conditional Token Endpoint requirements for code flows, required capability arrays, signing algorithms, scopes, PKCE, front-channel token/implicit-flow warnings and advertised client authentication methods.
- JWKS inspection: duplicate/missing `kid`, key type/use/operations and accidental private/symmetric key material.

### v0.3 — SAML 2.0

- SAML Response and standalone Assertion parsing.
- Response Status, Destination, InResponseTo, issuer and issue time.
- Subject / NameID and NameID format.
- SubjectConfirmation and SubjectConfirmationData recipient/time/InResponseTo checks.
- Conditions with time windows, separate AudienceRestriction groups, OneTimeUse and ProxyRestriction.
- Multiple AuthnStatement support including AuthnContext and SessionIndex.
- AttributeStatement extraction including multi-valued attributes.
- Multiple/encrypted assertion detection.
- SAML metadata inspection for IdP/SP/AA/AuthnAuthority/PDP roles, endpoints, NameID formats, requested attributes, validity and signing/encryption certificates.
- Duplicate XML ID detection and namespace-aware parsing.
- DTD/ENTITY rejection and rejection of external XMLDSig references.
- XML signature inspection: signature/reference locations, transforms, algorithms, embedded certificates/key names and signed-element coverage hints.
- Cryptographic XMLDSig verification through locally vendored `xmldsigjs`.

### v0.4 — Claims Compare

- JWT ↔ JWT, SAML ↔ JWT and WS-Fed ↔ modern-token comparison.
- Built-in aliases for common JWT and legacy Microsoft/SAML claim names.
- User-defined JSON claim mapping.
- Set-aware comparison for scopes, roles, groups, entitlements, audience and AMR values.
- Added/removed/changed/mapped/same classifications.
- High-impact claim highlighting.
- Downloadable/copyable claims-migration report.

### v0.5 — WS-Federation / WS-Trust

- `RequestSecurityTokenResponse` and response-collection parsing.
- Token type, request type, AppliesTo, Lifetime, key type/key size, ComputedKey and token references.
- Embedded SAML 2.0 assertion analysis.
- Embedded SAML 1.x assertion parsing for older enterprise / AD FS-style deployments.
- Audience and lifetime comparisons.
- WS-Fed claims feed directly into the Claims Compare migration workflow.

### v0.6 — Advanced federation analysis

- OIDC provider metadata comparison.
- JWKS comparison and signing-key rotation classification.
- SAML metadata comparison and signing-certificate rotation identifiers.
- Issuer / SAML EntityID migration detection.
- Field-by-field federation configuration diffing.
- Downloadable/copyable federation-migration report.
- OpenID Federation 1.0 Entity Statement analysis:
  - `entity-statement+jwt` typing and signing-header checks;
  - Entity Configuration vs Subordinate Statement classification;
  - `iss`, `sub`, `iat`, `exp`, `jwks` and key-ID checks;
  - `authority_hints` / `trust_anchor_hints`;
  - Entity Type metadata;
  - `metadata_policy`, `constraints` and critical-extension observations;
  - Trust Mark structural inspection;
  - optional `trust_chain` / `peer_trust_chain` header shape inspection;
  - self-contained Entity Configuration signature verification against its published `jwks`, reported as self-consistency rather than trust.

## Validation model

Identity Toolkit deliberately avoids a single green/red answer for identity artefacts.

For example, a JWT can be:

```text
structurally decoded
        |
        +-- time-valid
        +-- expected issuer/audience match
        +-- protocol profile-valid
        +-- cryptographic signature verifies
        +-- signing key provenance trusted
```

Those are separate questions. Likewise, a SAML XML signature can be cryptographically valid while the wrong element is consumed by a relying party, the audience is wrong, or the signing certificate is not trusted.

## Local third-party dependency and SRI

`xmldsigjs` is never loaded from a CDN at runtime.

The generated browser bundle is written to:

```text
public/assets/js/external/xmldsigjs-2.8.8.bundle.js
```

`npm run vendor:xmldsig`:

1. bundles the exact pinned `xmldsigjs` package and runtime dependencies for the browser;
2. copies the upstream MIT licence;
3. calculates SHA-384;
4. writes `vendor-manifest.json` with provenance and digest data;
5. writes the matching local `<script integrity="sha384-...">` value into `public/index.html`.

`npm run verify:vendor` independently recalculates SHA-384 from the exact deployment bytes and verifies the manifest and HTML SRI value. SRI is deliberately enforced even for this same-origin/local script as an additional immutability assertion.

The source checkout contains an SRI placeholder until the vendor step runs. GitHub Pages deployment cannot proceed unless vendoring and integrity verification succeed.

## Run locally

```bash
npm install --ignore-scripts --no-audit --no-fund
npm run check
npm run serve
```

Open:

```text
http://localhost:4173
```

Core first-party tests that do not require third-party packages can be run with:

```bash
npm run check:core
```

Browser tests:

```bash
npx playwright install
npm run test:browser
```

GitHub Actions runs vendor/SRI validation, unit tests and Chromium/Firefox/WebKit browser tests before Pages deployment.

## Repository layout

```text
identity-toolkit/
├── .github/workflows/
├── public/
│   ├── index.html
│   └── assets/
│       ├── css/
│       └── js/
│           ├── app.js
│           ├── external/
│           └── modules/
│               ├── claims/
│               ├── crypto/
│               ├── federation/
│               ├── jwt/
│               ├── oauth/
│               ├── oidc/
│               ├── saml/
│               ├── validation/
│               └── wsfed/
├── scripts/
├── tests/
│   ├── browser/
│   └── unit/
├── ARCHITECTURE.md
├── CHANGELOG.md
├── ROADMAP.md
├── SECURITY.md
├── THIRD_PARTY_NOTICES.md
├── README.md
└── package.json
```

## Related project

`identity-toolkit` deliberately remains separate from `pki-toolkit`.

Identity Toolkit consumes identity-layer material such as JWTs, SAML assertions and federation metadata. PKI Toolkit handles X.509 paths, keys, CSRs and revocation. Signing certificates are an integration point between the two domains, not a reason to collapse them into one application.

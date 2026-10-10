# Changelog

All notable changes to Identity Toolkit are documented here.

The project is pre-1.0. Protocol coverage and result schemas may change while the validation model is hardened.

## [0.6.0-alpha.3] - 2026-10-10

### Fixed

- Updated `@xmldom/xmldom` from `0.8.11` to the pinned `0.9.12` release so it satisfies the `xml-core@1.2.6` peer dependency range (`^0.9.10`).
- Added an `@xmldom/xmldom` override at `0.9.12` so direct and transitive dependency resolution cannot silently select a different DOM implementation version during CI.
- Kept strict npm dependency resolution; the project does **not** use `--force` or `--legacy-peer-deps` to bypass peer-dependency errors.

### Security

- Uses the current `0.9.12` xmldom release rather than the older `0.8.11` test dependency while preserving the XML parser's DTD/ENTITY rejection and non-iterable NodeList compatibility layer.

## [0.6.0-alpha.2] - 2026-10-10

### Fixed

- Made SAML/XML child traversal compatible with both browser `NodeList` objects and `@xmldom/xmldom` array-like collections. The parser no longer assumes `childNodes` implements `Symbol.iterator`.
- Corrected Node XMLDSig test initialisation to import `setNodeDependencies()` from the pinned `xml-core` package rather than calling a non-exported `xmldsigjs.setNodeDependencies()` function.
- Added `xml-core@1.2.6` as an explicit development dependency because the XMLDSig Node test uses its public Node dependency-registration API directly.

### Tests

- Added a regression test using a deliberately non-iterable DOM-style `NodeList` so the browser/xmldom compatibility boundary is covered by the dependency-light core suite.
- Core test selection now includes the XML utility regression tests.

## [0.6.0-alpha.1] - 2026-10-02

### Added — OIDC / OAuth (`v0.2`)

- Protocol-aware OIDC ID-token analysis layered on the generic JWT parser.
- Multi-audience trust analysis plus `azp` type/presence and expected-client comparison without inventing an `azp` requirement from multi-valued `aud` alone.
- Expected nonce validation.
- `auth_time` plus optional maximum-authentication-age checks.
- `acr` / `amr` reporting.
- Optional `at_hash` and `c_hash` validation using Web Crypto.
- RFC 9068 JWT access-token profile mode with `at+jwt` typing, required claims, `alg=none` rejection and asymmetric-signing guidance.
- Scope, role, group, entitlement and client-ID extraction.
- `cnf`, `act` and `may_act` security observations.
- Expanded OIDC Discovery inspection including conditional Token Endpoint requirements, required capability arrays, PKCE S256, front-channel token/implicit-flow warnings, signing algorithms, scopes and client authentication methods.
- Expanded JWKS analysis for duplicate/missing key IDs, incompatible key purpose/operations and private/symmetric key exposure.

### Added — SAML 2.0 (`v0.3`)

- Namespace-aware Response and Assertion parsing.
- Response Status, Destination, InResponseTo, consent and issue-time extraction.
- Subject / NameID qualifiers and format.
- SubjectConfirmation / SubjectConfirmationData recipient, request-binding and time checks.
- Separate AudienceRestriction groups with every-group expected-audience evaluation.
- OneTimeUse, ProxyRestriction and unsupported-condition diagnostics.
- Multiple AuthnStatements including SessionIndex, AuthnContext class/decl refs and authenticating authorities.
- Multi-valued AttributeStatement support.
- Multiple/encrypted assertion diagnostics.
- XMLDSig structural inspection for signature parent, references, transforms, digest/signature/canonicalisation algorithms and embedded X.509 / KeyName material.
- Signed-element coverage diagnostics for Response/Assertion IDs.
- Expanded SAML metadata analysis for IdP/SP/AttributeAuthority/AuthnAuthority/PDP roles, endpoints, NameID formats, requested attributes, validity and key descriptors.

### Added — Claims Compare (`v0.4`)

- Expanded canonical claim dictionary and legacy Microsoft/SAML aliases.
- User-defined JSON claim mapping.
- Set-aware scope/role/group/entitlement/audience/AMR comparison.
- `mapped` classification for equivalent values exposed under renamed claims.
- High-impact migration findings and copy/download migration report.
- Correct WS-Fed source provenance in normalised claim data.

### Added — WS-Federation (`v0.5`)

- WS-Trust response-collection support.
- TokenType, RequestType, AppliesTo, Lifetime, KeyType, KeySize, ComputedKey and security-token-reference extraction.
- Embedded SAML 1.x assertion parser alongside existing SAML 2.0 reuse.
- Expected audience and lifetime diagnostics for enterprise migration troubleshooting.

### Added — advanced federation analysis (`v0.6`)

- OIDC metadata, JWKS and SAML metadata configuration comparison.
- Signing-key rotation classification: unchanged, overlap addition, overlap rotation, hard cutover, removal or changed.
- SAML signing-certificate comparison using local SHA-256 identifiers.
- Issuer / EntityID migration classification.
- Copy/download federation migration report.
- OpenID Federation 1.0 Entity Configuration vs Subordinate Statement analysis.
- OpenID Federation checks for required JWT/header fields, Entity Identifiers, `jwks`, authority/trust-anchor hints, metadata, metadata policy, constraints, critical extensions, Trust Marks and optional embedded trust-chain headers.
- Entity Configuration self-signature consistency verification against its own published `jwks`, explicitly separated from trust-chain establishment.

### Changed

- Bumped project version to `0.6.0-alpha.1`.
- OAuth space-delimited scope strings now compare semantically with array representations.
- Explicit expected SAML Destination / SubjectConfirmation recipient / InResponseTo inputs fail when the corresponding expected value is absent or different.
- Browser smoke coverage expanded across v0.2–v0.6 workflows.
- Documentation updated to distinguish implemented roadmap surfaces from remaining standards hardening.

### Security

- Retains `connect-src 'none'`, no telemetry and no automatic endpoint/key retrieval.
- SAML parsing remains DTD/ENTITY rejecting and duplicate-ID aware.
- XMLDSig remains locally vendored from pinned `xmldsigjs` 2.8.8 with SHA-384/SRI verification in CI.
- JWK selection now rejects incompatible encryption-only/key-operation/key-type candidates.
- JOSE critical `b64` semantics remain indeterminate rather than being incorrectly verified.

### Known limitations

- Duplicate JWT JSON member detection is not yet implemented.
- SAML profile/schema conformance is broader than the initial alpha but is not a complete formal SAML profile validator.
- Embedded SAML signing certificates are not automatically trusted; certificate-path trust remains a separate decision.
- OpenID Federation trust-chain resolution and metadata-policy application across a supplied chain remain future hardening work.
- The public app does not decrypt EncryptedAssertion values or accept refresh-token/shared-secret workflows.

## [0.1.0-alpha.1] - 2026-10-02

### Added

- Initial static Identity Toolkit application and GitHub Pages structure.
- JWT/JWS parser with JOSE header, claims and signature bytes.
- Generic JWT, initial OIDC ID Token, OAuth JWT Access Token and OpenID Federation profile foundations.
- Token time, expected issuer and expected audience findings.
- JWK/JWKS parsing, key selection and Web Crypto signature verification.
- Initial OIDC discovery metadata inspection.
- Initial SAML 2.0 Response/Assertion parser and SAML metadata inspection.
- Duplicate XML ID detection and DTD/ENTITY rejection.
- Local build/vendoring pipeline for `xmldsigjs` 2.8.8.
- SHA-384 SRI plus CI byte-level integrity verification and upstream provenance.
- Claims dictionary and cross-protocol comparison foundation.
- WS-Federation / WS-Trust response parser foundation.
- Federation configuration inspection/comparison foundation.
- Redacted diagnostic report with copy/download controls.
- Local-only CSP and no-network architecture.
- Unit-test and Playwright foundations.
- `README.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `SECURITY.md` and `THIRD_PARTY_NOTICES.md`.

# Roadmap

Current implementation: **`v0.6.0-alpha.1`**.

The requested v0.2–v0.6 product surfaces are now implemented. Remaining work below is primarily standards hardening, adversarial testing and deeper trust semantics before stable 1.0.

## v0.1 — JWT / JOSE inspector

### Implemented

- [x] Compact JWT/JWS detection and parsing.
- [x] JOSE header and payload display.
- [x] Registered-claim descriptions.
- [x] `exp`, `nbf`, future `iat`, expected issuer and expected audience checks.
- [x] Local JWK/JWKS input and asymmetric Web Crypto verification.
- [x] Key compatibility checks for `kty`, `use`, `key_ops`, `kid` and algorithm family.
- [x] Conservative unsupported `crit` / `b64=false` handling.
- [x] Redacted diagnostic report.
- [x] GitHub Actions CI and Pages deployment.

### Hardening

- [ ] Duplicate JSON-member detection before JSON parsing.
- [ ] Nested JWT/JWE inspection.
- [ ] Full JOSE critical-extension support where safe/useful.
- [ ] Larger malformed-token / Unicode / resource-exhaustion corpus.
- [ ] Broader algorithm/key mismatch fixtures.

## v0.2 — OIDC / OAuth

### Implemented

- [x] OIDC ID-token profile and required-claim checks.
- [x] Multiple audience / `azp` semantics.
- [x] Expected nonce validation.
- [x] `auth_time` / maximum authentication age.
- [x] `acr` / `amr` analysis.
- [x] `at_hash` and `c_hash` validation from explicitly supplied related artefacts.
- [x] OAuth access-token scopes, roles, groups, entitlements, audience and client identity.
- [x] RFC 9068 `at+jwt` profile mode, signed-token requirements and asymmetric-signing guidance.
- [x] `cnf`, `act` and `may_act` observations.
- [x] OIDC Discovery document inspection.
- [x] JWKS inspection including duplicate/missing IDs and private/symmetric material warnings.
- [x] PKCE S256, conditional Token Endpoint requirements and front-channel token / implicit-flow security observations from discovery metadata.

### Later / optional

- [ ] DPoP proof JWT inspection and request binding inputs.
- [ ] OAuth authorisation-request parser.
- [ ] Offline PKCE request/verifier helper.
- [ ] Provider-specific profiles only where standards materially diverge.

## v0.3 — SAML 2.0

### Implemented

- [x] Response and standalone Assertion parsing.
- [x] Response status, Destination and InResponseTo.
- [x] Subject / NameID and NameID format.
- [x] SubjectConfirmation / SubjectConfirmationData time, recipient and request binding.
- [x] Conditions / validity windows.
- [x] Separate AudienceRestriction groups and expected-audience evaluation.
- [x] OneTimeUse / ProxyRestriction reporting.
- [x] Multiple AuthnStatements, AuthnContext and SessionIndex.
- [x] Multi-valued attributes.
- [x] Multiple/encrypted assertion diagnostics.
- [x] Duplicate XML ID detection and namespace-aware parsing.
- [x] DTD/ENTITY rejection.
- [x] External XMLDSig Reference rejection.
- [x] XML signature/reference/algorithm/key-material inspection.
- [x] Signed-parent / Response / Assertion reference coverage diagnostics.
- [x] Local `xmldsigjs` 2.8.8 cryptographic verification.
- [x] SHA-384 SRI and CI verification for the local vendor bundle.
- [x] SAML metadata roles, endpoints, NameID formats, requested attributes, validity and keys.
- [x] SAML metadata XMLDSig verification path.

### Hardening

- [ ] Larger signature-wrapping regression corpus based on published attack classes.
- [ ] SAML schema/profile conformance layer beyond the currently modelled semantics.
- [ ] Explicit signer-certificate trust input / optional PKI Toolkit hand-off.
- [ ] More encrypted-assertion diagnostics without accepting decryption secrets in the public app.

## v0.4 — Claims Compare

### Implemented

- [x] Canonical claim dictionary.
- [x] Common SAML/WS-Fed → JWT aliases.
- [x] User-defined JSON claim mapping.
- [x] JWT ↔ JWT, SAML ↔ JWT and WS-Fed migration comparison.
- [x] Set-aware comparison for scope/roles/groups/entitlements/audience/AMR.
- [x] Same / mapped / changed / added / removed classifications.
- [x] High-impact claim identification.
- [x] Exportable migration report.

### Later / optional

- [ ] User-configurable volatile-claim ignore list.
- [ ] Multi-sample claim-set comparison.
- [ ] Value transformation rules / regex diagnostics.
- [ ] Saved mapping profiles only if they can preserve the no-sensitive-persistence model.

## v0.5 — WS-Federation / WS-Trust

### Implemented

- [x] `RequestSecurityTokenResponse` parsing.
- [x] Response collection handling.
- [x] AppliesTo, Lifetime, TokenType, RequestType, KeyType, KeySize and ComputedKey.
- [x] Attached / unattached security token references.
- [x] Embedded SAML 2.0 analysis.
- [x] Embedded SAML 1.x assertion analysis for older enterprise deployments.
- [x] Expected audience and time-window diagnostics.
- [x] Claims integration with migration comparison.

### Later / optional

- [ ] WS-Federation passive request (`wa`, `wtrealm`, `wreply`, `wctx`) inspection.
- [ ] Broader WS-Trust issuance variants.
- [ ] Provider-specific migration hints where they can remain factual and standards-aware.

## v0.6 — Advanced federation analysis

### Implemented

- [x] OIDC provider metadata comparison.
- [x] SAML metadata comparison.
- [x] JWKS comparison.
- [x] Signing-key rotation classification with retained/added/removed keys.
- [x] SAML signing-certificate rotation identifiers.
- [x] Issuer / EntityID migration classification.
- [x] Federation configuration field diffing.
- [x] Exportable federation migration report.
- [x] OpenID Federation 1.0 Entity Configuration / Subordinate Statement structural analysis.
- [x] OpenID Federation `jwks`, authority/trust-anchor hints, metadata, metadata policy, constraints, critical extensions and Trust Mark structure.
- [x] OpenID Federation Entity Configuration self-signature consistency verification against its own published `jwks`.
- [x] `trust_chain` / `peer_trust_chain` header shape inspection without online dereferencing.

### Hardening / future federation depth

- [ ] Full offline OpenID Federation trust-chain resolution from a user-supplied bundle of Entity Statements.
- [ ] Metadata-policy application engine and policy-result explanation.
- [ ] Trust Mark JWT cryptographic validation against explicitly supplied issuer keys/trust data.
- [ ] Multi-entity SAML metadata comparison beyond the primary EntityDescriptor workflow.
- [ ] Federation bundle import/export for offline troubleshooting.

## Pre-1.0 cross-cutting work

- [ ] Input size/depth safety limits consistently enforced for every format.
- [ ] Structured fuzz/adversarial corpus.
- [ ] Accessibility pass.
- [ ] Extended mobile/desktop browser matrix.
- [ ] Differential tests against mature protocol implementations.
- [ ] Stable versioned result/report schema.
- [ ] Formal threat-model document and security review before stable 1.0.

# IDCS setup and legacy SAML integration

**The dashboard now uses OIDC by default.** Start with [OIDC setup](oidc-setup.md). Steps 2–3 below cover the IDCS resource, exchange client and inbound trust for either protocol. Steps 4–5 describe the original SAML-specific requesting app; use the OIDC guide for the new login and XAA client.

This page retains the original tenant and legacy SAML examples. New OIDC users should follow the [tenant-neutral end-to-end guide](end-to-end-setup.md).

## 1. Initialize the local project

Install the locked dependencies and run `python -m app.cli init` as described in README.md. Register only `secrets/okta-agent.jwk.json` with Okta; keep `secrets/okta-agent.pem` private. Put credentials in `.env`, never in source control or chat.

## 2. Create the IDCS protected resource and runtime client

Open the supplied IDCS domain in its administrative console or OCI Console → Identity & Security → Domains → your domain → Integrated applications.

Create a confidential application named `local-demo-resource`, configured as a resource server. For the included local API use primary audience `http://localhost:4142`; add scope `/demo:read`. Confirm the console's fully qualified scope is `http://localhost:4142/demo:read` and copy the actual value to `REQUESTED_SCOPE` and `RESOURCE_REQUIRED_SCOPE` if it differs. This audience is a local API identifier; IDCS does not need to contact localhost to issue the token. If tenant policy requires an HTTPS audience, choose an HTTPS identifier and update `RESOURCE_AUDIENCE` and both scope settings; the API can still run on loopback.

Create a second confidential application named `local-idjag-exchange`, configure it as a client with the **JWT assertion** grant enabled, and authorize it for the resource's specific scope in its token issuance policy. Use a confidential client with client-secret authentication. This application's own self-signed user assertion capability is not the trust used here; Okta is the external assertion signer. Activate both applications. Record the runtime client ID and secret in `IDCS_CLIENT_ID` and `IDCS_CLIENT_SECRET`.

Create or choose an active IDCS test user whose unique `userName` equals the email claim Okta will place in the signed ID-JAG. Okta's `sub` is normally an Okta user ID and should not be assumed to equal an IDCS userName. This implementation defaults to the signed `email` claim for the inbound mapping. If your identity contract uses another stable top-level claim, set `IDCS_SUBJECT_CLAIM` accordingly and configure the same claim on the trust. Manage account lifecycle and uniqueness for that mapping.

## 3. Configure the inbound Identity Propagation Trust in IDCS

**Gate:** verify this tenant supports external ID-JAG redemption and the ID-JAG fields of `IdentityPropagationTrusts`. JWT bearer grant support by itself is insufficient. A legacy trusted partner certificate alone does not establish the full ID-JAG policy.

The [Oracle inbound trust documentation](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/token_exchange-grant_type_jag-oauth.htm) binds the incoming ID-JAG `client_id` (source) and the authenticated IDCS client (target) within the same `idJagClients` entry.

In the dashboard, open **Inbound ID-JAG Trust** and click **Create or check inbound trust**. This setup operation is available before Okta sign-in and is protected by the local session's CSRF token and origin check. The app is bound to loopback; do not expose this administrative demo on a shared network.

1. Obtain an IDCS access token with `IDCS_ADMIN_CLIENT_ID` / `IDCS_ADMIN_CLIENT_SECRET` when configured, otherwise `IDCS_CLIENT_ID` / `IDCS_CLIENT_SECRET` using HTTP Basic authentication, `grant_type=client_credentials`, and `scope=urn:opc:idm:__myscopes__` (override with `IDCS_ADMIN_SCOPE`). The IDCS confidential app must have Client Credentials enabled and administrative permission to manage Identity Propagation Trusts. A runtime-only client can receive 403 here. See [Oracle API authentication](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/OATOAuthClientWebApp.htm).
2. Use the token as Bearer authentication to query `/admin/v1/IdentityPropagationTrusts` for the exact Okta issuer, including pagination.
3. If absent, POST the derived JSON. Display **201 Created** and the actual IDCS response, including generated ID and metadata. The app never invents these values.
4. If present, show **Trust already created**, the existing response and any configuration differences. An inactive/mismatched trust or multiple trusts for the issuer need review; they are never silently overwritten. A 409 is rechecked before it is reported as an existing trust. Other errors keep their actual HTTP status and diagnostics.

| Field | Derived value |
| --- | --- |
| `issuer` | `OKTA_ORG_URL` |
| `name` | `IDCS_TRUST_NAME`, default `Inbound ID-JAG trust` |
| `type`, `active`, `idJagEnabled` | `JWT`, `true`, `true` |
| `publicKeyEndpoint` | `OKTA_ORG_URL` + `/oauth2/v1/keys` |
| `subjectClaimName` | `IDCS_SUBJECT_CLAIM`, default `email` |
| `subjectMappingAttribute` | `IDCS_SUBJECT_MAPPING_ATTRIBUTE`, default `userName` |
| `oauthClients`, `idJagOauthClientIds` | `IDCS_CLIENT_ID` (target) |
| `inboundIdJagCrossDomainClientId` | `OKTA_OIDC_CLIENT_ID` (source), overridden by `IDCS_TRUST_SOURCE_CLIENT_ID` |
| Admin API base | `IDCS_ISSUER` without trailing slash |

For the legacy SAML-only configuration without `OKTA_OIDC_CLIENT_ID`, the source defaults to `IDCS_CLIENT_ID`, preserving the original resource-connection contract. If your signed ID-JAG uses a different `client_id`, set `IDCS_TRUST_SOURCE_CLIENT_ID` to that agreed source value. The local signature/claim verifier and trust payload use the same setting. Do not change the source setting just to bypass a mismatch without confirming the intended Okta connection.

All credentials and the temporary admin access token stay server-side. The admin token is used only for the setup request and is not saved in the login session or reused as the protected-resource token. Request/Response tabs show redacted token acquisition and each real admin API call. Save `.env` changes and restart the server before retrying. Existing trusts are queried on each click, so a server restart does not cause duplicate creation.

You can also preview the same payload without changing IDCS:

```bash
python -m app.cli trust-template
```

Review with an administrator if the endpoint returns missing-schema/unknown-attribute/unsupported-feature errors. Request ID-JAG enablement or the required service update through Oracle support. Do not replace the signed Okta assertion with a locally re-signed JWT to mask this limitation. If public-key endpoint retrieval is unsupported by your deployment, follow Oracle's documented static signing-certificate option and manage key rotation.

## 4. Create the requesting SAML app in Okta

Open [your Okta admin console](https://integrator-1242259-admin.okta.com/admin/dashboard). Under Applications create a SAML 2.0 integration named `local-saml-idjag-idcs`.

| SAML field | Value |
| --- | --- |
| Single sign-on / ACS URL | `http://localhost:4141/saml/acs` |
| Audience / SP Entity ID | `http://localhost:4141/saml/metadata` |
| Name ID format | EmailAddress |
| Application username | Email |
| Assertion signature | Signed, RSA-SHA256 / SHA256 |
| Assertion encryption | Unencrypted |

Assign the test user. From Sign On / setup instructions copy the actual IdP SSO URL to `OKTA_SAML_SSO_URL`, the actual SAML issuer to `OKTA_SAML_IDP_ISSUER`, and save the signing certificate as `secrets/okta-saml.crt` in PEM format. The SAML issuer is usually `http://www.okta.com/...`; it differs from the ID-JAG issuer. Use the org-specific values displayed by this SAML integration.

Run `python -m app.server` and test sign-in first. Start every sign-in from the application's **Sign in with Okta** button. IdP-initiated app tile responses are intentionally rejected.

## 5. Register the Okta AI Agent and IDCS resource connection

Use Directory → AI Agents; Cross App Access/AI Agents must be available in this organization. Create an agent, set its owner, and add the public RSA JWK from `secrets/okta-agent.jwk.json` under Credentials. Copy the **AI Agent OAuth client ID** to `OKTA_AGENT_CLIENT_ID`. Under Delegations add a **User sign-on** caller and choose the requesting SAML app. Activate the agent.

Create a separate OIDC application representing the IDCS resource authorization server; it is not used for browser sign-in. Under Resource Server enable Cross App Access and set the issuer to:

```text
https://idcs-ff3532e3a9ba4bd7887f5cf49e2ae425.identity.oraclecloud.com/
```

This is the exact issuer returned by IDCS discovery, including its trailing slash and without `:443`. It is **not** the local API audience or IDCS token endpoint.

Return to the AI Agent → Resource connections → add an **Application** connection to this resource app. Set **Client ID at resource** to the exact `IDCS_CLIENT_ID`, and permit the fully qualified `REQUESTED_SCOPE`. Ensure the connection and agent are active and the user has required access assignments.

The [reference setup](https://github.com/christian-posta/okta-saml-idjag/blob/main/docs/okta-setup.md) documents this registration pattern. Your current Okta release may label these screens differently. If Okta refuses IDCS's resource issuer because its metadata does not advertise the required XAA authorization grant profile, verify native ID-JAG enablement with Oracle and Okta. The public discovery checked for this tenant advertises JWT bearer, but does not advertise `authorization_grant_profiles_supported`. Do not publish fabricated discovery metadata or change issuer identities to bypass validation.

## 6. Run the legacy SAML flow

For the default OIDC flow, follow [OIDC setup](oidc-setup.md). To exercise the retained SAML routes, start sign-in at `/saml/login`.

Start the resource server (`python -m app.resource`) and dashboard (`python -m app.server`) in separate activated terminals. Browse to `http://localhost:4141`, sign in and click each exchange step.

The first Okta request is RFC 8693 with `subject_token_type=...:saml2`, `requested_token_type=...:refresh_token` and a **standard Base64** signed assertion. A fresh short-lived `private_key_jwt` authenticates each request as the agent. The refresh token is then exchanged for `...:id-jag`, with IDCS issuer as `audience`. No `resource` parameter is sent to Okta. These choices follow the reference's verified SAML flow.

The app verifies the ID-JAG against Okta's org JWKS, requires the IDCS audience and configured source client, and checks scope and mapping claim. It sends the unchanged token to IDCS as `assertion`, with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, the fully qualified scope, and HTTP Basic authentication for the IDCS exchange client. It then sends the returned access token to the API using `Authorization: Bearer`.

The IDCS signing keys are discovered from the configured tenant key endpoint by the resource server. The resource independently validates the JWT before returning a user-specific response. Raw tokens stay on the local app server; the dashboard shows redacted wire traces and verified ID-JAG claims.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| SAML state missing/expired | Start login in the app, finish within five minutes and keep the same hostname. |
| Browser binding failed | Cookies must be enabled; complete the same login in the same browser. Avoid concurrent login tabs. |
| SAML validation failed | Actual SAML issuer/certificate, assertion signing, RSA-SHA256, clock, ACS and audience; do not weaken strict mode. |
| Cannot preserve standalone assertion | Use Okta's normal unencrypted signed assertion with self-contained namespaces. Re-serializing a signed assertion can break its signature. |
| Local form returns 403 | Refresh the dashboard after app updates; use the configured BASE_URL and buttons. Expired CSRF tokens and unexpected origins are rejected before any Okta request. |
| `actor_token` missing at Okta | Use an active AI Agent with SAML User sign-on delegation, not an ordinary OIDC client. |
| `invalid_client` at Okta | Agent client ID, registered public JWK, matching `kid`, private key and endpoint audience. |
| `invalid_target` at Okta | Exact distinct IDCS issuer, reachable discovery, resource app XAA enablement and active connection. |
| ID-JAG `client_id` mismatch | The signed source client must match OKTA_OIDC_CLIENT_ID (or IDCS_TRUST_SOURCE_CLIENT_ID) and the inbound trust pairing. |
| `invalid_grant` at IDCS | ID-JAG support, exact single active inbound issuer trust, signing keys, token lifetime, mapped active user and both nested client lists. |
| `invalid_scope` / access denied | Exact fully qualified scope in both requests, signed ID-JAG, resource policy and runtime client grants; use one scope family per exchange. |
| Resource returns 401 | IDCS access token signature, expiry, issuer trailing slash, `tok_type=AT`, audience and JWKS reachability; an ID token/ID-JAG is rejected. |
| Resource returns 403 | Token lacks RESOURCE_REQUIRED_SCOPE. |
| Stale/expired session or token | Sign in again; SAML assertion reuse may be rejected by Okta. Get a new ID-JAG for a new redemption. |
| xmlsec import/build failure | Prefer Python 3.12 and binary wheels. If building on macOS, install `libxmlsec1`, `pkg-config`, `libxml2` with Homebrew and rebuild compatible lxml/xmlsec wheels. |

For tenant support, record the failing stage, HTTP status, protocol error code and timestamp; avoid sharing raw assertions, tokens, secrets or private keys.

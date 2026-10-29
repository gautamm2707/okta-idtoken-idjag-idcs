# OIDC sign-in and token inspector

OIDC is now the default browser sign-in protocol. The previous SAML routes remain available for existing integrations, but **Sign in with Okta** uses `/oidc/login`.

## Okta application

Use your existing Okta **OIDC Web Application** in `integrator-1242259.okta.com`. Configure:

| Field | Value |
| --- | --- |
| Grant types | Authorization Code; Refresh Token only if you also need refresh tokens |
| Sign-in redirect URI | `http://localhost:4141/oidc/callback` |
| Client authentication | Client secret: Basic or POST, matching `.env` |
| Assignment | Assign your test user |

An OIDC client ID and secret are separate from SAML metadata and from the IDCS client credentials. A client-secret-only service application cannot perform interactive OIDC user sign-in.

## Local settings

Save in the root `.env` file:

```dotenv
OKTA_OIDC_CLIENT_ID=YOUR_OKTA_WEB_APP_CLIENT_ID
OKTA_OIDC_CLIENT_SECRET=YOUR_OKTA_WEB_APP_CLIENT_SECRET
OKTA_OIDC_AUTH_METHOD=client_secret_basic
OKTA_OIDC_REDIRECT_URI=http://localhost:4141/oidc/callback
OKTA_OIDC_SCOPE="openid profile email offline_access"
OKTA_XAA_SUBJECT_TOKEN_TYPE=id_token
OKTA_XAA_AUDIENCE=https://idcs-ff3532e3a9ba4bd7887f5cf49e2ae425.identity.oraclecloud.com
OKTA_XAA_RESOURCE=https://idcs-ff3532e3a9ba4bd7887f5cf49e2ae425.identity.oraclecloud.com
REQUESTED_SCOPE=urn:opc:idm:__myscopes__
```

Set `OKTA_OIDC_AUTH_METHOD=client_secret_post` if that is the registered client authentication method. The client secret is sent only to the configured Okta org token endpoint, never to the browser or IDCS. Restart `python -m app.server` after editing `.env`; configuration is loaded at startup.

OIDC uses your **org** authorization server: `https://integrator-1242259.okta.com/oauth2/v1/authorize` and `/oauth2/v1/token`. It does not use the custom `/oauth2/default` authorization server. This keeps the resulting session tokens compatible with the org-level XAA exchange.

## What the dashboard shows

After successful authentication, **User Authentication (SSO)** displays:

- **Request**: the authorization GET URL and parameters, plus the code-to-token POST request. State, nonce, authorization code, PKCE verifier and client secret are redacted in the request display.
- **Response**: token endpoint status and response fields, including the actual `id_token` requested by the user. Access tokens and refresh tokens remain redacted.
- **Token**: verified ID-token header and payload, including its standard claims. The original nonce is visible as part of the decoded signed token.

No credentials or tokens enter the cookie session. The server validates the ID-token signature against Okta's org JWKS, issuer, client audience, expiration, issued-at, nonce, authorized party when applicable, and `at_hash` when present. Authorization Code requests use PKCE S256 and single-use, browser-bound state with a five-minute lifetime.

The inspector is a local debugging feature: its ID-token display intentionally replaces the old blanket redaction for this one token. Client secrets, refresh tokens, authorization codes and access tokens stay redacted. The page uses no third-party scripts and disables caching.

## Continue from OIDC to ID-JAG

**Get ID-JAG** uses the current session’s verified ID token from OIDC sign-in directly; it does not perform the SAML bootstrap exchange. It authenticates using the OIDC client credentials and the configured client authentication method. Register or bind this OIDC application as the XAA requesting app in Okta, then create its IDCS resource connection and permitted scopes. Do not assume an ordinary OIDC registration alone enables XAA.

Follow [Configure the XAA connection](https://developer.okta.com/docs/guides/xaa-agent-to-app/main/#configure-the-xaa-connection): bind the requesting OIDC app to the agent, enable XAA on the IDCS resource app, and configure the connection's resource identifier and allowed scopes. Set the registered target client ID to `IDCS_CLIENT_ID`.

Use the exact audience and resource from your working request. Here both are the IDCS domain URL **without** a trailing slash. `OKTA_XAA_AUDIENCE` controls the request's `audience` and the expected signed ID-JAG `aud` claim. It defaults to `IDCS_ISSUER` only when unset. Keep `IDCS_ISSUER` equal to IDCS discovery (including its trailing slash) for verification of IDCS-issued access tokens. These are separate settings; audience validation is never disabled or normalized.

`REQUESTED_SCOPE` is used in both the ID-JAG request and IDCS redemption. The working request uses `urn:opc:idm:__myscopes__`, an IDCS API scope profile. It does not by itself authorize the local API's `http://localhost:4142/demo:read` scope or audience. To call the local protected API, configure its resource audience/scope in IDCS and the Okta connection, then use that custom scope. Do not combine IDCS API and custom resource scope families in one request or weaken API validation.

The IDCS client secret is **not required** for OIDC sign-in or Get ID-JAG. It is required when you click **Exchange at IDCS** or **Create or check inbound trust**. IDCS inbound trust, user mapping and API scope configuration are still required; see [the IDCS setup steps](setup.md).

The default subject is `id_token`. There is no automatic fallback to a refresh token. If an ID token expires, sign in again. Refresh-token exchange remains an explicit option via `OKTA_XAA_SUBJECT_TOKEN_TYPE=refresh_token` for connections that support it.

## Protected resource: IDCS users

Leave `RESOURCE_URL` blank to derive `IDCS_ISSUER` + `/admin/v1/Users`. After **Exchange at IDCS**, click **Access Protected Resource**. This uses the redeemed access token, not the setup/admin client-credentials token. The app follows `startIndex`/`count` pagination and shows all returned users plus each page's HTTP response. See [Oracle Search Users](https://docs.oracle.com/en/cloud/paas/iam-domains-rest-api/op-admin-v1-users-get.html).

IDCS enforces the access token's scope and client/user permissions. A 401/403 from this endpoint is shown with the actual response; the app does not switch to an admin token or change grants. The local display is bounded to 10,000 users, 1 MiB per page and 5 MiB overall, with an explicit error if the result cannot be fully loaded. No port-4142 server is needed for this default flow.

## Troubleshooting

| Message or behavior | Action |
| --- | --- |
| Configure OKTA_OIDC_CLIENT_ID / SECRET | Save both values in the root `.env`, then restart the dashboard. |
| Okta redirect URI error | Register the exact callback above on the same OIDC client. |
| `invalid_client` | Check the OIDC client ID, current secret and Basic vs POST registration; do not put IDCS credentials in these fields. |
| Missing refresh token at Get ID-JAG | Enable Refresh Token for the OIDC app and request `offline_access`, then sign in again. Login and ID-token inspection can succeed without a refresh token. |
| ID-token validation failed | Confirm org issuer, client ID/audience, clock, signing keys, nonce and access-token hash. Validation is not bypassed for display. |
| `invalid_target` | Compare OKTA_XAA_AUDIENCE and OKTA_XAA_RESOURCE exactly (including trailing slashes) with the active XAA connection; check allowed REQUESTED_SCOPE. |
| ID-JAG exchange denied | Check XAA requesting-app binding, active resource connection, target IDCS client ID and allowed scopes. |
| IDCS credentials missing | Set IDCS_CLIENT_ID and IDCS_CLIENT_SECRET for the redemption step; these are different from Okta's OIDC credentials. |

## Sources

- [Okta Authorization Code](https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/)
- [Okta Authorization Code with PKCE](https://developer.okta.com/docs/guides/implement-grant-type/authcodepkce/main/)
- [Okta OIDC requesting app walkthrough](https://developer.okta.com/blog/2026/08/21/xaa-oidc-requesting)
- [Okta OIDC XAA token exchange](https://developer.okta.com/docs/guides/xaa-request-token-ex/openidconnect/main/)

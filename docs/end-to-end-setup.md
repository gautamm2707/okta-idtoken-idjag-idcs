# Set up Okta ID token → ID-JAG → Oracle IDCS in your own tenants

This guide starts with a fresh clone of [this repository](https://github.com/gautamm2707/okta-idtoken-idjag-idcs). The default flow signs a user in with **Okta OIDC**, exchanges the resulting ID token for an **ID-JAG** through Okta Cross App Access (XAA), redeems that ID-JAG in an **Oracle Identity Domain (IDCS)** for a Bearer access token, then calls the domain's **Users API**. The older SAML routes are optional and are covered separately in [setup.md](setup.md).

**Edit one local file for your tenant: `.env` in the repository root.** It is created from `.env.example` by the initialization command below. Do not edit `app/config.py` to put in credentials or commit `.env`. All commands in this guide run on your own computer. You need administrator access in both tenants to create the applications, connection, roles, and trust. A working OIDC login alone does not prove that XAA or inbound ID-JAG redemption is enabled.

## 1. Collect the tenant values

| From Okta | Where to find it | `.env` field |
| --- | --- | --- |
| **Org URL**, such as `https://your-org.okta.com` | Okta org URL in the Admin Console; use the org authorization server, not `/oauth2/default` | `OKTA_ORG_URL` |
| **OIDC requesting app client ID and secret** | The OIDC app linked to the AI agent; Okta says the linked app and agent share a client ID | `OKTA_OIDC_CLIENT_ID`, `OKTA_OIDC_CLIENT_SECRET` |
| **Client authentication method** | OIDC app registration: Client secret Basic or POST | `OKTA_OIDC_AUTH_METHOD` |
| **Resource audience and resource identifier** | The XAA resource app and its connection to the agent | `OKTA_XAA_AUDIENCE`, `OKTA_XAA_RESOURCE` |
| **Allowed ID-JAG scope** | The resource app's XAA scopes and the agent's connection scope policy | `REQUESTED_SCOPE` |
| **Source client ID in the signed ID-JAG** | Inspect the verified ID-JAG Token tab after the first successful exchange | `IDCS_TRUST_SOURCE_CLIENT_ID` only if it differs from `OKTA_OIDC_CLIENT_ID` |

| From IDCS | Where to find it | `.env` field |
| --- | --- | --- |
| **Identity domain URL and exact issuer** | Domain details and `https://YOUR_DOMAIN/.well-known/openid-configuration` | `IDCS_ISSUER` |
| **Token endpoint and signing-key URL** | The same discovery document (`token_endpoint`, `jwks_uri`); copy the actual values, including any `:443` | `IDCS_TOKEN_ENDPOINT`, `IDCS_JWKS_URL` |
| **Target confidential client ID and secret** | Identity domain integrated application that will redeem the ID-JAG | `IDCS_CLIENT_ID`, `IDCS_CLIENT_SECRET` |
| **Optional trust-admin client ID and secret** | Separate confidential app with Client Credentials and permission to manage Identity Propagation Trusts | `IDCS_ADMIN_CLIENT_ID`, `IDCS_ADMIN_CLIENT_SECRET` |
| **Target user's unique username** | An active user in the target domain | Must match the signed Okta `email` claim by default; adjust `IDCS_SUBJECT_CLAIM` / `IDCS_SUBJECT_MAPPING_ATTRIBUTE` if your mapping differs |

These are **three different OAuth client roles**: the Okta requesting client obtains the ID-JAG; the IDCS target client redeems it; an optional IDCS admin client creates the trust. The IDCS target client ID appears in the trust's `oauthClients` and `idJagOauthClientIds`. The signed Okta ID-JAG `client_id` appears in `inboundIdJagCrossDomainClientId`. [Oracle's inbound ID-JAG guide](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/token_exchange-grant_type_jag-oauth.htm) requires both IDs to be paired in the same entry.

## 2. Clone and initialize

Install Python 3.12 and [uv](https://docs.astral.sh/uv/getting-started/installation/) on your computer, then:

```bash
git clone https://github.com/gautamm2707/okta-idtoken-idjag-idcs.git
cd okta-idtoken-idjag-idcs
uv venv --python 3.12 .venv
source .venv/bin/activate
uv pip sync requirements.lock
python -m app.cli init
```

`init` creates `.env` with a random `APP_SECRET` and a local key pair used only by the optional legacy SAML path. It preserves an existing `.env`. On Windows, activate the virtual environment with `.venv\\Scripts\\activate` and then run the same Python commands. If you do not use uv, install the pinned packages into a Python 3.12 virtual environment with `python -m pip install -r requirements.lock`.

Open **`.env`**, replacing every `your-...` URL and setting the IDs and secrets. A portable OIDC example (placeholders are intentionally unusable) is:

```dotenv
BASE_URL=http://localhost:4141
OKTA_ORG_URL=https://your-org.okta.com
OKTA_OIDC_CLIENT_ID=YOUR_LINKED_OKTA_OIDC_CLIENT_ID
OKTA_OIDC_CLIENT_SECRET=YOUR_LINKED_OKTA_OIDC_CLIENT_SECRET
OKTA_OIDC_AUTH_METHOD=client_secret_basic
OKTA_OIDC_REDIRECT_URI=http://localhost:4141/oidc/callback
OKTA_OIDC_SCOPE="openid profile email offline_access"
OKTA_XAA_SUBJECT_TOKEN_TYPE=id_token
OKTA_XAA_AUDIENCE=https://your-idcs-domain.identity.oraclecloud.com
OKTA_XAA_RESOURCE=https://your-idcs-domain.identity.oraclecloud.com
REQUESTED_SCOPE=urn:opc:idm:__myscopes__
IDCS_ISSUER=https://your-idcs-domain.identity.oraclecloud.com/
IDCS_TOKEN_ENDPOINT=https://your-idcs-domain.identity.oraclecloud.com:443/oauth2/v1/token
IDCS_JWKS_URL=https://your-idcs-domain.identity.oraclecloud.com:443/admin/v1/SigningCert/jwk
IDCS_CLIENT_ID=YOUR_IDCS_TARGET_CLIENT_ID
IDCS_CLIENT_SECRET=YOUR_IDCS_TARGET_CLIENT_SECRET
IDCS_SUBJECT_CLAIM=email
IDCS_SUBJECT_MAPPING_ATTRIBUTE=userName
RESOURCE_URL=
```

Use the **actual IDCS discovery values**, not the example's assumed `:443` or slash formatting. For the Okta XAA `audience` and `resource`, use the **exact values registered on the resource connection**. In the original working tenant they were the domain URL without a trailing slash, while IDCS discovery returned an issuer with a trailing slash. The app validates both strings exactly. `RESOURCE_URL=` intentionally derives `IDCS_ISSUER` + `/admin/v1/Users`. `APP_SECRET` is already filled by `init`.

For trust setup, either leave both `IDCS_ADMIN_CLIENT_ID` and `IDCS_ADMIN_CLIENT_SECRET` blank to use the target client's credentials, or set **both** to a separate admin client's credentials. The separate admin app must have the Client Credentials grant and an IDCS app role that permits trust management. `IDCS_ADMIN_SCOPE=urn:opc:idm:__myscopes__` is the default. Keep `.env` and the generated `secrets/` directory private; they are ignored by Git.

## 3. Configure Okta sign-in and XAA

1. Create or select a **Web OIDC app integration** for the requesting app. Enable **Authorization Code**. Add `http://localhost:4141/oidc/callback` as an exact sign-in redirect URI, assign the test user, activate the app, and record the client ID, secret, and client authentication method. Enable Refresh Token only if you also want refresh tokens; the default ID-JAG exchange uses `id_token`. The app's OIDC login uses Authorization Code with PKCE against the Okta **org** `/oauth2/v1/authorize` and `/oauth2/v1/token` endpoints.
2. In **Directory → AI Agents**, register or select an AI agent and **link it to that OIDC app**. Activate the agent and grant the test user access. Okta's current wizard can create a new linked OIDC app; the linked app supplies the client credentials used by this demo. An ordinary unlinked OIDC app may sign users in but cannot assume XAA is configured. Follow [Okta's AI agent setup](https://developer.okta.com/docs/guides/xaa-agent-to-app/main/).
3. Create or select an **Okta resource app** representing the IDCS protected API. On its **Machine Assignments → Callers** page, enable XAA and configure the resource authorization server's issuer/audience and allowed scope. The labels in your Okta release may differ; use the values your resource app actually accepts.
4. On the agent's **Resource connections** tab, connect it to that XAA-enabled resource app. Set the agent's **client ID registered at the resource**, the **resource identifier**, and the allowed scope policy. Copy the resource audience to `OKTA_XAA_AUDIENCE`, resource identifier to `OKTA_XAA_RESOURCE`, and the requested scope to `REQUESTED_SCOPE`. The ID-JAG's signed `client_id` must match the source ID configured in the target trust. Inspect it after a successful exchange; set `IDCS_TRUST_SOURCE_CLIENT_ID` if it differs from the Okta OIDC client ID.

[Okta's OIDC XAA exchange guide](https://developer.okta.com/docs/guides/xaa-request-token-ex/openidconnect/main/) specifies the ID token as the default subject; the request also carries `audience`, `resource`, and `scope`. An `invalid_target` response usually means one of these identifiers or the active resource connection does not match. This app does not automatically fall back to a refresh token. If your connection intentionally uses refresh tokens, set `OKTA_XAA_SUBJECT_TOKEN_TYPE=refresh_token`, enable Refresh Token on the Okta app, request `offline_access`, and sign in again.

## 4. Configure the IDCS target

1. Confirm the domain supports **inbound ID-JAG from an external issuer** and the `IdentityPropagationTrusts` ID-JAG fields. Advertising the generic JWT bearer grant in discovery does not by itself prove that this feature is enabled. [Oracle's inbound ID-JAG guide](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/token_exchange-grant_type_jag-oauth.htm) lists the feature and validation requirements.
2. Create an **active confidential target application** in the IDCS domain. Enable the JWT assertion / RFC 7523 grant used to redeem the external ID-JAG and client-secret authentication. Authorize it for the IDCS API scope family that the flow requests. Copy its OAuth client ID and secret to `IDCS_CLIENT_ID` and `IDCS_CLIENT_SECRET`.
3. Give that target client and the mapped user the IDCS application roles or grants required to **list users**. `urn:opc:idm:__myscopes__` means “all scopes permitted to this client/user”; it does **not** grant administrator or user-read permission on its own. The exact role depends on your domain policy. [Oracle's API access guide](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/OATOAuthClientWebApp.htm) shows the client credentials and application-role setup, and [Oracle's Users API](https://docs.oracle.com/en/cloud/paas/iam-domains-rest-api/op-admin-v1-users-get.html) documents the endpoint and paging.
4. Create or identify an **active target-domain user** whose unique `userName` equals the Okta ID-JAG's signed `email` claim. If you use another claim, set `IDCS_SUBJECT_CLAIM` and `IDCS_SUBJECT_MAPPING_ATTRIBUTE` consistently and ensure that value identifies exactly one active target user.
5. For a separate trust-admin app, enable Client Credentials and grant a role that can list and create Identity Propagation Trusts. Fill `IDCS_ADMIN_CLIENT_ID` and `IDCS_ADMIN_CLIENT_SECRET`. If you use the target client for both setup and redemption, that same app must have the required trust-management role. The admin client is used only by **Create or check inbound trust**; its access token is never used for the protected-resource call.

Use **one scope family** in an exchange: IDCS API scopes such as `urn:opc:idm:__myscopes__`, or a fully qualified custom resource scope. To use the bundled `:4142` example API instead of IDCS Users, configure its resource audience and custom scope in IDCS and Okta, then change `RESOURCE_URL`, `REQUESTED_SCOPE`, `RESOURCE_AUDIENCE`, and `RESOURCE_REQUIRED_SCOPE` accordingly and run `python -m app.resource`. That server is not needed for the default Users API flow.

## 5. Check configuration, start the app, create or check trust

Run `python -m app.cli check` after saving `.env`. It verifies local values and public discovery but **cannot** confirm admin roles, XAA connection activation, user mapping, or ID-JAG enablement. Fix any exact issuer or token-endpoint mismatch it reports. Then start the app:

```bash
python -m app.cli check
python -m app.server
```

Open **http://localhost:4141** using the same hostname as `BASE_URL`. If you do not yet know the signed ID-JAG `client_id`, complete sign-in and **Get ID-JAG** first, inspect its verified Token tab, and set `IDCS_TRUST_SOURCE_CLIENT_ID` if it differs from the OIDC client ID. Restart the app after changing `.env`. Then, in **Inbound ID-JAG Trust**, review **Trust request derived from .env** and click **Create or check inbound trust**. The app obtains an IDCS administrative Bearer token using Client Credentials, queries existing trusts for the Okta issuer, then creates the trust only if none exists. It displays the real **201 Created** response and generated trust ID, or **Trust already created** and the existing response. An existing trust with different settings is flagged for review and is not overwritten. A 401/403 here means the admin credentials, grant, or trust-management role need attention. `python -m app.cli trust-template` prints the proposed JSON without contacting IDCS.

The trust payload binds:

```text
issuer/publicKeyEndpoint  ← your Okta org and org JWKS
subjectClaimName           ← IDCS_SUBJECT_CLAIM (default email)
subjectMappingAttribute    ← IDCS_SUBJECT_MAPPING_ATTRIBUTE (default userName)
oauthClients               ← IDCS_CLIENT_ID
idJagOauthClientIds         ← IDCS_CLIENT_ID
inboundIdJagCrossDomainClientId ← IDCS_TRUST_SOURCE_CLIENT_ID or OKTA_OIDC_CLIENT_ID
```

The trust's `issuer` must exactly match the signed ID-JAG `iss`, and IDCS must have exactly one active matching inbound trust. A trust can exist but still be unready if inactive or bound to the wrong client, claim, or key endpoint. [Oracle describes these checks](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/token_exchange-grant_type_jag-oauth.htm).

## 6. Run the four dashboard steps

1. **Sign in with Okta.** The browser returns to the local `/oidc/callback`. The **Request** tab shows the authorization and code exchange, **Response** contains the Okta `id_token`, and **Token** shows verified ID-token claims. The ID token is intentionally visible on this local page; keep screenshots private.
2. **Get ID-JAG.** The app POSTs to Okta `/oauth2/v1/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token_type=...:id_token`, `requested_token_type=...:id-jag`, and your exact audience, resource, and scope. A successful response has HTTP 200 and `issued_token_type=...:id-jag`; the raw ID-JAG is held in process memory, while its verified claims appear in the Token tab.
3. **Exchange at IDCS.** The app sends the unchanged ID-JAG as `assertion` to `IDCS_TOKEN_ENDPOINT` using `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `REQUESTED_SCOPE`, and HTTP Basic authentication with the **target** IDCS client. A successful response contains an IDCS Bearer access token, kept on the server. It expires; obtain a new ID-JAG and redeem again if needed.
4. **Access Protected Resource.** The app sends `Authorization: Bearer <redeemed IDCS access token>` to `IDCS_ISSUER` + `/admin/v1/Users` by default. It follows SCIM `startIndex`/`count` pagination, shows each request and response, and displays the combined users list. It never substitutes the trust-admin token. The local display limits are 10,000 users, 1 MiB per page, and 5 MiB total; exceeding them gives an explicit error.

The local app keeps tokens in server memory, not files. Restarting the server clears sign-in state, ID-JAGs, and access tokens. After **any** `.env` edit, restart the app and sign in again.

## 7. Troubleshoot by stage

| Stage / error | Check first |
| --- | --- |
| Sign-in does not return | Exact `OKTA_OIDC_REDIRECT_URI`, Okta app assignment and activation, `BASE_URL` hostname, client ID and secret, Basic vs POST method. |
| ID token rejected | `OKTA_ORG_URL` must be the issuing org; check issuer, OIDC client audience, nonce, time, and signing keys. |
| `invalid_target` while getting ID-JAG | Exact `OKTA_XAA_AUDIENCE` and `OKTA_XAA_RESOURCE` (including trailing slash), active resource app and connection, and `REQUESTED_SCOPE`. |
| `invalid_client` while getting ID-JAG | Linked requesting app/agent credentials and its registered client authentication method. |
| ID-JAG claim mismatch | Signed `aud`, `client_id`, `scope`, and mapping claim must match the XAA and IDCS trust settings. Check the Token tab; do not weaken signature checks. |
| Trust setup returns 401/403 | Admin client ID/secret, Client Credentials grant, `IDCS_ADMIN_SCOPE`, and role allowing trust read/create. |
| IDCS redemption returns `invalid_grant` | Feature availability, one active exact-issuer trust, key endpoint, signed ID-JAG lifetime, user mapping, and source/target client pair. |
| IDCS redemption returns `invalid_scope` | The same permitted scope family in Okta's ID-JAG and IDCS redemption; target client and user grants. |
| Users API returns 401/403 | Confirm the **redeemed** access token is valid for the IDCS Users API and that the target client/user has list-users permission. The dashboard shows the actual response. |
| Form returns 403 locally | Refresh the page; use the `BASE_URL` hostname and on-page buttons. Session CSRF or origin checks may reject an old tab. |

The app redacts client secrets, refresh tokens, ID-JAGs, and access tokens in the browser traces. Do not paste raw tokens, `.env`, or generated private keys into tickets or GitHub issues. The **OIDC ID token is displayed by design**, so take care when sharing screenshots.

# Okta OIDC → ID-JAG → Oracle IDCS

**New tenant? Follow the [end-to-end setup guide](docs/end-to-end-setup.md).** It lists every Okta and IDCS value to collect, the single local `.env` file to edit, tenant-side setup, expected responses, and troubleshooting. The sample `.env.example` uses placeholder URLs; replace them with your own.

Local Flask application inspired by [christian-posta/okta-saml-idjag](https://github.com/christian-posta/okta-saml-idjag). Browser sign-in now uses **OIDC Authorization Code + PKCE**, with **Request / Response / Token** tabs matching the requested flow inspector. The earlier SAML integration remains available through its explicit routes.

```text
Browser → Okta OIDC → local app :4141
                         │ verified ID token (refresh token optional)
                         ├→ Okta: ID token → ID-JAG (aud = OKTA_XAA_AUDIENCE)
                         ├→ IDCS: JWT bearer grant + ID-JAG → access token
                         └→ IDCS /admin/v1/Users (Bearer access token, paginated)
```

## Run locally

Python 3.11+ (tested with 3.12). With uv:

```bash
uv venv --python 3.12 .venv
source .venv/bin/activate
uv pip sync requirements.lock
python -m app.cli init
```

Without uv, create and activate a Python virtual environment, then `python -m pip install -r requirements.lock`.

Save your OIDC Web Application client ID and secret in the root `.env` as `OKTA_OIDC_CLIENT_ID` and `OKTA_OIDC_CLIENT_SECRET`. Register `http://localhost:4141/oidc/callback` as an Okta sign-in redirect URI. See [OIDC setup](docs/oidc-setup.md) for client authentication and Refresh Token settings.

```bash
# With the virtual environment active
python -m app.server
```

Open [http://localhost:4141](http://localhost:4141), click **Sign in with Okta**, then inspect:

- **Request**: authorization request and code-to-token request.
- **Response**: token endpoint status and body, including the actual `id_token`.
- **Token**: verified ID-token header and claims.

Your client secret stays on the server. Access tokens, refresh tokens and authorization codes are redacted in the UI; the ID token is intentionally visible as requested. Cookie sessions contain only random handles and CSRF/login state, never raw tokens.

## Continue to IDCS

OIDC sign-in needs no IDCS credentials. Get ID-JAG needs the Okta OIDC credentials, an enabled XAA resource connection and `IDCS_CLIENT_ID`. Exchange at IDCS additionally needs `IDCS_CLIENT_SECRET`, external ID-JAG support and a matching inbound trust.

The supplied XAA profile requests `urn:opc:idm:__myscopes__` for IDCS APIs. **Access Protected Resource** calls `IDCS_ISSUER` + `/admin/v1/Users` with the redeemed token and follows SCIM pagination. The response and per-page request/status/body appear in the dashboard. The IDCS grants must authorize the token to read users. Blank `RESOURCE_URL` derives this endpoint for any configured tenant.

The local API on port 4142 is optional: run `python -m app.resource` and set `RESOURCE_URL=http://localhost:4142/api/message` only to use that demo, with its separately authorized custom scope/audience.

See [OIDC and XAA setup](docs/oidc-setup.md) and [IDCS resource/client/trust setup](docs/setup.md). Copy the IDCS issuer, token endpoint and JWKS URL from your own domain discovery. JWT bearer support alone does not prove native ID-JAG enablement.

`python -m app.cli check` checks local settings and public discovery. `python -m app.cli trust-template` prints reviewable inbound trust JSON without modifying IDCS. The dashboard’s **Inbound ID-JAG Trust** section creates an IDCS trust only when you click **Create or check inbound trust**. It uses the optional dedicated IDCS admin credentials or falls back to the target client credentials, shows the actual response, and checks for an existing issuer trust first. See [trust setup](docs/setup.md#3-configure-the-inbound-identity-propagation-trust-in-idcs).

## Validate

```bash
python -m pytest -q
```

Automated tests use temporary signing keys and mocked HTTP to exercise state/nonce/PKCE, signed-token validation, callback replay, token display/redaction, ID-JAG redemption and API authorization. Live tenant authentication and policies require separately configured credentials and assignments.

## Files

| File | Purpose |
| --- | --- |
| `app/oidc.py` | OIDC code + PKCE login, confidential client authentication, ID-token validation |
| `app/server.py` | Dashboard, callbacks, server-side session flow and exchange actions |
| `app/protocol.py` | Okta ID-JAG exchange, IDCS RFC 7523 redemption, resource call |
| `app/resource.py` | Protected API verifying IDCS JWT signature, issuer, audience, type and scope |
| `app/saml.py` | Retained SAML integration at explicit `/saml/*` routes |
| `app/cli.py` | Local initialization, preflight and trust JSON template |
| `app/templates/index.html`, `app/static/` | Flow inspector, accessible tabs and local scripts/styles |

The local servers bind to loopback, use one process and keep bounded, expiring session state in memory. Restarting clears sessions. Configuration changes require a restart. Legacy SAML setup is documented in [docs/setup.md](docs/setup.md); the dashboard defaults to OIDC.

"""Real Okta RFC 8693 exchanges and OCI Identity Domains RFC 7523 redemption."""
import base64
import re
import time
import uuid
import jwt
import requests
from requests.auth import HTTPBasicAuth

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
CLIENT_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
TT = "urn:ietf:params:oauth:token-type:"
SENSITIVE = {"assertion", "subject_token", "client_assertion", "access_token", "refresh_token", "id_token", "client_secret", "authorization", "code", "code_verifier", "state", "nonce"}

class FlowError(ValueError):
    pass

def redact(value, secrets=()):
    if isinstance(value, dict):
        return {k: "[redacted]" if k.lower() in SENSITIVE else redact(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[redacted]")
        return re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[redacted JWT]", value)
    return value

class Exchanges:
    def __init__(self, cfg, http=None, okta_keys=None):
        self.cfg = cfg
        self.http = http or requests.Session()
        self.okta_keys = okta_keys or jwt.PyJWKClient(cfg.okta + "/oauth2/v1/keys", timeout=10)

    def agent_auth(self, form):
        self.cfg.require("okta")
        client = self.cfg.get("OKTA_AGENT_CLIENT_ID")
        now = int(time.time())
        assertion = jwt.encode({"iss": client, "sub": client, "aud": self.cfg.okta_token,
                                "iat": now, "exp": now + 120, "jti": str(uuid.uuid4())},
                               self.cfg.path("OKTA_AGENT_KEY_FILE", "secrets/okta-agent.pem").read_text(),
                               algorithm="RS256", headers={"kid": self.cfg.get("OKTA_AGENT_KID", "okta-agent-1")})
        return {**form, "client_id": client, "client_assertion_type": CLIENT_ASSERTION, "client_assertion": assertion}

    def post_token(self, label, url, form, traces, auth=None, auth_method=None):
        entry = {"step": label, "url": url, "request": redact(form),
                 "authentication": auth_method or ("client_secret_basic" if auth else "private_key_jwt")}
        traces.append(entry)
        try:
            response = self.http.post(url, data=form, auth=auth, timeout=(5, 25),
                                      headers={"Accept": "application/json"}, allow_redirects=False)
        except requests.RequestException:
            entry["error"] = "Connection failed or timed out"
            raise FlowError(f"{label}: connection failed or timed out") from None
        entry["status"] = response.status_code
        try:
            body = response.json()
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        # Only structured protocol fields are displayed; upstream diagnostics can echo secrets.
        entry["response"] = redact({k: body[k] for k in ("token_type", "issued_token_type", "expires_in", "scope", "access_token", "refresh_token") if k in body}, tuple(form.values()))
        if not 200 <= response.status_code < 300:
            code = body.get("error", "upstream_error")
            code = code if isinstance(code, str) and re.fullmatch(r"[a-z_]{1,60}", code) else "upstream_error"
            entry["error"] = code
            if code == "invalid_target":
                raise FlowError(f"{label}: HTTP {response.status_code}, invalid_target. Match OKTA_XAA_AUDIENCE, OKTA_XAA_RESOURCE and REQUESTED_SCOPE exactly to the active Okta XAA resource connection (including trailing slashes).")
            raise FlowError(f"{label}: HTTP {response.status_code}, {code}. See docs/setup.md troubleshooting.")
        return body

    def id_jag(self, assertion_xml, traces):
        self.cfg.require("id_jag")
        self.cfg.require("okta")
        first = self.post_token("1. SAML → refresh token", self.cfg.okta_token, self.agent_auth({
            "grant_type": TOKEN_EXCHANGE, "requested_token_type": TT + "refresh_token",
            "subject_token_type": TT + "saml2",
            "subject_token": base64.b64encode(assertion_xml).decode(),
            "scope": self.cfg.get("BOOTSTRAP_SCOPE", "openid offline_access email"),
        }), traces)
        refresh = first.get("refresh_token")
        if not refresh and first.get("issued_token_type") == TT + "refresh_token":
            refresh = first.get("access_token")
        if not refresh:
            raise FlowError("Okta did not return a refresh token of the requested type")
        second = self.post_token("2. Refresh token → ID-JAG", self.cfg.okta_token, self.agent_auth({
            "grant_type": TOKEN_EXCHANGE, "requested_token_type": TT + "id-jag",
            "subject_token_type": TT + "refresh_token", "subject_token": refresh,
            "audience": self.cfg.xaa_audience, "scope": self.cfg.scope,
        }), traces)
        return self.validate_id_jag(second)

    def id_jag_from_oidc(self, identity, traces):
        from .oidc import client_auth
        self.cfg.require("id_jag")
        kind = self.cfg.get("OKTA_XAA_SUBJECT_TOKEN_TYPE", "id_token")
        if kind not in {"refresh_token", "id_token"}:
            raise FlowError("OKTA_XAA_SUBJECT_TOKEN_TYPE must be refresh_token or id_token")
        subject = identity.get("tokens", {}).get(kind)
        if not subject:
            if kind == "id_token":
                raise FlowError("No id_token from OIDC sign-in; sign in again with the openid scope.")
            raise FlowError("No refresh_token from OIDC sign-in. Enable Refresh Token and offline_access in Okta, then sign in again; or set OKTA_XAA_SUBJECT_TOKEN_TYPE=id_token.")
        if kind == "id_token" and identity["claims"]["exp"] <= time.time():
            raise FlowError("OIDC ID token expired; sign in again")
        form = {"grant_type": TOKEN_EXCHANGE, "requested_token_type": TT + "id-jag",
                "subject_token_type": TT + kind, "subject_token": subject,
                "audience": self.cfg.xaa_audience, "scope": self.cfg.scope}
        resource = self.cfg.get("OKTA_XAA_RESOURCE")
        if resource:
            form["resource"] = resource
        form, auth, method = client_auth(self.cfg, form)
        body = self.post_token("2. " + kind + " → ID-JAG", self.cfg.okta_token, form, traces,
                               auth=auth, auth_method=method)
        return self.validate_id_jag(body)

    def validate_id_jag(self, body):
        token = body.get("access_token")
        if not token or body.get("issued_token_type") not in (None, TT + "id-jag"):
            raise FlowError("Okta did not return an ID-JAG")
        try:
            header = jwt.get_unverified_header(token)
            if header.get("typ") != "oauth-id-jag+jwt" or header.get("alg") != "RS256":
                raise FlowError("Expected a signed RS256 oauth-id-jag+jwt")
            claims = jwt.decode(token, self.okta_keys.get_signing_key_from_jwt(token).key,
                                algorithms=["RS256"], issuer=self.cfg.okta, audience=self.cfg.xaa_audience,
                                options={"require": ["iss", "aud", "sub", "exp", "iat", "jti", "client_id", "scope"]}, leeway=30)
        except (jwt.PyJWTError, ValueError) as exc:
            raise FlowError("ID-JAG signature, type, issuer, audience or lifetime validation failed") from exc
        if not isinstance(claims["client_id"], str) or claims["client_id"].casefold() != self.cfg.trust_source_client.casefold():
            raise FlowError("ID-JAG client_id must match the inbound trust source client (OKTA_OIDC_CLIENT_ID or IDCS_TRUST_SOURCE_CLIENT_ID); check the Okta connection and OCI Identity Domains trust")
        scopes = claims.get("scope")
        if not isinstance(scopes, str) or not set(self.cfg.scope.split()).issubset(scopes.split()):
            raise FlowError("ID-JAG does not contain the requested OCI Identity Domains scopes")
        if not claims.get(self.cfg.get("IDCS_SUBJECT_CLAIM", "email")):
            raise FlowError("ID-JAG lacks the claim configured for the OCI Identity Domains inbound user mapping")
        return token, {"header": header, "claims": claims, "signature_verified": True}

    def redeem(self, id_jag, traces):
        self.cfg.require("idcs")
        body = self.post_token("3. ID-JAG → OCI Identity Domains access token", self.cfg.token_endpoint,
            {"grant_type": JWT_BEARER, "assertion": id_jag, "scope": self.cfg.scope}, traces,
            auth=HTTPBasicAuth(self.cfg.get("IDCS_CLIENT_ID"), self.cfg.get("IDCS_CLIENT_SECRET")))
        if not body.get("access_token") or str(body.get("token_type", "")).lower() != "bearer":
            raise FlowError("OCI Identity Domains response is missing a Bearer access token")
        try:
            expires_in = int(body["expires_in"])
            if expires_in <= 0:
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            raise FlowError("OCI Identity Domains response has no valid expires_in") from None
        return {"value": body["access_token"], "expires_at": time.time() + expires_in,
                "scope": body.get("scope", self.cfg.scope)}

    def call_resource(self, access, traces):
        url = self.cfg.resource_url
        users_api = self.cfg.resource_is_users
        users, start, expected_total, total_bytes = [], 1, None, 0
        while True:
            if access["expires_at"] <= time.time():
                raise FlowError("OCI Identity Domains access token expired; obtain a fresh ID-JAG and redeem it")
            params = {"startIndex": start, "count": 100} if users_api else None
            entry = {"step": "4. OCI Identity Domains users" if users_api else "4. Protected resource", "url": url,
                     "request": {"method": "GET", "Authorization": "Bearer [redacted]", "query": params}}
            traces.append(entry)
            try:
                kwargs = {"params": params} if params else {}
                response = self.http.get(url, headers={"Authorization": "Bearer " + access["value"], "Accept": "application/json"},
                                         timeout=(5, 25), allow_redirects=False, stream=True, **kwargs)
                with response:
                    entry["status"] = response.status_code
                    chunks, size = [], 0
                    for chunk in response.iter_content(4096):
                        size += len(chunk)
                        total_bytes += len(chunk)
                        if size > (1024 * 1024 if users_api else 65536) or total_bytes > 5 * 1024 * 1024:
                            raise FlowError("Resource response exceeds the local display limit; the complete result was not loaded")
                        chunks.append(chunk)
                    import json
                    try:
                        body = json.loads(b"".join(chunks))
                    except ValueError:
                        body = {"message": "Resource returned a non-JSON response"}
            except requests.RequestException:
                raise FlowError("Protected resource connection failed or timed out") from None
            entry["response"] = redact(body, [access["value"], self.cfg.get("IDCS_CLIENT_SECRET")])
            if not 200 <= response.status_code < 300:
                hint = ""
                if users_api and response.status_code in (401, 403):
                    hint = ". OCI Identity Domains rejected the redeemed access token or its permission to list users; inspect the response below and check the OCI Identity Domains client/user grants."
                raise FlowError(f"Protected resource returned HTTP {response.status_code}" + hint)
            if not users_api:
                return entry["response"]
            if not isinstance(body, dict):
                raise FlowError("OCI Identity Domains returned an invalid users listing")
            total = body.get("totalResults")
            page = body.get("Resources", [] if total == 0 else None)
            if type(total) is not int or total < 0 or not isinstance(page, list) or any(not isinstance(u, dict) for u in page):
                raise FlowError("OCI Identity Domains returned an invalid users listing")
            if body.get("startIndex", start) != start:
                raise FlowError("OCI Identity Domains returned an unexpected page; complete users listing was not loaded")
            if expected_total is not None and total != expected_total:
                raise FlowError("The users list changed during pagination; retry to load a consistent listing")
            expected_total = total
            if total > 10000:
                raise FlowError("Users listing exceeds the 10,000-user local display limit")
            users.extend(page)
            if len(users) == total:
                return redact({"schemas": body.get("schemas", ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]),
                               "totalResults": total, "startIndex": 1, "itemsPerPage": len(users), "Resources": users},
                              [access["value"], self.cfg.get("IDCS_CLIENT_SECRET")])
            if not page or len(users) > total:
                raise FlowError("OCI Identity Domains pagination ended unexpectedly; complete users listing was not loaded")
            start += len(page)

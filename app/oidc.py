"""OIDC Authorization Code + PKCE with server-side client authentication."""
import base64
import hashlib
import hmac
import re
import secrets
from urllib.parse import urlencode, urlsplit
import jwt
import requests
from requests.auth import HTTPBasicAuth
from .protocol import FlowError, TT, redact


def client_auth(cfg, form):
    cfg.require("oidc")
    method = cfg.get("OKTA_OIDC_AUTH_METHOD", "client_secret_basic")
    client, secret = cfg.get("OKTA_OIDC_CLIENT_ID"), cfg.get("OKTA_OIDC_CLIENT_SECRET")
    if method == "client_secret_basic":
        # OAuth HTTP Basic credentials are form-encoded before base64 encoding.
        from urllib.parse import quote_plus
        return dict(form), HTTPBasicAuth(quote_plus(client), quote_plus(secret)), method
    if method == "client_secret_post":
        return {**form, "client_id": client, "client_secret": secret}, None, method
    raise FlowError("OKTA_OIDC_AUTH_METHOD must be client_secret_basic or client_secret_post")


class OidcLogin:
    def __init__(self, cfg, http=None, keys=None):
        self.cfg = cfg
        self.http = http or requests.Session()
        self.keys = keys or jwt.PyJWKClient(cfg.okta + "/oauth2/v1/keys", timeout=10)

    @property
    def redirect_uri(self):
        value = self.cfg.get("OKTA_OIDC_REDIRECT_URI", self.cfg.base + "/oidc/callback")
        expected, actual = urlsplit(self.cfg.base), urlsplit(value)
        if (actual.scheme, actual.netloc) != (expected.scheme, expected.netloc) or actual.path not in {"/oidc/callback", "/callback"} or actual.query or actual.fragment:
            raise FlowError("OKTA_OIDC_REDIRECT_URI must use BASE_URL and the /oidc/callback or /callback path")
        return value

    def start(self, pending):
        self.cfg.require("oidc")
        # Validate the selected confidential-client method before redirecting.
        client_auth(self.cfg, {})
        scope = self.cfg.get("OKTA_OIDC_SCOPE", "openid profile email offline_access")
        if "openid" not in scope.split():
            raise FlowError("OKTA_OIDC_SCOPE must include openid")
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        data = {"verifier": verifier, "nonce": secrets.token_urlsafe(32)}
        state = pending.put(data, ttl=300)
        params = {"client_id": self.cfg.get("OKTA_OIDC_CLIENT_ID"), "response_type": "code", "response_mode": "query",
                  "scope": scope, "redirect_uri": self.redirect_uri, "state": state, "nonce": data["nonce"],
                  "code_challenge": challenge, "code_challenge_method": "S256"}
        endpoint = self.cfg.okta + "/oauth2/v1/authorize"
        data["authorization"] = {"method": "GET", "url": endpoint + "?" + urlencode(redact(params)), "parameters": redact(params)}
        return endpoint + "?" + urlencode(params), state

    def finish(self, args, browser_state, pending):
        # Check browser binding before consuming the server-side one-time state.
        states = args.getlist("state")
        if len(states) != 1 or not browser_state or not hmac.compare_digest(states[0].encode(), browser_state.encode()):
            raise FlowError("OIDC state validation failed; start sign-in again in the same browser")
        data = pending.get(states[0], pop=True)
        if not data:
            raise FlowError("OIDC sign-in expired or was already completed; start sign-in again")
        if args.get("error"):
            # Never reflect arbitrary IdP error descriptions or callback values.
            raise FlowError("Okta did not complete sign-in. Check app assignment, consent and the registered redirect URI, then retry.")
        codes = args.getlist("code")
        if len(codes) != 1 or not codes[0]:
            raise FlowError("OIDC callback is missing one authorization code")
        form, auth, method = client_auth(self.cfg, {"grant_type": "authorization_code", "code": codes[0],
                                                   "redirect_uri": self.redirect_uri, "code_verifier": data["verifier"]})
        trace = {"authorization": data["authorization"],
                 "token_request": {"method": "POST", "url": self.cfg.okta_token,
                                   "authentication": method, "body": redact(form)}}
        try:
            response = self.http.post(self.cfg.okta_token, data=form, auth=auth, timeout=(5, 25),
                                      headers={"Accept": "application/json"}, allow_redirects=False)
        except requests.RequestException:
            raise FlowError("OIDC token endpoint connection failed or timed out") from None
        try:
            body = response.json()
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        if not 200 <= response.status_code < 300:
            code = body.get("error", "upstream_error")
            code = code if isinstance(code, str) and re.fullmatch(r"[a-z_]{1,60}", code) else "upstream_error"
            raise FlowError(f"OIDC token exchange failed: HTTP {response.status_code}, {code}. Check your client credentials and redirect URI.")
        token = body.get("id_token")
        if not isinstance(token, str) or not token:
            raise FlowError("Okta returned no id_token; request the openid scope")
        if not isinstance(body.get("access_token"), str) or str(body.get("token_type", "")).lower() != "bearer":
            raise FlowError("Okta returned no valid Bearer access token")
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256":
                raise jwt.InvalidAlgorithmError("Expected RS256")
            claims = jwt.decode(token, self.keys.get_signing_key_from_jwt(token).key,
                                algorithms=["RS256"], issuer=self.cfg.okta, audience=self.cfg.get("OKTA_OIDC_CLIENT_ID"),
                                options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]}, leeway=30)
            if not isinstance(claims["nonce"], str) or not hmac.compare_digest(claims["nonce"], data["nonce"]):
                raise jwt.InvalidTokenError("Nonce mismatch")
            audiences = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
            client = self.cfg.get("OKTA_OIDC_CLIENT_ID")
            if len(audiences) > 1 and claims.get("azp") != client:
                raise jwt.InvalidTokenError("Authorized party required")
            if claims.get("azp", client) != client:
                raise jwt.InvalidTokenError("Wrong authorized party")
            if "at_hash" in claims:
                digest = hashlib.sha256(body["access_token"].encode()).digest()
                expected = base64.urlsafe_b64encode(digest[:len(digest)//2]).decode().rstrip("=")
                if not isinstance(claims["at_hash"], str) or not hmac.compare_digest(expected, claims["at_hash"]):
                    raise jwt.InvalidTokenError("Access token hash mismatch")
        except (jwt.PyJWTError, ValueError, TypeError):
            raise FlowError("OIDC ID token signature, issuer, audience, nonce or lifetime validation failed") from None
        # The user explicitly requested the actual ID token in the local response
        # inspector. Access/refresh tokens and confidential auth material stay redacted.
        display = {k: body[k] for k in ("token_type", "expires_in", "scope") if k in body}
        display["id_token"] = token
        for name in ("access_token", "refresh_token"):
            if name in body:
                display[name] = "[redacted — retained on the server]"
        trace["response"] = {"status": response.status_code, "body": display}
        trace["decoded"] = {"token_type": TT + "id_token", "header": header, "claims": claims, "signature_verified": True}
        identity = {"protocol": "oidc", "name_id": claims.get("email") or claims.get("preferred_username") or claims["sub"],
                    "attributes": claims, "claims": claims, "tokens": {k: body[k] for k in ("id_token", "access_token", "refresh_token") if k in body}}
        return identity, trace

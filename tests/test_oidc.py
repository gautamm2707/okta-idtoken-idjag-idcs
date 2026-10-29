"""Real signed OIDC/ID-JAG validation against offline HTTP fixtures."""
import base64
import hashlib
import time
from urllib.parse import parse_qs, quote_plus, urlsplit
import jwt
import pytest
from app.oidc import OidcLogin
from app.protocol import Exchanges, TT
from app.server import create_app
from test_flow import Reply, TenantHTTP

class OidcHTTP(TenantHTTP):
    def __init__(self, m, changes=None, status=200):
        super().__init__(m)
        self.nonce = None
        self.challenge = None
        self.changes = changes or {}
        self.status = status
        self.tokens = None

    def post(self, url, **kwargs):
        if url == self.m.cfg.token_endpoint:
            return super().post(url, **kwargs)
        self.calls.append((url, kwargs))
        form = kwargs["data"]
        method = self.m.cfg.get("OKTA_OIDC_AUTH_METHOD", "client_secret_basic")
        if method == "client_secret_basic":
            assert kwargs["auth"].username == quote_plus(self.m.cfg.get("OKTA_OIDC_CLIENT_ID"))
            assert kwargs["auth"].password == quote_plus(self.m.cfg.get("OKTA_OIDC_CLIENT_SECRET"))
            assert "client_secret" not in form
        else:
            assert kwargs["auth"] is None
            assert form["client_id"] == self.m.cfg.get("OKTA_OIDC_CLIENT_ID")
            assert form["client_secret"] == self.m.cfg.get("OKTA_OIDC_CLIENT_SECRET")
        assert kwargs["allow_redirects"] is False
        if form["grant_type"] != "authorization_code":
            kind = self.m.cfg.get("OKTA_XAA_SUBJECT_TOKEN_TYPE", "id_token")
            assert form["subject_token_type"] == TT + kind
            assert form["subject_token"] == self.tokens[kind]
            assert form["audience"] == self.m.cfg.xaa_audience
            assert form["scope"] == self.m.cfg.scope
            return Reply({"access_token": self.jag(client_id=self.m.cfg.get("OKTA_OIDC_CLIENT_ID"), aud=self.m.cfg.xaa_audience), "issued_token_type": TT + "id-jag", "token_type": "N_A"})
        assert form["code"] == "one-time-code"
        challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).decode().rstrip("=")
        assert challenge == self.challenge
        assert form["redirect_uri"].endswith("/oidc/callback")
        if self.status != 200:
            return Reply({"error": "invalid_client", "error_description": "oidc-client-secret one-time-code"}, self.status)
        now = int(time.time())
        access = "oidc-access-secret"
        digest = hashlib.sha256(access.encode()).digest()
        claims = {"iss": self.m.cfg.okta, "sub": "okta-user", "aud": self.m.cfg.get("OKTA_OIDC_CLIENT_ID"),
                  "iat": now, "exp": now + 600, "nonce": self.nonce, "email": "alice@example.com", "name": "Alice Example",
                  "at_hash": base64.urlsafe_b64encode(digest[:len(digest)//2]).decode().rstrip("=")}
        claims.update(self.changes)
        if self.changes.get("remove_nonce"):
            claims.pop("nonce")
        token = jwt.encode(claims, self.m.pem, algorithm="RS256", headers={"kid": "test-key"})
        self.tokens = {"id_token": token, "access_token": access, "refresh_token": "oidc-refresh-secret",
                       "token_type": "Bearer", "scope": "openid profile email offline_access", "expires_in": 600}
        return Reply(self.tokens)


def setup_oidc(m, changes=None, method="client_secret_basic", status=200):
    m.cfg.env.update(OKTA_OIDC_CLIENT_ID="oidc-client", OKTA_OIDC_CLIENT_SECRET="oidc-client-secret", OKTA_OIDC_AUTH_METHOD=method)
    http = OidcHTTP(m, changes, status)
    app = create_app(m.cfg, Exchanges(m.cfg, http, m.keys), OidcLogin(m.cfg, http, m.keys))
    return app, app.test_client(), http


def begin(app, client, http):
    response = client.get("/oidc/login")
    assert response.status_code == 302
    u = urlsplit(response.headers["Location"])
    assert u.scheme + "://" + u.netloc + u.path == http.m.cfg.okta + "/oauth2/v1/authorize"
    params = parse_qs(u.query)
    assert params["response_type"] == ["code"]
    assert params["code_challenge_method"] == ["S256"]
    assert "openid" in params["scope"][0].split()
    assert "offline_access" in params["scope"][0].split()
    assert "client_secret" not in params
    http.nonce = params["nonce"][0]
    http.challenge = params["code_challenge"][0]
    return params["state"][0]


def flow_for(app, client):
    with client.session_transaction() as session:
        return app.extensions["flows"].get(session.get("flow"))


@pytest.mark.parametrize("method", ["client_secret_basic", "client_secret_post"])
def test_oidc_login_inspector_and_cookie_safety(material, method):
    app, client, http = setup_oidc(material, method=method)
    # OIDC login is independent of all IDCS and legacy SAML credentials.
    for key in ("IDCS_CLIENT_ID", "IDCS_CLIENT_SECRET", "OKTA_SAML_SSO_URL", "OKTA_SAML_IDP_ISSUER"):
        material.cfg.env.pop(key, None)
    state = begin(app, client, http)
    response = client.get("/oidc/callback", query_string={"code": "one-time-code", "state": state}, follow_redirects=True)
    assert response.status_code == 200
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]
    flow = flow_for(app, client)
    assert flow["identity"]["protocol"] == "oidc"
    assert flow["auth_trace"]["decoded"]["signature_verified"]
    assert flow["identity"]["claims"]["email"] == "alice@example.com"
    text = response.get_data(as_text=True)
    assert "User Authentication (SSO)" in text
    assert 'role="tab"' in text and 'id="sso-response"' in text and 'id="sso-token"' in text
    assert http.tokens["id_token"] in text
    for value in ("oidc-client-secret", "one-time-code", "oidc-refresh-secret", "oidc-access-secret"):
        assert value not in text
    assert http.nonce not in str(flow["auth_trace"]["authorization"])
    assert "one-time-code" not in str(flow["auth_trace"]["token_request"])
    with client.session_transaction() as session:
        assert set(session) == {"csrf", "flow"}
        cookie_data = str(dict(session))
        assert http.tokens["id_token"] not in cookie_data
    assert client.get("/oidc/callback", query_string={"code": "one-time-code", "state": state}).status_code == 302
    assert len(http.calls) == 1


@pytest.mark.parametrize("changes", [{"nonce": "wrong"}, {"iss": "https://evil.example"}, {"aud": "wrong"}, {"exp": 1},
    {"iat": int(time.time()) + 3600}, {"azp": "wrong"}, {"aud": ["oidc-client", "other"]},
    {"at_hash": "wrong"}, {"remove_nonce": True}])
def test_bad_oidc_claims_fail_before_session_creation(material, changes):
    app, client, http = setup_oidc(material, changes)
    state = begin(app, client, http)
    response = client.get("/oidc/callback", query_string={"code": "one-time-code", "state": state}, follow_redirects=True)
    assert flow_for(app, client) is None
    assert b"ID token signature, issuer, audience, nonce or lifetime validation failed" in response.data
    assert b"oidc-client-secret" not in response.data


def test_oidc_state_is_browser_bound_and_expiring(material):
    app, client, http = setup_oidc(material)
    state = begin(app, client, http)
    other = app.test_client()
    other.get("/oidc/callback", query_string={"code": "one-time-code", "state": state})
    assert flow_for(app, other) is None and http.calls == []
    # A rejected response from another browser must not consume valid state.
    assert app.extensions["pending"].get(state) is not None
    client.get("/oidc/callback", query_string={"code": "one-time-code", "state": state})
    assert flow_for(app, client) is not None
    state = begin(app, client, http)
    _, data = app.extensions["pending"].items[state]
    app.extensions["pending"].items[state] = (0, data)
    client.get("/oidc/callback", query_string={"code": "one-time-code", "state": state})
    assert len(http.calls) == 1


def test_oidc_duplicate_state_or_code_rejected(material):
    app, client, http = setup_oidc(material)
    state = begin(app, client, http)
    client.get("/oidc/callback", query_string=[("state", state), ("state", state), ("code", "one-time-code")])
    assert http.calls == []
    state = begin(app, client, http)
    client.get("/oidc/callback", query_string=[("state", state), ("code", "one-time-code"), ("code", "other")])
    assert http.calls == []


def test_oidc_remote_error_is_sanitized(material):
    app, client, http = setup_oidc(material, status=400)
    state = begin(app, client, http)
    response = client.get("/oidc/callback", query_string={"code": "one-time-code", "state": state}, follow_redirects=True)
    assert b"invalid_client" in response.data
    assert b"oidc-client-secret" not in response.data and b"one-time-code" not in response.data
    assert flow_for(app, client) is None


def test_oidc_idjag_needs_target_id_but_not_idcs_secret(material):
    app, client, http = setup_oidc(material)
    material.cfg.env.pop("IDCS_CLIENT_SECRET")
    state = begin(app, client, http)
    client.get("/oidc/callback", query_string={"code": "one-time-code", "state": state})
    with client.session_transaction() as session:
        csrf = session["csrf"]
    response = client.post("/flow/id-jag", data={"csrf": csrf}, headers={"Origin": material.cfg.base}, follow_redirects=True)
    flow = flow_for(app, client)
    assert response.status_code == 200
    assert flow["error"] is None, flow["error"]
    assert flow["decoded"]["signature_verified"]
    assert len(http.calls) == 2
    assert b"oidc-refresh-secret" not in response.data and b"oidc-client-secret" not in response.data
    client.post("/flow/redeem", data={"csrf": csrf}, headers={"Origin": material.cfg.base})
    assert "IDCS_CLIENT_SECRET" in flow["error"]
    assert len(http.calls) == 2


def test_oidc_invalid_signature_is_rejected(material):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from types import SimpleNamespace
    app, client, http = setup_oidc(material)
    wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    app.extensions["oidc"].keys = SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=wrong.public_key()))
    state = begin(app, client, http)
    client.get("/oidc/callback", query_string={"code": "one-time-code", "state": state})
    assert flow_for(app, client) is None


def test_oidc_no_refresh_token_still_allows_signin(material):
    app, client, http = setup_oidc(material)
    material.cfg.env["OKTA_XAA_SUBJECT_TOKEN_TYPE"] = "refresh_token"
    real_post = http.post
    def without_refresh(*args, **kwargs):
        response = real_post(*args, **kwargs)
        response.body.pop("refresh_token", None)
        return response
    http.post = without_refresh
    state = begin(app, client, http)
    client.get("/oidc/callback", query_string={"code": "one-time-code", "state": state})
    assert flow_for(app, client) is not None
    with client.session_transaction() as session:
        csrf = session["csrf"]
    client.post("/flow/id-jag", data={"csrf": csrf})
    assert "No refresh_token" in flow_for(app, client)["error"]
    assert len(http.calls) == 1


def test_oidc_callback_does_not_follow_arbitrary_redirect_uri(material):
    app, client, http = setup_oidc(material)
    material.cfg.env["OKTA_OIDC_REDIRECT_URI"] = "https://evil.example/callback"
    response = client.get("/oidc/login", follow_redirects=True)
    assert b"OKTA_OIDC_REDIRECT_URI must use BASE_URL" in response.data
    assert http.calls == []


def test_full_oidc_to_idcs_resource_flow(material):
    app, client, http = setup_oidc(material)
    state = begin(app, client, http)
    client.get("/oidc/callback", query_string={"code": "one-time-code", "state": state})
    with client.session_transaction() as session:
        csrf = session["csrf"]
    for action in ("id-jag", "redeem", "resource"):
        response = client.post("/flow/" + action, data={"csrf": csrf}, headers={"Origin": material.cfg.base}, follow_redirects=True)
        flow = flow_for(app, client)
        assert response.status_code == 200
        assert flow["error"] is None, flow["error"]
    assert b"Your IDCS access token was verified" in response.data
    assert len(http.calls) == 3
    assert b"target-secret" not in response.data
    assert b"oidc-client-secret" not in response.data
    assert b"oidc-refresh-secret" not in response.data


def test_explicit_oidc_id_token_subject(material):
    app, client, http = setup_oidc(material)
    material.cfg.env["OKTA_XAA_SUBJECT_TOKEN_TYPE"] = "id_token"
    state = begin(app, client, http)
    client.get("/oidc/callback", query_string={"code": "one-time-code", "state": state})
    with client.session_transaction() as session:
        csrf = session["csrf"]
    client.post("/flow/id-jag", data={"csrf": csrf})
    assert flow_for(app, client)["error"] is None
    assert len(http.calls) == 2


def test_idjag_target_id_checked_before_sending_oidc_refresh(material):
    app, client, http = setup_oidc(material)
    material.cfg.env.pop("IDCS_CLIENT_ID")
    state = begin(app, client, http)
    client.get("/oidc/callback", query_string={"code": "one-time-code", "state": state})
    with client.session_transaction() as session:
        csrf = session["csrf"]
    client.post("/flow/id-jag", data={"csrf": csrf})
    assert "IDCS_CLIENT_ID" in flow_for(app, client)["error"]
    assert len(http.calls) == 1


def test_id_token_exchange_matches_postman_and_exact_audience(material):
    import pytest
    from app.protocol import FlowError, TOKEN_EXCHANGE
    app, client, http = setup_oidc(material)
    cfg = material.cfg
    original_issuer = cfg.issuer
    target = cfg.issuer.rstrip("/")
    cfg.env.update(OKTA_XAA_AUDIENCE=target, OKTA_XAA_RESOURCE=target,
                   REQUESTED_SCOPE="urn:opc:idm:__myscopes__")
    state = begin(app, client, http)
    client.get("/oidc/callback", query_string={"code": "one-time-code", "state": state})
    flow = flow_for(app, client)
    # The default exchange must work without any refresh token.
    flow["identity"]["tokens"].pop("refresh_token")
    with client.session_transaction() as session:
        csrf = session["csrf"]
    client.post("/flow/id-jag", data={"csrf": csrf})
    assert flow["error"] is None
    form = http.calls[-1][1]["data"]
    assert form == {"grant_type": TOKEN_EXCHANGE, "requested_token_type": TT + "id-jag",
        "subject_token": http.tokens["id_token"], "subject_token_type": TT + "id_token",
        "scope": "urn:opc:idm:__myscopes__", "resource": target, "audience": target}
    assert flow["decoded"]["claims"]["aud"] == target
    assert cfg.issuer == original_issuer and original_issuer.endswith("/")
    # Configuring a separate audience must not weaken audience validation.
    with pytest.raises(FlowError, match="validation failed"):
        app.extensions["exchange"].validate_id_jag({"access_token": http.jag(client_id="oidc-client", aud=original_issuer)})


def test_expired_id_token_never_sent_to_exchange(material):
    app, client, http = setup_oidc(material)
    state = begin(app, client, http)
    client.get("/oidc/callback", query_string={"code": "one-time-code", "state": state})
    flow = flow_for(app, client)
    flow["identity"]["claims"]["exp"] = 1
    with client.session_transaction() as session:
        csrf = session["csrf"]
    client.post("/flow/id-jag", data={"csrf": csrf})
    assert "expired; sign in again" in flow["error"]
    assert len(http.calls) == 1


def test_explicit_refresh_subject_still_supported(material):
    app, client, http = setup_oidc(material)
    material.cfg.env["OKTA_XAA_SUBJECT_TOKEN_TYPE"] = "refresh_token"
    state = begin(app, client, http)
    client.get("/oidc/callback", query_string={"code": "one-time-code", "state": state})
    with client.session_transaction() as session:
        csrf = session["csrf"]
    client.post("/flow/id-jag", data={"csrf": csrf})
    assert flow_for(app, client)["error"] is None
    assert http.calls[-1][1]["data"]["subject_token"] == "oidc-refresh-secret"

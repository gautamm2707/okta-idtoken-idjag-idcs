"""Signed SAML + signed ID-JAG + signed target access token, offline HTTP."""
import base64
import datetime as dt
import json
import time
from urllib.parse import parse_qs, urlsplit
import jwt
import pytest
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from app.protocol import Exchanges, FlowError, TOKEN_EXCHANGE, JWT_BEARER, TT, redact
from app.resource import create_app as resource_app
from app.server import create_app
from app.saml import assertion_bytes, consume


def signed_saml(m, request_id="_request", audience="http://localhost:4141/saml/metadata", lifetime=300, signed=True):
    now = dt.datetime.now(dt.timezone.utc)
    stamp = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
    start, end = stamp(now - dt.timedelta(seconds=60)), stamp(now + dt.timedelta(seconds=lifetime))
    issue = stamp(now)
    assertion = f'''<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion" Version="2.0" IssueInstant="{issue}"><saml2:Issuer>http://www.okta.com/test</saml2:Issuer><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="{request_id}" NotOnOrAfter="{end}" Recipient="http://localhost:4141/saml/acs"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="{start}" NotOnOrAfter="{end}"><saml2:AudienceRestriction><saml2:Audience>{audience}</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="{issue}" SessionIndex="_session"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion>'''
    if signed:
        assertion = OneLogin_Saml2_Utils.add_sign(assertion, m.pem.decode(), m.cert.decode(), sign_algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", digest_algorithm="http://www.w3.org/2001/04/xmlenc#sha256").decode()
    # add_sign may include an XML declaration, which cannot be nested.
    if assertion.startswith("<?xml"):
        assertion = assertion.split("?>", 1)[1].lstrip()
    xml = f'''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response" Version="2.0" IssueInstant="{issue}" Destination="http://localhost:4141/saml/acs" InResponseTo="{request_id}"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/test</saml2:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{assertion}</samlp:Response>'''
    return xml.encode()


class Reply:
    def __init__(self, body, status=200):
        self.body, self.status_code = body, status
    def json(self):
        return self.body
    def iter_content(self, size):
        yield json.dumps(self.body).encode()
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False

class TenantHTTP:
    def __init__(self, m):
        self.m, self.calls = m, []
        self.api = resource_app(m.cfg, m.keys).test_client()
    def jag(self, **changes):
        claims = {"iss": self.m.cfg.okta, "sub": "okta-user", "email": "alice@example.com", "aud": self.m.cfg.issuer,
            "client_id": "target-client", "scope": self.m.cfg.scope, "iat": int(time.time()), "exp": int(time.time()) + 300, "jti": "jag-id"}
        claims.update(changes)
        return jwt.encode(claims, self.m.pem, algorithm="RS256", headers={"typ": "oauth-id-jag+jwt", "kid": "test-key"})
    def access(self, **changes):
        claims = {"iss": self.m.cfg.issuer, "sub": "alice@example.com", "aud": "http://localhost:4142", "scope": self.m.cfg.scope,
                  "iat": int(time.time()), "exp": int(time.time()) + 600, "tok_type": "AT"}
        claims.update(changes)
        return jwt.encode(claims, self.m.pem, algorithm="RS256", headers={"kid": "test-key"})
    def post(self, url, **kwargs):
        form = kwargs["data"]
        self.calls.append((url, kwargs))
        if url == self.m.cfg.okta_token:
            assert form["grant_type"] == TOKEN_EXCHANGE
            assert "resource" not in form
            auth = jwt.decode(form["client_assertion"], self.m.key.public_key(), algorithms=["RS256"], audience=url)
            assert auth["iss"] == auth["sub"] == "agent-client"
            if form["requested_token_type"] == TT + "refresh_token":
                assert b"Assertion" in base64.b64decode(form["subject_token"])
                return Reply({"access_token": "opaque-refresh", "issued_token_type": TT + "refresh_token", "token_type": "N_A"})
            assert form["subject_token"] == "opaque-refresh"
            assert form["audience"] == self.m.cfg.issuer
            return Reply({"access_token": self.jag(), "issued_token_type": TT + "id-jag", "token_type": "N_A"})
        assert url == self.m.cfg.token_endpoint
        assert form["grant_type"] == JWT_BEARER
        assert form["scope"] == self.m.cfg.scope
        assert kwargs["auth"].username == "target-client"
        assert kwargs["auth"].password == "target-secret"
        assert "client_assertion" not in form
        assert jwt.decode(form["assertion"], self.m.key.public_key(), algorithms=["RS256"], audience=self.m.cfg.issuer)["email"] == "alice@example.com"
        return Reply({"access_token": self.access(), "token_type": "Bearer", "expires_in": 600})
    def get(self, url, **kwargs):
        response = self.api.get("/api/message", headers=kwargs["headers"])
        return Reply(response.json, response.status_code)


def test_signed_saml_and_exact_preservation(material):
    xml = signed_saml(material)
    app = create_app(material.cfg)
    with app.test_request_context("/saml/acs", method="POST", data={"SAMLResponse": base64.b64encode(xml).decode()}):
        from flask import request
        identity = consume(material.cfg, request, "_request")
    assert identity["name_id"] == "alice@example.com"
    assert identity["assertion"] in xml

@pytest.mark.parametrize("change", ["audience", "expiry", "unsigned", "tamper", "request"])
def test_invalid_saml_rejected(material, change):
    options = {"audience": {"audience": "https://wrong.example"}, "expiry": {"lifetime": -600}, "unsigned": {"signed": False}}.get(change, {})
    xml = signed_saml(material, **options)
    if change == "tamper":
        xml = xml.replace(b"alice@example.com", b"attacker@example.com")
    app = create_app(material.cfg)
    with app.test_request_context("/saml/acs", method="POST", data={"SAMLResponse": base64.b64encode(xml).decode()}):
        from flask import request
        with pytest.raises(ValueError):
            consume(material.cfg, request, "_other" if change == "request" else "_request")


def test_full_browser_flow_and_redaction(material):
    http = TenantHTTP(material)
    app = create_app(material.cfg, Exchanges(material.cfg, http, material.keys))
    browser, cross_site = app.test_client(), app.test_client(use_cookies=False)
    assert browser.get("/").status_code == 200
    location = browser.get("/saml/login").headers["Location"]
    relay = parse_qs(urlsplit(location).query)["RelayState"][0]
    state = app.extensions["pending"].get(relay)
    saml = signed_saml(material, request_id=state["request_id"])
    posted = {"SAMLResponse": base64.b64encode(saml).decode(), "RelayState": relay}
    response = cross_site.post("/saml/acs", data=posted)
    assert response.status_code == 303
    assert cross_site.post("/saml/acs", data=posted).status_code == 400
    assert browser.get(response.headers["Location"]).status_code == 302
    with browser.session_transaction() as session:
        csrf = session["csrf"]
        assert "assertion" not in session and "access_token" not in session
    for route in ("id-jag", "redeem", "resource"):
        response = browser.post("/flow/" + route, data={"csrf": csrf}, follow_redirects=True)
        assert response.status_code == 200
        with browser.session_transaction() as session:
            flow = app.extensions["flows"].get(session["flow"])
            assert flow["error"] is None, flow["error"]
    assert b"Your IDCS access token was verified" in response.data
    text = response.get_data(as_text=True)
    assert "opaque-refresh" not in text and "target-secret" not in text
    assert http.access() not in text and http.jag() not in text
    assert len(http.calls) == 3
    assert browser.post("/flow/resource").status_code == 403
    assert browser.post("/flow/resource", data={"csrf": csrf}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert browser.post("/logout", data={"csrf": csrf}).status_code == 302
    assert browser.get("/").status_code == 200
    assert len(app.extensions["flows"].items) == 0


def test_completion_requires_browser_binding(material):
    app = create_app(material.cfg)
    ticket = app.extensions["completed"].put({"browser": "correct-browser", "identity": {}})
    assert app.test_client().get("/saml/complete?ticket=" + ticket).status_code == 400

@pytest.mark.parametrize("change", [{"iss": "https://evil.example"}, {"aud": "https://wrong.example"}, {"exp": 1}, {"client_id": "wrong"}, {"scope": "other"}, {"email": ""}])
def test_idjag_claim_failures(material, change):
    http = TenantHTTP(material)
    good_jag = http.jag
    http.jag = lambda: good_jag(**change)
    with pytest.raises(FlowError):
        Exchanges(material.cfg, http, material.keys).id_jag(b"<Assertion/>", [])


def test_protocol_error_never_echoes_credentials(material):
    http = TenantHTTP(material)
    http.post = lambda *args, **kwargs: Reply({"error": "invalid_grant", "error_description": "opaque-refresh target-secret"}, 400)
    traces = []
    with pytest.raises(FlowError, match="invalid_grant"):
        Exchanges(material.cfg, http, material.keys).id_jag(b"<Assertion/>", traces)
    assert "target-secret" not in str(traces) and "opaque-refresh" not in str(traces)


def test_redacts_nested_tokens():
    assert redact({"x": [{"Authorization": "Bearer abc"}], "text": "abc"}, ["abc"]) == {"x": [{"Authorization": "[redacted]"}], "text": "[redacted]"}


def test_saml_extraction_ignores_comments_and_rejects_ambiguity():
    a = b'<s:Assertion xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion">ok</s:Assertion>'
    assert assertion_bytes(b'<Response><!-- <Assertion>evil</Assertion> -->' + a + b'</Response>') == a
    with pytest.raises(ValueError):
        assertion_bytes(b'<Response>' + a + a + b'</Response>')
    with pytest.raises(ValueError):
        assertion_bytes(b'<!DOCTYPE x [<!ENTITY a "evil">]><Response>' + a + b'</Response>')


def test_resource_validates_access_token(material):
    http = TenantHTTP(material)
    api = http.api
    assert api.get("/api/message").status_code == 401
    assert api.get("/api/message", headers={"Authorization": "Bearer broken"}).status_code == 401
    assert api.get("/api/message", headers={"Authorization": "Bearer " + http.access()}).status_code == 200
    for changes in ({"aud": "wrong"}, {"iss": "wrong"}, {"exp": 1}, {"tok_type": "IT"}):
        assert api.get("/api/message", headers={"Authorization": "Bearer " + http.access(**changes)}).status_code == 401
    assert api.get("/api/message", headers={"Authorization": "Bearer " + http.access(scope="other")}).status_code == 403
    assert api.get("/api/message", headers={"Authorization": "Bearer " + http.jag()}).status_code == 401


def test_expired_access_token_is_not_sent(material):
    exchange = Exchanges(material.cfg, TenantHTTP(material), material.keys)
    with pytest.raises(FlowError, match="expired"):
        exchange.call_resource({"value": "old", "expires_at": 0}, [])


def test_wrong_signatures_and_token_types_are_rejected(material):
    from cryptography.hazmat.primitives.asymmetric import rsa
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    http = TenantHTTP(material)
    good_jag = http.jag
    original = good_jag()
    payload = jwt.decode(original, options={"verify_signature": False})
    for headers, signing_key in (({"typ": "JWT"}, material.key), ({"typ": "oauth-id-jag+jwt"}, other)):
        http.jag = lambda: jwt.encode(payload, signing_key, algorithm="RS256", headers=headers)
        with pytest.raises(FlowError):
            Exchanges(material.cfg, http, material.keys).id_jag(b"<Assertion/>", [])
    access_payload = jwt.decode(http.access(), options={"verify_signature": False})
    forged = jwt.encode(access_payload, other, algorithm="RS256")
    assert http.api.get("/api/message", headers={"Authorization": "Bearer " + forged}).status_code == 401


def test_saml_unsolicited_and_missing_request_are_rejected(material):
    client = create_app(material.cfg).test_client()
    response = client.post("/saml/acs", data={"SAMLResponse": base64.b64encode(signed_saml(material)).decode()})
    assert response.status_code == 400


def test_missing_settings_dashboard_and_login(material):
    from app.config import Settings
    client = create_app(Settings()).test_client()
    assert client.get("/").status_code == 200
    response = client.get("/saml/login", follow_redirects=True)
    assert response.status_code == 200
    assert b"Configure OKTA_SAML_SSO_URL" in response.data


def test_wrong_refresh_token_type_fails_closed(material):
    http = TenantHTTP(material)
    http.post = lambda *args, **kwargs: Reply({"access_token": "ordinary-access-token", "issued_token_type": TT + "access_token"})
    with pytest.raises(FlowError, match="refresh token"):
        Exchanges(material.cfg, http, material.keys).id_jag(b"<Assertion/>", [])


def test_idcs_error_is_traced_without_secret(material):
    http = TenantHTTP(material)
    http.post = lambda *args, **kwargs: Reply({"error": "invalid_grant", "error_description": kwargs["data"]["assertion"]}, 400)
    traces = []
    with pytest.raises(FlowError, match="invalid_grant"):
        Exchanges(material.cfg, http, material.keys).redeem("secret-id-jag", traces)
    assert traces[0]["status"] == 400
    assert "secret-id-jag" not in str(traces)


def test_token_requests_do_not_follow_redirects(material):
    http = TenantHTTP(material)
    observed = []
    def redirect_response(*args, **kwargs):
        observed.append(kwargs)
        return Reply({}, 302)
    http.post = redirect_response
    with pytest.raises(FlowError, match="302"):
        Exchanges(material.cfg, http, material.keys).redeem("secret-id-jag", [])
    assert observed[0]["allow_redirects"] is False


def test_dashboard_referrer_policy_preserves_form_origin(material):
    app = create_app(material.cfg)
    client = app.test_client()
    dashboard = client.get("/")
    assert dashboard.headers["Referrer-Policy"] == "same-origin"
    with client.session_transaction() as session:
        csrf = session["csrf"]
    # Exercise the real form route with no authenticated flow: 401 confirms
    # the request passed CSRF/origin validation and reached the session check.
    for path in ("/flow/id-jag", "/flow/redeem", "/flow/resource"):
        assert client.post(path, data={"csrf": csrf}, headers={"Origin": material.cfg.base}).status_code == 401
        assert client.post(path, data={"csrf": csrf}, headers={"Origin": "null"}).status_code == 403
        assert client.post(path, data={"csrf": csrf}, headers={"Origin": "https://evil.example"}).status_code == 403
        assert client.post(path, data={"csrf": "wrong"}, headers={"Origin": material.cfg.base}).status_code == 403
    assert client.get("/saml/complete?ticket=invalid").headers["Referrer-Policy"] == "no-referrer"
    assert client.post("/saml/acs").headers["Referrer-Policy"] == "no-referrer"
    expired = client.post("/flow/id-jag", data={"csrf": "wrong"}, headers={"Origin": material.cfg.base})
    assert b"form has expired" in expired.data

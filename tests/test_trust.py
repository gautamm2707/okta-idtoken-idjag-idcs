"""Offline admin API tests: real request construction, duplicate/error handling."""
import json
import pytest
import requests
from app.server import create_app
from app.trust import TrustSetup, trust_payload
from app.protocol import FlowError, Exchanges
from test_flow import Reply, TenantHTTP


class AdminHTTP:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        assert kwargs["allow_redirects"] is False
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def setup(material, *responses):
    material.cfg.env.update(OKTA_OIDC_CLIENT_ID="okta-source")
    http = AdminHTTP([Reply({"access_token": "admin-token-secret", "token_type": "Bearer", "expires_in": 3600}), *responses])
    return TrustSetup(material.cfg, http), http


def listing(*resources):
    return Reply({"Resources": list(resources), "totalResults": len(resources)})


def created(material):
    material.cfg.env["OKTA_OIDC_CLIENT_ID"] = "okta-source"
    return {**trust_payload(material.cfg), "id": "server-generated-id", "meta": {"resourceType": "IdentityPropagationTrust"}}


def test_create_uses_env_and_real_201_body(material):
    body = created(material)
    service, http = setup(material, listing(), Reply(body, 201))
    traces = []
    result = service.ensure(traces)
    assert result["status"] == 201 and result["ready"]
    assert result["body"] == body
    method, url, token_request = http.calls[0]
    assert (method, url) == ("POST", material.cfg.token_endpoint)
    assert token_request["auth"].username == "target-client"
    assert token_request["auth"].password == "target-secret"
    assert token_request["data"] == {"grant_type": "client_credentials", "scope": "urn:opc:idm:__myscopes__"}
    for method, url, kwargs in http.calls[1:]:
        assert url == material.cfg.issuer.rstrip("/") + "/admin/v1/IdentityPropagationTrusts"
        assert kwargs["headers"]["Authorization"] == "Bearer admin-token-secret"
    payload = http.calls[2][2]["json"]
    assert payload["idJagClients"] == [{"idJagOauthClientIds": ["target-client"], "inboundIdJagCrossDomainClientId": ["okta-source"]}]
    assert "id" not in payload and "meta" not in payload
    assert "target-secret" not in json.dumps(traces)
    assert "admin-token-secret" not in json.dumps(traces)


def test_existing_never_posts_create(material):
    body = created(material)
    service, http = setup(material, listing(body))
    result = service.ensure([])
    assert result["message"] == "Trust already created" and result["ready"]
    assert result["status"] == 200 and result["body"] == body
    assert len(http.calls) == 2


@pytest.mark.parametrize("change", [{"active": False}, {"idJagEnabled": False}, {"publicKeyEndpoint": "https://wrong.example/keys"},
    {"subjectClaimName": "sub"}, {"oauthClients": []}, {"idJagClients": [
        {"idJagOauthClientIds": ["target-client"], "inboundIdJagCrossDomainClientId": ["other"]},
        {"idJagOauthClientIds": ["other"], "inboundIdJagCrossDomainClientId": ["okta-source"]}]}])
def test_existing_mismatch_never_claims_ready_or_overwrites(material, change):
    body = {**created(material), **change}
    service, http = setup(material, listing(body))
    result = service.ensure([])
    assert result["message"] == "Trust already created"
    assert not result["ready"] and result["differences"]
    assert len(http.calls) == 2


def test_conflict_rechecked_and_duplicate_issuers_flagged(material):
    body = created(material)
    service, http = setup(material, listing(), Reply({"detail": "duplicate"}, 409), listing(body))
    assert service.ensure([])["message"] == "Trust already created"
    assert len(http.calls) == 4
    service, http = setup(material, listing(body, {**body, "id": "second"}))
    result = service.ensure([])
    assert not result["ready"] and "multiple" in result["differences"][0]
    assert len(http.calls) == 2


@pytest.mark.parametrize("status", [400, 401, 403, 500, 302])
def test_failed_check_does_not_create_or_report_already_created(material, status):
    service, http = setup(material, Reply({"detail": "bad target-secret admin-token-secret"}, status))
    traces = []
    with pytest.raises(FlowError, match="HTTP " + str(status)):
        service.ensure(traces)
    assert len(http.calls) == 2
    assert "target-secret" not in json.dumps(traces) and "admin-token-secret" not in json.dumps(traces)


def test_bad_listing_and_create_conflict_not_assumed_duplicate(material):
    service, http = setup(material, Reply({"Resources": []}))
    with pytest.raises(FlowError, match="invalid trust listing"):
        service.ensure([])
    assert len(http.calls) == 2
    service, http = setup(material, listing(), Reply({}, 409), listing())
    with pytest.raises(FlowError, match="HTTP 409"):
        service.ensure([])


def test_pagination_and_connection_failure(material):
    body = created(material)
    service, http = setup(material, Reply({"Resources": [{"issuer": "https://other.example"}], "totalResults": 2}), listing(body))
    assert service.ensure([])["ready"]
    assert http.calls[2][2]["params"]["startIndex"] == 2
    service, http = setup(material, listing(), requests.Timeout())
    with pytest.raises(FlowError, match="check again"):
        service.ensure([])


def test_env_overrides_portable_payload_and_validation(material):
    cfg = material.cfg
    cfg.env.update(IDCS_ISSUER="https://new-idcs.example/", OKTA_ORG_URL="https://new-okta.example",
        IDCS_CLIENT_ID="new-target", IDCS_TRUST_SOURCE_CLIENT_ID="explicit-source", IDCS_TRUST_NAME="Team trust",
        IDCS_SUBJECT_CLAIM="sub", IDCS_SUBJECT_MAPPING_ATTRIBUTE="externalId")
    payload = trust_payload(cfg)
    assert cfg.trust_endpoint == "https://new-idcs.example/admin/v1/IdentityPropagationTrusts"
    assert payload["publicKeyEndpoint"] == "https://new-okta.example/oauth2/v1/keys"
    assert payload["name"] == "Team trust" and payload["subjectMappingAttribute"] == "externalId"
    assert payload["idJagClients"][0]["inboundIdJagCrossDomainClientId"] == ["explicit-source"]
    http = TenantHTTP(material)
    exchange = Exchanges(cfg, http, material.keys)
    assert exchange.validate_id_jag({"access_token": http.jag(client_id="explicit-source")})[1]["signature_verified"]
    with pytest.raises(FlowError, match="inbound trust source"):
        exchange.validate_id_jag({"access_token": http.jag(client_id="new-target")})


def test_route_csrf_and_result_redaction(material):
    body = created(material)
    service, http = setup(material, listing(), Reply(body, 201))
    app = create_app(material.cfg, trust_setup=service)
    client = app.test_client()
    page = client.get("/")
    assert b"Inbound ID-JAG Trust" in page.data and len(http.calls) == 0
    assert client.post("/setup/trust").status_code == 403
    with client.session_transaction() as session:
        csrf = session["csrf"]
    assert client.post("/setup/trust", data={"csrf": csrf}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert len(http.calls) == 0
    page = client.post("/setup/trust", data={"csrf": csrf}, headers={"Origin": material.cfg.base}, follow_redirects=True)
    assert page.status_code == 200 and b"201 Created" in page.data
    assert b"server-generated-id" in page.data and b"trust-result-response" in page.data
    assert b"admin-token-secret" not in page.data and b"target-secret" not in page.data
    with client.session_transaction() as session:
        assert "server-generated-id" not in str(dict(session))
        assert "admin-token-secret" not in str(dict(session))


def test_missing_credentials_and_token_failure(material):
    service, http = setup(material)
    material.cfg.env["IDCS_CLIENT_SECRET"] = ""
    with pytest.raises(ValueError, match="IDCS_CLIENT_SECRET"):
        service.ensure([])
    assert not http.calls
    material.cfg.env["IDCS_CLIENT_SECRET"] = "target-secret"
    for response in (Reply({"error": "invalid_client"}, 401), Reply({"token_type": "Bearer"})):
        http.responses = [response]
        with pytest.raises(FlowError):
            service.ensure([])
    assert len(http.calls) == 2


def test_separate_admin_client_creates_trust_for_runtime_client(material):
    body = created(material)
    material.cfg.env.update(IDCS_ADMIN_CLIENT_ID="admin-client", IDCS_ADMIN_CLIENT_SECRET="admin-secret")
    service, http = setup(material, listing(), Reply(body, 201))
    traces = []
    result = service.ensure(traces)
    assert result["ready"] and result["status"] == 201
    assert http.calls[0][2]["auth"].username == "admin-client"
    assert http.calls[0][2]["auth"].password == "admin-secret"
    assert http.calls[2][2]["json"]["oauthClients"] == ["target-client"]
    assert "admin-secret" not in json.dumps(traces)
    assert "admin-secret" not in json.dumps(result)
    assert "target-secret" not in json.dumps(result)


def test_partial_admin_credentials_rejected_before_network(material):
    material.cfg.env["IDCS_ADMIN_CLIENT_ID"] = "admin-client"
    service, http = setup(material)
    with pytest.raises(FlowError, match="both IDCS_ADMIN_CLIENT_ID"):
        service.ensure([])
    assert not http.calls

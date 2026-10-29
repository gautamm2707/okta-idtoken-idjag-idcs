import time
import pytest
from app.protocol import Exchanges, FlowError
from app.server import create_app
from test_flow import Reply


class UsersHTTP:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        assert kwargs["headers"]["Authorization"] == "Bearer redeemed-access-token"
        assert kwargs["allow_redirects"] is False
        assert "auth" not in kwargs
        return self.replies.pop(0)


def exchange(material, replies):
    material.cfg.env["RESOURCE_URL"] = ""
    http = UsersHTTP(replies)
    return Exchanges(material.cfg, http, material.keys), http


def access():
    return {"value": "redeemed-access-token", "expires_at": time.time() + 600}


def test_users_pagination_and_ui(material):
    service, http = exchange(material, [
        Reply({"totalResults": 3, "startIndex": 1, "Resources": [{"id": "one"}, {"id": "two"}]}),
        Reply({"totalResults": 3, "startIndex": 3, "Resources": [{"id": "three"}]})])
    app = create_app(material.cfg, exchanges=service)
    client = app.test_client()
    state = {"identity": {"name_id": "alice@example.com", "attributes": {}}, "traces": [],
             "id_jag": None, "decoded": None, "access": access(), "resource": None, "error": None}
    with client.session_transaction() as session:
        session["csrf"] = "test-csrf"
        session["flow"] = app.extensions["flows"].put(state)
    response = client.post("/flow/resource", data={"csrf": "test-csrf"}, follow_redirects=True)
    assert response.status_code == 200 and state["error"] is None
    assert state["resource"]["totalResults"] == 3
    assert [u["id"] for u in state["resource"]["Resources"]] == ["one", "two", "three"]
    assert all(url == material.cfg.issuer.rstrip("/") + "/admin/v1/Users" for url, _ in http.calls)
    assert [kw["params"]["startIndex"] for _, kw in http.calls] == [1, 3]
    assert b"Retrieved 3 users from IDCS" in response.data
    assert b"resource-1-response" in response.data
    assert b"redeemed-access-token" not in response.data


@pytest.mark.parametrize("status", [401, 403])
def test_users_denied_shows_response_without_fallback(material, status):
    service, http = exchange(material, [Reply({"detail": "denied redeemed-access-token target-secret"}, status)])
    traces = []
    with pytest.raises(FlowError, match="permission to list users"):
        service.call_resource(access(), traces)
    assert len(http.calls) == 1 and traces[0]["status"] == status
    assert "redeemed-access-token" not in str(traces) and "target-secret" not in str(traces)


def test_empty_users_and_portable_endpoint(material):
    service, http = exchange(material, [Reply({"totalResults": 0})])
    material.cfg.env["IDCS_ISSUER"] = "https://another-idcs.example/"
    assert service.call_resource(access(), [])["Resources"] == []
    assert http.calls[0][0] == "https://another-idcs.example/admin/v1/Users"


@pytest.mark.parametrize("reply", [
    {"Resources": []}, {"totalResults": 1, "Resources": []},
    {"totalResults": 1, "startIndex": 20, "Resources": [{"id": "one"}]},
    {"totalResults": 10001, "Resources": []}])
def test_incomplete_listing_never_reported_complete(material, reply):
    service, _ = exchange(material, [Reply(reply)])
    with pytest.raises(FlowError):
        service.call_resource(access(), [])


def test_expired_access_does_not_call_users(material):
    service, http = exchange(material, [])
    with pytest.raises(FlowError, match="expired"):
        service.call_resource({"value": "redeemed-access-token", "expires_at": 0}, [])
    assert http.calls == []

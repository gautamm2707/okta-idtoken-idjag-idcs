"""Create-or-inspect inbound ID-JAG trusts using server-side IDCS credentials."""
import base64
import json
from threading import RLock
import requests
from requests.auth import HTTPBasicAuth
from .protocol import FlowError, redact


def trust_payload(cfg):
    client = cfg.get("IDCS_CLIENT_ID")
    if not client:
        raise FlowError("Configure IDCS_CLIENT_ID in .env first")
    return {
        "schemas": ["urn:ietf:params:scim:schemas:oracle:idcs:IdentityPropagationTrust"],
        "name": cfg.get("IDCS_TRUST_NAME") or "Inbound ID-JAG trust",
        "description": "Allows a target-domain client to redeem an approved source ID-JAG",
        "type": "JWT", "issuer": cfg.okta, "active": True,
        "subjectClaimName": cfg.get("IDCS_SUBJECT_CLAIM", "email"),
        "subjectMappingAttribute": cfg.get("IDCS_SUBJECT_MAPPING_ATTRIBUTE") or "userName",
        "publicKeyEndpoint": cfg.okta + "/oauth2/v1/keys",
        "oauthClients": [client], "idJagEnabled": True,
        "idJagClients": [{"idJagOauthClientIds": [client],
                          "inboundIdJagCrossDomainClientId": [cfg.trust_source_client]}],
    }


def differences(existing, desired):
    fields = ("type", "issuer", "active", "subjectClaimName", "subjectMappingAttribute",
              "publicKeyEndpoint", "idJagEnabled")
    result = [key for key in fields if existing.get(key) != desired[key]]
    target = desired["oauthClients"][0].casefold()
    source = desired["idJagClients"][0]["inboundIdJagCrossDomainClientId"][0].casefold()
    def contains(values, value):
        return isinstance(values, list) and any(isinstance(v, str) and v.casefold() == value for v in values)
    if not contains(existing.get("oauthClients"), target):
        result.append("oauthClients")
    pairs = existing.get("idJagClients")
    if not isinstance(pairs, list) or not any(
        isinstance(pair, dict) and contains(pair.get("idJagOauthClientIds"), target)
        and contains(pair.get("inboundIdJagCrossDomainClientId"), source) for pair in pairs
    ):
        result.append("idJagClients source/target pairing")
    return result


class TrustSetup:
    def __init__(self, cfg, http=None):
        self.cfg, self.http, self.lock = cfg, http or requests.Session(), RLock()

    def _request(self, method, url, traces, secrets, **kwargs):
        entry = {"method": method, "url": url,
                 "authentication": "client_secret_basic" if "auth" in kwargs else "Bearer [redacted]",
                 "body": kwargs.get("data", kwargs.get("json")), "query": kwargs.get("params")}
        traces.append({"request": entry})
        trace = traces[-1]
        try:
            response = self.http.request(method, url, timeout=(5, 25), allow_redirects=False, **kwargs)
        except requests.RequestException:
            trace["error"] = "Connection failed or timed out; check again before retrying creation."
            raise FlowError(trace["error"]) from None
        trace["status"] = response.status_code
        try:
            body = response.json()
        except ValueError:
            body = {"message": "IDCS returned a non-JSON response"}
        if not isinstance(body, dict):
            body = {"message": "IDCS returned an unexpected JSON response"}
        # Even token endpoint diagnostics that echo a newly issued token are scrubbed.
        hidden = secrets + [body.get(k) for k in ("access_token", "refresh_token", "id_token") if isinstance(body.get(k), str)]
        trace["response"] = redact(body, hidden)
        return response.status_code, body

    @staticmethod
    def _failure(status):
        if status in (401, 403):
            raise FlowError(f"IDCS returned HTTP {status}. Check IDCS_CLIENT_ID/IDCS_CLIENT_SECRET, enable Client Credentials, and grant the client permission to manage Identity Propagation Trusts.")
        raise FlowError(f"IDCS returned HTTP {status}. Inspect the response below; trust creation was not confirmed.")

    def _existing(self, payload, token, traces, secrets):
        matches, start = [], 1
        while True:
            status, body = self._request("GET", self.cfg.trust_endpoint, traces, secrets,
                params={"filter": "issuer eq " + json.dumps(payload["issuer"]), "startIndex": start, "count": 100},
                headers={"Authorization": "Bearer " + token, "Accept": "application/scim+json"})
            if status != 200:
                self._failure(status)
            resources, total = body.get("Resources"), body.get("totalResults")
            if not isinstance(resources, list) or type(total) is not int or total < 0:
                raise FlowError("IDCS returned an invalid trust listing; no trust was created.")
            if any(not isinstance(item, dict) for item in resources):
                raise FlowError("IDCS returned invalid trust entries; no trust was created.")
            matches.extend(item for item in resources if item.get("issuer") == payload["issuer"])
            start += len(resources)
            if start > total:
                return matches
            if not resources or start > 10000:
                raise FlowError("Could not finish checking existing trusts; no trust was created.")

    def _existing_result(self, matches, payload):
        issues = differences(matches[0], payload) if len(matches) == 1 else ["multiple trusts for this issuer"]
        return {"status": 200, "message": "Trust already created", "ready": not issues,
                "differences": issues, "body": matches[0] if len(matches) == 1 else {"Resources": matches}}

    def ensure(self, traces):
        # Serialize local clicks; re-query after a remote duplicate conflict too.
        with self.lock:
            self.cfg.require("idcs")
            payload = trust_payload(self.cfg)
            client, secret = self.cfg.get("IDCS_CLIENT_ID"), self.cfg.get("IDCS_CLIENT_SECRET")
            hidden = [secret, base64.b64encode((client + ":" + secret).encode()).decode()]
            status, body = self._request("POST", self.cfg.token_endpoint, traces, hidden,
                data={"grant_type": "client_credentials", "scope": self.cfg.get("IDCS_ADMIN_SCOPE") or "urn:opc:idm:__myscopes__"},
                auth=HTTPBasicAuth(client, secret), headers={"Accept": "application/json"})
            if status != 200:
                self._failure(status)
            token = body.get("access_token")
            if not isinstance(token, str) or not token or str(body.get("token_type", "")).lower() != "bearer":
                raise FlowError("IDCS did not return a Bearer admin access token.")
            hidden.append(token)
            matches = self._existing(payload, token, traces, hidden)
            if matches:
                return redact(self._existing_result(matches, payload), hidden)
            status, body = self._request("POST", self.cfg.trust_endpoint, traces, hidden, json=payload,
                headers={"Authorization": "Bearer " + token, "Content-Type": "application/scim+json", "Accept": "application/scim+json"})
            if status == 201:
                issues = differences(body, payload)
                if not body.get("id"):
                    issues.append("missing trust id in creation response")
                return {"status": 201, "message": "201 Created", "ready": not issues,
                        "differences": issues, "body": redact(body, hidden)}
            if status == 409:
                matches = self._existing(payload, token, traces, hidden)
                if matches:
                    return redact(self._existing_result(matches, payload), hidden)
            self._failure(status)

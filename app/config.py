"""Tenant defaults from public discovery; credentials stay in .env."""
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
IDCS = "https://idcs-ff3532e3a9ba4bd7887f5cf49e2ae425.identity.oraclecloud.com"

def require_url(value, name, local=False):
    u = urlsplit(value)
    if not u.hostname or u.username or u.password or u.fragment:
        raise ValueError(f"Invalid {name} URL")
    if u.scheme != "https" and not (local and u.scheme == "http" and u.hostname in {"localhost", "127.0.0.1"}):
        raise ValueError(f"{name} must use HTTPS (HTTP is allowed only on loopback)")
    return value

@dataclass
class Settings:
    env: dict = field(default_factory=dict)

    @classmethod
    def load(cls):
        load_dotenv(ROOT / ".env")
        return cls(dict(os.environ))

    def get(self, name, default=""):
        return self.env.get(name, default).strip()

    def path(self, name, default=""):
        return ROOT / self.get(name, default)

    @property
    def base(self):
        return self.get("BASE_URL", "http://localhost:4141").rstrip("/")

    @property
    def okta(self):
        return self.get("OKTA_ORG_URL", "https://integrator-1242259.okta.com").rstrip("/")

    @property
    def okta_token(self):
        return self.okta + "/oauth2/v1/token"

    @property
    def issuer(self):
        return self.get("IDCS_ISSUER", IDCS + "/")

    @property
    def token_endpoint(self):
        return self.get("IDCS_TOKEN_ENDPOINT", IDCS + ":443/oauth2/v1/token")

    @property
    def jwks(self):
        return self.get("IDCS_JWKS_URL", IDCS + ":443/admin/v1/SigningCert/jwk")

    @property
    def xaa_audience(self):
        # Exact identifier registered on the Okta XAA resource connection.
        # Do not change IDCS_ISSUER, which validates IDCS-issued access tokens.
        return self.get("OKTA_XAA_AUDIENCE") or self.issuer

    @property
    def resource_url(self):
        return self.get("RESOURCE_URL") or self.issuer.rstrip("/") + "/admin/v1/Users"

    @property
    def resource_is_users(self):
        return self.resource_url.rstrip("/") == self.issuer.rstrip("/") + "/admin/v1/Users"

    @property
    def trust_endpoint(self):
        return self.issuer.rstrip("/") + "/admin/v1/IdentityPropagationTrusts"

    @property
    def trust_source_client(self):
        # OIDC uses the requesting Okta client; preserve the legacy resource-ID
        # contract when no OIDC client is configured. Override for other contracts.
        return self.get("IDCS_TRUST_SOURCE_CLIENT_ID") or self.get("OKTA_OIDC_CLIENT_ID") or self.get("IDCS_CLIENT_ID")

    @property
    def scope(self):
        return self.get("REQUESTED_SCOPE", "http://localhost:4142/demo:read")

    def missing(self, stage):
        names = {
            "saml": ["OKTA_SAML_SSO_URL", "OKTA_SAML_IDP_ISSUER"],
            "oidc": ["OKTA_OIDC_CLIENT_ID", "OKTA_OIDC_CLIENT_SECRET"],
            "id_jag": ["IDCS_CLIENT_ID"],
            "okta": ["OKTA_AGENT_CLIENT_ID"],
            "idcs": ["IDCS_CLIENT_ID", "IDCS_CLIENT_SECRET"],
        }[stage]
        missing = [name for name in names if not self.get(name)]
        file_name = {"saml": ("OKTA_SAML_CERT_FILE", "secrets/okta-saml.crt"),
                     "okta": ("OKTA_AGENT_KEY_FILE", "secrets/okta-agent.pem")}.get(stage)
        if file_name and not self.path(*file_name).is_file():
            missing.append(file_name[0])
        return missing

    def require(self, stage):
        missing = self.missing(stage)
        if missing:
            raise ValueError("Configure " + ", ".join(missing) + " in .env first")

    def validate_urls(self):
        require_url(self.base, "BASE_URL", local=True)
        require_url(self.okta, "OKTA_ORG_URL")
        require_url(self.issuer, "IDCS_ISSUER")
        require_url(self.token_endpoint, "IDCS_TOKEN_ENDPOINT")
        require_url(self.jwks, "IDCS_JWKS_URL")
        require_url(self.resource_url, "RESOURCE_URL", local=True)

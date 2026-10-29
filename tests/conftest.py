import datetime as dt
from types import SimpleNamespace
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from app.config import Settings

@pytest.fixture
def material(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test signing key")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1)).sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    (tmp_path / "key.pem").write_bytes(pem)
    (tmp_path / "cert.pem").write_bytes(cert)
    cfg = Settings({"APP_SECRET": "test-secret", "OKTA_SAML_SSO_URL": "https://integrator-1242259.okta.com/app/test/sso/saml",
        "OKTA_SAML_IDP_ISSUER": "http://www.okta.com/test", "OKTA_SAML_CERT_FILE": str(tmp_path / "cert.pem"),
        "OKTA_AGENT_CLIENT_ID": "agent-client", "OKTA_AGENT_KEY_FILE": str(tmp_path / "key.pem"),
        "RESOURCE_URL": "http://localhost:4142/api/message", "IDCS_CLIENT_ID": "target-client", "IDCS_CLIENT_SECRET": "target-secret"})
    keys = SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=key.public_key()))
    return SimpleNamespace(key=key, pem=pem, cert=cert, cfg=cfg, keys=keys)

"""Local setup and read-only tenant preflight. Never modifies either tenant."""
import argparse
import json
import os
import secrets
from pathlib import Path
import requests
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from .config import ROOT, Settings


def init():
    directory = ROOT / "secrets"
    directory.mkdir(mode=0o700, exist_ok=True)
    private = directory / "okta-agent.pem"
    public = directory / "okta-agent.jwk.json"
    if not private.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key = serialization.load_pem_private_key(private.read_bytes(), password=None)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid=Settings.load().get("OKTA_AGENT_KID", "okta-agent-1"), alg="RS256", use="sig")
    public.write_text(json.dumps(jwk, indent=2) + "\n")
    env = ROOT / ".env"
    if not env.exists():
        text = (ROOT / ".env.example").read_text().replace("APP_SECRET=\n", "APP_SECRET=" + secrets.token_hex(32) + "\n")
        fd = os.open(env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
    print("Created/preserved .env and secrets/okta-agent.pem. Register secrets/okta-agent.jwk.json on the Okta AI Agent.")


def trust():
    from .trust import trust_payload
    print(json.dumps(trust_payload(Settings.load()), indent=2))


def check():
    cfg = Settings.load()
    cfg.validate_urls()
    problems = False
    for stage in ("oidc", "id_jag", "idcs"):
        missing = cfg.missing(stage)
        problems |= bool(missing)
        print(stage + ": " + ("missing " + ", ".join(missing) if missing else "local settings present"))
    for label, url in (("Okta", cfg.okta + "/.well-known/openid-configuration"),
                       ("IDCS", cfg.issuer.rstrip("/") + "/.well-known/openid-configuration")):
        try:
            r = requests.get(url, timeout=15, allow_redirects=False)
            r.raise_for_status()
            metadata = r.json()
            print(label + " discovery: " + json.dumps({k: metadata.get(k) for k in ("issuer", "token_endpoint", "jwks_uri", "authorization_grant_profiles_supported")}))
            if label == "IDCS":
                if metadata.get("issuer") != cfg.issuer or metadata.get("token_endpoint") != cfg.token_endpoint:
                    print("ERROR: configured issuer/token endpoint differs from IDCS discovery")
                    problems = True
                print("IDCS JWT bearer grant advertised:", "urn:ietf:params:oauth:grant-type:jwt-bearer" in metadata.get("grant_types_supported", []))
                print("ID-JAG enablement, inbound trust and user/client mapping still require tenant admin verification.")
        except (requests.RequestException, ValueError):
            print(label + " discovery failed")
            problems = True
    raise SystemExit(1 if problems else 0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["init", "trust-template", "check"])
    args = parser.parse_args()
    {"init": init, "trust-template": trust, "check": check}[args.command]()

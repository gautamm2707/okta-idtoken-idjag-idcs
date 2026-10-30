"""Protected local API: verifies OCI Identity Domains JWT signatures, issuer, audience and scope."""
import jwt
from flask import Flask, jsonify, request
from .config import Settings


def create_app(cfg=None, keys=None):
    cfg = cfg or Settings.load()
    cfg.validate_urls()
    app = Flask(__name__)
    keys = keys or jwt.PyJWKClient(cfg.jwks, timeout=10)

    @app.after_request
    def no_cache(response):
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.get("/api/message")
    def message():
        auth = request.headers.get("Authorization", "").split()
        if len(auth) != 2 or auth[0].lower() != "bearer":
            return jsonify(error="missing_bearer_token"), 401, {"WWW-Authenticate": "Bearer"}
        try:
            token = auth[1]
            claims = jwt.decode(token, keys.get_signing_key_from_jwt(token).key, algorithms=["RS256"],
                                issuer=cfg.issuer, audience=cfg.get("RESOURCE_AUDIENCE", "http://localhost:4142"),
                                options={"require": ["iss", "aud", "sub", "exp", "iat"]}, leeway=30)
            # A signature from OCI Identity Domains alone does not make a JWT an API access token.
            if claims.get("tok_type") != "AT":
                raise jwt.InvalidTokenError("Expected an OCI Identity Domains access token")
        except (jwt.PyJWTError, ValueError):
            return jsonify(error="invalid_token"), 401, {"WWW-Authenticate": 'Bearer error="invalid_token"'}
        scopes = claims.get("scope", "")
        if isinstance(scopes, str):
            scopes = scopes.split()
        if not isinstance(scopes, list) or cfg.get("RESOURCE_REQUIRED_SCOPE", "http://localhost:4142/demo:read") not in scopes:
            return jsonify(error="insufficient_scope"), 403, {"WWW-Authenticate": 'Bearer error="insufficient_scope"'}
        return {"message": "Hello from the protected resource. Your OCI Identity Domains access token was verified.",
                "subject": claims["sub"], "issuer": claims["iss"], "scope": scopes}

    return app

if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=4142, debug=False)

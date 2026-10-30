"""Dashboard; raw assertions and tokens never enter Flask's cookie session."""
import hmac
import secrets
from functools import wraps
from urllib.parse import urlsplit
from flask import Flask, abort, redirect, render_template, request, session
from .config import Settings
from .protocol import Exchanges, FlowError
from .store import Store


def create_app(cfg=None, exchanges=None, oidc=None, trust_setup=None):
    cfg = cfg or Settings.load()
    cfg.validate_urls()
    app = Flask(__name__)
    app.config.update(SECRET_KEY=cfg.get("APP_SECRET") or secrets.token_hex(32), MAX_CONTENT_LENGTH=1024 * 1024,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_SECURE=cfg.base.startswith("https://"), SESSION_COOKIE_NAME="idjag_session")
    flows, pending, completed = Store(), Store(), Store()
    exchange = exchanges or Exchanges(cfg)
    from .oidc import OidcLogin
    oidc = oidc or OidcLogin(cfg)
    app.extensions.update(flows=flows, pending=pending, completed=completed, exchange=exchange, oidc=oidc)

    from .trust import TrustSetup, trust_payload
    trusts = Store()
    trust_setup = trust_setup or TrustSetup(cfg)
    app.extensions.update(trusts=trusts, trust_setup=trust_setup)

    @app.before_request
    def csrf_check():
        if request.method == "POST" and request.path != "/saml/acs":
            expected = session.get("csrf", "")
            if not expected or not hmac.compare_digest(expected, request.form.get("csrf", "")):
                abort(403, "This form has expired or belongs to an earlier session. Open the dashboard, sign in again if needed, and retry from the button.")
            origin = request.headers.get("Origin")
            if origin and origin != cfg.base:
                abort(403, "The browser did not send the configured app origin. Open the dashboard using its configured hostname, refresh it, and retry from the button.")

    @app.after_request
    def headers(response):
        # no-referrer makes browser form POSTs send Origin: null. Keep the
        # origin on same-origin dashboard forms, and suppress cross-site referrers.
        # SAML completion URLs carry a one-time ticket and have no forms.
        referrer_policy = "no-referrer" if request.path in {"/saml/acs", "/saml/complete", "/oidc/callback", "/callback"} else "same-origin"
        response.headers.update({"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff",
                                 "Referrer-Policy": referrer_policy, "X-Frame-Options": "DENY",
                                 "Content-Security-Policy": "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
        return response

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.get("/")
    def dashboard():
        session.setdefault("csrf", secrets.token_urlsafe(32))
        flow = flows.get(session.get("flow"))
        try:
            trust_preview = trust_payload(cfg)
        except ValueError:
            trust_preview = None
        return render_template("index.html", cfg=cfg, flow=flow, csrf=session["csrf"],
                               trust_preview=trust_preview, trust_state=trusts.get(session.get("trust")),
                               missing={stage: cfg.missing(stage) for stage in ("oidc", "id_jag", "idcs")},
                               error=session.pop("notice", None))

    @app.post("/setup/trust")
    def setup_trust():
        state = {"traces": [], "result": None, "error": None}
        trusts.get(session.get("trust"), pop=True)
        session["trust"] = trusts.put(state)
        try:
            state["result"] = trust_setup.ensure(state["traces"])
        except ValueError as exc:
            state["error"] = str(exc)
        return redirect("/#inbound-trust", code=303)

    @app.get("/login")
    @app.get("/oidc/login")
    def oidc_login():
        try:
            pending.get(session.get("oidc_state"), pop=True)
            url, state = oidc.start(pending)
            session["oidc_state"] = state
            return redirect(url)
        except (ValueError, OSError) as exc:
            session["notice"] = str(exc) if isinstance(exc, ValueError) else "Cannot read OIDC configuration"
            return redirect("/")

    @app.get("/oidc/callback")
    @app.get("/callback")
    def oidc_callback():
        try:
            identity, trace = oidc.finish(request.args, session.get("oidc_state"), pending)
        except ValueError as exc:
            session.pop("oidc_state", None)
            session["notice"] = str(exc)
            return redirect("/")
        flows.get(session.get("flow"), pop=True)
        session.clear()
        session["csrf"] = secrets.token_urlsafe(32)
        session["flow"] = flows.put({"identity": identity, "auth_trace": trace, "traces": [], "decoded": None,
                                    "id_jag": None, "access": None, "resource": None, "error": None})
        return redirect("/")

    @app.get("/saml/login")
    def login():
        from .saml import auth_for
        try:
            auth = auth_for(cfg, request)
            browser = secrets.token_urlsafe(32)
            # State is correlated server-side at ACS. Browser binding is checked
            # on the following GET, where a SameSite=Lax localhost cookie is sent.
            relay = pending.put({"browser": browser}, ttl=300)
            url = auth.login(return_to=relay)
            item = pending.get(relay)
            item["request_id"] = auth.get_last_request_id()
            session["login_browser"] = browser
            return redirect(url)
        except ValueError as exc:
            session["notice"] = str(exc)
            return redirect("/")

    @app.post("/saml/acs")
    def acs():
        from .saml import consume
        state = pending.get(request.form.get("RelayState"), pop=True)
        if not state or not state.get("request_id"):
            abort(400, "SAML login state expired or already used; start sign-in again")
        try:
            identity = consume(cfg, request, state["request_id"])
        except ValueError as exc:
            abort(400, str(exc))
        ticket = completed.put({"identity": identity, "browser": state["browser"]}, ttl=60)
        return redirect("/saml/complete?ticket=" + ticket, code=303)

    @app.get("/saml/complete")
    def complete():
        item = completed.get(request.args.get("ticket"), pop=True)
        browser = session.get("login_browser", "")
        if not item or not browser or not hmac.compare_digest(browser, item["browser"]):
            abort(400, "SAML browser binding failed; use the same browser and hostname for sign-in")
        flows.get(session.get("flow"), pop=True)
        session.clear()
        session["csrf"] = secrets.token_urlsafe(32)
        session["flow"] = flows.put({"identity": item["identity"], "traces": [], "decoded": None,
                                     "id_jag": None, "access": None, "resource": None, "error": None})
        return redirect("/")

    @app.get("/saml/metadata")
    def sp_metadata():
        from .saml import metadata
        try:
            return app.response_class(metadata(cfg), mimetype="application/samlmetadata+xml")
        except ValueError as exc:
            return {"error": str(exc)}, 400

    def signed_in(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            flow = flows.get(session.get("flow"))
            if flow is None:
                abort(401, "Sign in with Okta first")
            # Single-user actions are serialized to avoid duplicate assertion redemption.
            with flows.lock:
                try:
                    flow["error"] = None
                    fn(flow, *args, **kwargs)
                except (ValueError, OSError) as exc:
                    # Local errors have controlled messages; never reflect arbitrary token bodies.
                    flow["error"] = str(exc) if isinstance(exc, ValueError) else "Cannot read a configured key or certificate file"
            return redirect("/")
        return inner

    @app.post("/flow/id-jag")
    @signed_in
    def get_jag(flow):
        # Clear downstream state before any retry; never show stale success.
        flow.update(id_jag=None, decoded=None, access=None, resource=None, traces=[])
        if flow["identity"].get("protocol") == "oidc":
            flow["id_jag"], flow["decoded"] = exchange.id_jag_from_oidc(flow["identity"], flow["traces"])
        else:
            flow["id_jag"], flow["decoded"] = exchange.id_jag(flow["identity"]["assertion"], flow["traces"])

    @app.post("/flow/redeem")
    @signed_in
    def redeem(flow):
        flow.update(access=None, resource=None)
        if not flow["id_jag"]:
            raise FlowError("Obtain an ID-JAG first")
        flow["access"] = exchange.redeem(flow["id_jag"], flow["traces"])
        # ID-JAG no longer needed after redemption.
        flow["id_jag"] = None

    @app.post("/flow/resource")
    @signed_in
    def resource(flow):
        flow["resource"] = None
        if not flow["access"]:
            raise FlowError("Redeem an ID-JAG at OCI Identity Domains first")
        flow["resource"] = exchange.call_resource(flow["access"], flow["traces"])

    @app.post("/logout")
    def logout():
        flows.get(session.get("flow"), pop=True)
        trusts.get(session.get("trust"), pop=True)
        session.clear()
        return redirect("/")

    @app.errorhandler(500)
    def server_error(error):
        return "The local app encountered an error. Check configuration and the server console.", 500

    return app

if __name__ == "__main__":
    cfg = Settings.load()
    create_app(cfg).run(host="127.0.0.1", port=urlsplit(cfg.base).port or 4141, debug=False)

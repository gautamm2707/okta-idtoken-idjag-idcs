"""Strict SP-initiated SAML; preserve signed assertion bytes for Okta."""
import base64
from urllib.parse import urlsplit
from xml.parsers import expat
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

NS = "urn:oasis:names:tc:SAML:2.0:assertion"

def assertion_bytes(xml):
    # Expat supplies byte offsets, so we never reserialize signed XML. Namespace
    # matching avoids selecting an Assertion-shaped string in a comment/attribute.
    parser = expat.ParserCreate(namespace_separator="|")
    starts, spans = [], []
    def start(name, attrs):
        if name == NS + "|Assertion":
            starts.append(parser.CurrentByteIndex)
    def end(name):
        if name == NS + "|Assertion":
            start_at = starts.pop()
            end_at = xml.find(b">", parser.CurrentByteIndex) + 1
            spans.append((start_at, end_at))
    def reject(*args):
        raise ValueError("DTD and entities are not allowed in SAML")
    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.StartDoctypeDeclHandler = reject
    parser.EntityDeclHandler = reject
    parser.ExternalEntityRefHandler = reject
    parser.Parse(xml, True)
    if len(spans) != 1:
        raise ValueError("Expected exactly one unencrypted SAML Assertion")
    begin, end_at = spans[0]
    assertion = xml[begin:end_at]
    # An assertion with inherited namespace bindings cannot be detached without
    # changing its signed bytes. Fail explicitly instead of damaging the signature.
    probe = expat.ParserCreate(namespace_separator="|")
    probe.Parse(assertion, True)
    return assertion

def settings(cfg):
    cfg.require("saml")
    return {"strict": True, "debug": False,
        "sp": {"entityId": cfg.base + "/saml/metadata",
               "assertionConsumerService": {"url": cfg.base + "/saml/acs", "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"},
               "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"},
        "idp": {"entityId": cfg.get("OKTA_SAML_IDP_ISSUER"),
                "singleSignOnService": {"url": cfg.get("OKTA_SAML_SSO_URL"), "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"},
                "x509cert": cfg.path("OKTA_SAML_CERT_FILE", "secrets/okta-saml.crt").read_text()},
        "security": {"wantAssertionsSigned": True, "wantNameId": True, "wantAttributeStatement": False,
                     "rejectUnsolicitedResponsesWithInResponseTo": True,
                     "rejectDeprecatedAlgorithm": True, "requestedAuthnContext": False}}

def auth_for(cfg, request):
    # Use the configured external origin, never untrusted Host/Forwarded headers.
    u = urlsplit(cfg.base)
    return OneLogin_Saml2_Auth({"https": "on" if u.scheme == "https" else "off",
        "http_host": u.netloc,
        "script_name": request.path, "get_data": request.args.copy(), "post_data": request.form.copy()}, settings(cfg))

def consume(cfg, request, request_id):
    auth = auth_for(cfg, request)
    auth.process_response(request_id=request_id)
    if auth.get_errors() or not auth.is_authenticated():
        raise ValueError("SAML signature, request correlation, audience, destination or time validation failed")
    raw = base64.b64decode(request.form.get("SAMLResponse", ""), validate=True)
    try:
        assertion = assertion_bytes(raw)
    except (ValueError, expat.ExpatError):
        raise ValueError("Cannot preserve one standalone signed assertion; use unencrypted, assertion-signed Okta SAML") from None
    return {"name_id": auth.get_nameid(), "attributes": auth.get_attributes(), "assertion": assertion}

def metadata(cfg):
    s = OneLogin_Saml2_Settings(settings(cfg), sp_validation_only=True)
    xml = s.get_sp_metadata()
    if s.validate_metadata(xml):
        raise ValueError("SP metadata validation failed")
    return xml

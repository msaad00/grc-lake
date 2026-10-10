"""Exercise incoming SAML algorithm policy with real, locally signed assertions."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("onelogin.saml2.auth")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from onelogin.saml2.constants import OneLogin_Saml2_Constants as C
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from security_lakehouse.auth.saml import SAMLConfig, build_saml_auth, saml_request_data

_ACS = "https://grc.test/api/v1/auth/saml/acs"
_ENTITY = "https://grc.test/saml/metadata"
_IDP = "https://idp.test"
_REQUEST_ID = "_test_request"


@pytest.fixture(scope="module")
def signing_material():
    # Ephemeral test-only material; never write a private key into a fixture file.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SAML test IdP")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    return (
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode(),
        cert.public_bytes(serialization.Encoding.PEM).decode(),
    )


def _signed_response(signing_material, signature_algorithm, digest_algorithm):
    key, cert = signing_material
    now = datetime.now(UTC)
    issued = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    before = (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    after = (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assertion = f"""
    <saml:Assertion xmlns:saml="{C.NS_SAML}" ID="_test_assertion" Version="2.0" IssueInstant="{issued}">
      <saml:Issuer>{_IDP}</saml:Issuer>
      <saml:Subject>
        <saml:NameID Format="{C.NAMEID_EMAIL_ADDRESS}">human@example.test</saml:NameID>
        <saml:SubjectConfirmation Method="{C.CM_BEARER}">
          <saml:SubjectConfirmationData InResponseTo="{_REQUEST_ID}" Recipient="{_ACS}" NotOnOrAfter="{after}"/>
        </saml:SubjectConfirmation>
      </saml:Subject>
      <saml:Conditions NotBefore="{before}" NotOnOrAfter="{after}">
        <saml:AudienceRestriction><saml:Audience>{_ENTITY}</saml:Audience></saml:AudienceRestriction>
      </saml:Conditions>
      <saml:AuthnStatement AuthnInstant="{issued}" SessionIndex="_test_session">
        <saml:AuthnContext><saml:AuthnContextClassRef>{C.AC_PASSWORD}</saml:AuthnContextClassRef></saml:AuthnContext>
      </saml:AuthnStatement>
    </saml:Assertion>"""
    signed = OneLogin_Saml2_Utils.add_sign(
        assertion, key, cert, sign_algorithm=signature_algorithm, digest_algorithm=digest_algorithm
    )
    response = etree.fromstring(
        f"""
    <samlp:Response xmlns:samlp="{C.NS_SAMLP}" xmlns:saml="{C.NS_SAML}"
      ID="_test_response" Version="2.0" IssueInstant="{issued}" Destination="{_ACS}" InResponseTo="{_REQUEST_ID}">
      <saml:Issuer>{_IDP}</saml:Issuer>
      <samlp:Status><samlp:StatusCode Value="{C.STATUS_SUCCESS}"/></samlp:Status>
    </samlp:Response>""".encode()
    )
    response.append(etree.fromstring(signed))
    return etree.tostring(response)


def _authenticate(signing_material, xml):
    config = SAMLConfig(
        sp_entity_id=_ENTITY,
        acs_url=_ACS,
        idp_entity_id=_IDP,
        idp_sso_url=f"{_IDP}/sso",
        idp_x509_cert=signing_material[1],
    )
    request = saml_request_data(scheme="https", host="grc.test", port=443, path="/api/v1/auth/saml/acs", query={})
    request["post_data"]["SAMLResponse"] = base64.b64encode(xml).decode()
    auth = build_saml_auth(config, request)
    auth.process_response(request_id=_REQUEST_ID)
    return auth


@pytest.mark.parametrize(
    ("signature_algorithm", "digest_algorithm", "reason"),
    [
        (C.RSA_SHA1, C.SHA256, "Deprecated signature algorithm"),
        (C.RSA_SHA256, C.SHA1, "Deprecated digest algorithm"),
    ],
    ids=["sha1-signature", "sha1-digest"],
)
def test_saml_rejects_deprecated_incoming_algorithms(signing_material, signature_algorithm, digest_algorithm, reason):
    xml = _signed_response(signing_material, signature_algorithm, digest_algorithm)
    auth = _authenticate(signing_material, xml)
    assert not auth.is_authenticated()
    assert reason in auth.get_last_error_reason()


@pytest.mark.parametrize(
    ("signature_algorithm", "digest_algorithm"), [(C.RSA_SHA256, C.SHA256), (C.RSA_SHA512, C.SHA512)]
)
def test_saml_accepts_modern_signed_assertions(signing_material, signature_algorithm, digest_algorithm):
    xml = _signed_response(signing_material, signature_algorithm, digest_algorithm)
    auth = _authenticate(signing_material, xml)
    assert auth.get_errors() == [], auth.get_last_error_reason()
    assert auth.is_authenticated()
    assert auth.get_nameid() == "human@example.test"


def test_saml_rejects_tampered_modern_assertion(signing_material):
    xml = _signed_response(signing_material, C.RSA_SHA256, C.SHA256)
    auth = _authenticate(signing_material, xml.replace(b"human@example.test", b"other@example.test"))
    assert not auth.is_authenticated()
    assert "Signature validation failed" in auth.get_last_error_reason()

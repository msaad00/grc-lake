"""SAML SSO configuration and login completion for server mode.

The endpoint-level SAML protocol handling stays optional and is imported only
when a deployment configures SAML. The local identity mapping intentionally
matches OIDC: a verified email resolves to one tenant user, then receives the
same hashed browser session token used by all human SSO flows.
"""

from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import parse_qs

from itsdangerous import BadData, URLSafeTimedSerializer

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from security_lakehouse.db import repository
from security_lakehouse.db.models import User

_TRUTHY = {"1", "true", "yes", "on"}
_REQUIRED_ENV = {
    "TRUSTOPS_SAML_SP_ENTITY_ID",
    "TRUSTOPS_SAML_ACS_URL",
    "TRUSTOPS_SAML_IDP_ENTITY_ID",
    "TRUSTOPS_SAML_IDP_SSO_URL",
    "TRUSTOPS_SAML_IDP_X509_CERT",
}
SAML_REQUEST_COOKIE = "trustops_saml_request"
SAML_REQUEST_MAX_AGE_SECONDS = 600
_SAML_REQUEST_SALT = "trustops-saml-authn-request"
_EMAIL_ATTRIBUTE_NAMES = (
    "email",
    "mail",
    "EmailAddress",
    "emailAddress",
    "urn:oid:0.9.2342.19200300.100.1.3",
)


class SAMLConfigError(RuntimeError):
    """Raised when SAML environment configuration is incomplete."""


class SAMLLoginError(Exception):
    """Raised when a SAML assertion cannot be turned into a local session."""


@dataclass(frozen=True)
class SAMLConfig:
    """Resolved SAML service-provider and identity-provider settings."""

    sp_entity_id: str
    acs_url: str
    idp_entity_id: str
    idp_sso_url: str
    idp_x509_cert: str
    sls_url: str = ""
    tenant_slug: str = "default"
    auto_provision: bool = False
    default_role: str = "read_only"
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    role_attribute: str = "groups"
    role_map: dict[str, str] | None = None
    allow_idp_initiated: bool = False

    def settings(self) -> dict[str, Any]:
        """Return OneLogin python3-saml settings."""
        settings = {
            "strict": True,
            "debug": False,
            "sp": {
                "entityId": self.sp_entity_id,
                "assertionConsumerService": {
                    "url": self.acs_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                "NameIDFormat": self.name_id_format,
            },
            "idp": {
                "entityId": self.idp_entity_id,
                "singleSignOnService": {
                    "url": self.idp_sso_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "x509cert": self.idp_x509_cert,
            },
            "security": {
                "wantAssertionsSigned": True,
                "wantMessagesSigned": False,
                "wantNameId": True,
                "wantNameIdEncrypted": False,
                "wantAttributeStatement": False,
                "authnRequestsSigned": False,
                "logoutRequestSigned": False,
                "logoutResponseSigned": False,
                "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
            },
        }
        if self.sls_url:
            settings["sp"]["singleLogoutService"] = {
                "url": self.sls_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            }
        return settings


def load_saml_config() -> SAMLConfig | None:
    """Build SAML config from the environment, or ``None`` when disabled."""
    from security_lakehouse.auth.idp_roles import load_role_map

    present = {name for name in _REQUIRED_ENV if os.environ.get(name)}
    if not present:
        return None
    missing = sorted(_REQUIRED_ENV - present)
    if missing:
        raise SAMLConfigError(f"incomplete SAML configuration; missing: {', '.join(missing)}")
    role_map: dict[str, str] = {}
    try:
        role_map = load_role_map("TRUSTOPS_SAML_ROLE_MAP")
    except ValueError:
        role_map = {}
    return SAMLConfig(
        sp_entity_id=os.environ["TRUSTOPS_SAML_SP_ENTITY_ID"],
        acs_url=os.environ["TRUSTOPS_SAML_ACS_URL"],
        idp_entity_id=os.environ["TRUSTOPS_SAML_IDP_ENTITY_ID"],
        idp_sso_url=os.environ["TRUSTOPS_SAML_IDP_SSO_URL"],
        idp_x509_cert=os.environ["TRUSTOPS_SAML_IDP_X509_CERT"],
        sls_url=os.environ.get("TRUSTOPS_SAML_SLS_URL", ""),
        tenant_slug=os.environ.get("TRUSTOPS_SAML_TENANT_SLUG", "default"),
        auto_provision=os.environ.get("TRUSTOPS_SAML_AUTO_PROVISION", "").lower() in _TRUTHY,
        default_role=os.environ.get("TRUSTOPS_SAML_DEFAULT_ROLE", "read_only"),
        name_id_format=os.environ.get(
            "TRUSTOPS_SAML_NAME_ID_FORMAT",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        ),
        role_attribute=os.environ.get("TRUSTOPS_SAML_ROLE_ATTRIBUTE", "groups"),
        role_map=role_map,
        allow_idp_initiated=os.environ.get("TRUSTOPS_SAML_ALLOW_IDP_INITIATED", "").lower() in _TRUTHY,
    )


def build_saml_auth(config: SAMLConfig, request_data: dict[str, Any]):
    """Create a OneLogin SAML Auth object for the current request."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    return OneLogin_Saml2_Auth(request_data, old_settings=config.settings())


def saml_request_data(
    *,
    scheme: str,
    host: str,
    port: int | None,
    path: str,
    query: dict[str, str],
    body: bytes = b"",
) -> dict[str, Any]:
    """Convert an ASGI request into python3-saml's request shape."""
    post_data: dict[str, str] = {}
    if body:
        parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True)
        post_data = {key: values[-1] if values else "" for key, values in parsed.items()}
    return {
        "https": "on" if scheme == "https" else "off",
        "http_host": host,
        "server_port": port,
        "script_name": path,
        "get_data": query,
        "post_data": post_data,
    }


def email_from_saml_assertion(auth: Any) -> str:
    """Extract the best email identifier from a processed SAML assertion."""
    attributes = auth.get_attributes() or {}
    for name in _EMAIL_ATTRIBUTE_NAMES:
        values = attributes.get(name)
        if values:
            return str(values[0])
    name_id = auth.get_nameid()
    return str(name_id or "")


def groups_from_saml_assertion(auth: Any, *, attribute_name: str) -> list[str]:
    """Extract IdP group/role attribute values from a SAML assertion."""
    attributes = auth.get_attributes() or {}
    values = attributes.get(attribute_name)
    if not values:
        return []
    if isinstance(values, list):
        return [str(item).strip() for item in values if str(item).strip()]
    return [str(values).strip()] if str(values).strip() else []


def complete_saml_login(
    session: Session,
    *,
    config: SAMLConfig,
    email: str,
    now: datetime | None = None,
    idp_claim_values: list[str] | None = None,
) -> tuple[User, str]:
    """Map a verified SAML email to a local user + browser session token."""
    from security_lakehouse.auth.idp_roles import resolve_role_from_claims, sync_role_on_login_enabled

    if not email:
        raise SAMLLoginError("identity provider returned no email")
    tenant = repository.get_tenant_by_slug(session, slug=config.tenant_slug)
    if tenant is None:
        raise SAMLLoginError(f"SAML tenant {config.tenant_slug!r} does not exist")
    mapped_role = config.default_role
    if config.role_map and idp_claim_values:
        mapped_role = resolve_role_from_claims(
            idp_claim_values,
            role_map=config.role_map,
            default_role=config.default_role,
        )
    try:
        user = repository.find_or_provision_user(
            session,
            tenant_id=tenant.id,
            email=email,
            auto_provision=config.auto_provision,
            default_role=mapped_role,
        )
    except IntegrityError:
        session.rollback()
        user = repository.get_user_by_email(session, tenant_id=tenant.id, email=email)
    if user is None:
        raise SAMLLoginError(f"no provisioned user for {email!r} and auto-provisioning is disabled")
    if config.role_map and idp_claim_values and sync_role_on_login_enabled() and mapped_role != user.role:
        user.role = mapped_role
    if not user.is_active:
        raise SAMLLoginError(f"user {email!r} is disabled")
    _row, token = repository.create_user_session(session, tenant_id=tenant.id, user_id=user.id, idp="saml", now=now)
    return user, token


def _request_serializer() -> URLSafeTimedSerializer | None:
    from security_lakehouse.auth.sessions import cookie_signing_key

    key = cookie_signing_key()
    return URLSafeTimedSerializer(key, salt=_SAML_REQUEST_SALT) if key else None


def encode_saml_request_id(request_id: str) -> str:
    """Sign the AuthnRequest ID for the short-lived login cookie."""
    serializer = _request_serializer()
    if serializer is None:
        raise RuntimeError("TRUSTOPS_COOKIE_SIGNING_KEY is required for SAML login")
    return serializer.dumps(request_id)


def decode_saml_request_id(value: str | None) -> str | None:
    """Return the AuthnRequest ID from a signed, unexpired login cookie, else ``None``."""
    serializer = _request_serializer()
    if not value or serializer is None:
        return None
    try:
        data = serializer.loads(value, max_age=SAML_REQUEST_MAX_AGE_SECONDS)
    except BadData:
        return None
    return data if isinstance(data, str) and data else None


class AssertionReplayCache:
    """Remembers consumed assertion IDs until their ``NotOnOrAfter`` passes.

    In-process and bounded: each replica keeps its own cache, so a replay
    routed to a different replica is not caught. The oldest entries are
    evicted first when the cache is full.
    """

    def __init__(self, *, max_entries: int = 10_000, default_ttl_seconds: int = 3600) -> None:
        self._entries: OrderedDict[str, float] = OrderedDict()
        self._max = max_entries
        self._default_ttl = default_ttl_seconds
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._entries)

    def check_and_store(self, assertion_id: str, *, not_on_or_after: float | None, now: float | None = None) -> bool:
        """Record ``assertion_id``; return ``False`` if it was already consumed and is still valid."""
        moment = time.time() if now is None else now
        expires = float(not_on_or_after) if not_on_or_after else moment + self._default_ttl
        with self._lock:
            for key in [k for k, exp in self._entries.items() if exp <= moment]:
                del self._entries[key]
            if assertion_id in self._entries:
                return False
            self._entries[assertion_id] = expires
            while len(self._entries) > self._max:
                self._entries.popitem(last=False)
        return True

"""Public auth method metadata for the console login and access surfaces.

Returns only non-secret deployment facts (issuer host, tenant slug, protocol).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from security_lakehouse.auth.oidc import OIDCConfig
from security_lakehouse.auth.saml import SAMLConfig

_SETUP_HINTS: dict[str, str] = {
    "okta": "Okta OIDC app with openid, email, and profile scopes; map users to the GRC Lake tenant.",
    "azure_ad": "Entra ID app registration with redirect URI to /api/v1/auth/callback.",
    "google": "Google OAuth client with authorized redirect to the GRC Lake callback URL.",
    "auth0": "Auth0 application with OIDC callback and email in the ID token.",
    "onelogin": "OneLogin OIDC connector pointed at the GRC Lake redirect URI.",
    "generic_oidc": "OIDC issuer, client ID, and secret mounted server-side; email claim required.",
    "okta_saml": "Upload GRC Lake SP metadata to Okta; map NameID to email.",
    "azure_ad_saml": "Enterprise application SAML SSO with ACS URL and email NameID.",
    "generic_saml": "IdP metadata with ACS URL, entity ID, and x509 cert mounted on the server.",
    "api_key": "Paste an API key on the sign-in page for a browser session, or use Bearer auth for MCP and CI.",
}

_OIDC_PROVIDER_RULES: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("okta.com",), "okta", "Okta"),
    (
        ("microsoftonline.com", "sts.windows.net"),
        "azure_ad",
        "Microsoft Entra ID",
    ),
    (("accounts.google.com", "google.com"), "google", "Google"),
    (("auth0.com",), "auth0", "Auth0"),
    (("onelogin.com",), "onelogin", "OneLogin"),
)

_SAML_PROVIDER_RULES: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("okta.com",), "okta_saml", "Okta SAML"),
    (
        ("microsoftonline.com", "sts.windows.net", "microsoft.com"),
        "azure_ad_saml",
        "Microsoft Entra ID SAML",
    ),
    (("google.com",), "google_saml", "Google SAML"),
    (("onelogin.com",), "onelogin_saml", "OneLogin SAML"),
)


def _host_from_url(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        # Support host-like values without a URL scheme.
        fallback = urlparse(f"//{url.strip().rstrip('/')}")
        host = fallback.hostname
    if not host:
        return ""
    return host.lower().rstrip(".")


def _host_matches_domain(host: str, domain: str) -> bool:
    if not host:
        return False
    normalized_host = host.lower().rstrip(".")
    normalized_domain = domain.lower().rstrip(".")
    return normalized_host == normalized_domain or normalized_host.endswith(f".{normalized_domain}")


def _host_matches_any_domain(host: str, domains: tuple[str, ...]) -> bool:
    return any(_host_matches_domain(host, domain) for domain in domains)


def _match_provider(
    hosts: tuple[str, ...],
    rules: tuple[tuple[tuple[str, ...], str, str], ...],
    *,
    default_kind: str,
    default_label: str,
) -> tuple[str, str]:
    for domains, kind, label in rules:
        if any(_host_matches_any_domain(host, domains) for host in hosts if host):
            return kind, label
    return default_kind, default_label


def _detect_from_host(host: str) -> tuple[str, str]:
    return _match_provider(
        (host,),
        _OIDC_PROVIDER_RULES,
        default_kind="generic_oidc",
        default_label="OIDC identity provider",
    )


def detect_oidc_provider(issuer: str) -> tuple[str, str]:
    return _detect_from_host(_host_from_url(issuer))


def detect_saml_provider(*, idp_sso_url: str, idp_entity_id: str) -> tuple[str, str]:
    hosts = (_host_from_url(idp_sso_url), _host_from_url(idp_entity_id))
    return _match_provider(
        hosts,
        _SAML_PROVIDER_RULES,
        default_kind="generic_saml",
        default_label="SAML identity provider",
    )


def _method(
    *,
    method_id: str,
    label: str,
    configured: bool,
    login_url: str,
    protocol: str,
    provider_kind: str,
    provider_label: str,
    setup_hint: str,
    issuer_host: str = "",
    tenant_slug: str = "",
    auto_provision: bool = False,
    metadata_url: str = "",
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": method_id,
        "label": label,
        "configured": configured,
        "login_url": login_url,
        "protocol": protocol,
        "provider_kind": provider_kind,
        "provider_label": provider_label,
        "setup_hint": setup_hint,
    }
    if issuer_host:
        row["issuer_host"] = issuer_host
    if tenant_slug:
        row["tenant_slug"] = tenant_slug
    row["auto_provision"] = auto_provision
    if metadata_url:
        row["metadata_url"] = metadata_url
    return row


def build_auth_methods_payload(
    *,
    require_auth: bool,
    oidc_config: OIDCConfig | None,
    saml_config: SAMLConfig | None,
) -> dict[str, Any]:
    """Shape returned by GET /api/v1/auth/methods."""
    methods: list[dict[str, Any]] = []

    if oidc_config is not None:
        kind, provider_label = detect_oidc_provider(oidc_config.issuer)
        host = _host_from_url(oidc_config.issuer)
        methods.append(
            _method(
                method_id="oidc",
                label=f"Continue with {provider_label}",
                configured=True,
                login_url="/api/v1/auth/login",
                protocol="OIDC",
                provider_kind=kind,
                provider_label=provider_label,
                setup_hint=_SETUP_HINTS.get(kind, _SETUP_HINTS["generic_oidc"]),
                issuer_host=host,
                tenant_slug=oidc_config.tenant_slug,
                auto_provision=oidc_config.auto_provision,
                metadata_url=oidc_config.metadata_url,
            )
        )
    else:
        methods.append(
            _method(
                method_id="oidc",
                label="OIDC SSO",
                configured=False,
                login_url="/api/v1/auth/login",
                protocol="OIDC",
                provider_kind="generic_oidc",
                provider_label="OIDC identity provider",
                setup_hint=_SETUP_HINTS["generic_oidc"],
            )
        )

    if saml_config is not None:
        kind, provider_label = detect_saml_provider(
            idp_sso_url=saml_config.idp_sso_url,
            idp_entity_id=saml_config.idp_entity_id,
        )
        host = _host_from_url(saml_config.idp_sso_url)
        methods.append(
            _method(
                method_id="saml",
                label=f"Continue with {provider_label}",
                configured=True,
                login_url="/api/v1/auth/saml/login",
                protocol="SAML 2.0",
                provider_kind=kind,
                provider_label=provider_label,
                setup_hint=_SETUP_HINTS.get(kind, _SETUP_HINTS["generic_saml"]),
                issuer_host=host,
                tenant_slug=saml_config.tenant_slug,
                auto_provision=saml_config.auto_provision,
                metadata_url="/api/v1/auth/saml/metadata",
            )
        )
    else:
        methods.append(
            _method(
                method_id="saml",
                label="SAML SSO",
                configured=False,
                login_url="/api/v1/auth/saml/login",
                protocol="SAML 2.0",
                provider_kind="generic_saml",
                provider_label="SAML identity provider",
                setup_hint=_SETUP_HINTS["generic_saml"],
            )
        )

    methods.append(
        _method(
            method_id="api_key",
            label="API key (headless)",
            configured=True,
            login_url="/api/v1/auth/session-from-key",
            protocol="API key",
            provider_kind="api_key",
            provider_label="GRC Lake API keys",
            setup_hint=_SETUP_HINTS["api_key"],
        )
    )

    return {"require_auth": require_auth, "methods": methods}

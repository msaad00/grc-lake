# Identity & Auth Boundary

TrustOps server mode uses one identity model for browser SSO and headless API
keys — the same tenant, role, scope, and audit envelope.

## Identity flow

```mermaid
flowchart LR
  subgraph IdP["Company identity"]
    OIDC["OIDC<br/>Okta / Entra / Google"]
    SAML["SAML 2.0"]
  end

  subgraph Headless["Automation"]
    KEY["API key<br/>agents / CI / MCP"]
    SESS["API key → browser session"]
  end

  subgraph TrustOps["TrustOps auth core"]
    MAP["Map email → user<br/>IdP group → role"]
    TEN["Tenant scope"]
    RBAC["Role + scopes"]
    SIGN["Signed session cookie"]
    AUD["Request audit log"]
  end

  subgraph Apps["Protected surfaces"]
    CON["Console + audit room"]
    V1["/api/v1 + MCP"]
    SCIM["SCIM Users (hosted)"]
  end

  OIDC --> MAP
  SAML --> MAP
  KEY --> TEN
  SESS --> SIGN
  MAP --> TEN --> RBAC --> SIGN --> AUD
  RBAC --> CON
  RBAC --> V1
  RBAC --> SCIM
```

## OIDC vs SAML vs API key

| Method            | Best for                             | TrustOps endpoints                   |
| ----------------- | ------------------------------------ | ------------------------------------ |
| **OIDC**          | Modern IdPs (Okta, Entra ID, Google) | `GET /api/v1/auth/login` → callback  |
| **SAML 2.0**      | Enterprise IdPs without OIDC         | `GET /api/v1/auth/saml/login` → ACS  |
| **API key**       | Agents, CI, MCP clients              | `Authorization: Bearer tops_…`       |
| **Key → session** | Console without SSO                  | `POST /api/v1/auth/session-from-key` |
| **SCIM**          | Hosted enterprise provisioning       | `/api/v1/scim/v2/Users` (commercial) |

## Session contract

Browser session cookies are **always signed** when auth is enabled
(`TRUSTOPS_COOKIE_SIGNING_KEY`). OIDC OAuth state uses a separate
`TRUSTOPS_SESSION_SECRET`.

```mermaid
sequenceDiagram
  participant User as Human user
  participant IdP as Identity provider
  participant TO as TrustOps API
  participant DB as App state DB

  User->>TO: GET /api/v1/auth/login
  TO->>IdP: OAuth / SAML redirect
  IdP-->>User: Authenticate
  IdP-->>TO: Assertion / token
  TO->>DB: Resolve tenant user + role
  TO-->>User: Signed HttpOnly session cookie
  User->>TO: Console / API (scoped)
  TO->>DB: Append audit event
```

## Admin surfaces

| Surface                              | Purpose                                             |
| ------------------------------------ | --------------------------------------------------- |
| `GET/PATCH /api/v1/auth/users`       | Tenant user directory (admin)                       |
| `POST /api/v1/auth/session-from-key` | Paste API key on login page                         |
| Console **Access**                   | API keys, users & roles, invites                    |
| IdP role maps                        | `TRUSTOPS_OIDC_ROLE_MAP` / `TRUSTOPS_SAML_ROLE_MAP` |

## Roles (summary)

| Role                  | Typical access                   |
| --------------------- | -------------------------------- |
| `admin`               | Full platform + key admin        |
| `security_admin`      | Connectors, workflows, snapshots |
| `compliance_reviewer` | Read + mapping review decisions  |
| `contributor`         | Triage, evidence requests        |
| `auditor`             | Read-only + redaction            |
| `read_only`           | Internal read                    |

See [SERVER_AUTH.md](../SERVER_AUTH.md) and
[identity boundary SVG](../images/trustops-identity-boundary.svg).

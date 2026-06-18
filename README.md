# @acastellon/auth

**Authentication Control System for microservices — legacy NTLM+LDAP+JWT plus AWS Cognito, Azure AD/Entra ID, OIDC, SAML 2.0, hybrids and secrets from environment variables.**

It supports:
- **Legacy**: NTLM + LDAP + internal JWT (fully backward compatible)
- **Modern providers**: AWS Cognito, Microsoft Azure AD / Entra ID, generic OIDC / OAuth2
- **SAML 2.0** (full login + ACS flows)
- **Hybrid** modes (external + optional LDAP role enrichment)
- **Secrets via environment variables** (no hard-coded passwords, private keys or JWT secrets)

See the per-provider `config.auth.*.template.js` files and the examples below. Full backward compatibility with v1 NTLM+LDAP+JWT setups.

## Install

```bash
npm install @acastellon/auth
```

## Quick Start

### Legacy NTLM (on-prem)

```js
const auth = require('@acastellon/auth')(require('./config.auth.js'));

auth.setNTLMAuth(app);           // protects routes with NTLM + optional LDAP roles
// or
auth.validateToken(app);         // validates internal JWT + LDAP roles
```

**Security note (service-to-service):**
- Client-supplied `auth-user` and `is-*` headers are **always stripped** on entry to prevent spoofing.
- The previous `service-brother` + spoofable `Host`/`auth-user` header bypass has been **removed**.
- Secure service-to-service is now supported via **mTLS client certificates** (recommended when using `CERTIFICATION_PATH` + `requestCert: true` on the https server in rest/graphql/etc.). When a valid peer cert is seen, the CN is trusted as `service:<cn>` and appropriate headers/req.user are set by the auth middleware.
  - Optional allowlist via `TRUSTED_MTLS_SERVICES: ['rest', 'graphql']` in setup to restrict which CNs are accepted.

See also module-rest and module-dns-client for mTLS client configuration.

(Keep secrets out of config.auth.js — see env var section.)

### Modern (AWS Cognito example)

```js
const auth = require('@acastellon/auth')({
  AUTH_TYPE: 'EXTERNAL_JWT',
  COGNITO: {
    region: 'eu-west-1',
    userPoolId: 'eu-west-1_xxxxxxxx',
    clientId: 'your-app-client-id',     // for audience validation
    rolesClaim: 'cognito:groups',
    roleMapper: { 'Admins': 'Admin' }
  },
  ROLES: { Admin: 'Admins', User: 'Users' },
  EXPIRES: 3600
});

// Use the dedicated external validator (recommended)
auth.validateExternalToken(app);

// or the smart one that auto-detects
auth.validateToken(app);
```

### SAML 2.0 Example (Okta / ADFS / etc.)

```js
const auth = require('@acastellon/auth')({
  AUTH_TYPE: 'SAML',
  SAML: {
    identityProvider: {
      ssoLoginUrl: 'https://your-idp.com/app/sso/saml',
      ssoLogoutUrl: 'https://your-idp.com/app/slo/saml',
      certificates: [
        `-----BEGIN CERTIFICATE-----
MIIC... (paste IdP cert here)
-----END CERTIFICATE-----`
      ]
    },
    serviceProvider: {
      entityId: 'https://your-app.com',
      assertEndpoint: 'https://your-app.com/auth/saml/acs'
    },
    rolesClaim: 'http://schemas.xmlsoap.org/claims/Group',
    roleMapper: { 'Admins': 'Admin' },
    loginPath: '/auth/saml/login',
    acsPath: '/auth/saml/acs'
  },
  ROLES: { Admin: 'Admins', User: 'Users' }
});

// Setup the SAML routes (login + ACS)
auth.setupSaml(app);

// Protect routes
app.get('/dashboard', auth.samlAuth, (req, res) => {
  res.json({ user: req.user });
});

// Users go to /auth/saml/login to start SAML flow
```

## Configuration

Use the split per-method templates for clean examples:

- `config.auth.legacy.template.js` (NTLM + LDAP)
- `config.auth.cognito.template.js`
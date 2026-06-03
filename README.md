# @acastellon/auth

**Modern & Legacy Authentication / Authorization middleware for Express microservices.**

Supports:
- **Legacy**: NTLM + LDAP + internal JWT (fully backward compatible)
- **Modern cloud providers**: AWS Cognito, Microsoft Azure AD / Entra ID, generic OIDC / OAuth2 (Auth0, Okta, Keycloak, Google, etc.)
- **Hybrid** modes (external token + LDAP role enrichment)

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
// auth.validateToken(app);
```

## Configuration

See the heavily commented `config.auth.template.js` for all options.

Key new settings for v2:

```js
{
  AUTH_TYPE: 'NTLM' | 'EXTERNAL_JWT',

  // One of the following provider blocks:
  COGNITO: { region, userPoolId, clientId?, rolesClaim?, roleMapper? },
  AZURE:   { tenantId, clientId, rolesClaim?, roleMapper? },
  OIDC:    { issuer, clientId?, rolesClaim?, roleMapper?, jwksUri? },

  // Optional hybrid / advanced
  useLdapForRoles: false,     // still call the LDAP module for extra roles
  rolesClaim: 'roles',        // default claim name containing roles/groups
  roleMapper: { ... },        // map provider role names → your ROLES keys

  // Legacy NTLM/LDAP fields remain supported
}
```

## API

### `setNTLMAuth(app)`
Legacy NTLM protection (express-ntlm) with optional LDAP role lookup and internal JWT re-issuing.

### `validateToken(app)`
Smart middleware:
- If external provider is configured → uses JWKS verification for Cognito/Azure/OIDC.
- Otherwise → falls back to legacy internal JWT + LDAP behavior.

### `validateExternalToken(app)` (new)
Dedicated, clean middleware for pure external JWT providers. Recommended when you no longer use NTLM.

### `setRoles(app)` / `getRoles(req, res)` / `removeCache4(userName)`
Legacy role attachment and cache helpers (still work).

## How External JWT Validation Works

1. Client obtains a JWT from Cognito / Azure / your OIDC provider.
2. Client sends it in `Authorization: Bearer <token>` or `x-access-token`.
3. Middleware fetches the provider's JWKS, verifies signature + issuer + audience.
4. Extracts user id and roles from configured claims.
5. (Optional) Enriches roles via the LDAP module.
6. Sets the usual headers (`auth-user`, `isXXX`, `is-authenticated`) so your existing code continues to work.
7. Optionally re-issues a short-lived internal JWT.

## Migrating from v1

- Existing NTLM + LDAP + internal JWT code continues to work unchanged.
- Add one of the provider blocks (`COGNITO`, `AZURE`, `OIDC`) to your config.
- Switch to `validateExternalToken(app)` (or let `validateToken` auto-detect).
- The module now depends on `jwks-rsa` for external providers.

## License

MIT

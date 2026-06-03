# @acastellon/auth

**Modern & Legacy Authentication / Authorization middleware for Express microservices.**

Supports:
- **Legacy**: NTLM + LDAP + internal JWT (fully backward compatible)
- **Modern cloud providers**: AWS Cognito, Microsoft Azure AD / Entra ID, generic OIDC / OAuth2 (Auth0, Okta, Keycloak, Google, etc.)
- **SAML 2.0** (Okta, ADFS, Ping, etc.)
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

See the heavily commented `config.auth.template.js` for all options and ready-to-use examples for every provider (including SAML).

Key settings:

```js
{
  AUTH_TYPE: 'NTLM' | 'EXTERNAL_JWT' | 'SAML',

  // Modern providers
  COGNITO: { ... },
  AZURE:   { ... },
  OIDC:    { ... },
  SAML:    { identityProvider, serviceProvider, rolesClaim?, roleMapper?, loginPath?, acsPath? },

  // Optional
  useLdapForRoles: false,
  rolesClaim: 'roles',
  roleMapper: { ... }
}
```

## API Reference

### Legacy / NTLM
- `setNTLMAuth(app)`
- `setRoles(app)`
- `getRoles(req, res)`
- `removeCache4(userName)`

### JWT-based (Cognito, Azure, OIDC, custom)
- `validateToken(app)` — smart, works for legacy + external
- `validateExternalToken(app)` — clean dedicated middleware for cloud JWTs

### SAML 2.0
- `setupSaml(app)` — registers login, ACS (assertion consumer), and logout routes based on config
- `samlAuth` — middleware to protect routes (checks SAML session cookie or token)

After successful SAML login, an internal JWT is issued and stored in an httpOnly cookie (`saml_auth_token`). The `samlAuth` middleware validates it and populates `req.user` + sets the usual `isXXX` headers.

## More Examples

### Protecting an API route with external JWT (Cognito)

```js
const auth = require('@acastellon/auth')(cognitoConfig);

auth.validateExternalToken(app);

app.get('/api/data', (req, res) => {
  // req.user contains { id, isAdmin: true, ... }
  res.json({ data: 'secret', user: req.user });
});
```

### Full SAML flow with role-based access

```js
// In your main app
app.use(auth.samlAuth); // or per-route

app.get('/admin', (req, res) => {
  if (!req.user.isAdmin) return res.status(403).send('Admins only');
  res.send('Welcome admin');
});
```

### Hybrid: External JWT + LDAP roles

```js
{
  AUTH_TYPE: 'EXTERNAL_JWT',
  COGNITO: { ... },
  useLdapForRoles: true,   // still calls LDAP for additional roles
  // ... ldap config
}
```

## Migrating from v1

- Existing NTLM + LDAP + internal JWT code continues to work unchanged.
- Add provider blocks to config.
- For JWT providers use `validateExternalToken` or `validateToken`.
- For SAML use `setupSaml(app)` + `samlAuth` middleware.
- New dependency `saml2-js` for SAML support.

## License

MIT

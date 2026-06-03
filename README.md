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
- `config.auth.azure.template.js`
- `config.auth.oidc.template.js`
- `config.auth.saml.template.js`

`config.auth.template.js` remains as a combined overview / starting point (it shows common settings + how to pick one provider block).

**Important:** Use environment variables for all passwords, private keys and `passToken` (see "Secrets from Environment Variables" section below). Never commit real secrets.

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

## Secrets from Environment Variables

To avoid putting real passwords, private keys or JWT signing secrets directly in committed configuration files, the module supports reading them from environment variables.

**Supported variables (the first matching one wins):**

- `password` (LDAP bind): `LDAP_PASSWORD`, `AUTH_LDAP_PASSWORD`, `AD_PASSWORD`, `LDAP_BIND_PASSWORD`
- `passToken` (internal JWT signing — important for stable tokens across restarts): `AUTH_JWT_SECRET`, `JWT_SECRET`, `AUTH_PASS_TOKEN`, `PASS_TOKEN`
- SAML `serviceProvider.privateKey`: `SAML_PRIVATE_KEY`, `AUTH_SAML_PRIVATE_KEY`, `SP_PRIVATE_KEY`
- SAML `serviceProvider.certificate` / IdP certs: `SAML_CERTIFICATE`, `SAML_IDP_CERT` etc.
- TLS CA content: `LDAP_TLS_CA`, `AUTH_LDAP_CA`

**How to use (recommended — zero secrets in your config file):**

```js
// config.auth.js  (safe to commit)
module.exports = {
  url: 'ldap://ldap.example.com:389',
  DOMAIN: 'EXAMPLE',
  baseDN: 'dc=example,dc=com',
  // password omitted — comes from env at runtime
  // passToken omitted — comes from env
  ROLES: { Admin: 'Admins', User: 'Users' },
  // For SAML, you can also omit privateKey
};
```

Then run with:

```bash
LDAP_PASSWORD=supersecret AUTH_JWT_SECRET=my-super-jwt-key node server.js
```

The module resolves at construction time (before passing anything to LDAP or SAML libs). Explicit values in the config object always take precedence over env.

You can also use the classic `process.env.XXX` references inside the config file if you prefer visibility of the var name.

See the per-provider `config.auth.*.template.js` (and the combined `config.auth.template.js`) for more commented examples with env var usage.

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

// Generic OIDC / OAuth2 provider config (Auth0, Okta, Keycloak, Google, etc.)
//
// const auth = require('@acastellon/auth')(require('./config.auth.oidc.template.js'));
// auth.validateExternalToken(app);

module.exports = {
  AUTH_TYPE: 'EXTERNAL_JWT',

  OIDC: {
    issuer: 'https://your-tenant.auth0.com',   // or https://accounts.google.com , https://your.okta.com etc.
    clientId: 'your-client-id',
    // rolesClaim: 'groups',                   // or 'roles'
    // roleMapper: { 'admin': 'Admin' },
    // jwksUri: 'https://.../.well-known/jwks.json'  // usually auto-discovered
  },

  ROLES: {
    'Admin': 'Admins',
    'User': 'Users'
  },

  EXPIRES: 3600
};
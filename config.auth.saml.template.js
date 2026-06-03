// SAML 2.0 config for @acastellon/auth
//
// const auth = require('@acastellon/auth')(require('./config.auth.saml.template.js'));
// auth.setupSaml(app);
// app.get('/protected', auth.samlAuth, handler);

module.exports = {
  AUTH_TYPE: 'SAML',

  SAML: {
    identityProvider: {
      ssoLoginUrl: 'https://idp.example.com/app/sso/saml',
      ssoLogoutUrl: 'https://idp.example.com/app/slo/saml',
      certificates: [
        `-----BEGIN CERTIFICATE-----
MIIC... (paste IdP signing cert)
-----END CERTIFICATE-----`
      ]
    },
    serviceProvider: {
      entityId: 'https://your-app.example.com',
      // privateKey: process.env.SAML_PRIVATE_KEY,   // for signed requests (omit + use env!)
      // certificate: `-----BEGIN CERTIFICATE----- ...`,
      assertEndpoint: 'https://your-app.example.com/auth/saml/acs'
    },
    // rolesClaim: 'http://schemas.xmlsoap.org/claims/Group',
    // roleMapper: { 'Admins': 'Admin' },
    // loginPath: '/auth/saml/login',
    // acsPath: '/auth/saml/acs'
  },

  ROLES: {
    'Admin': 'Admins',
    'User': 'Users'
  }
};
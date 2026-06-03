// AWS Cognito config for @acastellon/auth (v2+)
//
// const auth = require('@acastellon/auth')(require('./config.auth.cognito.template.js'));
// auth.validateExternalToken(app);   // or the smart validateToken(app)

module.exports = {
  AUTH_TYPE: 'EXTERNAL_JWT',

  COGNITO: {
    region: 'eu-west-1',
    userPoolId: 'eu-west-1_YourPoolId',
    clientId: 'your-app-client-id',      // for audience validation (optional but recommended)
    // rolesClaim: 'cognito:groups',      // claim that contains the array of groups/roles
    // roleMapper: { 'Admins': 'Admin' }  // map Cognito group names to your ROLES keys
  },

  // Common
  ROLES: {
    'Admin': 'Admins',
    'User': 'Users'
  },

  EXPIRES: 3600,

  // Secrets (passToken etc.) should come from env vars - see README
  // passToken: process.env.AUTH_JWT_SECRET,   // omit to let env resolution handle it

  // Hybrid example: still enrich with LDAP roles
  // useLdapForRoles: true,
  // url: 'ldap://...', DOMAIN: '...'
};
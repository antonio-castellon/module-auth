// Microsoft Azure AD / Entra ID config for @acastellon/auth
//
// const auth = require('@acastellon/auth')(require('./config.auth.azure.template.js'));
// auth.validateExternalToken(app);

module.exports = {
  AUTH_TYPE: 'EXTERNAL_JWT',

  AZURE: {
    tenantId: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
    clientId: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',  // Application (client) ID
    // rolesClaim: 'roles',                            // or 'groups'
    // roleMapper: { 'App.Admin': 'Admin' }
  },

  ROLES: {
    'Admin': 'Admins',
    'User': 'Users'
  },

  EXPIRES: 3600,

  // passToken and other secrets via env (AUTH_JWT_SECRET etc.)
};
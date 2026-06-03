// Combined / overview template for @acastellon/auth v2+
//
// This file shows common settings + how to select ONE provider block.
// For clean per-method examples, see the dedicated templates instead:
//   config.auth.legacy.template.js
//   config.auth.cognito.template.js
//   config.auth.azure.template.js
//   config.auth.oidc.template.js
//   config.auth.saml.template.js
//
// SECURITY: Never hardcode real passwords, private keys or signing secrets here.
// Use environment variables (the module resolves them automatically).
// See README "Secrets from Environment Variables" for the full list of supported var names
// (LDAP_PASSWORD, AUTH_JWT_SECRET, SAML_PRIVATE_KEY, etc.).
//
// You can (and should) omit secret fields entirely from committed files.

module.exports = {
  // === Common settings (see dedicated per-provider templates for full details) ===
  EXPIRES: 86400,

  // Role mapping (used by LDAP + all external providers)
  ROLES: {
    'User': 'Users',
    'Admin': 'Admins',
    'Viewer': 'Viewers'
  },

  // === AUTH TYPE (optional but recommended for clarity) ===
  // 'NTLM' | 'EXTERNAL_JWT' | 'SAML'
  // AUTH_TYPE: 'NTLM',

  // === Provider blocks - see the split templates ===
  // config.auth.legacy.template.js
  // config.auth.cognito.template.js
  // config.auth.azure.template.js
  // config.auth.oidc.template.js
  // config.auth.saml.template.js

  // Hybrid example (cloud provider + LDAP roles):
  // useLdapForRoles: true,
  // url: 'ldap://...', DOMAIN: '...', baseDN: '...'
  // (password and passToken come from env vars)

  // (Full per-provider examples with all options and env notes live in the dedicated template files.)
};
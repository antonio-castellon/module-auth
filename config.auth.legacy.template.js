// Legacy NTLM + (optional) LDAP config for @acastellon/auth
//
// Use with: const auth = require('@acastellon/auth')(require('./config.auth.legacy.template.js'));
// Then: auth.setNTLMAuth(app); or auth.validateToken(app);
//
// SECURITY: Passwords and passToken MUST come from environment variables.
// The module auto-resolves them so you can omit them here.
// See README "Secrets from Environment Variables".

module.exports = {
  // === LDAP connection (for roles + NTLM domain controller) ===
  url: 'ldap://your-ldap-server:389',
  DOMAIN: 'YOURDOMAIN',
  baseDN: 'dc=yourdomain,dc=com',
  username: 'binduser',                    // can be omitted if using env
  // password: process.env.LDAP_PASSWORD,  // or simply omit the key entirely

  tlsOptions: {
    // ca: process.env.LDAP_TLS_CA,
    rejectUnauthorized: false
  },

  // === NTLM settings ===
  NTLM_DEBUG: false,
  NTLM_OPTIONS: true,
  NTLM_LDAP: true,           // enrich NTLM user with LDAP roles
  NTLM_PATH: '*',

  // === JWT signing (passToken) - strongly recommended from env ===
  // passToken: process.env.AUTH_JWT_SECRET,   // or omit entirely
  EXPIRES: 86400,                              // 24h

  // === Roles (map your LDAP group strings to isXXX flags) ===
  ROLES: {
    'User': 'GI RD USER',
    'Admin': 'GI RD ADMINISTRATOR',
    'Viewer': 'GI RD VIEWER'
  },

  // MOCKUP for local dev (when SERVER_ENVIRONMENT=local or no LDAP)
  MOCKUP_USERS: ['yourname'],
  MOCKUP_ROLES: ['User'],

  // === mTLS service-to-service security (recommended replacement for old header bypasses) ===
  // TRUSTED_MTLS_SERVICES: ['rest-service', 'graphql-service'], // optional CN allowlist from client certs
  // When using https server with requestCert + CA, services presenting matching client certs are auto-authenticated as 'service:<CN>'
};
// Legacy NTLM + LDAP config (existing behavior)
module.exports = {
  // === LDAP (used for role lookup in NTLM or hybrid modes) ===
  url: 'ldap://<address>:389',
  DOMAIN: '<domain>',
  baseDN: '<baseDN>',
  username: '<user-ldap>',
  password: '<password>',
  tlsOptions: { ca: '<path>', 'rejectUnauthorized': false },

  // === NTLM settings ===
  NTLM_DEBUG: false,
  NTLM_OPTIONS: false,
  NTLM_LDAP: false,        // whether to enrich NTLM user with LDAP roles
  NTLM_PATH: '*',

  CNAME: 'dev.example.com',

  // === Internal JWT signing (for re-issuing normalized tokens) ===
  passToken: '<passphrase-optional>',  // if not provided, one is auto-generated
  EXPIRES: 86400,                      // 24 hours

  // === Role mapping (used by LDAP or claim mappers) ===
  MOCKUP_USERS: ['acastellon', 'rlopez'],
  MOCKUP_ROLES: ['User', 'CManager'],
  ROLES: {
    'User': 'GI RD USER ',
    'Admin': 'GI RD  ADMINISTRATOR ',
    'Viewer': 'GI RD  VIEWER '
  },

  // === AUTH TYPE ===
  // 'NTLM' (default, legacy) | 'EXTERNAL_JWT' | 'SAML'
  AUTH_TYPE: 'NTLM',

  // === EXTERNAL AUTH PROVIDERS (new in v2) ===
  // Choose one (or implement custom)

  // --- AWS Cognito ---
  // COGNITO: {
  //   region: 'eu-west-1',
  //   userPoolId: 'eu-west-1_xxxxxxxxx',
  //   clientId: 'xxxxxxxxxxxxxxxxxxxxxxxxxx',   // optional, for audience check
  //   // rolesClaim: 'cognito:groups',            // claim containing array of groups
  //   // roleMapper: { 'Admins': 'Admin' }       // map provider groups to your ROLES keys
  // },

  // --- Microsoft Azure AD / Entra ID ---
  // AZURE: {
  //   tenantId: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
  //   clientId: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',  // app registration client id
  //   // rolesClaim: 'roles',                           // or 'groups'
  //   // roleMapper: { 'App.Admin': 'Admin' }
  // },

  // --- Generic OIDC / OAuth2 provider (Google, Okta, Keycloak, Auth0, etc.) ---
  // OIDC: {
  //   issuer: 'https://your-tenant.okta.com',   // or https://accounts.google.com for Google
  //   // clientId: 'your-client-id',
  //   // rolesClaim: 'groups' or 'roles',
  //   // roleMapper: { ... }
  //   // jwksUri: 'https://.../.well-known/jwks.json'  // optional, auto-discovered if not provided
  // },

  // --- SAML 2.0 ---
  // SAML: {
  //   // Identity Provider (IdP) metadata - usually from your IdP (Okta, ADFS, etc.)
  //   identityProvider: {
  //     ssoLoginUrl: 'https://idp.example.com/saml/sso',
  //     ssoLogoutUrl: 'https://idp.example.com/saml/slo',
  //     certificates: [ '-----BEGIN CERTIFICATE-----
MIIC...-----END CERTIFICATE-----' ]
  //   },
  //   // Service Provider (your app) config
  //   serviceProvider: {
  //     entityId: 'https://your-app.example.com',
  //     privateKey: '-----BEGIN RSA PRIVATE KEY-----
MIIE...-----END RSA PRIVATE KEY-----',  // optional for signed requests
  //     certificate: '-----BEGIN CERTIFICATE-----
MIIC...-----END CERTIFICATE-----', // optional
  //     assertEndpoint: 'https://your-app.example.com/auth/saml/acs'  // ACS URL where IdP posts assertion
  //   },
  //   // How to extract roles from SAML assertion
  //   rolesClaim: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role', // or custom attribute name
  //   // roleMapper: { 'CN=Admins,OU=Groups': 'Admin' },
  //   // loginPath: '/auth/saml/login',  // default
  //   // acsPath: '/auth/saml/acs',      // default
  //   // logoutPath: '/auth/saml/logout' // optional
  // },

  // === Hybrid / Advanced ===
  // useLdapForRoles: false,   // set true to still call LDAP even for external JWT users
  // rolesClaim: 'roles',      // default claim to look for roles in external tokens
  // roleMapper: {},           // global mapper from provider role names to your internal isXXX keys
};

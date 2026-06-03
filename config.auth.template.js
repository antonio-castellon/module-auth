module.exports = {
  url: 'ldap://<address>:389',
  DOMAIN:'<domain>',
  baseDN: '<baseDN>',
  username: '<user-ldap>',
  password: '<password>',
  NTLM_DEBUG: false,
  NTLM_OPTIONS: false,
  NTLM_LDAP: false,
  NTLM_PATH: '*',
  tlsOptions: { ca: '<path>', 'rejectUnauthorized': false },
  CNAME: 'dev.example.com',
  passToken: '<passphrase-optional>',
  EXPIRES: 86400,
  MOCKUP_USERS : ['acastellon','rlopez'],
  MOCKUP_ROLES : ['User','CManager'],
  ROLES : {
    'User': 'GI RD USER ',
    'Admin': 'GI RD  ADMINISTRATOR ',
    'Viewer': 'GI RD  VIEWER '
  }
};

# @acastellon/auth

Authentication Control System for microservices that uses a combination of 
NTLM + LDAP + JWT to check the security.

## Install

```bash
npm install @acastellon/auth
```

## Config (see config.auth.template.js for full)

module.exports = { ... NTLM/JWT/LDAP settings, ROLES map, MOCKUP_*, passToken, EXPIRES, etc. };

const auth = require('@acastellon/auth')(def_auth);

## Usage in Express app

In case of NTLM (usually for Web FrontEnd):

    auth.setNTLMAuth(app);

For JWT (common for WS):

    auth.validateToken(app);

Other: auth.setRoles(app); auth.getRoles(req, res); auth.removeCache4(user);

## Headers set
- x-access-token (JWT)
- is-authenticated
- auth-user
- isXXX role flags from LDAP

Uses internal cache to avoid repeated LDAP queries.

**Note:** For production, consider shorter EXPIRES or token refresh strategies.

## License

MIT

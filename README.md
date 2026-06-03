# @acastellon/auth

Authentication Control System for microservices that uses a combination of NTLM + LDAP + JWT.

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

## API

### setNTLMAuth(app)
Installs express-ntlm + post-auth hook that does LDAP role lookup (if enabled) and issues JWT. Sets headers.

### validateToken(app)
Middleware that validates x-access-token + re-issues from LDAP roles.

### setRoles(app)
Middleware that only attaches roles from LDAP (no token validation).

### getRoles(req, res)
Endpoint helper to return roles for current user (from ntlm or header).

### removeCache4(userName)
Invalidates the in-memory JWT cache for a user.

**Headers produced**:
- x-access-token
- is-authenticated
- auth-user
- isXXX (from ROLES)

Uses in-memory ldapCache. Consider production token strategies.

## License

MIT

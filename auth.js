"use strict";
// -- Authentication Control System (v2)
//
// Castellon.CH - 2019-2026 (c)
// Author: Antonio Castellon - antonio@castellon.ch
//
// Supports:
//   - Legacy: NTLM (express-ntlm) + LDAP role lookup + internal JWT
//   - Modern: AWS Cognito, Azure AD/Entra ID, generic OIDC/OAuth2 JWT validation
//   - SAML 2.0
//   - Hybrid: external token + optional LDAP role enrichment
//
// Usage remains similar: module.exports = function(setup) { return { setNTLMAuth, validateToken, ... } }

const os = require('os');
const ntlm = require('express-ntlm');
const jwt = require('jsonwebtoken');
const secureRandom = require('secure-random');
const jwksClient = require('jwks-rsa');
const saml2 = require('saml2-js');

module.exports = function(setup = {}) {
  const PASS_TOKEN = setup.passToken || secureRandom(256, { type: 'Buffer' });
  const model = {};

  // LDAP is optional for pure external auth scenarios
  let ldap = null;
  try {
    if (setup.url || setup.NTLM_LDAP || setup.useLdapForRoles) {
      ldap = require('@acastellon/ldap')(setup);
    }
  } catch (e) {
    console.warn('[@acastellon/auth] LDAP module not available or not configured. Pure external JWT/SAML mode only.');
  }

  let ldapCache = new Array();

  // Public API (backward compatible + new)
  model.setNTLMAuth = setNTLMAuth;
  model.validateToken = validateToken;
  model.validateExternalToken = validateExternalToken;
  model.setRoles = setRoles;
  model.getRoles = getRoles;
  model.removeCache4 = removeCache4;
  model.setupSaml = setupSaml;
  model.samlAuth = samlAuth;

  function getHostName() {
    return process.env.CNAME || os.hostname();
  }

  function removeCache4(userName) {
    ldapCache[userName] = null;
  }

  function setContent(into, from) {
    Object.keys(from || {}).forEach(function(value) {
      if (value.startsWith('is')) {
        into[value] = from[value];
      }
    });
  }

  function setHeaders(res, v) {
    Object.keys(v || {}).forEach(function(value) {
      if (value.startsWith('is')) {
        res.setHeader(value, v[value]);
      }
    });
  }

  // ===========================================
  // LEGACY NTLM + LDAP (unchanged behavior)
  // ===========================================
  function setNTLMAuth (app) {
    let options = {};
    if (setup.NTLM_OPTIONS){
      options = {
        debug: function () {
          if (setup.NTLM_DEBUG) {
            var args = Array.prototype.slice.apply( arguments );
            console.log.apply( null, args );
          }
        },
        domain: ldap ? ldap.DOMAIN : setup.DOMAIN,
        domaincontroller: ldap ? ldap.LDAP_URL : setup.url,
        tlsOptions: setup.tlsOptions,
        forbidden: function (req, res) {
          res.status(401).location(req.url).end();
        }
      };
    }

    app.use(ntlm(options));

    app.all(setup.NTLM_PATH || '*', function (request, res, next) {
      let userName = request.ntlm.UserName;

      if(ldapCache[userName] != null){
        if (jwt.decode(ldapCache[userName]).exp >= new Date().getTime()/1000) {
          res.setHeader('x-access-token', ldapCache[userName]);
          res.setHeader('is-authenticated', true);
          res.setHeader('auth-user', userName);
          next();
          return;
        }
      }

      if (request.ntlm.Authenticated && !res.hasHeader('is-authenticated')) {
        res.setHeader('is-authenticated', true);
        res.setHeader('auth-user', userName);

        let _content = { id: userName };

        const doLdap = setup.NTLM_LDAP && ldap;
        if (doLdap) {
          ldap.getRoles(userName).then(function (v) {
            setContent(_content, v);
            let token = jwt.sign(_content, PASS_TOKEN, { expiresIn: setup.EXPIRES });
            res.setHeader('x-access-token', token);
            ldapCache[userName] = token;
            next();
          });
        } else {
          let token = jwt.sign(_content, PASS_TOKEN, { expiresIn: setup.EXPIRES });
          res.setHeader('x-access-token', token);
          ldapCache[userName] = token;
          next();
        }
      } else {
        Object.keys(setup.ROLES || {}).forEach(function(value){
          res.setHeader(value, false);
        });
        res.setHeader('x-access-token', null);
        ldapCache[userName] = null;
        res.status(401).json({Message: 'Unauthorized access ', AuthUser: userName});
      }
    });
  }

  // ===========================================
  // EXTERNAL JWT VERIFICATION (Cognito, Azure, OIDC)
  // ===========================================
  function createExternalJwtVerifier(setup) {
    // Determine provider config
    let providerConfig = null;
    let providerType = null;

    if (setup.COGNITO) {
      providerType = 'cognito';
      providerConfig = setup.COGNITO;
    } else if (setup.AZURE) {
      providerType = 'azure';
      providerConfig = setup.AZURE;
    } else if (setup.OIDC) {
      providerType = 'oidc';
      providerConfig = setup.OIDC;
    } else if (setup.externalAuth) {
      // generic
      providerType = setup.externalAuth.type || 'oidc';
      providerConfig = setup.externalAuth;
    }

    if (!providerConfig) {
      throw new Error('No external auth provider configured (COGNITO, AZURE, OIDC or externalAuth)');
    }

    const rolesClaim = providerConfig.rolesClaim || setup.rolesClaim || 'roles';
    const roleMapper = providerConfig.roleMapper || setup.roleMapper || {};

    let jwksUri = providerConfig.jwksUri;
    let issuer = providerConfig.issuer;
    let audience = providerConfig.clientId || providerConfig.audience;

    if (providerType === 'cognito' && !jwksUri) {
      const region = providerConfig.region || 'eu-west-1';
      const userPoolId = providerConfig.userPoolId;
      if (!userPoolId) throw new Error('Cognito userPoolId is required');
      jwksUri = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;
      issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
    }

    if (providerType === 'azure' && !jwksUri) {
      const tenantId = providerConfig.tenantId;
      if (!tenantId) throw new Error('Azure tenantId is required');
      jwksUri = `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`;
      issuer = `https://login.microsoftonline.com/${tenantId}/v2.0`;
    }

    if (!jwksUri) {
      // try to construct from issuer for generic OIDC
      if (issuer) {
        jwksUri = issuer.replace(/\/$/, '') + '/.well-known/jwks.json';
      }
    }

    if (!jwksUri) {
      throw new Error('Could not determine jwksUri for external JWT verification');
    }

    const client = jwksClient({
      jwksUri: jwksUri,
      cache: true,
      cacheMaxEntries: 5,
      cacheMaxAge: 36000000 // 10 hours
    });

    function getKey(header, callback) {
      client.getSigningKey(header.kid, function(err, key) {
        if (err) return callback(err);
        const signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
      });
    }

    return function verifyExternalToken(token) {
      return new Promise((resolve, reject) => {
        const verifyOptions = {
          algorithms: ['RS256'],
          issuer: issuer,
          audience: audience
        };

        jwt.verify(token, getKey, verifyOptions, (err, decoded) => {
          if (err) return reject(err);

          // Extract roles from claims
          let rawRoles = decoded[rolesClaim] || decoded.roles || decoded.groups || [];
          if (!Array.isArray(rawRoles)) rawRoles = [rawRoles];

          const roles = { id: decoded.sub || decoded['cognito:username'] || decoded.upn || decoded.email || 'unknown' };

          rawRoles.forEach(roleName => {
            const mapped = roleMapper[roleName] || roleName;
            if (setup.ROLES && setup.ROLES[mapped]) {
              roles['is' + mapped] = true;
            } else {
              // allow any role from provider
              roles['is' + mapped] = true;
            }
          });

          // If hybrid mode, we can still call LDAP later in middleware
          resolve({ claims: decoded, roles, userName: roles.id });
        });
      });
    };
  }

  let externalVerifier = null;
  function getVerifier() {
    if (!externalVerifier && (setup.AUTH_TYPE === 'EXTERNAL_JWT' || setup.COGNITO || setup.AZURE || setup.OIDC || setup.externalAuth)) {
      externalVerifier = createExternalJwtVerifier(setup);
    }
    return externalVerifier;
  }

  // ===========================================
  // validateToken - works for both legacy internal JWT and external
  // ===========================================
  function validateToken (app) {
    const verifier = getVerifier();

    app.all('*', function(req, res, next) {
      const token = req.headers['x-access-token'];
      let userName = req.headers['auth-user'];

      // Service-to-service bypass (legacy)
      if (userName === 'service-brother' && req.get('host').startsWith(getHostName())) {
        return next();
      }

      if (!token) {
        return res.status(401).send({ auth: false, message: 'No token provided.' });
      }

      // If we have an external verifier, use it
      if (verifier) {
        verifier(token)
          .then(async ({ claims, roles: externalRoles, userName: extUser }) => {
            let finalRoles = externalRoles;

            // Optional LDAP enrichment (hybrid)
            if (setup.useLdapForRoles && ldap) {
              try {
                const ldapRoles = await ldap.getRoles(extUser);
                // merge
                Object.keys(ldapRoles || {}).forEach(k => {
                  if (k.startsWith('is')) finalRoles[k] = finalRoles[k] || ldapRoles[k];
                });
              } catch (e) {
                console.warn('LDAP enrichment failed for', extUser, e.message);
              }
            }

            setContent(finalRoles, finalRoles); // ensure isXXX
            setHeaders(res, finalRoles);
            res.setHeader('auth-user', extUser);
            res.setHeader('is-authenticated', true);

            // Optionally re-issue a normalized internal token
            if (setup.reissueInternalToken !== false) {
              const internalToken = jwt.sign(finalRoles, PASS_TOKEN, { expiresIn: setup.EXPIRES });
              res.setHeader('x-access-token', internalToken);
            }

            // attach to req for downstream use
            req.user = finalRoles;
            req.authClaims = claims;
            next();
          })
          .catch(err => {
            console.error('External token validation failed:', err.message);
            return res.status(403).send({
              auth: false,
              message: 'Invalid or expired external token.',
              error: err.message
            });
          });
        return;
      }

      // === Legacy internal JWT path (with LDAP) ===
      if (!ldap) {
        return res.status(500).send({ auth: false, message: 'LDAP not configured for legacy JWT validation.' });
      }

      let _content = { id: userName };
      ldap.getRoles(userName).then(function(v) {
        setContent(_content, v);
        setHeaders(res, v);
        res.setHeader('auth-user', userName);

        var _token = jwt.sign(_content, PASS_TOKEN, { expiresIn: setup.EXPIRES });

        if (!token || !isEqualToken(token, _token, userName)) {
          return res.status(403).send({
            auth: false,
            message: 'No token provided, or incorrect ones.',
            host : getHostName(),
            origin: req.get('host'),
            user : userName
          });
        }

        jwt.verify(token, PASS_TOKEN, function (err, decoded) {
          if (err) {
            return res.status(500).send({auth: false, message: 'Failed to authenticate token. Maybe token is expired.'});
          } else {
            req.user = decoded;
            next();
          }
        });
      });
    });
  }

  // Dedicated external-only middleware (recommended for new apps)
  function validateExternalToken (app) {
    const verifier = getVerifier();
    if (!verifier) {
      throw new Error('No external JWT provider configured. Use COGNITO, AZURE, OIDC or externalAuth in setup.');
    }

    app.all('*', async function(req, res, next) {
      const authHeader = req.headers['authorization'] || req.headers['x-access-token'];
      const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : authHeader;

      if (!token) {
        return res.status(401).send({ auth: false, message: 'No token provided.' });
      }

      try {
        const { claims, roles, userName } = await verifier(token);

        let finalRoles = { ...roles };

        if (setup.useLdapForRoles && ldap) {
          try {
            const ldapRoles = await ldap.getRoles(userName);
            Object.keys(ldapRoles || {}).forEach(k => {
              if (k.startsWith('is')) finalRoles[k] = finalRoles[k] || ldapRoles[k];
            });
          } catch (e) { /* ignore enrichment errors */ }
        }

        setHeaders(res, finalRoles);
        res.setHeader('auth-user', userName);
        res.setHeader('is-authenticated', true);

        if (setup.reissueInternalToken) {
          const internalToken = jwt.sign(finalRoles, PASS_TOKEN, { expiresIn: setup.EXPIRES || 3600 });
          res.setHeader('x-access-token', internalToken);
        }

        req.user = finalRoles;
        req.authClaims = claims;
        next();
      } catch (err) {
        console.error('External token validation error:', err.message);
        return res.status(403).send({ auth: false, message: 'Invalid token', error: err.message });
      }
    });
  }

  // ===========================================
  // SAML 2.0 Support
  // ===========================================
  let samlIdp = null;
  let samlSp = null;
  let samlConfig = null;

  if (setup.SAML) {
    samlConfig = setup.SAML;
    try {
      samlIdp = new saml2.IdentityProvider(samlConfig.identityProvider || {});
      samlSp = new saml2.ServiceProvider(samlConfig.serviceProvider || {});
    } catch (e) {
      console.error('Failed to initialize SAML providers:', e.message);
    }
  }

  function setupSaml(app) {
    if (!samlSp || !samlIdp) {
      throw new Error('SAML not configured in setup. Provide SAML.identityProvider and SAML.serviceProvider');
    }

    const loginPath = samlConfig.loginPath || '/auth/saml/login';
    const acsPath = samlConfig.acsPath || '/auth/saml/acs';
    const logoutPath = samlConfig.logoutPath || '/auth/saml/logout';

    // Initiate SAML login - redirect to IdP
    app.get(loginPath, (req, res) => {
      samlSp.create_login_request_url(samlIdp, {}, (err, loginUrl) => {
        if (err) {
          console.error('SAML login request error:', err);
          return res.status(500).send('SAML login error');
        }
        res.redirect(loginUrl);
      });
    });

    // Assertion Consumer Service (ACS) - IdP posts the SAMLResponse here
    app.post(acsPath, (req, res) => {
      const options = { request_body: req.body };
      samlSp.post_assert(samlIdp, options, (err, samlResponse) => {
        if (err) {
          console.error('SAML assert error:', err);
          return res.status(403).send('SAML authentication failed');
        }

        const user = samlResponse.user;
        const userName = user.name_id || user.email || user.attributes?.email || 'saml-user';

        // Build roles object similar to other providers
        let roles = { id: userName, user: userName };

        const rolesClaim = samlConfig.rolesClaim || setup.rolesClaim || 'roles';
        let rawRoles = user[rolesClaim] || user.attributes?.[rolesClaim] || [];
        if (!Array.isArray(rawRoles)) rawRoles = [rawRoles];

        const roleMapper = samlConfig.roleMapper || setup.roleMapper || {};
        rawRoles.forEach(roleName => {
          const mapped = roleMapper[roleName] || roleName;
          roles['is' + mapped] = true;
        });

        // Issue internal JWT (stateless)
        const token = jwt.sign(roles, PASS_TOKEN, { expiresIn: setup.EXPIRES || 86400 });

        // Set httpOnly cookie for browser apps
        res.cookie('saml_auth_token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

        // For API clients, could return JSON with token instead
        // res.json({ token });

        // Redirect to app home or requested URL
        const redirectTo = req.query.RelayState || '/';
        res.redirect(redirectTo);
      });
    });

    // Simple logout (clear cookie)
    app.get(logoutPath, (req, res) => {
      res.clearCookie('saml_auth_token');
      res.redirect('/');
    });

    console.log(`SAML routes registered: ${loginPath}, ${acsPath}, ${logoutPath}`);
  }

  // Middleware to protect routes with SAML session (checks the cookie or header)
  function samlAuth (req, res, next) {
    const token = req.cookies?.saml_auth_token || req.headers['x-access-token'] || req.headers['authorization']?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({ message: 'SAML authentication required. Please login at /auth/saml/login' });
    }

    try {
      const decoded = jwt.verify(token, PASS_TOKEN);
      req.user = decoded;
      res.setHeader('auth-user', decoded.id || decoded.user);
      setHeaders(res, decoded);
      next();
    } catch (err) {
      res.clearCookie('saml_auth_token');
      return res.status(403).json({ message: 'Invalid or expired SAML session' });
    }
  }

  // ===========================================
  // Helper / legacy methods
  // ===========================================
  function isEqualToken (token, _token, userName) {
    let allRoles = true;
    Object.keys(setup.ROLES || {}).forEach(function(value) {
      allRoles = allRoles && (jwt.decode(token)[value] == jwt.decode(_token)[value]);
    });
    return allRoles &&
      (jwt.decode(token).id == jwt.decode(_token).id) &&
      (jwt.decode(token).id == userName);
  }

  function setRoles (app) {
    app.all('*', function (req, res, next) {
      let userName = req.headers['auth-user'];

      if (typeof userName == 'undefined' || userName == '') {
        res.status(401).send({message: 'Authentication required'});
      } else if (ldap) {
        ldap.getRoles(userName).then(function (v) {
          setHeaders(res, v);
          res.setHeader('auth-user', userName);
          next();
        });
      } else {
        next();
      }
    });
  }

  function getRoles (req, res) {
    let userName = '';
    if (typeof req.ntlm != 'undefined') {
      userName = req.ntlm.UserName || req.headers['auth-user'] ;
    } else {
      userName = req.headers['auth-user'] ;
    }

    if (typeof userName == 'undefined' || userName == '') {
      res.status(401).send({message: 'Authentication required'});
    } else if (ldap) {
      ldap.getRoles(userName).then(function (v) {
        res.json(v);
      });
    } else {
      res.json({ user: userName });
    }
  }

  return model;
};

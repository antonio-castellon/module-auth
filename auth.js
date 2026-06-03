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
//   - Passwords, private keys and signing secrets from environment variables
//     (e.g. LDAP_PASSWORD, AUTH_JWT_SECRET, SAML_PRIVATE_KEY) so they are never
//     hardcoded in committed config files.
//
// Usage remains similar: module.exports = function(setup) { return { setNTLMAuth, validateToken, ... } }

const os = require('os');
const ntlm = require('express-ntlm');
const jwt = require('jsonwebtoken');
const secureRandom = require('secure-random');
const jwksClient = require('jwks-rsa');
const saml2 = require('saml2-js');

/**
 * Authentication Control System factory (v2).
 *
 * Supports legacy NTLM (express-ntlm) + LDAP, modern external JWT providers
 * (AWS Cognito, Azure AD/Entra ID, generic OIDC), SAML 2.0 (via saml2-js),
 * hybrid (external + LDAP role enrichment), and internal JWT issuance.
 *
 * Secrets (LDAP passwords, JWT signing keys, SAML private keys/certs, TLS CAs)
 * can be supplied directly in setup or resolved from environment variables
 * at initialization time (e.g. LDAP_PASSWORD, AUTH_JWT_SECRET, SAML_PRIVATE_KEY,
 * SAML_IDP_CERT). This keeps config files free of secrets.
 *
 * The returned model exposes the public API methods. Call the methods that
 * take an Express `app` to install the desired middlewares/routes.
 *
 * @param {object} [setup={}]
 * @param {string} [setup.url] - LDAP/AD URL for legacy NTLM or role lookup
 * @param {string} [setup.DOMAIN] - NTLM domain
 * @param {string} [setup.password] - LDAP bind password (or via LDAP_PASSWORD / AUTH_LDAP_PASSWORD env)
 * @param {string} [setup.passToken] - HMAC secret for signing internal JWTs (or AUTH_JWT_SECRET / JWT_SECRET env; falls back to random)
 * @param {string} [setup.EXPIRES='1h'] - expiry for issued tokens (jwt 'expiresIn')
 * @param {object} [setup.ROLES] - map of known role names to enable isXXX header flags, e.g. { admin: true, user: true }
 * @param {boolean} [setup.NTLM_OPTIONS] - if truthy, enable and configure legacy NTLM middleware in setNTLMAuth
 * @param {string} [setup.NTLM_PATH='*'] - path scope for NTLM handler
 * @param {boolean} [setup.NTLM_LDAP] - whether NTLM path should enrich roles via LDAP
 * @param {boolean} [setup.NTLM_DEBUG] - forward express-ntlm debug logs
 * @param {object} [setup.tlsOptions] - TLS options for LDAP (ca resolved from env too)
 * @param {'EXTERNAL_JWT'} [setup.AUTH_TYPE] - hint to prefer external validation in validateToken
 * @param {object} [setup.COGNITO] - AWS Cognito config: {userPoolId, region?, clientId?, rolesClaim?, roleMapper?, jwksUri?}
 * @param {object} [setup.AZURE] - Azure/Entra: {tenantId, clientId?, rolesClaim?, roleMapper?}
 * @param {object} [setup.OIDC] - Generic OIDC: {issuer, clientId?, audience?, jwksUri?, rolesClaim?, roleMapper?}
 * @param {object} [setup.externalAuth] - Generic external: {type?, issuer?, jwksUri?, clientId?, rolesClaim?, roleMapper?}
 * @param {object} [setup.SAML] - SAML 2.0: {identityProvider: {entryPoint, issuer, certs?}, serviceProvider: {entityID, privateKey?, certificate?, ...}, loginPath?, acsPath?, logoutPath?, rolesClaim?, roleMapper? }
 * @param {boolean} [setup.useLdapForRoles=false] - hybrid mode: after external/SAML success, also call LDAP getRoles and merge isXXX flags
 * @param {boolean} [setup.reissueInternalToken=true] - in external flows, also issue a normalized internal JWT as x-access-token
 * @returns {{setNTLMAuth: Function, validateToken: Function, validateExternalToken: Function, setupSaml: Function, samlAuth: Function, setRoles: Function, getRoles: Function, removeCache4: Function}}
 */
module.exports = function(setup = {}) {
  // Shallow copy to allow safe secret resolution from env vars without mutating
  // the caller's config object.
  setup = { ...setup };

  // Resolve secrets (passwords/keys) from env if not provided with a concrete value.
  // This lets config files omit secrets entirely (or use placeholders) while
  // supporting 12-factor / no-hardcoded-secrets in source control.
  // Precedence: real value from setup > matching process.env > placeholder/undefined.
  /**
   * Resolve a secret value.
   * Returns the provided value if it is a non-empty, non-placeholder string.
   * Otherwise scans the listed env var names (in order) and returns the first non-empty value found.
   * Used for LDAP password, JWT secret, SAML keys, TLS CA etc.
   *
   * @private
   * @param {string|undefined|null} provided - explicit value from setup
   * @param {...string} envNames - candidate env var names (e.g. 'LDAP_PASSWORD', 'AUTH_JWT_SECRET')
   * @returns {string|undefined} resolved secret or the original provided (placeholder/undefined)
   */
  function getSecret(provided, ...envNames) {
    if (provided != null && typeof provided === 'string' && provided.length > 0 && !provided.startsWith('<')) {
      return provided;
    }
    for (const envName of envNames) {
      const val = process.env[envName];
      if (val != null && val !== '') {
        return val;
      }
    }
    return provided;
  }

  // Apply to known sensitive fields (affects both direct use and delegation to @acastellon/ldap)
  setup.password = getSecret(setup.password, 'LDAP_PASSWORD', 'AUTH_LDAP_PASSWORD', 'AD_PASSWORD', 'LDAP_BIND_PASSWORD');
  setup.passToken = getSecret(setup.passToken, 'AUTH_JWT_SECRET', 'JWT_SECRET', 'AUTH_PASS_TOKEN', 'PASS_TOKEN');

  if (setup.tlsOptions) {
    setup.tlsOptions = { ...setup.tlsOptions };
    setup.tlsOptions.ca = getSecret(setup.tlsOptions.ca, 'LDAP_TLS_CA', 'AUTH_LDAP_CA', 'TLS_CA');
  }

  // SAML requires deep handling because privateKey lives in nested serviceProvider
  if (setup.SAML) {
    setup.SAML = { ...setup.SAML };
    if (setup.SAML.serviceProvider) {
      setup.SAML.serviceProvider = { ...setup.SAML.serviceProvider };
      if (setup.SAML.serviceProvider.privateKey != null) {
        setup.SAML.serviceProvider.privateKey = getSecret(
          setup.SAML.serviceProvider.privateKey,
          'SAML_PRIVATE_KEY', 'AUTH_SAML_PRIVATE_KEY', 'SP_PRIVATE_KEY'
        );
      }
      if (setup.SAML.serviceProvider.certificate != null) {
        setup.SAML.serviceProvider.certificate = getSecret(
          setup.SAML.serviceProvider.certificate,
          'SAML_CERTIFICATE', 'AUTH_SAML_CERT'
        );
      }
    }
    if (setup.SAML.identityProvider) {
      setup.SAML.identityProvider = { ...setup.SAML.identityProvider };
      if (Array.isArray(setup.SAML.identityProvider.certificates)) {
        setup.SAML.identityProvider.certificates = setup.SAML.identityProvider.certificates.map((c) =>
          getSecret(c, 'SAML_IDP_CERT', 'AUTH_SAML_IDP_CERT', 'IDP_CERT')
        );
      }
    }
  }

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

  /**
   * Internal hostname resolution (honors CNAME env override, used for service-to-service legacy bypass).
   * @private
   * @returns {string}
   */
  function getHostName() {
    return process.env.CNAME || os.hostname();
  }

  /**
   * Clear any cached internal JWT for the given userName.
   * Forces fresh LDAP role lookup + new token on the next NTLM request for that user.
   * Useful when roles have changed externally.
   *
   * @param {string} userName
   */
  function removeCache4(userName) {
    ldapCache[userName] = null;
  }

  /**
   * Copy only 'is*' role flags from source object into target object (in place).
   * Used to normalize role objects coming from LDAP / external claims before setting headers or signing.
   * @private
   * @param {object} into
   * @param {object} from
   */
  function setContent(into, from) {
    Object.keys(from || {}).forEach(function(value) {
      if (value.startsWith('is')) {
        into[value] = from[value];
      }
    });
  }

  /**
   * Copy 'is*' role flags from a roles object as response headers (e.g. is-admin: true).
   * @private
   * @param {object} res - Express response
   * @param {object} v - roles object
   */
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

  /**
   * Install legacy NTLM authentication (using express-ntlm) + optional LDAP role enrichment + internal JWT minting.
   *
   * Mounts ntlm middleware (if NTLM_OPTIONS) and a handler on NTLM_PATH (default '*').
   * On successful NTLM auth: sets is-authenticated, auth-user, x-access-token (signed JWT),
   * and isXXX headers from ROLES or from ldap.getRoles().
   * Caches the issued token briefly in memory (ldapCache) to avoid repeated LDAP calls within expiry.
   *
   * @param {object} app - Express application instance
   */
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

  /**
   * Build (and return) a verifier function for external JWTs (RS256 + JWKS).
   * Supports Cognito (auto jwks/issuer from userPoolId+region), Azure (tenantId), generic OIDC (issuer or explicit jwks).
   * Role extraction: prefers provider's rolesClaim (or top-level rolesClaim), falls back to 'roles'/'groups'.
   * Applies optional roleMapper and intersects with setup.ROLES to produce isXXX flags.
   *
   * The returned function is used by validateToken / validateExternalToken.
   *
   * @private
   * @param {object} setup - the factory setup (may contain COGNITO / AZURE / OIDC / externalAuth / rolesClaim / roleMapper)
   * @returns {Function} async (token: string) => Promise<{claims:object, roles:object, userName:string}>
   */
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

  /**
   * Lazy-initialize (and cache) the external JWT verifier if any external provider is configured.
   * @private
   * @returns {Function|null} the verifyExternalToken function or null
   */
  function getVerifier() {
    if (!externalVerifier && (setup.AUTH_TYPE === 'EXTERNAL_JWT' || setup.COGNITO || setup.AZURE || setup.OIDC || setup.externalAuth)) {
      externalVerifier = createExternalJwtVerifier(setup);
    }
    return externalVerifier;
  }

  // ===========================================
  // validateToken - works for both legacy internal JWT and external
  // ===========================================

  /**
   * Install catch-all token validation middleware.
   *
   * Behavior depends on configuration:
   * - If external provider(s) configured (COGNITO/AZURE/OIDC/externalAuth or AUTH_TYPE=EXTERNAL_JWT):
   *     uses JWKS verification, supports optional hybrid LDAP role merge, sets req.user/req.authClaims,
   *     sets auth headers, and (unless reissueInternalToken===false) also mints a normalized internal JWT.
   * - Otherwise (legacy path): requires LDAP, validates incoming internal JWT against a freshly generated
   *     one from current LDAP roles (isEqualToken), then jwt.verify.
   *
   * Special legacy bypass: user 'service-brother' from same hostname is allowed without token.
   *
   * @param {object} app - Express app
   */
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

  /**
   * Install dedicated external-JWT-only validation middleware (recommended for apps using Cognito/Azure/OIDC/SAML-issued tokens).
   *
   * Accepts token from Authorization: Bearer ... or x-access-token header.
   * Always requires an external verifier (throws at mount time if none configured).
   * Optional LDAP role enrichment when useLdapForRoles + ldap present.
   * Optionally re-issues internal token (only if setup.reissueInternalToken truthy).
   * Sets req.user, req.authClaims, auth headers on success.
   *
   * @param {object} app - Express app
   * @throws {Error} if no external provider configured at factory time
   */
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

  /**
   * Register SAML 2.0 routes on the Express app:
   *   GET  loginPath (default /auth/saml/login)  -> redirects to IdP with AuthnRequest
   *   POST acsPath   (default /auth/saml/acs)    -> Assertion Consumer Service (receives SAMLResponse)
   *   GET  logoutPath (default /auth/saml/logout) -> clears cookie
   *
   * On successful ACS:
   * - extracts user + roles from assertion (name_id / email / attributes + rolesClaim)
   * - applies roleMapper
   * - signs an internal JWT
   * - sets httpOnly 'saml_auth_token' cookie (secure in prod)
   * - redirects to RelayState or '/'
   *
   * Must be called with SAML.* present in the original setup.
   *
   * @param {object} app - Express app instance
   * @throws {Error} if SAML not configured (no samlSp/samlIdp)
   */
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

  /**
   * SAML session guard middleware.
   *
   * Looks for token in:
   *   - req.cookies.saml_auth_token (set by setupSaml ACS)
   *   - x-access-token header
   *   - Authorization: Bearer <token>
   *
   * Verifies as internal JWT (signed with PASS_TOKEN). On success:
   *   sets req.user = decoded, auth-user header, isXXX headers via setHeaders.
   * On failure: clears cookie + 401/403 JSON.
   *
   * Intended to be used after setupSaml routes are mounted.
   *
   * @param {object} req - Express request (expects req.cookies if using cookie auth)
   * @param {object} res
   * @param {Function} next
   */
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

  /**
   * Legacy token equality check used inside validateToken (NTLM+LDAP path).
   * Ensures that the presented token and a freshly signed token from current LDAP roles
   * have identical role flags + same id, and that id matches the NTLM userName.
   *
   * @private
   * @param {string} token - presented x-access-token
   * @param {string} _token - freshly computed expected token
   * @param {string} userName - the authenticated NTLM user
   * @returns {boolean}
   */
  function isEqualToken (token, _token, userName) {
    let allRoles = true;
    Object.keys(setup.ROLES || {}).forEach(function(value) {
      allRoles = allRoles && (jwt.decode(token)[value] == jwt.decode(_token)[value]);
    });
    return allRoles &&
      (jwt.decode(token).id == jwt.decode(_token).id) &&
      (jwt.decode(token).id == userName);
  }

  /**
   * Legacy middleware: on every request, lookup roles via LDAP for the 'auth-user' header
   * and set the corresponding isXXX response headers. Does not issue/validate tokens itself.
   *
   * @param {object} app - Express app
   */
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

  /**
   * Legacy role lookup endpoint helper.
   * Returns JSON roles from LDAP (or minimal {user}) for the current auth-user
   * (prefers req.ntlm.UserName when available).
   *
   * @param {object} req
   * @param {object} res
   */
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

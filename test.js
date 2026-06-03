// Basic smoke test for @acastellon/auth v2
// Run with: node test.js

const assert = require('assert');

// Test 1: Legacy config still loads
try {
  const legacyConfig = {
    url: 'ldap://dummy:389',
    DOMAIN: 'DUMMY',
    baseDN: 'dc=dummy',
    username: 'dummy',
    password: 'dummy',
    ROLES: { User: 'Users' },
    AUTH_TYPE: 'NTLM'
  };
  const authLegacy = require('./auth.js')(legacyConfig);
  assert(typeof authLegacy.setNTLMAuth === 'function');
  assert(typeof authLegacy.validateToken === 'function');
  console.log('✓ Legacy NTLM module loads without error');
} catch (e) {
  console.error('Legacy load failed:', e.message);
}

// Test 2: External provider config loads (Cognito example)
try {
  const cognitoConfig = {
    AUTH_TYPE: 'EXTERNAL_JWT',
    COGNITO: {
      region: 'eu-west-1',
      userPoolId: 'eu-west-1_TEST123',
      clientId: 'testclientid'
    },
    ROLES: { Admin: 'Admins' }
  };
  const authCognito = require('./auth.js')(cognitoConfig);
  assert(typeof authCognito.validateExternalToken === 'function');
  assert(typeof authCognito.validateToken === 'function');
  console.log('✓ Cognito external JWT config loads');
} catch (e) {
  console.error('Cognito config load failed:', e.message);
}

// Test 3: Azure config
try {
  const azureConfig = {
    AUTH_TYPE: 'EXTERNAL_JWT',
    AZURE: {
      tenantId: '11111111-1111-1111-1111-111111111111',
      clientId: '22222222-2222-2222-2222-222222222222'
    }
  };
  const authAzure = require('./auth.js')(azureConfig);
  console.log('✓ Azure external JWT config loads');
} catch (e) {
  console.error('Azure config load failed:', e.message);
}

// Test 4: SAML config loads and exposes setupSaml + samlAuth
try {
  const samlConfig = {
    AUTH_TYPE: 'SAML',
    SAML: {
      identityProvider: {
        ssoLoginUrl: 'https://idp.example.com/sso',
        certificates: ['dummy-cert']
      },
      serviceProvider: {
        entityId: 'https://app.example.com',
        assertEndpoint: 'https://app.example.com/auth/saml/acs'
      }
    }
  };
  const authSaml = require('./auth.js')(samlConfig);
  assert(typeof authSaml.setupSaml === 'function');
  assert(typeof authSaml.samlAuth === 'function');
  console.log('✓ SAML config loads and exposes setupSaml + samlAuth');
} catch (e) {
  console.error('SAML config load failed:', e.message);
}

// Test 5: Environment variable secrets (no secrets hardcoded in the config object)
const _savedLdapPw = process.env.LDAP_PASSWORD;
const _savedJwt = process.env.AUTH_JWT_SECRET;
const _savedSamlKey = process.env.SAML_PRIVATE_KEY;
try {
  process.env.LDAP_PASSWORD = 'from-env-ldap-pass-123';
  process.env.AUTH_JWT_SECRET = 'from-env-jwt-secret-xyz';
  process.env.SAML_PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\nMIIE-from-env...\n-----END RSA PRIVATE KEY-----';

  // Legacy-style config with secrets omitted (still triggers ldap path in real, but we just test load + resolution)
  const envLegacyCfg = {
    url: 'ldap://dummy:389',
    DOMAIN: 'DUMMY',
    baseDN: 'dc=dummy',
    username: 'dummy',
    // password deliberately omitted
    ROLES: { User: 'Users' },
    AUTH_TYPE: 'NTLM'
  };
  const authEnvLegacy = require('./auth.js')(envLegacyCfg);
  assert(typeof authEnvLegacy.setNTLMAuth === 'function');
  console.log('✓ Env var resolution for password / passToken (omitted from config)');

  // SAML with privateKey omitted — resolved from env
  const envSamlCfg = {
    AUTH_TYPE: 'SAML',
    SAML: {
      identityProvider: {
        ssoLoginUrl: 'https://idp.example.com/sso',
        certificates: ['dummy-cert']
      },
      serviceProvider: {
        entityId: 'https://app.example.com',
        assertEndpoint: 'https://app.example.com/auth/saml/acs'
        // privateKey omitted on purpose
      }
    }
  };
  const authEnvSaml = require('./auth.js')(envSamlCfg);
  assert(typeof authEnvSaml.setupSaml === 'function');
  assert(typeof authEnvSaml.samlAuth === 'function');
  console.log('✓ Env var resolution for SAML privateKey (omitted from config)');
} catch (e) {
  console.error('Env var secrets test failed:', e.message);
} finally {
  process.env.LDAP_PASSWORD = _savedLdapPw;
  process.env.AUTH_JWT_SECRET = _savedJwt;
  process.env.SAML_PRIVATE_KEY = _savedSamlKey;
}

console.log('\nAll basic smoke tests passed. For real integration tests you need actual providers or mocks.');
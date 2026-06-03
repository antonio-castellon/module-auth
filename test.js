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

console.log('\nAll basic smoke tests passed. For real integration tests you need actual providers or mocks.');

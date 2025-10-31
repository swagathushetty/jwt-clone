// examples/02b-token-tampering.js
const MiniJWT = require('../src/jwt');

const jwt = new MiniJWT('my-secret-key');

console.log('Token Tampering Demo\n');
console.log('='.repeat(70));

// Create a token
console.log('\nStep 1: Create legitimate token');
const originalToken = jwt.sign({ userId: 123, role: 'user' });
console.log('Original token:', originalToken);

// Decode it
const decoded = jwt.decode(originalToken);
console.log('\nOriginal payload:', decoded.payload);

// Try to tamper with it
console.log('\n' + '='.repeat(70));
console.log('\nStep 2: Attacker tries to tamper');
console.log('Attacker changes role: "user" → "admin"');

// Modify payload
const tamperedPayload = { ...decoded.payload, role: 'admin' };
console.log('Tampered payload:', tamperedPayload);

// Re-encode (but with WRONG signature)
const tamperedPayloadB64 = jwt.base64UrlEncode(JSON.stringify(tamperedPayload));
const headerB64 = originalToken.split('.')[0];
const originalSignature = originalToken.split('.')[2];

const tamperedToken = `${headerB64}.${tamperedPayloadB64}.${originalSignature}`;
console.log('\nTampered token:', tamperedToken);

// Show what changed
console.log('\nComparison:');
console.log('Original payload:', decoded.payload);
console.log('Tampered payload:', jwt.decode(tamperedToken).payload);

console.log('\nNotice: Payload changed, but signature stayed the same!');
console.log('    This will fail verification in Step 3!');

console.log('\n' + '='.repeat(70));
console.log('\nSecurity Insight:');
console.log('   Without the secret key, attacker cannot create valid signature.');
console.log('   Server will detect tampering during verification!\n');
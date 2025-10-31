const MiniJWT = require('../src/jwt');

const jwt = new MiniJWT('my-secret-key');

console.log('JWT Verification Examples\n');
console.log('='.repeat(70));

// Example 1: Verify valid token
console.log('\nExample 1: Valid Token');
const validToken = jwt.sign({ userId: 123, role: 'user' }, { expiresIn: '1h' });
console.log('Token:', validToken.substring(0, 50) + '...');

try {
  const decoded = jwt.verify(validToken);
  console.log('Verification successful!');
  console.log('Decoded payload:', decoded);
} catch (err) {
  console.log('Verification failed:', err.message);
}

// Example 2: Tampered token (wrong signature)
console.log('\n' + '='.repeat(70));
console.log('\nExample 2: Tampered Token');
const parts = validToken.split('.');
const tamperedToken = parts[0] + '.' + parts[1] + '.wrong_signature';
console.log('Token:', tamperedToken.substring(0, 50) + '...');

try {
  jwt.verify(tamperedToken);
  console.log('Verification successful!');
} catch (err) {
  console.log('Verification failed:', err.message);
  console.log('   (Expected - signature is invalid)');
}

// Example 3: Expired token
console.log('\n' + '='.repeat(70));
console.log('\nExample 3: Expired Token');
const expiredToken = jwt.sign({ userId: 456 }, { expiresIn: '0s' });

// Wait a moment for it to expire
setTimeout(() => {
  console.log('Token:', expiredToken.substring(0, 50) + '...');

  try {
    jwt.verify(expiredToken);
    console.log('Verification successful!');
  } catch (err) {
    console.log('Verification failed:', err.message);
    console.log('   (Expected - token is expired)');
  }

  // Example 4: Wrong secret key
  console.log('\n' + '='.repeat(70));
  console.log('\nExample 4: Wrong Secret Key');
  const jwt2 = new MiniJWT('different-secret');
  const token = jwt.sign({ userId: 789 });
  console.log('Token:', token.substring(0, 50) + '...');

  try {
    jwt2.verify(token);  // Using different secret!
    console.log('Verification successful!');
  } catch (err) {
    console.log('Verification failed:', err.message);
    console.log('   (Expected - wrong secret key)');
  }

  console.log('\n' + '='.repeat(70));
  console.log('\nVerification examples complete!\n');
}, 100);
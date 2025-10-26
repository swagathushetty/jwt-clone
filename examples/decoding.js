const MiniJWT = require('../src/jwt');

const jwt = new MiniJWT('my-secret-key');

const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEyMywibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

console.log(token);
console.log('\n' + '='.repeat(60));

try {
  const decoded = jwt.decode(token)
  console.log('Full decoded token:');
  console.log(JSON.stringify(decoded, null, 2));

} catch (err) {
  console.error('Error:', err.message);
}

console.log('\n' + '='.repeat(60));

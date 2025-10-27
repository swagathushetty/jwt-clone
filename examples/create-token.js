const MiniJWT = require('../src/jwt');

const jwt = new MiniJWT('my-super-secret-key');

console.log('JWT Token Generation Examples\n');
console.log('='.repeat(70));

// Example 1: Simple token
console.log('\nExample 1: Simple Token');
const token1 = jwt.sign({ userId: 123, username: 'john_doe' });
console.log('\nToken:', token1);
console.log('\nDecoded:');
console.log(jwt.decode(token1).payload);

// Example 2: Token with expiration
console.log('\n' + '='.repeat(70));
console.log('\nExample 2: Token with 1 Hour Expiration');
const token2 = jwt.sign(
  { userId: 456, role: 'admin' },
  { expiresIn: '1h' }
);
console.log('\nToken:', token2);
console.log('\nDecoded:');
const decoded2 = jwt.decode(token2);
console.log('Payload:', decoded2.payload);
console.log('Expires:', new Date(decoded2.payload.exp * 1000));

// Example 3: Different expiration formats
console.log('\n' + '='.repeat(70));
console.log('\n Example 3: Different Expiration Formats');

const formats = ['30s', '5m', '2h', '7d'];
formats.forEach(format => {
  const token = jwt.sign({ userId: 789 }, { expiresIn: format });
  const decoded = jwt.decode(token);
  const expiresAt = new Date(decoded.payload.exp * 1000);
  console.log(`\n${format.padEnd(5)} → Expires: ${expiresAt.toLocaleString()}`);
});

// Example 4: Rich payload
console.log('\n' + '='.repeat(70));
console.log('\n Example 4: Rich Payload');
const token4 = jwt.sign({
  userId: 101,
  email: 'alice@example.com',
  role: 'admin',
  permissions: ['read', 'write', 'delete'],
  metadata: {
    loginTime: new Date().toISOString(),
    ipAddress: '192.168.1.1'
  }
}, { expiresIn: '24h' });

console.log('\nToken:', token4);
console.log('\nDecoded:');
console.log(JSON.stringify(jwt.decode(token4).payload, null, 2));

console.log('\n' + '='.repeat(70));
console.log('\n All tokens created successfully!\n');
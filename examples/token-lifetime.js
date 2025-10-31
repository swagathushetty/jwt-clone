// examples/02c-token-lifetime.js
const MiniJWT = require('../src/jwt');


const jwt = new MiniJWT('secret');

console.log('JWT Token Lifetime\n');
console.log('='.repeat(70));

// Create token with 30 second expiration
const token = jwt.sign({ userId: 123 }, { expiresIn: '1s' });
const decoded = jwt.decode(token);

console.log('Token created with 30 second expiration\n');
console.log('Issued at (iat):', new Date(decoded.payload.iat * 1000).toLocaleTimeString());
console.log('Expires at (exp):', new Date(decoded.payload.exp * 1000).toLocaleTimeString());
console.log('\nTime remaining:', decoded.payload.exp - decoded.payload.iat, 'seconds');

let i=1
while(i< 100000000000){
    i++
}
// Show timeline
const now = Math.floor(Date.now() / 1000);
const timeElapsed = now - decoded.payload.iat;
const timeRemaining = decoded.payload.exp - now;

console.log('\nTimeline:');
console.log('  Created: ' + new Date(decoded.payload.iat * 1000).toLocaleTimeString());
console.log('  Now:     ' + new Date(now * 1000).toLocaleTimeString() + ` (+${timeElapsed}s)`);
console.log('  Expires: ' + new Date(decoded.payload.exp * 1000).toLocaleTimeString() + ` (+${timeRemaining}s)`);

if (timeRemaining > 0) {
  console.log('\nToken is currently VALID');
  console.log(`   Time remaining: ${timeRemaining} seconds`);
} else {
  console.log('\nToken is EXPIRED');
  console.log(`   Expired ${Math.abs(timeRemaining)} seconds ago`);
}

console.log('\nTip: Tokens should have reasonable expiration times:');
console.log('   - Access tokens: 15m - 1h');
console.log('   - Refresh tokens: 7d - 30d');
console.log('   - API keys: No expiration or very long (1y+)\n');
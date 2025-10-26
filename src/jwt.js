const crypto = require('crypto');

class MiniJWT {
  constructor(secret) {
    if (!secret) {
      throw new Error('Secret key is required');
    }
    this.secret = secret;
  }

  base64UrlEncode(str) {
    const base64 = Buffer.from(str).toString('base64');

    // Make URL-safe
    return base64
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  base64UrlDecode(str) {
    let base64 = str
      .replace(/-/g, '+')
      .replace(/_/g, '/');

    while (base64.length % 4) {
      base64 += '=';
    }

    return Buffer.from(base64, 'base64').toString('utf8');
  }



  // Parse a JWT token (without verification)
  decode(token) {

    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    const header = JSON.parse(this.base64UrlDecode(headerB64));
    console.log('Header:', header);

    const payload = JSON.parse(this.base64UrlDecode(payloadB64));
    console.log('Payload:', payload);

    console.log('Signature:', signatureB64.substring(0, 20) + '...');

    return {
      header,
      payload,
      signature: signatureB64
    };
  }

  createSignature(headerB64, payloadB64) {
    const data = `${headerB64}.${payloadB64}`;

    const signature = crypto
      .createHmac('sha256', this.secret)  
      .update(data)
      .digest('base64');

      return signature
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
  }
}

module.exports = MiniJWT;
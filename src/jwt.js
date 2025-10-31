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

    const payload = JSON.parse(this.base64UrlDecode(payloadB64));

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

  parseExpiresIn(expiresIn) {
    if (typeof expiresIn === 'number') {
      return expiresIn;
    }

    // Parse strings like "1h", "30m", "7d"
    const regex = /^(\d+)([smhd])$/;
    const match = expiresIn.match(regex); //if in full no assuming its in seconds

    if (!match) {
      throw new Error('Invalid expiresIn format. Use: 30s, 5m, 2h, 7d');
    }

    const value = parseInt(match[1]);
    const unit = match[2];

    const multipliers = {
      s: 1,           // seconds
      m: 60,          // minutes
      h: 60 * 60,     // hours
      d: 60 * 60 * 24 // days
    };

    return value * multipliers[unit];
  }

  sign(payload, options = {}) {
    const header = {
      alg: 'HS256',
      typ: 'JWT'
    };

    const now = Math.floor(Date.now() / 1000);
    const claims = {
      ...payload,
      iat: now  // Issued At
    };

    if (options.expiresIn) {
      const expiresInSeconds = this.parseExpiresIn(options.expiresIn);
      claims.exp = now + expiresInSeconds;
    }

    const headerB64 = this.base64UrlEncode(JSON.stringify(header));
    const payloadB64 = this.base64UrlEncode(JSON.stringify(claims));

    const signature = this.createSignature(headerB64, payloadB64);

    const token = `${headerB64}.${payloadB64}.${signature}`;

    return token;
  }

  decode(token) {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    return {
      header: JSON.parse(this.base64UrlDecode(headerB64)),
      payload: JSON.parse(this.base64UrlDecode(payloadB64)),
      signature: signatureB64
    };
  }

  verify(token) {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    const [headerB64, payloadB64, providedSignature] = parts;

    // Step 2: Recalculate signature
    const expectedSignature = this.createSignature(headerB64, payloadB64);

    if (expectedSignature !== providedSignature) {
      throw new Error('Invalid signature');
    }

    const payload = JSON.parse(this.base64UrlDecode(payloadB64));

    if (payload.exp) {
      const now = Math.floor(Date.now() / 1000);

      if (now >= payload.exp) {
        throw new Error('Token expired');
      }
    }

    return payload;
  }

}

module.exports = MiniJWT;
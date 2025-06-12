#!/usr/bin/env node
/**
 * Node.js JWE Token Generation Example
 * 
 * This example shows how to generate a JWE token compatible with our system
 * using Node.js built-in crypto module. This is much simpler than the PHP approach since
 * Node.js has proper support for RSA-OAEP-256.
 * 
 * Requirements:
 * - Node.js 16+ (built-in crypto support for RSA-OAEP-256)
 * - RSA key pair files (same as used by the system)
 * 
 * Token Structure: JWE(JWS(payload))
 * - Inner: JWT signed with RS256
 * - Outer: JWE encrypted with RSA-OAEP-256 + A256GCM
 */

const crypto = require('crypto');
const fs = require('fs');

class NodeJWEGenerator {
    constructor(signingPrivateKeyPath, encryptionPublicKeyPath) {
        this.signingPrivateKey = fs.readFileSync(signingPrivateKeyPath, 'utf8');
        this.encryptionPublicKey = fs.readFileSync(encryptionPublicKeyPath, 'utf8');
    }
    
    /**
     * Generate a JWE token with the given payload
     */
    generateJWE(payload) {
        // Step 1: Create the inner JWT (JWS)
        const jws = this.createJWS(payload);
        
        // Step 2: Encrypt the JWS as JWE
        const jwe = this.createJWE(jws);
        
        return jwe;
    }
    
    /**
     * Create a JWT (JWS) signed with RS256
     */
    createJWS(payload) {
        // JWT Header for RS256
        const header = {
            alg: 'RS256',
            typ: 'JWT'
        };
        
        // Base64URL encode header and payload
        const headerEncoded = this.base64UrlEncode(JSON.stringify(header));
        const payloadEncoded = this.base64UrlEncode(JSON.stringify(payload));
        
        // Create signature base
        const signatureBase = `${headerEncoded}.${payloadEncoded}`;
        
        // Sign with RS256 (SHA256 + RSA PKCS1 v1.5 padding, not PSS!)
        const signature = crypto.sign('sha256', Buffer.from(signatureBase), {
            key: this.signingPrivateKey,
            padding: crypto.constants.RSA_PKCS1_PADDING  // Changed from PSS to PKCS1
        });
        
        const signatureEncoded = this.base64UrlEncode(signature);
        
        return `${signatureBase}.${signatureEncoded}`;
    }
    
    /**
     * Create a JWE token encrypted with RSA-OAEP-256 + A256GCM
     */
    createJWE(plaintext) {
        // JWE Header - cty indicates the content type being encrypted
        const header = {
            alg: 'RSA-OAEP-256',
            enc: 'A256GCM',
            cty: 'JWT'  // Critical: indicates content is a JWT
        };
        
        // Generate a random 256-bit Content Encryption Key (CEK)
        const cek = crypto.randomBytes(32); // 256 bits
        
        // Generate a random 96-bit IV for AES-GCM (12 bytes is standard)
        const iv = crypto.randomBytes(12); // 96 bits
        
        // Encrypt the CEK with RSA-OAEP-256 (this is the key difference from PHP!)
        const encryptedKey = crypto.publicEncrypt({
            key: this.encryptionPublicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'  // This is what PHP can't do!
        }, cek);
        
        // Base64URL encode the header
        const headerEncoded = this.base64UrlEncode(JSON.stringify(header));
        
        // Create Additional Authenticated Data (AAD)
        const aad = Buffer.from(headerEncoded, 'ascii');
        
        // Encrypt the plaintext with AES-256-GCM
        const cipher = crypto.createCipheriv('aes-256-gcm', cek, iv);
        cipher.setAAD(aad);
        
        let ciphertext = cipher.update(plaintext, 'utf8');
        ciphertext = Buffer.concat([ciphertext, cipher.final()]);
        const tag = cipher.getAuthTag();
        
        // Base64URL encode all components
        const encryptedKeyEncoded = this.base64UrlEncode(encryptedKey);
        const ivEncoded = this.base64UrlEncode(iv);
        const ciphertextEncoded = this.base64UrlEncode(ciphertext);
        const tagEncoded = this.base64UrlEncode(tag);
        
        // Return JWE in Compact Serialization format
        return `${headerEncoded}.${encryptedKeyEncoded}.${ivEncoded}.${ciphertextEncoded}.${tagEncoded}`;
    }
    
    /**
     * Base64URL encoding (RFC 7515)
     */
    base64UrlEncode(data) {
        if (typeof data === 'string') {
            data = Buffer.from(data, 'utf8');
        }
        return data.toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }
}

// Example usage
try {
    // Use the same keys as your system
    const generator = new NodeJWEGenerator(
        'jwt_signing_private.pem',
        'jwt_encryption_public.pem'
    );
    
    // Create payload - same structure as your system expects
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        iat: now,                    // Issued at
        nbf: now,                    // Not before
        exp: now + 3600,             // Expires in 1 hour
        iss: 'ISSUER',               // Issuer
        aud: 'AUDIENCE',             // Audience
        sub: 'AF8F35F0-8DC3-4488-8D9D-2B2A663AFDED',  // Subject (external ID)
    };
    
    console.log('Generating JWE token with payload:');
    console.log(JSON.stringify(payload, null, 2));
    console.log('');
    
    const jwe = generator.generateJWE(payload);
    
    console.log('Generated JWE Token:');
    console.log(jwe);
    console.log('');
    
    console.log('Test URL:');
    console.log(`https://your-endpoint.com/?jwe=${encodeURIComponent(jwe)}`);
    
} catch (error) {
    console.error('Error:', error.message);
}
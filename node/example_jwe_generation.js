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
const path = require('path');
require('dotenv').config();

// Simple .env file loader (since we're not using npm packages)
function loadEnv() {
    const envPath = path.join(__dirname, '..', '.env');
    if (fs.existsSync(envPath)) {
        const envContent = fs.readFileSync(envPath, 'utf8');
        envContent.split('\n').forEach(line => {
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith('#')) {
                const [key, ...valueParts] = trimmed.split('=');
                const value = valueParts.join('=');
                process.env[key.trim()] = value.trim();
            }
        });
    }
}

// Load environment variables
loadEnv();

class NodeJWEGenerator {
    constructor(signingPrivateKeyPath, encryptionPublicKeyPath, verificationPublicKeyPath = null, decryptionPrivateKeyPath = null) {
        this.signingPrivateKey = fs.readFileSync(signingPrivateKeyPath, 'utf8');
        this.encryptionPublicKey = fs.readFileSync(encryptionPublicKeyPath, 'utf8');

        // Optional keys for decryption/verification
        if (verificationPublicKeyPath && fs.existsSync(verificationPublicKeyPath)) {
            this.verificationPublicKey = fs.readFileSync(verificationPublicKeyPath, 'utf8');
        }
        if (decryptionPrivateKeyPath && fs.existsSync(decryptionPrivateKeyPath)) {
            this.decryptionPrivateKey = fs.readFileSync(decryptionPrivateKeyPath, 'utf8');
        }
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
     * Decrypt a JWE token and return the plaintext
     */
    decryptJWE(jweToken) {
        // Split JWE into its 5 parts
        const parts = jweToken.split('.');
        if (parts.length !== 5) {
            throw new Error('Invalid JWE format - expected 5 parts');
        }

        const [headerEncoded, encryptedKeyEncoded, ivEncoded, ciphertextEncoded, tagEncoded] = parts;

        // Decode header
        const header = JSON.parse(this.base64UrlDecode(headerEncoded).toString('utf8'));

        // Validate header
        if (header.alg !== 'RSA-OAEP-256' || header.enc !== 'A256GCM') {
            throw new Error(`Unsupported JWE algorithm: ${header.alg}/${header.enc}`);
        }

        // Decode components
        const encryptedKey = this.base64UrlDecode(encryptedKeyEncoded);
        const iv = this.base64UrlDecode(ivEncoded);
        const ciphertext = this.base64UrlDecode(ciphertextEncoded);
        const tag = this.base64UrlDecode(tagEncoded);

        // Decrypt the Content Encryption Key (CEK) with RSA-OAEP-256
        const cek = crypto.privateDecrypt({
            key: this.decryptionPrivateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        }, encryptedKey);

        // Create Additional Authenticated Data (AAD)
        const aad = Buffer.from(headerEncoded, 'ascii');

        // Decrypt the ciphertext with AES-256-GCM
        const decipher = crypto.createDecipheriv('aes-256-gcm', cek, iv);
        decipher.setAAD(aad);
        decipher.setAuthTag(tag);

        let plaintext = decipher.update(ciphertext);
        plaintext = Buffer.concat([plaintext, decipher.final()]);

        return plaintext.toString('utf8');
    }

    /**
     * Verify a JWS (JWT) signature and return the payload
     */
    verifyJWS(jwsToken) {
        // Split JWS into its 3 parts
        const parts = jwsToken.split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid JWS format - expected 3 parts');
        }

        const [headerEncoded, payloadEncoded, signatureEncoded] = parts;

        // Decode header
        const header = JSON.parse(this.base64UrlDecode(headerEncoded).toString('utf8'));

        // Validate header
        if (header.alg !== 'RS256' || header.typ !== 'JWT') {
            throw new Error(`Unsupported JWS algorithm: ${header.alg}/${header.typ}`);
        }

        // Decode payload
        const payload = JSON.parse(this.base64UrlDecode(payloadEncoded).toString('utf8'));

        // Verify signature
        const signatureBase = `${headerEncoded}.${payloadEncoded}`;
        const signature = this.base64UrlDecode(signatureEncoded);

        const isValid = crypto.verify('sha256', Buffer.from(signatureBase), {
            key: this.verificationPublicKey,
            padding: crypto.constants.RSA_PKCS1_PADDING
        }, signature);

        if (!isValid) {
            throw new Error('Invalid JWS signature');
        }

        // Check expiration if present
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < now) {
            throw new Error('JWT has expired');
        }

        // Check not before if present
        if (payload.nbf && payload.nbf > now) {
            throw new Error('JWT not yet valid');
        }

        return payload;
    }

    /**
     * Decrypt a JWE token and verify the inner JWS, returning the payload
     */
    decryptAndVerify(jweToken) {
        // Step 1: Decrypt the JWE to get the inner JWS
        const jwsToken = this.decryptJWE(jweToken);

        // Step 2: Verify the JWS and return the payload
        return this.verifyJWS(jwsToken);
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

    /**
     * Base64URL decoding (RFC 7515)
     */
    base64UrlDecode(data) {
        // Add padding if needed
        let padded = data;
        while (padded.length % 4) {
            padded += '=';
        }
        // Convert back to standard base64
        const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
        return Buffer.from(base64, 'base64');
    }
}

// Show usage if --help is passed
if (process.argv.includes('--help') || process.argv.includes('-h')) {
    console.log('\nUsage: node example_jwe_generation.js [subject | --decrypt <token>]');
    console.log('\nArguments:');
    console.log('  subject         The subject (sub) claim for the JWT. Default: AF8F35F0-8DC3-4488-8D9D-2B2A663AFDED');
    console.log('  --decrypt <token>   Decrypt and verify a JWE token');
    console.log('\nExamples:');
    console.log('  node example_jwe_generation.js 1234567890');
    console.log('  node example_jwe_generation.js --decrypt "eyJ..."');
    process.exit(0);
}

// Example usage
try {
    const args = process.argv.slice(2);

    // Check if we're decrypting a token
    if (args.includes('--decrypt')) {
        const decryptIndex = args.indexOf('--decrypt');
        const jweToken = args[decryptIndex + 1];

        if (!jweToken) {
            console.error('Error: --decrypt requires a JWE token argument');
            process.exit(1);
        }

        // Initialize generator with all keys for decryption
        const generator = new NodeJWEGenerator(
            'jwt_signing_private.pem',
            'jwt_encryption_public.pem',
            'jwt_signing_public.pem',      // For verification
            'jwt_encryption_private.pem'   // For decryption
        );

        console.log('Decrypting and verifying JWE token...');
        console.log('');

        const payload = generator.decryptAndVerify(jweToken);

        console.log('Decrypted payload:');
        console.log(JSON.stringify(payload, null, 2));
        console.log('');

        // Validate token timing
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp) {
            const expiresIn = payload.exp - now;
            if (expiresIn > 0) {
                console.log(`Token expires in: ${Math.floor(expiresIn / 60)} minutes`);
            } else {
                console.log('⚠️  Token has expired');
            }
        }

    } else {
        // Token generation mode
        const subject = args[0] || 'AF8F35F0-8DC3-4488-8D9D-2B2A663AFDED';

        if (args.length > 0) {
            console.log(`Using custom subject: ${subject}`);
            console.log('');
        }

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
            iss: process.env.JWT_ISSUER || 'ISSUER',               // Issuer
            aud: process.env.JWT_AUDIENCE || 'AUDIENCE',             // Audience
            sub: subject,                // Subject (external ID)
        };

        console.log('Generating JWE token with payload:');
        console.log(JSON.stringify(payload, null, 2));
        console.log('');

        const jwe = generator.generateJWE(payload);

        console.log('Generated JWE Token:');
        console.log(jwe);
        console.log('');

        // Use APP_URL from .env or fallback to example.com
        const appUrl = process.env.APP_URL || 'https://example.com';
        console.log('Test URL:');
        console.log(`${appUrl}/?jwe=${encodeURIComponent(jwe)}`);
    }

} catch (error) {
    console.error('Error:', error.message);
}
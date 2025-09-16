#!/usr/bin/env ts-node
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as zlib from 'zlib';
import * as dotenv from 'dotenv';

type Base64UrlString = string;

type JwtNumericDate = number;

interface JwtClaims {
  readonly iat: JwtNumericDate;
  readonly nbf: JwtNumericDate;
  readonly exp: JwtNumericDate;
  readonly iss: string;
  readonly aud: string;
  readonly sub: string;
  readonly [claim: string]: string | number | boolean | undefined;
}

interface JwsHeader {
  readonly alg: 'RS256';
  readonly typ: 'JWT';
}

interface JweProtectedHeader {
  readonly alg: 'RSA-OAEP-256';
  readonly enc: 'A256GCM';
  readonly cty: 'JWT';
  readonly zip: 'DEF';
}

interface KeyMaterialPaths {
  readonly signingPrivateKeyPath: string;
  readonly encryptionPublicKeyPath: string;
  readonly verificationPublicKeyPath?: string;
  readonly decryptionPrivateKeyPath?: string;
}

dotenv.config({ path: path.resolve(__dirname, '..', '.env') });

class TypeScriptJWEGenerator {
  private static readonly JWS_HEADER: JwsHeader = { alg: 'RS256', typ: 'JWT' };
  private static readonly JWE_PROTECTED_HEADER: JweProtectedHeader = {
    alg: 'RSA-OAEP-256',
    enc: 'A256GCM',
    cty: 'JWT',
    zip: 'DEF',
  };

  private readonly signingPrivateKey: string;
  private readonly encryptionPublicKey: string;
  private readonly verificationPublicKey?: string;
  private readonly decryptionPrivateKey?: string;

  constructor(paths: KeyMaterialPaths) {
    this.signingPrivateKey = fs.readFileSync(paths.signingPrivateKeyPath, 'utf8');
    this.encryptionPublicKey = fs.readFileSync(paths.encryptionPublicKeyPath, 'utf8');

    if (paths.verificationPublicKeyPath && fs.existsSync(paths.verificationPublicKeyPath)) {
      this.verificationPublicKey = fs.readFileSync(paths.verificationPublicKeyPath, 'utf8');
    }
    if (paths.decryptionPrivateKeyPath && fs.existsSync(paths.decryptionPrivateKeyPath)) {
      this.decryptionPrivateKey = fs.readFileSync(paths.decryptionPrivateKeyPath, 'utf8');
    }
  }

  generateJWE(payload: JwtClaims): string {
    const jws = this.createJWS(payload);
    return this.createJWE(jws);
  }

  decryptAndVerify(jweToken: string): JwtClaims {
    const jwsToken = this.decryptJWE(jweToken);
    return this.verifyJWS(jwsToken);
  }

  private createJWS(payload: JwtClaims): string {
    const headerEncoded = TypeScriptJWEGenerator.base64UrlEncode(
      JSON.stringify(TypeScriptJWEGenerator.JWS_HEADER),
    );
    const payloadEncoded = TypeScriptJWEGenerator.base64UrlEncode(JSON.stringify(payload));
    const signatureBase = `${headerEncoded}.${payloadEncoded}`;

    const signature = crypto.sign('sha256', Buffer.from(signatureBase, 'utf8'), {
      key: this.signingPrivateKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    });

    const signatureEncoded = TypeScriptJWEGenerator.base64UrlEncode(signature);
    return `${signatureBase}.${signatureEncoded}`;
  }

  private createJWE(jwsToken: string): string {
    const protectedHeader = TypeScriptJWEGenerator.JWE_PROTECTED_HEADER;
    const headerEncoded = TypeScriptJWEGenerator.base64UrlEncode(
      JSON.stringify(protectedHeader),
    );

    const cek = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);

    const encryptedKey = crypto.publicEncrypt(
      {
        key: this.encryptionPublicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      cek,
    );

    const aad = Buffer.from(headerEncoded, 'ascii');

    const compressedPayload = TypeScriptJWEGenerator.compressDeflate(Buffer.from(jwsToken, 'utf8'));

    const cipher = crypto.createCipheriv('aes-256-gcm', cek, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(compressedPayload), cipher.final()]);
    const tag = cipher.getAuthTag();

    const encryptedKeyEncoded = TypeScriptJWEGenerator.base64UrlEncode(encryptedKey);
    const ivEncoded = TypeScriptJWEGenerator.base64UrlEncode(iv);
    const ciphertextEncoded = TypeScriptJWEGenerator.base64UrlEncode(ciphertext);
    const tagEncoded = TypeScriptJWEGenerator.base64UrlEncode(tag);

    return `${headerEncoded}.${encryptedKeyEncoded}.${ivEncoded}.${ciphertextEncoded}.${tagEncoded}`;
  }

  private decryptJWE(jweToken: string): string {
    if (!this.decryptionPrivateKey) {
      throw new Error('Decrypting a JWE token requires the RSA decryption private key.');
    }

    const parts = jweToken.split('.');
    if (parts.length !== 5) {
      throw new Error('Invalid JWE compact serialization.');
    }

    const [headerEncoded, encryptedKeyEncoded, ivEncoded, ciphertextEncoded, tagEncoded] = parts;

    const headerJson = TypeScriptJWEGenerator.base64UrlDecode(headerEncoded).toString('utf8');
    const header: JweProtectedHeader = JSON.parse(headerJson);

    if (
      header.alg !== 'RSA-OAEP-256' ||
      header.enc !== 'A256GCM' ||
      header.cty !== 'JWT' ||
      header.zip !== 'DEF'
    ) {
      throw new Error('Unsupported JWE header parameters.');
    }

    const encryptedKey = TypeScriptJWEGenerator.base64UrlDecode(encryptedKeyEncoded);
    const iv = TypeScriptJWEGenerator.base64UrlDecode(ivEncoded);
    const ciphertext = TypeScriptJWEGenerator.base64UrlDecode(ciphertextEncoded);
    const tag = TypeScriptJWEGenerator.base64UrlDecode(tagEncoded);

    const cek = crypto.privateDecrypt(
      {
        key: this.decryptionPrivateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      encryptedKey,
    );

    const decipher = crypto.createDecipheriv('aes-256-gcm', cek, iv);
    decipher.setAAD(Buffer.from(headerEncoded, 'ascii'));
    decipher.setAuthTag(tag);

    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const decompressed = TypeScriptJWEGenerator.decompressDeflate(plaintext);

    return decompressed.toString('utf8');
  }

  private verifyJWS(jwsToken: string): JwtClaims {
    if (!this.verificationPublicKey) {
      throw new Error('Verifying a JWS token requires the RSA verification public key.');
    }

    const parts = jwsToken.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWS compact serialization.');
    }

    const [headerEncoded, payloadEncoded, signatureEncoded] = parts;

    const headerJson = TypeScriptJWEGenerator.base64UrlDecode(headerEncoded).toString('utf8');
    const header: JwsHeader = JSON.parse(headerJson);
    if (header.alg !== 'RS256' || header.typ !== 'JWT') {
      throw new Error('Unsupported JWS header parameters.');
    }

    const signatureBase = `${headerEncoded}.${payloadEncoded}`;
    const signature = TypeScriptJWEGenerator.base64UrlDecode(signatureEncoded);

    const isValid = crypto.verify('sha256', Buffer.from(signatureBase, 'utf8'), {
      key: this.verificationPublicKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    }, signature);

    if (!isValid) {
      throw new Error('Invalid JWS signature.');
    }

    const payloadJson = TypeScriptJWEGenerator.base64UrlDecode(payloadEncoded).toString('utf8');
    const payload: JwtClaims = JSON.parse(payloadJson);

    const now = Math.floor(Date.now() / 1000);
    const skewAllowanceSeconds = 60;
    if (typeof payload.exp === 'number' && payload.exp + skewAllowanceSeconds < now) {
      throw new Error('JWT has expired.');
    }
    if (typeof payload.nbf === 'number' && payload.nbf - skewAllowanceSeconds > now) {
      throw new Error('JWT not yet valid.');
    }

    return payload;
  }

  private static base64UrlEncode(data: Buffer | string): Base64UrlString {
    const buffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    return buffer
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
  }

  private static base64UrlDecode(data: Base64UrlString): Buffer {
    const padded = data.padEnd(data.length + ((4 - (data.length % 4)) % 4), '=');
    const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
    return Buffer.from(base64, 'base64');
  }

  private static compressDeflate(data: Buffer): Buffer {
    return zlib.deflateRawSync(data);
  }

  private static decompressDeflate(data: Buffer): Buffer {
    return zlib.inflateRawSync(data);
  }
}

const DEFAULT_SUBJECT = 'AF8F35F0-8DC3-4488-8D9D-2B2A663AFDED';

function resolveKey(relativePath: string): string {
  return path.resolve(__dirname, '..', relativePath);
}

function printHelp(): void {
  const scriptName = path.basename(__filename);
  console.log('\nUsage: npx ts-node example_jwe_generation.ts [subject | --decrypt <token>]');
  console.log('\nArguments:');
  console.log('  subject            The subject (sub) claim for the JWT.');
  console.log('  --decrypt <token>  Decrypt and verify a compact JWE token.');
  console.log('  --help             Show this help message.');
  console.log('\nExamples:');
  console.log(`  npx ts-node ${scriptName}`);
  console.log(`  npx ts-node ${scriptName} 1234567890`);
  console.log(`  npx ts-node ${scriptName} --decrypt "<JWE>"`);
}

function buildGenerator(forDecryption: boolean): TypeScriptJWEGenerator {
  const keyPaths: KeyMaterialPaths = {
    signingPrivateKeyPath: resolveKey('jwt_signing_private.pem'),
    encryptionPublicKeyPath: resolveKey('jwt_encryption_public.pem'),
    verificationPublicKeyPath: forDecryption ? resolveKey('jwt_signing_public.pem') : undefined,
    decryptionPrivateKeyPath: forDecryption ? resolveKey('jwt_encryption_private.pem') : undefined,
  };

  return new TypeScriptJWEGenerator(keyPaths);
}

function createPayload(subject: string): JwtClaims {
  const now = Math.floor(Date.now() / 1000);
  return {
    iat: now,
    nbf: now,
    exp: now + 3600,
    iss: process.env.JWT_ISSUER ?? 'ISSUER',
    aud: process.env.JWT_AUDIENCE ?? 'AUDIENCE',
    sub: subject,
  };
}

function main(): void {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    return;
  }

  if (args.includes('--decrypt')) {
    const index = args.indexOf('--decrypt');
    const token = args[index + 1];
    if (!token) {
      throw new Error('The --decrypt flag requires a JWE token parameter.');
    }

    const generator = buildGenerator(true);
    const payload = generator.decryptAndVerify(token);

    console.log('Decrypted payload:');
    console.log(JSON.stringify(payload, null, 2));
    return;
  }

  const subject = args[0] ?? DEFAULT_SUBJECT;
  if (args.length > 0) {
    console.log(`Using custom subject: ${subject}`);
  }

  const generator = buildGenerator(false);
  const payload = createPayload(subject);
  console.log('Generating JWE token with payload:');
  console.log(JSON.stringify(payload, null, 2));

  const jwe = generator.generateJWE(payload);
  console.log('\nGenerated JWE Token:');
  console.log(jwe);

  const appUrl = process.env.APP_URL ?? 'https://example.com';
  console.log('\nTest URL:');
  console.log(`${appUrl}/?jwe=${encodeURIComponent(jwe)}`);
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : 'Unknown error';
  console.error('Error:', message);
  process.exitCode = 1;
}

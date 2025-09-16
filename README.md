# JWE Token Generation Examples

This repository contains working examples of how to generate JWE (JSON Web Encryption) tokens compatible with our system, along with tools for analyzing and comparing tokens.

## Overview

The system expects **nested tokens** in this format:
```
JWE(JWS(payload))
```

Where:
- **Inner layer**: JWT signed with RS256
- **Outer layer**: JWE encrypted with RSA-OAEP-256 + A256GCM

## Quick Start

### Interactive Script (Recommended)

Use the interactive script for a guided experience:

```bash
./jwe.sh
```

This script provides:
- Automatic dependency checking (Node.js and .NET SDK)
- Interactive menu for language selection
- JWE token generation in both Node.js and C#
- Custom subject (external ID) input for token generation
- Token analysis and comparison tools (C# only)
- Support for custom token file comparisons

### Manual Usage

#### C# (.NET)
```bash
# Generate JWE token with default subject
cd csharp/JWEGenerator
dotnet run

# Generate JWE token with custom subject
dotnet run -- 1234567890

# Show help
dotnet run -- --help

# Analyze and compare tokens
cd csharp/JWETokenAnalyzer
dotnet run  # Uses default token_a.txt and token_b.txt files
```

#### Node.js
```bash
cd node

# Generate JWE token with default subject
node example_jwe_generation.js

# Generate JWE token with custom subject
node example_jwe_generation.js 1234567890

# Show help
node example_jwe_generation.js --help
```

#### TypeScript
```bash
cd ts

# Install dependencies (first run only)
npm install

# Generate JWE token with default subject
npx ts-node example_jwe_generation.ts

# Generate JWE token with custom subject
npx ts-node example_jwe_generation.ts 1234567890

# Decrypt and verify an existing token
npx ts-node example_jwe_generation.ts --decrypt "<JWE token>"

# Compile to JavaScript
npm run build

# Show help
npx ts-node example_jwe_generation.ts --help
```

## Configuration

### Environment Variables

Create a `.env` file in the root directory to configure the application:

```bash
# Copy the example file
cp .env.example .env

# Edit .env to set your configuration
```

Available environment variables:

- `APP_URL`: The URL endpoint for testing JWE tokens (defaults to `https://example.com`)
- `JWT_ISSUER`: The issuer claim for JWT tokens (defaults to `ISSUER`)
- `JWT_AUDIENCE`: The audience claim for JWT tokens (defaults to `AUDIENCE`)

### Example .env

```env
# JWE Token Examples Configuration

# The URL endpoint for testing JWE tokens
# Leave empty to use default fallback (https://example.com)
APP_URL=http://ls-cde-card-linking-app-sdk-cde.localhost/iframe

# JWT Claims Configuration
# Issuer - who issued the token
JWT_ISSUER=ISSUER

# Audience - who the token is intended for
JWT_AUDIENCE=AUDIENCE
```

## Project Structure

```
jwe-token-examples/
├── .env.example          # Example environment configuration
├── .env                  # Your local configuration (git ignored)
├── jwe.sh               # Interactive script for all operations
├── csharp/              # C# implementations
│   ├── JWETokenExamples.sln
│   ├── JWEGenerator/    # Token generation
│   └── JWETokenAnalyzer/ # Token analysis and comparison
├── node/                # Node.js implementation
│   └── example_jwe_generation.js
└── ts/                  # TypeScript implementation
    ├── example_jwe_generation.ts
    ├── package.json
    ├── package-lock.json
    └── tsconfig.json
```

## Examples Included

### ✅ C# (.NET) - **RECOMMENDED**
- **Generator**: `csharp/JWEGenerator/JWEGenerator.cs`
- **Analyzer**: `csharp/JWETokenAnalyzer/JWETokenAnalyzer.cs`
- Features:
  - JWE token generation
  - Token analysis and comparison
  - Detailed component breakdown
  - Character-level diff analysis

### ✅ Node.js - **WORKS**
- **File**: `node/example_jwe_generation.js`
- Features:
  - JWE token generation
  - Simple and straightforward implementation

### ✅ TypeScript - **WORKS**
- **File**: `ts/example_jwe_generation.ts`
- Features:
  - Strongly typed JWE/JWS implementation mirroring production flow
  - Supports both generation and decrypt/verify paths
  - One-to-one parity with the Node.js command-line interface

### ❌ PHP - **LIMITATION**
- PHP's OpenSSL extension doesn't support RSA-OAEP-256 (only RSA-OAEP with SHA-1)
- Would require a proper JOSE library like `web-token/jwt-library`
## Requirements

### System Requirements

For the interactive script (`jwe.sh`):
- macOS with Homebrew installed
- The script will check and offer to install missing dependencies

### Manual Requirements

#### For All Examples
- RSA key pair for signing (RS256)
- RSA key pair for encryption (RSA-OAEP-256)
- Keys should be in PEM format

#### Generating Required Keys

You need to create 4 key files using OpenSSL. These commands will generate two key pairs - one for signing JWTs and one for encrypting JWE tokens.

**Step 1: Generate JWT Signing Keys**
```bash
# Create private key for signing JWTs (keep this secret!)
openssl genrsa -out jwt_signing_private.pem 2048

# Extract public key for verifying JWTs (this can be shared)
openssl rsa -in jwt_signing_private.pem -pubout -out jwt_signing_public.pem
```

**Step 2: Generate JWE Encryption Keys**
```bash
# Create private key for decrypting JWE tokens (keep this secret!)
openssl genrsa -out jwt_encryption_private.pem 2048

# Extract public key for encrypting JWE tokens (this can be shared)
openssl rsa -in jwt_encryption_private.pem -pubout -out jwt_encryption_public.pem
```

**Step 3: Place Keys in Correct Directories**
```bash
# For Node.js examples - copy all 4 files to node directory
cp jwt_*.pem node/

# For C# examples - copy all 4 files to csharp directories
cp jwt_*.pem csharp/JWEGenerator/
cp jwt_*.pem csharp/JWETokenAnalyzer/
```

**Step 4: Verify Key Generation**
```bash
# Verify the keys were generated correctly
ls -la jwt_*.pem
# Should show 4 files:
# jwt_signing_private.pem (1700+ bytes)
# jwt_signing_public.pem (~450 bytes)
# jwt_encryption_private.pem (1700+ bytes)
# jwt_encryption_public.pem (~450 bytes)

# Test that public keys were derived from private keys correctly
openssl rsa -in jwt_signing_private.pem -pubout -noout -text | head -n2
openssl rsa -in jwt_encryption_private.pem -pubout -noout -text | head -n2
```

**Key Summary:**
- `jwt_signing_private.pem` - Signs JWTs with RS256 (keep secret)
- `jwt_signing_public.pem` - Verifies JWT signatures (can be public)
- `jwt_encryption_private.pem` - Decrypts JWE tokens with RSA-OAEP-256 (keep secret)
- `jwt_encryption_public.pem` - Encrypts JWE tokens with RSA-OAEP-256 (can be public)

### Key Usage in Code

Understanding exactly how each key is used in the code helps clarify the dual key-pair architecture:

#### Token Generation Flow (Encoding)
1. **JWT Signing** - Creates the inner signed token
2. **JWE Encryption** - Encrypts the JWT into a JWE token

#### Token Decryption Flow (Decoding)
1. **JWE Decryption** - Decrypts the outer JWE to reveal the inner JWT
2. **JWT Verification** - Verifies the JWT signature and extracts payload

#### Constructor Usage
```javascript
// For token generation only
const generator = new NodeJWEGenerator(
    'jwt_signing_private.pem',      // Signs JWTs
    'jwt_encryption_public.pem'     // Encrypts JWE
);

// For full encode/decode functionality
const generator = new NodeJWEGenerator(
    'jwt_signing_private.pem',      // Signs JWTs
    'jwt_encryption_public.pem',    // Encrypts JWE
    'jwt_signing_public.pem',       // Verifies JWTs
    'jwt_encryption_private.pem'    // Decrypts JWE
);
```

#### Key Usage Examples

**1. JWT Signing (node/example_jwe_generation.js:86-88)**
```javascript
// Sign with RS256 (SHA256 + RSA PKCS1 v1.5 padding)
const signature = crypto.sign('sha256', Buffer.from(signatureBase), {
    key: this.signingPrivateKey,        // jwt_signing_private.pem
    padding: crypto.constants.RSA_PKCS1_PADDING
});
```

**2. JWE Encryption (node/example_jwe_generation.js:114-117)**
```javascript
// Encrypt the CEK with RSA-OAEP-256
const encryptedKey = crypto.publicEncrypt({
    key: this.encryptionPublicKey,      // jwt_encryption_public.pem
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
}, cek);
```

**3. JWE Decryption (node/example_jwe_generation.js:171-174)**
```javascript
// Decrypt the Content Encryption Key (CEK) with RSA-OAEP-256
const cek = crypto.privateDecrypt({
    key: this.decryptionPrivateKey,     // jwt_encryption_private.pem
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
}, encryptedKey);
```

**4. JWT Verification (node/example_jwe_generation.js:218-220)**
```javascript
// Verify JWT signature
const isValid = crypto.verify('sha256', Buffer.from(signatureBase), {
    key: this.verificationPublicKey,    // jwt_signing_public.pem
    padding: crypto.constants.RSA_PKCS1_PADDING
}, signature);
```

#### Visual Flow Diagram
```
TOKEN GENERATION:
[Payload]
    ↓ Sign with jwt_signing_private.pem (RS256)
[Signed JWT]
    ↓ Encrypt with jwt_encryption_public.pem (RSA-OAEP-256 + A256GCM)
[JWE Token]

TOKEN DECRYPTION:
[JWE Token]
    ↓ Decrypt with jwt_encryption_private.pem (RSA-OAEP-256 + A256GCM)
[Signed JWT]
    ↓ Verify with jwt_signing_public.pem (RS256)
[Payload]
```

#### Why Two Key Pairs?

**Separation of Concerns:**
- **Signing Keys** - Prove authenticity (who created the token)
- **Encryption Keys** - Ensure confidentiality (only intended recipients can read it)

**Security Benefits:**
- Different keys can have different lifecycles
- Signing keys can be rotated independently of encryption keys
- Supports scenarios where different entities handle signing vs encryption

#### C# Requirements
- .NET 5.0 or later (install via `brew install dotnet-sdk`)
- No external packages needed

#### Node.js Requirements  
- Node.js 16+ (install via `brew install node`)
- No external packages needed

## Key Technical Details

### Required Headers

**JWT Header (inner token):**
```json
{
  "alg": "RS256",
  "typ": "JWT"
}
```

**JWE Header (outer token):**
```json
{
  "alg": "RSA-OAEP-256",
  "enc": "A256GCM", 
  "cty": "JWT"
}
```

### Payload Structure
```json
{
  "iat": 1640995200,           // Issued at (Unix timestamp)
  "nbf": 1640995200,           // Not before (Unix timestamp)  
  "exp": 1640998800,           // Expires at (Unix timestamp)
  "iss": "LS",                // Issuer
  "aud": "Audience",           // Audience
  "sub": "USER_EXTERNAL_ID"    // Subject (user's external ID)
}
```

## Usage

### Basic Usage

1. **Configure endpoint** (optional):
   ```bash
   cp .env.example .env
   # Edit .env to set your APP_URL
   ```

2. **Run the interactive script**:
   ```bash
   ./jwe.sh
   ```

3. **Generate tokens** using the menu options

4. **Use generated tokens** - they will be displayed with the configured URL:
   ```
   http://your-endpoint.com/?jwe={generated_token}
   ```

### Advanced Usage

For custom implementations:

1. **Update key paths** in the code to point to your RSA key files
2. **Set the subject** (`sub`) to your user's external ID
3. **Configure custom payload** fields as needed
4. **Generate token** using either C# or Node.js example

## Why These Examples Work

Both C# and Node.js have proper built-in support for:
- **RSA-OAEP-256** encryption (critical requirement)
- **AES-256-GCM** content encryption
- **RS256** JWT signing
- **Base64URL** encoding

This eliminates the need for complex external cryptographic libraries while ensuring full compatibility with our system.

## Testing

### Token Generation Testing

Both examples generate tokens that have been verified to work with our system. Generated tokens include a test URL with your configured endpoint.

### Token Analysis

The C# Token Analyzer can help debug and compare tokens:

```bash
cd csharp/JWETokenAnalyzer

# Analyze default example tokens
dotnet run

# Analyze your own tokens
dotnet run -- "your-token-1" "your-token-2"
```

The analyzer provides:
- Component breakdown (header, key, IV, ciphertext, tag)
- Base64URL validation
- Character-level differences between tokens
- Decoded header comparison
- Token statistics and analysis

## Troubleshooting

### Common Key-Related Issues

#### 1. "Key file not found" errors
**Problem**: Missing key files in the expected directories
**Solution**:
```bash
# Check if keys exist in the right location
ls -la node/jwt_*.pem
ls -la csharp/JWEGenerator/jwt_*.pem

# If missing, copy from root directory
cp jwt_*.pem node/
cp jwt_*.pem csharp/JWEGenerator/
cp jwt_*.pem csharp/JWETokenAnalyzer/
```

#### 2. "RSA OAEP decoding error"
**Problem**: Trying to decrypt with mismatched keys
**Cause**: The encryption public key doesn't match the decryption private key
**Solution**:
```bash
# Regenerate matching key pair
openssl genrsa -out jwt_encryption_private.pem 2048
openssl rsa -in jwt_encryption_private.pem -pubout -out jwt_encryption_public.pem

# Copy to directories and regenerate tokens
cp jwt_*.pem node/
```

#### 3. "Invalid JWS signature" errors
**Problem**: JWT verification fails
**Cause**: The signing private key doesn't match the verification public key
**Solution**:
```bash
# Regenerate matching key pair
openssl genrsa -out jwt_signing_private.pem 2048
openssl rsa -in jwt_signing_private.pem -pubout -out jwt_signing_public.pem

# Copy to directories
cp jwt_*.pem node/
```

#### 4. Verify Key Pairs Match
**Check that your key pairs are correctly matched**:
```bash
# For signing keys - these should produce identical output
openssl rsa -in jwt_signing_private.pem -pubout | openssl sha256
openssl rsa -pubin -in jwt_signing_public.pem -pubout | openssl sha256

# For encryption keys - these should produce identical output
openssl rsa -in jwt_encryption_private.pem -pubout | openssl sha256
openssl rsa -pubin -in jwt_encryption_public.pem -pubout | openssl sha256
```

#### 5. File Permission Issues
**Problem**: "Permission denied" when reading key files
**Solution**:
```bash
# Set appropriate permissions
chmod 600 jwt_*_private.pem  # Private keys - owner read/write only
chmod 644 jwt_*_public.pem   # Public keys - owner read/write, others read
```

### General Troubleshooting

1. **Missing dependencies**: Run `./jwe.sh` which will check and offer to install them
2. **Key file errors**: See key-related issues above
3. **.env not loading**: Check file exists in root directory and has proper format
4. **Token validation errors**: Use the C# analyzer to debug token structure
5. **Interactive script issues**: Ensure all 4 key files exist in the node/ directory before running `./jwe.sh`

### Testing Your Setup

**Generate and immediately decrypt a token to verify everything works**:
```bash
cd node

# Generate a test token
TOKEN=$(node example_jwe_generation.js test-user | grep "Generated JWE Token:" -A1 | tail -n1)

# Decrypt the same token
node example_jwe_generation.js --decrypt "$TOKEN"

# Should show the original payload with subject "test-user"
```

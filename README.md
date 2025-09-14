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

## Configuration

### Environment Variables

Create a `.env` file in the root directory to configure the endpoint URL:

```bash
# Copy the example file
cp .env.example .env

# Edit .env to set your endpoint
APP_URL=https://your-endpoint.com
```

If `APP_URL` is not set or is empty, the system will fall back to `https://example.com`.

### Example .env

```env
# JWE Token Examples Configuration

# The URL endpoint for testing JWE tokens
# Leave empty to use default fallback (https://example.com)
APP_URL=http://ls-cde-card-linking-app-sdk-cde.localhost/iframe
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
└── node/                # Node.js implementation
    └── example_jwe_generation.js
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

You need to create 4 key files using OpenSSL. These commands will generate two key pairs - one for signing JWTs and one for encrypting JWE tokens:

**For JWT signing:**
```bash
# Create private key for signing JWTs (keep this secret!)
openssl genrsa -out jwt_signing_private.pem 2048

# Extract public key for verifying JWTs (this can be shared)
openssl rsa -in jwt_signing_private.pem -pubout -out jwt_signing_public.pem
```

**For JWE encryption:**
```bash
# Create private key for decrypting JWE tokens (keep this secret!)
openssl genrsa -out jwt_encryption_private.pem 2048

# Extract public key for encrypting JWE tokens (this can be shared)
openssl rsa -in jwt_encryption_private.pem -pubout -out jwt_encryption_public.pem
```

After running these commands, you'll have:
- `jwt_signing_private.pem` - Used to sign JWTs (keep secret)
- `jwt_signing_public.pem` - Used to verify JWTs (can be public)
- `jwt_encryption_private.pem` - Used to decrypt JWE tokens (keep secret)
- `jwt_encryption_public.pem` - Used to encrypt JWE tokens (can be public)

The code examples use `jwt_signing_private.pem` and `jwt_encryption_public.pem` to create tokens.

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

1. **Missing dependencies**: Run `./jwe.sh` which will check and offer to install them
2. **Key file errors**: Ensure PEM files are in the correct directories
3. **.env not loading**: Check file exists in root directory and has proper format
4. **Token validation errors**: Use the C# analyzer to debug token structure

# JWE Token Generation Examples

This repository contains working examples of how to generate JWE (JSON Web Encryption) tokens compatible with our system.

## Overview

The system expects **nested tokens** in this format:
```
JWE(JWS(payload))
```

Where:
- **Inner layer**: JWT signed with RS256
- **Outer layer**: JWE encrypted with RSA-OAEP-256 + A256GCM

## Examples Included

### ✅ C# (.NET) - **RECOMMENDED**
- **File**: `JWEGenerator.cs`

**Run C# example:**
```bash
dotnet run
```

### ✅ Node.js - **WORKS**
- **File**: `example_jwe_generation.js`

**Run Node.js example:**
```bash
node example_jwe_generation.js
```

### ❌ PHP - **LIMITATION**
- PHP's OpenSSL extension doesn't support RSA-OAEP-256 (only RSA-OAEP with SHA-1)
- Would require a proper JOSE library like `web-token/jwt-library`
## Requirements

### For Both Examples
- RSA key pair for signing (RS256)
- RSA key pair for encryption (RSA-OAEP-256)
- Keys should be in PEM format

### C# Requirements
- .NET 5.0 or later
- No external packages needed

### Node.js Requirements  
- Node.js 16+ 
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
  "iss": "FBF",                // Issuer
  "aud": "Audience",           // Audience
  "sub": "USER_EXTERNAL_ID"    // Subject (user's external ID)
}
```

## Usage

1. **Update key paths** in the code to point to your RSA key files
2. **Set the subject** (`sub`) to your user's external ID
3. **Generate token** using either C# or Node.js example
4. **Use token** by appending to the URL:
   ```
   https://endpoint.localhost/?jwe={generated_token}
   ```

## Why These Examples Work

Both C# and Node.js have proper built-in support for:
- **RSA-OAEP-256** encryption (critical requirement)
- **AES-256-GCM** content encryption
- **RS256** JWT signing
- **Base64URL** encoding

This eliminates the need for complex external cryptographic libraries while ensuring full compatibility with our system.

## Testing

Both examples generate tokens that have been verified to work with our system. You can test them by appending the generated JWE token to the URL we provided.

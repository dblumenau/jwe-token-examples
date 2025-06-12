# C# JWE Token Generation

This document provides a complete C#/.NET example for generating JWE tokens compatible with our system, specifically designed for .NET-based technology stacks.

## Why C#/.NET is Perfect for This

C#/.NET has excellent built-in cryptographic support that makes JWE token generation straightforward:

- **Built-in RSA-OAEP-256 support** via `RSAEncryptionPadding.OaepSHA256`
- **Native AES-GCM encryption** via the `AesGcm` class (.NET 5+)
- **PEM key import** via `RSA.ImportFromPem()` 
- **No external dependencies** - uses only standard library
- **Perfect fit** for Umbraco, Sitecore, and Optimizely implementations

## Requirements

- **.NET 5.0 or later** (for `AesGcm` class support)
- **RSA key pair files** in PEM format

## Token Structure

The system expects **nested tokens**:
```
JWE(JWS(payload))
```

Where:
- **Inner layer**: JWT signed with RS256
- **Outer layer**: JWE encrypted with RSA-OAEP-256 + A256GCM

## Implementation

### 1. Required Headers

**JWT Header** (inner):
```json
{
  "alg": "RS256",
  "typ": "JWT"
}
```

**JWE Header** (outer):
```json
{
  "alg": "RSA-OAEP-256",
  "enc": "A256GCM",
  "cty": "JWT"
}
```

### 2. Payload Structure

```json
{
  "iat": 1640995200,           // Issued at (Unix timestamp)
  "nbf": 1640995200,           // Not before (Unix timestamp)  
  "exp": 1640998800,           // Expires at (Unix timestamp)
  "iss": "ISSUER",             // Issuer (must match system config)
  "aud": "AUDIENCE",           // Audience (must match system config)
  "sub": "USER_EXTERNAL_ID"    // Subject (your user's external ID)
}
```

### 3. Key C# Classes Used

- **`RSA`**: For key loading and RSA operations
- **`AesGcm`**: For AES-256-GCM encryption (.NET 5+)
- **`RSAEncryptionPadding.OaepSHA256`**: For proper RSA-OAEP-256 padding
- **`RSASignaturePadding.Pkcs1`**: For RS256 JWT signatures
- **`RandomNumberGenerator`**: For cryptographically secure random generation

## Usage Example

```csharp
// Initialize with your RSA key files
using var generator = new JWEGenerator(
    "path/to/signing_private_key.pem",
    "path/to/encryption_public_key.pem"
);

// Create payload
var payload = new
{
    iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
    nbf = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
    exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600,
    iss = "ISSUER",
    aud = "AUDIENCE",
    sub = "your-user-external-id"
};

// Generate token
var jweToken = generator.GenerateJWE(payload);

// Use token
var url = $"https://your-endpoint.com/?jwe={Uri.EscapeDataString(jweToken)}";
```

## Integration with Umbraco/Sitecore/Optimizely

### Umbraco Integration
```csharp
public class CardLinkingService : ICardLinkingService
{
    private readonly JWEGenerator _jweGenerator;
    
    public CardLinkingService(IOptions<JWEConfig> config)
    {
        _jweGenerator = new JWEGenerator(
            config.Value.SigningKeyPath,
            config.Value.EncryptionKeyPath
        );
    }
    
    public string GenerateCardLinkingUrl(string userExternalId)
    {
        var payload = new
        {
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            nbf = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600,
            iss = "ISSUER",
            aud = "AUDIENCE",
            sub = userExternalId
        };
        
        var token = _jweGenerator.GenerateJWE(payload);
        return $"https://your-endpoint.com/?jwe={Uri.EscapeDataString(token)}";
    }
}
```

### Dependency Injection Setup
```csharp
// In Startup.cs or Program.cs
services.Configure<JWEConfig>(configuration.GetSection("JWE"));
services.AddScoped<ICardLinkingService, CardLinkingService>();
```

### Configuration
```json
{
  "JWE": {
    "SigningKeyPath": "/path/to/jwt_signing_private.pem",
    "EncryptionKeyPath": "/path/to/jwt_encryption_public.pem"
  }
}
```

## Security Considerations

- **Key Management**: Store private keys securely (Azure Key Vault, etc.)
- **Token Expiry**: Use short expiration times (1 hour recommended)
- **Transport Security**: Always use HTTPS
- **Key Rotation**: Plan for regular key rotation
- **Validation**: System validates all timestamps strictly

## Error Handling

```csharp
try
{
    var token = generator.GenerateJWE(payload);
    return token;
}
catch (CryptographicException ex)
{
    // Handle cryptographic errors (invalid keys, etc.)
    _logger.LogError(ex, "Failed to generate JWE token");
    throw;
}
catch (Exception ex)
{
    // Handle other errors
    _logger.LogError(ex, "Unexpected error generating JWE token");
    throw;
}
```

## Testing

The generated tokens can be tested by sending them to:
```
https://your-endpoint.com/?jwe={token}
```

The system will validate the token and either:
- **Success**: Display the form
- **Error**: Show an error page with details

## Advantages for .NET Developers

1. **Native .NET Integration**: Works seamlessly with existing Umbraco/Sitecore/Optimizely projects
2. **No External Dependencies**: Uses only .NET standard library
3. **Type Safety**: Full IntelliSense and compile-time checking
4. **Performance**: Excellent performance with built-in crypto
5. **Familiar Patterns**: Standard .NET dependency injection and configuration
6. **Security**: Leverages Microsoft's well-tested cryptographic implementations
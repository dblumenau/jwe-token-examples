using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO;

/// <summary>
/// C# JWE Token Generation Example
///
/// This example shows how to generate a JWE token compatible with our system
/// using C#/.NET built-in cryptographic libraries. This is ideal for .NET-based applications
/// and requires no external dependencies beyond the standard library.
///
/// Requirements:
/// - .NET Core 3.1+ or .NET 5+ (for AES-GCM support)
/// - RSA key pair files (same format as used by the system)
///
/// Token Structure: JWE(JWS(payload))
/// - Inner: JWT signed with RS256
/// - Outer: JWE encrypted with RSA-OAEP-256 + A256GCM
/// </summary>
public class JWEGenerator : IDisposable
{
    private readonly RSA _signingPrivateKey;
    private readonly RSA _encryptionPublicKey;

    public JWEGenerator(string signingPrivateKeyPath, string encryptionPublicKeyPath)
    {
        // Load RSA keys from PEM files
        var signingKeyPem = File.ReadAllText(signingPrivateKeyPath);
        var encryptionKeyPem = File.ReadAllText(encryptionPublicKeyPath);

        _signingPrivateKey = RSA.Create();
        _signingPrivateKey.ImportFromPem(signingKeyPem);

        _encryptionPublicKey = RSA.Create();
        _encryptionPublicKey.ImportFromPem(encryptionKeyPem);
    }

    /// <summary>
    /// Generate a JWE token with the given payload
    /// </summary>
    public string GenerateJWE(object payload)
    {
        // Step 1: Create the inner JWT (JWS)
        var jws = CreateJWS(payload);

        // Step 2: Encrypt the JWS as JWE
        var jwe = CreateJWE(jws);

        return jwe;
    }

    /// <summary>
    /// Create a JWT (JWS) signed with RS256
    /// </summary>
    private string CreateJWS(object payload)
    {
        // JWT Header for RS256
        var header = new
        {
            alg = "RS256",
            typ = "JWT"
        };

        // Serialize and Base64URL encode header and payload
        var headerJson = JsonSerializer.Serialize(header);
        var payloadJson = JsonSerializer.Serialize(payload);

        var headerEncoded = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadEncoded = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));

        // Create signature base
        var signatureBase = $"{headerEncoded}.{payloadEncoded}";
        var signatureBaseBytes = Encoding.UTF8.GetBytes(signatureBase);

        // Sign with RS256 (SHA256 + RSA PKCS1 v1.5 padding)
        var signature = _signingPrivateKey.SignData(signatureBaseBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var signatureEncoded = Base64UrlEncode(signature);

        return $"{signatureBase}.{signatureEncoded}";
    }

    /// <summary>
    /// Create a JWE token encrypted with RSA-OAEP-256 + A256GCM
    /// </summary>
    private string CreateJWE(string plaintext)
    {
        // JWE Header - cty indicates the content type being encrypted
        var header = new
        {
            alg = "RSA-OAEP-256",
            enc = "A256GCM",
            cty = "JWT"  // Critical: indicates content is a JWT
        };

        // Generate a random 256-bit Content Encryption Key (CEK)
        var cek = new byte[32]; // 256 bits
        RandomNumberGenerator.Fill(cek);

        // Generate a random 96-bit IV for AES-GCM (12 bytes is standard)
        var iv = new byte[12]; // 96 bits
        RandomNumberGenerator.Fill(iv);

        // Encrypt the CEK with RSA-OAEP-256
        var encryptedKey = _encryptionPublicKey.Encrypt(cek, RSAEncryptionPadding.OaepSHA256);

        // Serialize and Base64URL encode the header
        var headerJson = JsonSerializer.Serialize(header);
        var headerEncoded = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));

        // Create Additional Authenticated Data (AAD)
        var aad = Encoding.ASCII.GetBytes(headerEncoded);

        // Encrypt the plaintext with AES-256-GCM
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[16]; // AES-GCM auth tag is 16 bytes

        using (var aesGcm = new AesGcm(cek, 16)) // 16-byte tag size
        {
            aesGcm.Encrypt(iv, plaintextBytes, ciphertext, tag, aad);
        }

        // Base64URL encode all components
        var encryptedKeyEncoded = Base64UrlEncode(encryptedKey);
        var ivEncoded = Base64UrlEncode(iv);
        var ciphertextEncoded = Base64UrlEncode(ciphertext);
        var tagEncoded = Base64UrlEncode(tag);

        // Return JWE in Compact Serialization format
        return $"{headerEncoded}.{encryptedKeyEncoded}.{ivEncoded}.{ciphertextEncoded}.{tagEncoded}";
    }

    /// <summary>
    /// Base64URL encoding (RFC 7515)
    /// </summary>
    private static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public void Dispose()
    {
        _signingPrivateKey?.Dispose();
        _encryptionPublicKey?.Dispose();
    }
}

/// <summary>
/// Example usage and demonstration
/// </summary>
public class Program
{
    public static void Main(string[] args)
    {
        try
        {
            // Use the same keys as your system
            using var generator = new JWEGenerator(
                "jwt_signing_private.pem",
                "jwt_encryption_public.pem"
            );

            // Create payload - same structure as your system expects
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var payload = new
            {
                iat = now,                    // Issued at
                nbf = now,                    // Not before
                exp = now + 3600,             // Expires in 1 hour
                iss = "ISSUER",               // Issuer
                aud = "AUDIENCE",             // Audience
                sub = "AF8F35F0-8DC3-4488-8D9D-2B2A663AFDED"  // Subject (external ID)
            };

            Console.WriteLine("Generating JWE token with payload:");
            Console.WriteLine(JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine();

            var jwe = generator.GenerateJWE(payload);

            Console.WriteLine("Generated JWE Token:");
            Console.WriteLine(jwe);
            Console.WriteLine();

            Console.WriteLine("Test URL:");
            Console.WriteLine($"https://your-endpoint.com/?jwe={Uri.EscapeDataString(jwe)}");

        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            Console.WriteLine($"Stack trace: {ex.StackTrace}");
        }
    }
}

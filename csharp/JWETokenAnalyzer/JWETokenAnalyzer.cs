using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

class JWETokenAnalyzer
{
    static void Main(string[] args)
    {
        Console.WriteLine("=== JWE Token Analyzer - Extended Analysis ===\n");

        string tokenA = null;
        string tokenB = null;

        // Check if tokens are provided as command line arguments first
        if (args.Length >= 2)
        {
            Console.WriteLine("Using tokens from command line arguments...");
            tokenA = args[0];
            tokenB = args[1];
        }
        else
        {
            // Try to load tokens from files
            string tokenAPath = "token_a.txt";
            string tokenBPath = "token_b.txt";
            
            if (!File.Exists(tokenAPath))
            {
                Console.WriteLine($"❌ Error: Required file not found: {tokenAPath}");
                Console.WriteLine("\nUsage:");
                Console.WriteLine("  1. Create 'token_a.txt' and 'token_b.txt' in the current directory");
                Console.WriteLine("  2. Or pass two tokens as command line arguments: dotnet run <token_a> <token_b>");
                Environment.Exit(1);
            }
            
            if (!File.Exists(tokenBPath))
            {
                Console.WriteLine($"❌ Error: Required file not found: {tokenBPath}");
                Console.WriteLine("\nUsage:");
                Console.WriteLine("  1. Create 'token_a.txt' and 'token_b.txt' in the current directory");
                Console.WriteLine("  2. Or pass two tokens as command line arguments: dotnet run <token_a> <token_b>");
                Environment.Exit(1);
            }
            
            try
            {
                tokenA = File.ReadAllText(tokenAPath).Trim();
                Console.WriteLine($"✓ Loaded token A from: {tokenAPath}");
                
                tokenB = File.ReadAllText(tokenBPath).Trim();
                Console.WriteLine($"✓ Loaded token B from: {tokenBPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error loading token files: {ex.Message}");
                Environment.Exit(1);
            }
        }

        Console.WriteLine("\n" + new string('-', 80) + "\n");

        AnalyzeTokenExtended(tokenA, "Token A");
        AnalyzeTokenExtended(tokenB, "Token B");

        CompareTokens(tokenA, tokenB);
    }

    static void AnalyzeTokenExtended(string token, string label)
    {
        Console.WriteLine($"\n{new string('=', 80)}");
        Console.WriteLine($"=== Analyzing {label} Token ===");
        Console.WriteLine($"{new string('=', 80)}\n");
        
        // Split JWE into components
        string[] parts = token.Split('.');
        
        if (parts.Length != 5)
        {
            Console.WriteLine($"ERROR: Invalid JWE format. Expected 5 parts, got {parts.Length}");
            return;
        }
        
        string[] componentNames = {
            "JOSE Header",
            "Encrypted Key",
            "Initialization Vector",
            "Ciphertext",
            "Authentication Tag"
        };
        
        // Store decoded components for further analysis
        byte[] ivBytes = null;
        byte[] authTagBytes = null;
        byte[] encryptedKeyBytes = null;
        byte[] ciphertextBytes = null;
        
        // Analyze each component
        for (int i = 0; i < parts.Length; i++)
        {
            Console.WriteLine($"\n{componentNames[i]}:");
            Console.WriteLine($"  Length: {parts[i].Length} characters");
            
            string preview = parts[i].Length > 50 
                ? parts[i].Substring(0, 50) + "..." 
                : parts[i];
            Console.WriteLine($"  Base64URL: {preview}");
            
            try
            {
                byte[] decodedBytes = Base64UrlDecodeBytes(parts[i]);
                Console.WriteLine($"  Decoded byte length: {decodedBytes.Length} bytes");
                
                // Store for later analysis
                switch (i)
                {
                    case 1: encryptedKeyBytes = decodedBytes; break;
                    case 2: ivBytes = decodedBytes; break;
                    case 3: ciphertextBytes = decodedBytes; break;
                    case 4: authTagBytes = decodedBytes; break;
                }
                
                // Show hex for smaller components
                if (i == 2 || i == 4) // IV and Auth Tag
                {
                    Console.WriteLine($"  Hex: {BitConverter.ToString(decodedBytes).Replace("-", "")}");
                }
                
                // Decode header
                if (i == 0)
                {
                    string decoded = Encoding.UTF8.GetString(decodedBytes);
                    Console.WriteLine($"  Decoded: {decoded}");
                    
                    try
                    {
                        var json = JObject.Parse(decoded);
                        Console.WriteLine($"  Parsed JSON: {json.ToString(Formatting.Indented)}");
                        
                        // Analyze header fields
                        Console.WriteLine($"  Algorithm: {json["alg"]}");
                        Console.WriteLine($"  Encryption: {json["enc"]}");
                        Console.WriteLine($"  Content Type: {json["cty"]}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"  Error parsing JSON: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  Error decoding: {ex.Message}");
            }
        }
        
        // Additional analysis
        Console.WriteLine($"\n=== Token Statistics ===");
        Console.WriteLine($"Total token length: {token.Length} characters");
        Console.WriteLine($"Header: {parts[0].Length} chars");
        Console.WriteLine($"Encrypted Key: {parts[1].Length} chars ({encryptedKeyBytes?.Length ?? 0} bytes)");
        Console.WriteLine($"IV: {parts[2].Length} chars ({ivBytes?.Length ?? 0} bytes)");
        Console.WriteLine($"Ciphertext: {parts[3].Length} chars ({ciphertextBytes?.Length ?? 0} bytes)");
        Console.WriteLine($"Auth Tag: {parts[4].Length} chars ({authTagBytes?.Length ?? 0} bytes)");
        
        // Try to analyze if this looks like a nested JWT
        if (ciphertextBytes != null && ciphertextBytes.Length > 0)
        {
            Console.WriteLine($"\n=== Ciphertext Analysis ===");
            Console.WriteLine($"First 32 bytes (hex): {BitConverter.ToString(ciphertextBytes.Take(Math.Min(32, ciphertextBytes.Length)).ToArray()).Replace("-", "")}");
            
            // Check if it might contain a JWT (looking for base64url-like patterns)
            string ciphertextString = Encoding.UTF8.GetString(ciphertextBytes.Take(100).ToArray());
            bool mightBeJWT = ciphertextString.Contains("eyJ") || HasBase64UrlPattern(ciphertextBytes);
            Console.WriteLine($"Might contain nested JWT: {(mightBeJWT ? "Possibly" : "Unlikely")}");
        }
        
        // Timestamp analysis if possible
        Console.WriteLine($"\n=== Timestamp Analysis ===");
        long currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        Console.WriteLine($"Current Unix timestamp: {currentTime}");
        Console.WriteLine($"Current time: {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
    }

    static void CompareTokens(string tokenA, string tokenB)
    {
        Console.WriteLine($"\n\n{new string('=', 80)}");
        Console.WriteLine("=== Token Comparison: A vs B ===");
        Console.WriteLine($"{new string('=', 80)}\n");

        string[] partsA = tokenA.Split('.');
        string[] partsB = tokenB.Split('.');

        string[] componentNames = {"Header", "Encrypted Key", "IV", "Ciphertext", "Auth Tag"};

        Console.WriteLine("=== Component Length Differences ===");
        for (int i = 0; i < componentNames.Length && i < partsA.Length && i < partsB.Length; i++)
        {
            int lenA = partsA[i].Length;
            int lenB = partsB[i].Length;
            
            string status = lenA == lenB ? "SAME" : "DIFFERENT";
            Console.WriteLine($"{componentNames[i],-20} Token A: {lenA,4} chars | Token B: {lenB,4} chars | {status}");
        }

        // Compare headers character by character
        Console.WriteLine("\n=== Header Character Comparison ===");
        string headerA = partsA[0];
        string headerB = partsB[0];
        
        Console.WriteLine($"Token A header: {headerA}");
        Console.WriteLine($"Token B header: {headerB}");
        
        Console.WriteLine("\nDifferences found at:");
        int maxLen = Math.Max(headerA.Length, headerB.Length);
        bool foundDifferences = false;
        
        for (int i = 0; i < maxLen; i++)
        {
            char charA = i < headerA.Length ? headerA[i] : '\0';
            char charB = i < headerB.Length ? headerB[i] : '\0';
            
            if (charA != charB)
            {
                Console.WriteLine($"  Position {i}: Token A='{charA}' (0x{(int)charA:X2}) vs Token B='{charB}' (0x{(int)charB:X2})");
                foundDifferences = true;
            }
        }
        
        if (!foundDifferences)
        {
            Console.WriteLine("  No differences found - headers are identical");
        }

        // Decode and compare headers
        Console.WriteLine("\n=== Decoded Header Comparison ===");
        try
        {
            string decodedA = Base64UrlDecode(headerA);
            string decodedB = Base64UrlDecode(headerB);
            
            Console.WriteLine($"Token A decoded: {decodedA}");
            Console.WriteLine($"Token B decoded: {decodedB}");
            
            // Show bytes at difference positions
            byte[] bytesA = Base64UrlDecodeBytes(headerA);
            byte[] bytesB = Base64UrlDecodeBytes(headerB);
            
            Console.WriteLine("\nByte differences:");
            bool foundByteDiffs = false;
            for (int i = 0; i < Math.Min(bytesA.Length, bytesB.Length); i++)
            {
                if (bytesA[i] != bytesB[i])
                {
                    char charA = (char)bytesA[i];
                    char charB = (char)bytesB[i];
                    Console.WriteLine($"  Byte {i}: Token A=0x{bytesA[i]:X2} ('{(char.IsControl(charA) ? "?" : charA.ToString())}') vs Token B=0x{bytesB[i]:X2} ('{(char.IsControl(charB) ? "?" : charB.ToString())}')");
                    foundByteDiffs = true;
                }
            }
            
            if (!foundByteDiffs)
            {
                Console.WriteLine("  No byte differences found");
            }
            
            // Try to identify the exact problem
            Console.WriteLine("\n=== Analysis ===");
            bool headersDiffer = decodedA != decodedB;
            if (headersDiffer)
            {
                Console.WriteLine("The headers are different between the two tokens.");
                
                // Check for the common RSA-OAEP-256 corruption
                if ((decodedA.Contains("RSA-OAEP-256") && !decodedB.Contains("RSA-OAEP-256")) ||
                    (!decodedA.Contains("RSA-OAEP-256") && decodedB.Contains("RSA-OAEP-256")))
                {
                    Console.WriteLine("Specific issue: The algorithm field differs between tokens.");
                    Console.WriteLine($"Token A algorithm: {(decodedA.Contains("RSA-OAEP-256") ? "RSA-OAEP-256" : "Other/Corrupted")}");
                    Console.WriteLine($"Token B algorithm: {(decodedB.Contains("RSA-OAEP-256") ? "RSA-OAEP-256" : "Other/Corrupted")}");
                }
                else
                {
                    Console.WriteLine("Headers have different content but both appear to be valid JSON.");
                }
            }
            else
            {
                Console.WriteLine("Headers are identical. Any differences must be in other components.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error comparing headers: {ex.Message}");
        }

        // Check for invalid characters in both tokens
        Console.WriteLine("\n=== Base64URL Character Validation ===");
        string validBase64UrlChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        
        Console.WriteLine("Token A:");
        bool hasInvalidCharsA = false;
        for (int i = 0; i < tokenA.Length; i++)
        {
            char c = tokenA[i];
            if (c != '.' && !validBase64UrlChars.Contains(c))
            {
                Console.WriteLine($"  Invalid character '{c}' (0x{(int)c:X2}) at position {i}");
                hasInvalidCharsA = true;
            }
        }
        if (!hasInvalidCharsA)
        {
            Console.WriteLine("  All characters are valid Base64URL characters.");
        }
        
        Console.WriteLine("\nToken B:");
        bool hasInvalidCharsB = false;
        for (int i = 0; i < tokenB.Length; i++)
        {
            char c = tokenB[i];
            if (c != '.' && !validBase64UrlChars.Contains(c))
            {
                Console.WriteLine($"  Invalid character '{c}' (0x{(int)c:X2}) at position {i}");
                hasInvalidCharsB = true;
            }
        }
        if (!hasInvalidCharsB)
        {
            Console.WriteLine("  All characters are valid Base64URL characters.");
        }
        
        // Summary
        Console.WriteLine("\n=== Summary ===");
        if (headerA != headerB)
        {
            Console.WriteLine("The tokens have different headers.");
        }
        else
        {
            Console.WriteLine("The headers are identical. Differences exist in other components.");
        }
        
        // List all differences
        Console.WriteLine("\nComponent differences:");
        for (int i = 0; i < componentNames.Length && i < partsA.Length && i < partsB.Length; i++)
        {
            if (partsA[i].Length != partsB[i].Length)
            {
                Console.WriteLine($"  - {componentNames[i]}: Token A ({partsA[i].Length} chars) vs Token B ({partsB[i].Length} chars)");
            }
        }
    }
    
    static bool HasBase64UrlPattern(byte[] bytes)
    {
        if (bytes.Length < 10) return false;
        
        int validChars = 0;
        string validBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=.";
        
        for (int i = 0; i < Math.Min(100, bytes.Length); i++)
        {
            if (validBase64.Contains((char)bytes[i]))
                validChars++;
        }
        
        return validChars > 80; // More than 80% valid base64 chars
    }

    static string Base64UrlDecode(string base64Url)
    {
        byte[] bytes = Base64UrlDecodeBytes(base64Url);
        return Encoding.UTF8.GetString(bytes);
    }
    
    static byte[] Base64UrlDecodeBytes(string base64Url)
    {
        string padded = PadBase64(base64Url);
        return Convert.FromBase64String(padded);
    }

    static string PadBase64(string base64Url)
    {
        // Replace URL-safe characters
        string base64 = base64Url.Replace('-', '+').Replace('_', '/');
        
        // Add padding if necessary
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        
        return base64;
    }
}
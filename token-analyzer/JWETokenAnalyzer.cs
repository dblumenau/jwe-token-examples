using System;
using System.Text;
using System.Linq;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

class JWETokenAnalyzer
{
    static void Main(string[] args)
    {
        // Working token
        string workingToken = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIiwiY3R5IjoiSldUIn0.cK8s3O0bLQfhhFxxjbE6usQfPqXf2guUG9LHFhphr0whAOSY-sGJzcFZANorggjLB5viF341vgyNZ2qGAc9dIyMWBJ5ISFj47lngM_dBiQsnNIritMJSoJjyBwiArTg9aHrzK6Ja_6H6T_VgZq40O9_4BxpDOR7a9A1sYxt6v2yxB601inIXcr67q7ObTRly9dIzCc2Jnf0kyEJaLA7R_Kh9LBp3f5vj7sBotmnPDfTBW-xioxGbSpjfycu5S2OxK1E8Wmc54P8WG6BMEv-56_bGwI8Qyb44FSjy0fEzHsqPhW8Xjfb2RXjXAGDbL2TNjJRQ45FmgDtn6AzMApDfsw.covQyuFmnNSl1Utt.hSY0jGz3ZnJRYFpdpYhgVCTofXJVJh32yXncxwjekT9SbUsy1qslAskQcpPqDlSYdL9Syw41qQwt067Z06wbRkHUVwW8lszE4A7YdBJsmh_Y2qGZtu9jKwgjozrwY7FIoS4qJRFZneJ3jFjqyT4ruug_BFuV_dC9udaMPRNeIt-7P6XAf0-DokzRI7NpXj-XuFggatkCw5HaF9vu4DkiVXqbqzuEmeXyqgyBb5lIkWcFf1AaB6KKRdoS4jqTNSyEbfnbOyh9ATZ8YbRrU95fJTw5Z_fTKcWsHHuGI2GjU0HPbbtkpjY8QVF9k7SrdXBLLQl3RixWrRsNLR4fwcfvSJFg6LMrKOrjOrdBvUmaQO7KfHjWfxHyuU3rvAiY2xWDIIOxmGBaVIJpwvxfyav-IZf049WOXI-Rkh_pmbjQRpm7giNegzoCrLRjK0ffE-yqUmy17FgErqSld0sgPsVa1OZ8UPFOUCtQCGK6iZbkWig9KWRuivNst3r2-HQO3G-e8hC3lnw5b4GNAmuye9qUAjo5BMzabowjev3gZSlvBXfxK-AyE1rdwXyUBZhN9wD_oRwqIZ0-CFzgHnNtHjVteVw2DH3zeZtCsKq8rR-A68nXOBEDSamgUjvXR7HqHtLmHXiYQGdJ8QgYA-MTYDJDYjRAcGmsLsukZjwklivK6CRHdY5gWo64YkdUvkhlZf9F9_GRTYvTb3kv2pYaxlk.lbIyVfldBlf4CCEDF_wygA";

        // Not working token
        string notWorkingToken = "eyJhbGciOiJSU0EtT0FFCI0yNTYiLCJlbmMiOiJBMjU2R0NNIiwiY3R5IjoiSldUIn0.FAks9MskT5xPX9-AxSOJ0GWdmO4uP-rUOUlIL2ET2RpgvQPX3fH8B0jxVdZUrVAg7WbVJhiN4nSemyKeEneQHLATS3PK5HS-p8SteDcIl5y6OwMf2iMchJyZE4B_WRWNk9xRA97t2oAKlIGjhFWv6y2-Ga3eVqdCIjXEFLZRnTpWY5t24gDcQ81bs0X47mJ9I808Gxl_ieo2D6r5znvqP_Y-a5RNGhaf3O9NfDzy9luZHbEO4gU95WhZTvb4fGZTyfWs-vt8ra2WKIeyrJtSQMMc9Lz0dzSx5xCOFs_NQBZegASs2cX34TWqCCpFXglH493B0QXHgUuutVd2wSaMAw.o-DPrt5-TrFB837N.0-JMlKsLMh0tav1YVQsUMx1AMX9vyQG0dl9_Vwi0btQvXm5AjXEVFfSmv2Gj7YlBeuLazYdTKKspNwqgot_9MF0URkkoLo3KEn-D9L2udIvxSjXtjC92F4oRCuOU7ID3xuGxDnfP-2UPRbyF7HvdjTLdKqLEgUaRyTJ5ksXTwrnjdsqkdajX_0Z3vPbHJb6uhp5bhjVtqFz0SShFZSEzfTC7h0wVZZZ22ZRdkxbcXJPn8f0JCfSMZmEqIxWlKMpuTiqGWaL2S7tHt-8OQObdM_u1YyLOMiaoD08MX06y6R4TShkJLZHhr_ZCssa3IRRpAeEusBDmHbayxiNNFrnjDV5GliIaVAvHUhqCPL3BB0Bfb0Bx5ZrNUeMlJi3ZUQTtnLmfZwIZyd9uxTYN7IqHlSnnO8_r5IJry_MeYBP3Af3kQrw77LPQzTDrd0KuZRRB3GpkBY0Yr9X4OcX1kzRGGE4JPkxx225DGS894qc2863m364mOlJ8VQNz8QZTh5S0WGL1ThKtMhH1NKdIyVZtgyyDLPfpZkSinWxoCSGasJcdMtpsbZNqFfED25Brs3_t0i11UbJj9b1-gE_kbn-x9IxK8LTcdSOQhZcG9aUW4rovOjacDC_1-nerTQkzJJjna5rleVznSqjL-gU9O5OhgPK90OzE1FmnJ3X8_4Gx4u6kldLk7kBsofDiZzfSg7O2n4xnnMEnZUCsdMTQX_clWwnyzdv5fIMhF3wXlQ5XStXh2F28ZCA7glSLt2lF1fj8FFaH4qMYfYi0O5XvG4ccX7vVPb6Vb62kEgCZdQrsdqERP2hkFrt7uOE.xQfoUjXTumFLwbfXBkOC9A";

        Console.WriteLine("=== JWE Token Analyzer - Extended Analysis ===\n");

        AnalyzeTokenExtended(workingToken, "Working");
        AnalyzeTokenExtended(notWorkingToken, "Not Working");

        CompareTokens(workingToken, notWorkingToken);
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

    static void CompareTokens(string workingToken, string notWorkingToken)
    {
        Console.WriteLine($"\n\n{new string('=', 80)}");
        Console.WriteLine("=== Token Comparison ===");
        Console.WriteLine($"{new string('=', 80)}\n");

        string[] workingParts = workingToken.Split('.');
        string[] notWorkingParts = notWorkingToken.Split('.');

        string[] componentNames = {"Header", "Encrypted Key", "IV", "Ciphertext", "Auth Tag"};

        Console.WriteLine("=== Component Length Differences ===");
        for (int i = 0; i < componentNames.Length && i < workingParts.Length && i < notWorkingParts.Length; i++)
        {
            int workingLen = workingParts[i].Length;
            int notWorkingLen = notWorkingParts[i].Length;
            
            string status = workingLen == notWorkingLen ? "SAME" : "DIFFERENT";
            Console.WriteLine($"{componentNames[i],-20} Working: {workingLen,4} chars | Not Working: {notWorkingLen,4} chars | {status}");
        }

        // Compare headers character by character
        Console.WriteLine("\n=== Header Character Comparison ===");
        string workingHeader = workingParts[0];
        string notWorkingHeader = notWorkingParts[0];
        
        Console.WriteLine($"Working header:     {workingHeader}");
        Console.WriteLine($"Not working header: {notWorkingHeader}");
        
        Console.WriteLine("\nDifferences found at:");
        int maxLen = Math.Max(workingHeader.Length, notWorkingHeader.Length);
        
        for (int i = 0; i < maxLen; i++)
        {
            char wChar = i < workingHeader.Length ? workingHeader[i] : '\0';
            char nChar = i < notWorkingHeader.Length ? notWorkingHeader[i] : '\0';
            
            if (wChar != nChar)
            {
                Console.WriteLine($"  Position {i}: Working='{wChar}' (0x{(int)wChar:X2}) vs NotWorking='{nChar}' (0x{(int)nChar:X2})");
            }
        }

        // Decode and compare headers
        Console.WriteLine("\n=== Decoded Header Comparison ===");
        try
        {
            string workingDecoded = Base64UrlDecode(workingHeader);
            string notWorkingDecoded = Base64UrlDecode(notWorkingHeader);
            
            Console.WriteLine($"Working decoded: {workingDecoded}");
            Console.WriteLine($"Not working decoded: {notWorkingDecoded}");
            
            // Show bytes at difference positions
            byte[] workingBytes = Base64UrlDecodeBytes(workingHeader);
            byte[] notWorkingBytes = Base64UrlDecodeBytes(notWorkingHeader);
            
            Console.WriteLine("\nByte differences:");
            for (int i = 0; i < Math.Min(workingBytes.Length, notWorkingBytes.Length); i++)
            {
                if (workingBytes[i] != notWorkingBytes[i])
                {
                    char wChar = (char)workingBytes[i];
                    char nChar = (char)notWorkingBytes[i];
                    Console.WriteLine($"  Byte {i}: Working=0x{workingBytes[i]:X2} ('{(char.IsControl(wChar) ? "?" : wChar.ToString())}') vs NotWorking=0x{notWorkingBytes[i]:X2} ('{(char.IsControl(nChar) ? "?" : nChar.ToString())}')");
                }
            }
            
            // Try to identify the exact problem
            Console.WriteLine("\n=== Problem Analysis ===");
            if (workingDecoded.Contains("RSA-OAEP-256") && !notWorkingDecoded.Contains("RSA-OAEP-256"))
            {
                Console.WriteLine("ISSUE FOUND: The algorithm field is corrupted in the not-working token.");
                Console.WriteLine("Expected: \"alg\":\"RSA-OAEP-256\"");
                Console.WriteLine("Actual: Contains invalid UTF-8 sequence where 'P-' should be");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error comparing headers: {ex.Message}");
        }

        // Check for invalid characters
        Console.WriteLine("\n=== Base64URL Character Validation ===");
        string validBase64UrlChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        
        bool hasInvalidChars = false;
        for (int i = 0; i < notWorkingToken.Length; i++)
        {
            char c = notWorkingToken[i];
            if (c != '.' && !validBase64UrlChars.Contains(c))
            {
                Console.WriteLine($"Invalid character '{c}' (0x{(int)c:X2}) at position {i}");
                hasInvalidChars = true;
            }
        }
        
        if (!hasInvalidChars)
        {
            Console.WriteLine("All characters are valid Base64URL characters.");
        }
        
        // Summary
        Console.WriteLine("\n=== Summary ===");
        Console.WriteLine("The not-working token has a corrupted JOSE header where the algorithm name");
        Console.WriteLine("'RSA-OAEP-256' has been damaged. The characters 'UC' (which decode to 'P-')");
        Console.WriteLine("have been replaced with 'CI' (which decode to invalid UTF-8 bytes).");
        Console.WriteLine("This makes the header invalid JSON and prevents the token from being processed.");
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
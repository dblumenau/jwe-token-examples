# JWE Token Analyzer

A comprehensive C# tool for analyzing and comparing JWE (JSON Web Encryption) tokens. This tool helps debug token validation issues by providing detailed analysis of token structure, components, and differences between tokens.

## Features

- **Detailed Token Analysis**: Breaks down JWE tokens into their 5 components (Header, Encrypted Key, IV, Ciphertext, Authentication Tag)
- **Header Parsing**: Decodes and validates JOSE headers, showing algorithm, encryption method, and content type
- **Byte-Level Comparison**: Identifies exact differences between tokens at the character and byte level
- **Component Statistics**: Shows sizes of each token component in both base64url characters and decoded bytes
- **Hex Display**: Shows IV and Authentication Tag values in hexadecimal format
- **Validation**: Checks for invalid Base64URL characters and malformed headers
- **File Loading**: Loads tokens from files (token_a.txt and token_b.txt)
- **Command Line Support**: Can analyze tokens passed as command line arguments

## Prerequisites

- .NET 9.0 SDK or later
- Newtonsoft.Json package (automatically restored)

## Installation

1. Navigate to the token analyzer directory:
   ```bash
   cd /Users/davidblumenau/projects/fbf-cde/card-linking-web-sdk-cde/jwe-token-examples/token-analyzer
   ```

2. Build the project:
   ```bash
   dotnet build
   ```

## Usage

### Method 1: Using Token Files (Default)

1. Create token sample files in the analyzer directory:
   - `token_a.txt` - Contains the first JWE token to analyze
   - `token_b.txt` - Contains the second JWE token to compare

2. Run the analyzer:
   ```bash
   dotnet run
   ```

The analyzer will load tokens from these files and perform the comparison.

### Method 2: Command Line Arguments

Pass tokens directly as command line arguments:

```bash
dotnet run "eyJhbGciOiJSU0..." "eyJhbGciOiJSU0..."
```

First argument is token A, second is token B.

## Output Explanation

The analyzer provides several sections of output:

### 1. Token Component Analysis
For each token component:
- **Length**: Number of Base64URL characters
- **Base64URL**: Preview of the encoded data
- **Decoded byte length**: Size after Base64URL decoding
- **Hex**: Hexadecimal representation (for IV and Auth Tag)

### 2. Header Analysis
- **Decoded**: Raw JSON string of the header
- **Parsed JSON**: Pretty-printed JSON object
- **Algorithm**: Key encryption algorithm (e.g., RSA-OAEP-256)
- **Encryption**: Content encryption algorithm (e.g., A256GCM)
- **Content Type**: Type of nested content (e.g., JWT)

### 3. Token Statistics
Summary of component sizes for quick reference.

### 4. Ciphertext Analysis
- First 32 bytes in hex format
- Detection of potential nested JWT content

### 5. Token Comparison
- **Component Length Differences**: Shows which components differ in size
- **Header Character Comparison**: Character-by-character comparison of headers
- **Decoded Header Comparison**: Compares decoded JSON headers
- **Byte Differences**: Shows exact bytes that differ
- **Problem Analysis**: Identifies specific issues (e.g., corrupted algorithm field)
- **Base64URL Validation**: Checks for invalid characters

## Common Issues Detected

1. **Corrupted Algorithm Field**: When the algorithm name (e.g., "RSA-OAEP-256") contains invalid UTF-8 sequences
2. **Invalid JSON Headers**: Malformed JSON that can't be parsed
3. **Length Mismatches**: Different component sizes indicating structural issues
4. **Invalid Base64URL Characters**: Characters outside the allowed alphabet

## Example Output

```
=== JWE Token Analyzer - Extended Analysis ===

✓ Loaded valid token from: valid_token_sample.txt
✓ Loaded invalid token from: invalid_token_sample.txt

================================================================================
=== Analyzing Valid/Working Token ===
================================================================================

JOSE Header:
  Length: 67 characters
  Base64URL: eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIi...
  Decoded: {"alg":"RSA-OAEP-256","enc":"A256GCM","cty":"JWT"}
  Algorithm: RSA-OAEP-256
  Encryption: A256GCM
  Content Type: JWT
...
```

## Troubleshooting

1. **File not found errors**: Ensure token files are in the same directory as the executable
2. **Build errors**: Make sure you have .NET 9.0 SDK installed
3. **Invalid token format**: Ensure tokens are complete JWE tokens with 5 dot-separated components

## Contributing

To extend the analyzer:
1. Add new analysis methods in the `AnalyzeTokenExtended` method
2. Add new comparison logic in the `CompareTokens` method
3. Update the README with new features
#!/bin/bash

# JWE Token Generator/Analyzer Interactive Script
# Assumes macOS with Homebrew installed

set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Colors for better UI
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Function to print colored text
print_color() {
    color=$1
    text=$2
    echo -e "${color}${text}${NC}"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check dependencies
check_dependencies() {
    local missing_deps=()
    
    if ! command_exists node; then
        missing_deps+=("node")
    fi
    
    if ! command_exists dotnet; then
        missing_deps+=("dotnet-sdk")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_color $RED "Missing dependencies detected!"
        echo "Please install the following using Homebrew:"
        for dep in "${missing_deps[@]}"; do
            echo "  brew install $dep"
        done
        echo ""
        read -p "Would you like to install them now? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            for dep in "${missing_deps[@]}"; do
                print_color $YELLOW "Installing $dep..."
                brew install "$dep"
            done
            print_color $GREEN "Dependencies installed successfully!"
        else
            print_color $RED "Cannot proceed without required dependencies."
            exit 1
        fi
    fi
}

# Function to display the main menu
show_main_menu() {
    clear
    print_color $BLUE "${BOLD}═══════════════════════════════════════════════════"
    print_color $BLUE "${BOLD}        JWE Token Generator & Analyzer"
    print_color $BLUE "${BOLD}═══════════════════════════════════════════════════"
    echo ""
    echo "Select a language:"
    echo ""
    print_color $GREEN "  1) Node.js"
    print_color $GREEN "  2) C# (.NET)"
    echo ""
    print_color $YELLOW "  0) Exit"
    echo ""
    print_color $BLUE "═══════════════════════════════════════════════════"
}

# Function to handle Node.js operations
handle_nodejs() {
    clear
    print_color $GREEN "${BOLD}Node.js JWE Operations"
    print_color $GREEN "═══════════════════════════════════════════════════"
    echo ""
    echo "What would you like to do?"
    echo ""
    echo "  1) Generate a JWE token"
    echo "  2) Decrypt & verify a JWE token"
    echo "  3) Back to main menu"
    echo ""
    read -p "Enter your choice (1-3): " choice
    
    case $choice in
        1)
            print_color $YELLOW "\nGenerating JWE token using Node.js..."
            cd "$SCRIPT_DIR/node"
            if [ ! -f "jwt_signing_private.pem" ] || [ ! -f "jwt_encryption_public.pem" ]; then
                print_color $RED "Error: PEM key files not found in node directory!"
                print_color $YELLOW "Please ensure jwt_signing_private.pem and jwt_encryption_public.pem exist."
                read -p "Press any key to continue..."
                return
            fi
            echo ""
            read -p "Enter subject (external ID) or press Enter for default: " subject
            echo ""
            if [ -z "$subject" ]; then
                node example_jwe_generation.js
            else
                node example_jwe_generation.js "$subject"
            fi
            echo ""
            read -p "Press any key to continue..."
            ;;
        2)
            print_color $YELLOW "\nDecrypting JWE token using Node.js..."
            cd "$SCRIPT_DIR/node"

            # Check for all required key files for decryption
            local missing_keys=()
            if [ ! -f "jwt_signing_private.pem" ]; then missing_keys+=("jwt_signing_private.pem"); fi
            if [ ! -f "jwt_encryption_public.pem" ]; then missing_keys+=("jwt_encryption_public.pem"); fi
            if [ ! -f "jwt_signing_public.pem" ]; then missing_keys+=("jwt_signing_public.pem"); fi
            if [ ! -f "jwt_encryption_private.pem" ]; then missing_keys+=("jwt_encryption_private.pem"); fi

            if [ ${#missing_keys[@]} -ne 0 ]; then
                print_color $RED "Error: Missing key files required for decryption!"
                echo "Required files in node directory:"
                for key in "${missing_keys[@]}"; do
                    echo "  - $key"
                done
                echo ""
                print_color $YELLOW "To generate missing keys, see the README.md file."
                read -p "Press any key to continue..."
                return
            fi

            echo ""
            echo "Enter the JWE token to decrypt (paste the full token):"
            echo ""
            read -p "Token: " jwe_token
            echo ""

            if [ -z "$jwe_token" ]; then
                print_color $RED "Error: No token provided!"
            else
                node example_jwe_generation.js --decrypt "$jwe_token"
            fi
            echo ""
            read -p "Press any key to continue..."
            ;;
        3)
            return
            ;;
        *)
            print_color $RED "Invalid choice!"
            sleep 1
            handle_nodejs
            ;;
    esac
}

# Function to handle C# operations
handle_csharp() {
    clear
    print_color $GREEN "${BOLD}C# (.NET) JWE Operations"
    print_color $GREEN "═══════════════════════════════════════════════════"
    echo ""
    echo "What would you like to do?"
    echo ""
    echo "  1) Generate a JWE token"
    echo "  2) Analyze JWE tokens (compare files)"
    echo "  3) Back to main menu"
    echo ""
    read -p "Enter your choice (1-3): " choice
    
    case $choice in
        1)
            print_color $YELLOW "\nGenerating JWE token using C#..."
            cd "$SCRIPT_DIR/csharp/JWEGenerator"
            if [ ! -f "jwt_signing_private.pem" ] || [ ! -f "jwt_encryption_public.pem" ]; then
                print_color $RED "Error: PEM key files not found in JWEGenerator directory!"
                print_color $YELLOW "Please ensure jwt_signing_private.pem and jwt_encryption_public.pem exist."
                read -p "Press any key to continue..."
                return
            fi
            echo ""
            read -p "Enter subject (external ID) or press Enter for default: " subject
            echo ""
            if [ -z "$subject" ]; then
                dotnet run
            else
                dotnet run -- "$subject"
            fi
            echo ""
            read -p "Press any key to continue..."
            ;;
        2)
            print_color $YELLOW "\nJWE Token Analyzer"
            cd "$SCRIPT_DIR/csharp/JWETokenAnalyzer"
            echo ""
            echo "This tool can analyze and compare JWE tokens from files."
            echo ""
            
            # Check if example files exist
            if [ -f "token_a.txt" ] && [ -f "token_b.txt" ]; then
                echo "Found example token files:"
                echo "  - token_a.txt"
                echo "  - token_b.txt"
                echo ""
                read -p "Use these files for comparison? (y/n): " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    dotnet run
                else
                    echo ""
                    read -p "Enter path to first token file: " file1
                    read -p "Enter path to second token file: " file2
                    if [ -f "$file1" ] && [ -f "$file2" ]; then
                        # Read tokens from files and pass as arguments
                        token1=$(cat "$file1" | tr -d '\n\r')
                        token2=$(cat "$file2" | tr -d '\n\r')
                        dotnet run -- "$token1" "$token2"
                    else
                        print_color $RED "Error: One or both files not found!"
                    fi
                fi
            else
                echo "Enter the paths to two JWE token files to compare:"
                echo ""
                read -p "First token file: " file1
                read -p "Second token file: " file2
                if [ -f "$file1" ] && [ -f "$file2" ]; then
                    # Read tokens from files and pass as arguments
                    token1=$(cat "$file1" | tr -d '\n\r')
                    token2=$(cat "$file2" | tr -d '\n\r')
                    dotnet run -- "$token1" "$token2"
                else
                    print_color $RED "Error: One or both files not found!"
                fi
            fi
            echo ""
            read -p "Press any key to continue..."
            ;;
        3)
            return
            ;;
        *)
            print_color $RED "Invalid choice!"
            sleep 1
            handle_csharp
            ;;
    esac
}

# Main script execution
main() {
    # Check if running on macOS
    if [[ "$OSTYPE" != "darwin"* ]]; then
        print_color $RED "This script is designed for macOS with Homebrew."
        echo "Please modify it for your operating system."
        exit 1
    fi
    
    # Check if Homebrew is installed
    if ! command_exists brew; then
        print_color $RED "Homebrew is not installed!"
        echo "Please install Homebrew first: https://brew.sh"
        exit 1
    fi
    
    # Check dependencies
    print_color $YELLOW "Checking dependencies..."
    check_dependencies
    
    # Main loop
    while true; do
        show_main_menu
        read -p "Enter your choice (0-2): " choice
        
        case $choice in
            1)
                handle_nodejs
                ;;
            2)
                handle_csharp
                ;;
            0)
                print_color $GREEN "\nGoodbye!"
                exit 0
                ;;
            *)
                print_color $RED "Invalid choice!"
                sleep 1
                ;;
        esac
    done
}

# Run the main function
main
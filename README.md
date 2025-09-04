# Go Hello Private Registry - Security Helpers Demo

A comprehensive Go web application demonstrating security utilities from `github.com/octofelickz/go-hello-privateregistry-dependency`.

## Features

This web application showcases all the security helper functions with interactive examples:

### 🧼 HTML Sanitization
- **SanitizeHTML()** - Strict HTML sanitization that removes all HTML tags
- **SanitizeUGC()** - User-generated content sanitization with safe HTML tags allowed
- **NewSanitizer()** - Create custom HTML sanitizer with strict policy
- **NewUGCSanitizer()** - Create custom HTML sanitizer for user-generated content

### 🔒 Output Encoding
- **EncodeHTML()** - HTML entity encoding to prevent XSS
- **EncodeHTMLAttr()** - Safe HTML attribute encoding
- **EncodeJS()** - JavaScript string encoding
- **EncodeURL()** - URL component encoding
- **EncodeCSS()** - CSS value encoding

### ✅ Input Validation
- **ValidateEmail()** - Email address validation using regex
- **ValidateAlphanumeric()** - Check if input contains only alphanumeric characters
- **SanitizeInput()** - Remove common SQL injection patterns
- **SanitizeFilename()** - Clean filenames by removing dangerous characters
- **LimitLength()** - Truncate input to maximum length

### 🔐 Cryptographic Utilities
- **HashPassword()** - Hash passwords using bcrypt
- **VerifyPassword()** - Verify password against bcrypt hash
- **GenerateSecureToken()** - Generate cryptographically secure random tokens
- **GenerateSecureHex()** - Generate secure random hex strings
- **GenerateSalt()** - Generate cryptographic salt
- **DeriveKey()** - Derive keys from passwords using scrypt
- **SecureCompare()** - Constant-time string comparison

### 🛡️ CSRF Protection
- **GenerateCSRFToken()** - Generate CSRF tokens for form protection
- **ValidateCSRFToken()** - Validate CSRF tokens securely

## Installation & Usage

### Prerequisites
- Go 1.24.6 or later

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/octofelickz/go-hello-privateregistry.git
   cd go-hello-privateregistry
   ```

2. Install dependencies:
   ```bash
   go mod tidy
   ```

3. Run the application:
   ```bash
   go run .
   ```

4. Open your browser and visit: `http://localhost:8080`

### Building
```bash
go build
./go-hello-privateregistry
```

## Web Interface

The application provides an intuitive web interface with:

- **Navigation menu** - Easy access to all security feature demos
- **Interactive forms** - Test security functions with your own input
- **Real-time results** - See the output of each security function
- **Educational content** - Learn about each security utility and its purpose

### Example Pages

1. **Home** (`/`) - Overview of all available security features
2. **HTML Sanitization** (`/html-sanitization`) - Test XSS prevention functions
3. **Output Encoding** (`/output-encoding`) - Test encoding functions for different contexts
4. **Input Validation** (`/input-validation`) - Test validation and sanitization functions
5. **Crypto Utils** (`/crypto-utils`) - Test cryptographic functions
6. **CSRF Protection** (`/csrf-protection`) - Test CSRF token generation and validation

## Dependencies

- **[github.com/octofelickz/go-hello-privateregistry-dependency](https://github.com/octofelickz/go-hello-privateregistry-dependency)** - Core security helper functions
- **[github.com/microcosm-cc/bluemonday](https://github.com/microcosm-cc/bluemonday)** - HTML sanitization (transitive)
- **[golang.org/x/crypto](https://golang.org/x/crypto)** - Cryptographic functions (transitive)

## Security Features Demonstrated

This application serves as a practical example of how to:

- Prevent XSS attacks through proper HTML sanitization and output encoding
- Validate and sanitize user input to prevent injection attacks
- Implement secure password hashing and verification
- Generate cryptographically secure tokens and keys
- Protect against CSRF attacks
- Use constant-time comparison to prevent timing attacks

## Contributing

This project demonstrates the usage of security helpers from the private registry dependency. For issues with the core security functions, please refer to the [dependency repository](https://github.com/octofelickz/go-hello-privateregistry-dependency).

## License

This project is for demonstration purposes of security helper utilities.
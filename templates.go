package main

const htmlSanitizationTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .nav { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007bff; }
        .nav a:hover { text-decoration: underline; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group textarea, .form-group input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .form-group textarea { height: 100px; resize: vertical; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #0056b3; }
        .results { margin-top: 20px; }
        .result-item { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background: #f8f9fa; }
        .result-item h4 { margin-top: 0; color: #333; }
        .result-value { background: #e9ecef; padding: 10px; border-radius: 3px; font-family: monospace; word-break: break-all; }
        .error { color: #dc3545; background: #f8d7da; padding: 10px; border-radius: 4px; margin-bottom: 15px; }
    </style>
</head>
<body>
    <nav class="nav">
        <a href="/">Home</a>
        <a href="/html-sanitization">HTML Sanitization</a>
        <a href="/output-encoding">Output Encoding</a>
        <a href="/input-validation">Input Validation</a>
        <a href="/crypto-utils">Crypto Utils</a>
        <a href="/csrf-protection">CSRF Protection</a>
    </nav>

    <h1>{{.Title}}</h1>

    {{if .Error}}
    <div class="error">{{.Error}}</div>
    {{end}}

    <form method="POST">
        <div class="form-group">
            <label for="input">HTML Input to Sanitize:</label>
            <textarea name="input" id="input" placeholder="Enter HTML content to test sanitization (e.g., &lt;script&gt;alert('xss')&lt;/script&gt;&lt;p&gt;Hello &lt;strong&gt;World&lt;/strong&gt;&lt;/p&gt;)">{{.Results.original}}</textarea>
        </div>
        <button type="submit" class="btn">Test HTML Sanitization</button>
    </form>

    {{if .Results.original}}
    <div class="results">
        <div class="result-item">
            <h4>Original Input:</h4>
            <div class="result-value">{{.Results.original}}</div>
        </div>

        <div class="result-item">
            <h4>SanitizeHTML() - Strict sanitization (removes all HTML):</h4>
            <div class="result-value">{{.Results.sanitizeHTML}}</div>
        </div>

        <div class="result-item">
            <h4>SanitizeUGC() - User-generated content (allows safe HTML):</h4>
            <div class="result-value">{{.Results.sanitizeUGC}}</div>
        </div>

        <div class="result-item">
            <h4>NewSanitizer() - Custom strict sanitizer:</h4>
            <div class="result-value">{{.Results.customStrict}}</div>
        </div>

        <div class="result-item">
            <h4>NewUGCSanitizer() - Custom UGC sanitizer:</h4>
            <div class="result-value">{{.Results.customUGC}}</div>
        </div>
    </div>
    {{end}}

    <div style="margin-top: 30px; padding: 20px; background: #e7f3ff; border-radius: 5px;">
        <h3>About HTML Sanitization</h3>
        <p><strong>SanitizeHTML()</strong> performs strict sanitization that removes all HTML tags, leaving only text content.</p>
        <p><strong>SanitizeUGC()</strong> allows safe HTML tags commonly used in user-generated content while removing dangerous elements.</p>
        <p><strong>NewSanitizer()</strong> creates a custom sanitizer with a strict policy.</p>
        <p><strong>NewUGCSanitizer()</strong> creates a custom sanitizer optimized for user-generated content.</p>
    </div>
</body>
</html>`

const outputEncodingTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .nav { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007bff; }
        .nav a:hover { text-decoration: underline; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group textarea, .form-group input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .form-group textarea { height: 80px; resize: vertical; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #0056b3; }
        .results { margin-top: 20px; }
        .result-item { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background: #f8f9fa; }
        .result-item h4 { margin-top: 0; color: #333; }
        .result-value { background: #e9ecef; padding: 10px; border-radius: 3px; font-family: monospace; word-break: break-all; }
        .error { color: #dc3545; background: #f8d7da; padding: 10px; border-radius: 4px; margin-bottom: 15px; }
    </style>
</head>
<body>
    <nav class="nav">
        <a href="/">Home</a>
        <a href="/html-sanitization">HTML Sanitization</a>
        <a href="/output-encoding">Output Encoding</a>
        <a href="/input-validation">Input Validation</a>
        <a href="/crypto-utils">Crypto Utils</a>
        <a href="/csrf-protection">CSRF Protection</a>
    </nav>

    <h1>{{.Title}}</h1>

    {{if .Error}}
    <div class="error">{{.Error}}</div>
    {{end}}

    <form method="POST">
        <div class="form-group">
            <label for="input">Input to Encode:</label>
            <textarea name="input" id="input" placeholder="Enter text to test encoding (e.g., &lt;script&gt;alert('test')&lt;/script&gt; or user@domain.com)">{{.Results.original}}</textarea>
        </div>
        <button type="submit" class="btn">Test Output Encoding</button>
    </form>

    {{if .Results.original}}
    <div class="results">
        <div class="result-item">
            <h4>Original Input:</h4>
            <div class="result-value">{{.Results.original}}</div>
        </div>

        <div class="result-item">
            <h4>EncodeHTML() - HTML entity encoding:</h4>
            <div class="result-value">{{.Results.encodeHTML}}</div>
        </div>

        <div class="result-item">
            <h4>EncodeHTMLAttr() - HTML attribute encoding:</h4>
            <div class="result-value">{{.Results.encodeHTMLAttr}}</div>
        </div>

        <div class="result-item">
            <h4>EncodeJS() - JavaScript string encoding:</h4>
            <div class="result-value">{{.Results.encodeJS}}</div>
        </div>

        <div class="result-item">
            <h4>EncodeURL() - URL component encoding:</h4>
            <div class="result-value">{{.Results.encodeURL}}</div>
        </div>

        <div class="result-item">
            <h4>EncodeCSS() - CSS value encoding:</h4>
            <div class="result-value">{{.Results.encodeCSS}}</div>
        </div>
    </div>
    {{end}}

    <div style="margin-top: 30px; padding: 20px; background: #e7f3ff; border-radius: 5px;">
        <h3>About Output Encoding</h3>
        <p><strong>EncodeHTML()</strong> encodes special characters for safe inclusion in HTML content.</p>
        <p><strong>EncodeHTMLAttr()</strong> encodes text for safe use in HTML attributes.</p>
        <p><strong>EncodeJS()</strong> encodes text for safe inclusion in JavaScript strings.</p>
        <p><strong>EncodeURL()</strong> encodes text for safe use as URL components.</p>
        <p><strong>EncodeCSS()</strong> encodes text for safe use in CSS values.</p>
    </div>
</body>
</html>`

const inputValidationTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .nav { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007bff; }
        .nav a:hover { text-decoration: underline; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group textarea, .form-group input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .form-group textarea { height: 60px; resize: vertical; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #0056b3; }
        .results { margin-top: 20px; }
        .result-item { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background: #f8f9fa; }
        .result-item h4 { margin-top: 0; color: #333; }
        .result-value { background: #e9ecef; padding: 10px; border-radius: 3px; font-family: monospace; word-break: break-all; }
        .valid { color: #28a745; font-weight: bold; }
        .invalid { color: #dc3545; font-weight: bold; }
        .error { color: #dc3545; background: #f8d7da; padding: 10px; border-radius: 4px; margin-bottom: 15px; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
    </style>
</head>
<body>
    <nav class="nav">
        <a href="/">Home</a>
        <a href="/html-sanitization">HTML Sanitization</a>
        <a href="/output-encoding">Output Encoding</a>
        <a href="/input-validation">Input Validation</a>
        <a href="/crypto-utils">Crypto Utils</a>
        <a href="/csrf-protection">CSRF Protection</a>
    </nav>

    <h1>{{.Title}}</h1>

    {{if .Error}}
    <div class="error">{{.Error}}</div>
    {{end}}

    <form method="POST">
        <div class="form-row">
            <div class="form-group">
                <label for="email">Email Address:</label>
                <input type="text" name="email" id="email" placeholder="test@example.com">
            </div>
            <div class="form-group">
                <label for="username">Username (Alphanumeric):</label>
                <input type="text" name="username" id="username" placeholder="user123">
            </div>
        </div>

        <div class="form-group">
            <label for="sql_input">SQL Input (to sanitize):</label>
            <textarea name="sql_input" id="sql_input" placeholder="Enter text that might contain SQL injection attempts"></textarea>
        </div>

        <div class="form-group">
            <label for="filename">Filename (to sanitize):</label>
            <input type="text" name="filename" id="filename" placeholder="../../../etc/passwd">
        </div>

        <div class="form-row">
            <div class="form-group">
                <label for="long_text">Long Text (to limit):</label>
                <textarea name="long_text" id="long_text" placeholder="Enter long text to test length limiting"></textarea>
            </div>
            <div class="form-group">
                <label for="max_length">Max Length:</label>
                <input type="number" name="max_length" id="max_length" placeholder="50" min="1">
            </div>
        </div>

        <button type="submit" class="btn">Test Input Validation</button>
    </form>

    {{if .Results.validations}}
    <div class="results">
        {{if .Results.validations.email}}
        <div class="result-item">
            <h4>Email Validation:</h4>
            <div class="result-value">Input: {{.Results.validations.email.input}}</div>
            <div class="result-value">Valid: <span class="{{if .Results.validations.email.valid}}valid{{else}}invalid{{end}}">{{.Results.validations.email.valid}}</span></div>
        </div>
        {{end}}

        {{if .Results.validations.username}}
        <div class="result-item">
            <h4>Alphanumeric Validation:</h4>
            <div class="result-value">Input: {{.Results.validations.username.input}}</div>
            <div class="result-value">Valid: <span class="{{if .Results.validations.username.valid}}valid{{else}}invalid{{end}}">{{.Results.validations.username.valid}}</span></div>
        </div>
        {{end}}

        {{if .Results.validations.sql}}
        <div class="result-item">
            <h4>SQL Input Sanitization:</h4>
            <div class="result-value">Input: {{.Results.validations.sql.input}}</div>
            <div class="result-value">Sanitized: {{.Results.validations.sql.sanitized}}</div>
        </div>
        {{end}}

        {{if .Results.validations.filename}}
        <div class="result-item">
            <h4>Filename Sanitization:</h4>
            <div class="result-value">Input: {{.Results.validations.filename.input}}</div>
            <div class="result-value">Sanitized: {{.Results.validations.filename.sanitized}}</div>
        </div>
        {{end}}

        {{if .Results.validations.length}}
        <div class="result-item">
            <h4>Length Limiting:</h4>
            <div class="result-value">Input: {{.Results.validations.length.input}}</div>
            <div class="result-value">Max Length: {{.Results.validations.length.maxLen}}</div>
            <div class="result-value">Limited: {{.Results.validations.length.limited}}</div>
        </div>
        {{end}}
    </div>
    {{end}}

    <div style="margin-top: 30px; padding: 20px; background: #e7f3ff; border-radius: 5px;">
        <h3>About Input Validation</h3>
        <p><strong>ValidateEmail()</strong> validates email addresses using regex patterns.</p>
        <p><strong>ValidateAlphanumeric()</strong> checks if input contains only alphanumeric characters.</p>
        <p><strong>SanitizeInput()</strong> removes common SQL injection patterns.</p>
        <p><strong>SanitizeFilename()</strong> cleans filenames by removing dangerous characters.</p>
        <p><strong>LimitLength()</strong> truncates input to a maximum length.</p>
    </div>
</body>
</html>`

const cryptoUtilsTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .nav { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007bff; }
        .nav a:hover { text-decoration: underline; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group textarea, .form-group input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .form-group textarea { height: 60px; resize: vertical; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin-right: 10px; margin-bottom: 10px; }
        .btn:hover { background: #0056b3; }
        .results { margin-top: 20px; }
        .result-item { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background: #f8f9fa; }
        .result-item h4 { margin-top: 0; color: #333; }
        .result-value { background: #e9ecef; padding: 10px; border-radius: 3px; font-family: monospace; word-break: break-all; }
        .error { color: #dc3545; background: #f8d7da; padding: 10px; border-radius: 4px; margin-bottom: 15px; }
        .form-section { border: 1px solid #ddd; padding: 20px; margin-bottom: 20px; border-radius: 5px; }
        .form-section h3 { margin-top: 0; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
    </style>
</head>
<body>
    <nav class="nav">
        <a href="/">Home</a>
        <a href="/html-sanitization">HTML Sanitization</a>
        <a href="/output-encoding">Output Encoding</a>
        <a href="/input-validation">Input Validation</a>
        <a href="/crypto-utils">Crypto Utils</a>
        <a href="/csrf-protection">CSRF Protection</a>
    </nav>

    <h1>{{.Title}}</h1>

    {{if .Error}}
    <div class="error">{{.Error}}</div>
    {{end}}

    <div class="form-section">
        <h3>Password Hashing</h3>
        <form method="POST">
            <input type="hidden" name="action" value="hash_password">
            <div class="form-group">
                <label for="password">Password to Hash:</label>
                <input type="password" name="password" id="password" placeholder="Enter password">
            </div>
            <button type="submit" class="btn">Hash Password & Verify</button>
        </form>
    </div>

    <div class="form-section">
        <h3>Token Generation</h3>
        <form method="POST">
            <input type="hidden" name="action" value="generate_tokens">
            <div class="form-group">
                <label for="token_size">Token Size (bytes):</label>
                <input type="number" name="token_size" id="token_size" value="32" min="1" max="128">
            </div>
            <button type="submit" class="btn">Generate Secure Tokens</button>
        </form>
    </div>

    <div class="form-section">
        <h3>Key Derivation</h3>
        <form method="POST">
            <input type="hidden" name="action" value="key_derivation">
            <div class="form-group">
                <label for="derive_password">Password for Key Derivation:</label>
                <input type="password" name="derive_password" id="derive_password" placeholder="Enter password">
            </div>
            <button type="submit" class="btn">Derive Key</button>
        </form>
    </div>

    <div class="form-section">
        <h3>Secure String Comparison</h3>
        <form method="POST">
            <input type="hidden" name="action" value="secure_compare">
            <div class="form-row">
                <div class="form-group">
                    <label for="string1">String 1:</label>
                    <input type="text" name="string1" id="string1" placeholder="First string">
                </div>
                <div class="form-group">
                    <label for="string2">String 2:</label>
                    <input type="text" name="string2" id="string2" placeholder="Second string">
                </div>
            </div>
            <button type="submit" class="btn">Compare Strings</button>
        </form>
    </div>

    {{if .Results}}
    <div class="results">
        {{if .Results.password}}
        <div class="result-item">
            <h4>Password Hashing Results:</h4>
            <div class="result-value">Password: {{.Results.password}}</div>
            <div class="result-value">Hash: {{.Results.hash}}</div>
            <div class="result-value">Verification: {{.Results.verified}}</div>
        </div>
        {{end}}

        {{if .Results.secureToken}}
        <div class="result-item">
            <h4>Token Generation Results:</h4>
            <div class="result-value">Secure Token: {{.Results.secureToken}}</div>
            {{if .Results.secureHex}}<div class="result-value">Secure Hex: {{.Results.secureHex}}</div>{{end}}
        </div>
        {{end}}

        {{if .Results.derivedKey}}
        <div class="result-item">
            <h4>Key Derivation Results:</h4>
            <div class="result-value">Password: {{.Results.password}}</div>
            <div class="result-value">Salt: {{.Results.salt}}</div>
            <div class="result-value">Derived Key: {{.Results.derivedKey}}</div>
        </div>
        {{end}}

        {{if .Results.secureEqual}}
        <div class="result-item">
            <h4>String Comparison Results:</h4>
            <div class="result-value">String 1: {{.Results.string1}}</div>
            <div class="result-value">String 2: {{.Results.string2}}</div>
            <div class="result-value">Secure Equal: {{.Results.secureEqual}}</div>
            <div class="result-value">Regular Equal: {{.Results.regularEqual}}</div>
        </div>
        {{end}}
    </div>
    {{end}}

    <div style="margin-top: 30px; padding: 20px; background: #e7f3ff; border-radius: 5px;">
        <h3>About Cryptographic Utilities</h3>
        <p><strong>HashPassword()</strong> uses bcrypt to securely hash passwords.</p>
        <p><strong>VerifyPassword()</strong> verifies a password against its bcrypt hash.</p>
        <p><strong>GenerateSecureToken()</strong> generates cryptographically secure random tokens.</p>
        <p><strong>GenerateSecureHex()</strong> generates secure random hex strings.</p>
        <p><strong>GenerateSalt()</strong> generates cryptographic salt for key derivation.</p>
        <p><strong>DeriveKey()</strong> derives keys from passwords using scrypt.</p>
        <p><strong>SecureCompare()</strong> performs constant-time string comparison to prevent timing attacks.</p>
    </div>
</body>
</html>`

const csrfProtectionTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .nav { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007bff; }
        .nav a:hover { text-decoration: underline; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group textarea, .form-group input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .form-group textarea { height: 60px; resize: vertical; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin-right: 10px; margin-bottom: 10px; }
        .btn:hover { background: #0056b3; }
        .results { margin-top: 20px; }
        .result-item { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background: #f8f9fa; }
        .result-item h4 { margin-top: 0; color: #333; }
        .result-value { background: #e9ecef; padding: 10px; border-radius: 3px; font-family: monospace; word-break: break-all; }
        .error { color: #dc3545; background: #f8d7da; padding: 10px; border-radius: 4px; margin-bottom: 15px; }
        .form-section { border: 1px solid #ddd; padding: 20px; margin-bottom: 20px; border-radius: 5px; }
        .form-section h3 { margin-top: 0; }
        .valid { color: #28a745; font-weight: bold; }
        .invalid { color: #dc3545; font-weight: bold; }
    </style>
</head>
<body>
    <nav class="nav">
        <a href="/">Home</a>
        <a href="/html-sanitization">HTML Sanitization</a>
        <a href="/output-encoding">Output Encoding</a>
        <a href="/input-validation">Input Validation</a>
        <a href="/crypto-utils">Crypto Utils</a>
        <a href="/csrf-protection">CSRF Protection</a>
    </nav>

    <h1>{{.Title}}</h1>

    {{if .Error}}
    <div class="error">{{.Error}}</div>
    {{end}}

    <div class="form-section">
        <h3>Generate CSRF Token</h3>
        <form method="POST">
            <input type="hidden" name="action" value="generate">
            <p>Click the button below to generate a new CSRF token:</p>
            <button type="submit" class="btn">Generate CSRF Token</button>
        </form>
    </div>

    <div class="form-section">
        <h3>Validate CSRF Token</h3>
        <form method="POST">
            <input type="hidden" name="action" value="validate">
            <div class="form-group">
                <label for="token">CSRF Token:</label>
                <input type="text" name="token" id="token" placeholder="Enter CSRF token to validate">
            </div>
            <div class="form-group">
                <label for="secret">Secret Key:</label>
                <input type="text" name="secret" id="secret" placeholder="Enter secret key used for validation">
            </div>
            <button type="submit" class="btn">Validate CSRF Token</button>
        </form>
    </div>

    {{if .Results}}
    <div class="results">
        {{if .Results.generatedToken}}
        <div class="result-item">
            <h4>Generated CSRF Token:</h4>
            <div class="result-value">{{.Results.generatedToken}}</div>
        </div>
        {{end}}

        {{if .Results.token}}
        <div class="result-item">
            <h4>CSRF Token Validation:</h4>
            <div class="result-value">Token: {{.Results.token}}</div>
            <div class="result-value">Secret: {{.Results.secret}}</div>
            <div class="result-value">Valid: <span class="{{if .Results.valid}}valid{{else}}invalid{{end}}">{{.Results.valid}}</span></div>
        </div>
        {{end}}
    </div>
    {{end}}

    <div style="margin-top: 30px; padding: 20px; background: #e7f3ff; border-radius: 5px;">
        <h3>About CSRF Protection</h3>
        <p><strong>GenerateCSRFToken()</strong> generates secure tokens for Cross-Site Request Forgery protection.</p>
        <p><strong>ValidateCSRFToken()</strong> validates CSRF tokens to ensure requests are legitimate.</p>
        <p>CSRF tokens should be included in forms and validated on the server to prevent unauthorized requests.</p>
    </div>
</body>
</html>`
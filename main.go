package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"

	"github.com/octofelickz/go-hello-privateregistry-dependency"
)

type PageData struct {
	Title   string
	Results map[string]interface{}
	Error   string
}

func main() {
	// Setup routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/html-sanitization", htmlSanitizationHandler)
	http.HandleFunc("/output-encoding", outputEncodingHandler)
	http.HandleFunc("/input-validation", inputValidationHandler)
	http.HandleFunc("/crypto-utils", cryptoUtilsHandler)
	http.HandleFunc("/csrf-protection", csrfProtectionHandler)

	// Serve static files
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static/"))))

	fmt.Println("Starting server on :8080")
	fmt.Println("Visit http://localhost:8080 to see the security helpers demo")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>Go Security Helpers Demo</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .nav { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007bff; }
        .nav a:hover { text-decoration: underline; }
        .feature-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .feature-card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; background: #f8f9fa; }
        .feature-card h3 { margin-top: 0; color: #333; }
        .feature-card ul { padding-left: 20px; }
        .feature-card li { margin-bottom: 5px; }
        h1 { color: #333; text-align: center; }
        .description { text-align: center; margin-bottom: 30px; color: #666; }
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

    <h1>Go Security Helpers Demo</h1>
    <p class="description">
        This web application demonstrates the security helpers from 
        <code>github.com/octofelickz/go-hello-privateregistry-dependency</code>
    </p>

    <div class="feature-grid">
        <div class="feature-card">
            <h3>🧼 HTML Sanitization</h3>
            <p>Prevent XSS attacks with HTML sanitization</p>
            <ul>
                <li>SanitizeHTML() - Strict HTML sanitization</li>
                <li>SanitizeUGC() - User-generated content sanitization</li>
                <li>NewSanitizer() - Custom HTML sanitizer</li>
                <li>NewUGCSanitizer() - Custom UGC sanitizer</li>
            </ul>
        </div>

        <div class="feature-card">
            <h3>🔒 Output Encoding</h3>
            <p>Safe encoding for different contexts</p>
            <ul>
                <li>EncodeHTML() - HTML entity encoding</li>
                <li>EncodeHTMLAttr() - HTML attribute encoding</li>
                <li>EncodeJS() - JavaScript string encoding</li>
                <li>EncodeURL() - URL component encoding</li>
                <li>EncodeCSS() - CSS value encoding</li>
            </ul>
        </div>

        <div class="feature-card">
            <h3>✅ Input Validation</h3>
            <p>Validate and sanitize user input</p>
            <ul>
                <li>ValidateEmail() - Email validation</li>
                <li>ValidateAlphanumeric() - Alphanumeric check</li>
                <li>SanitizeInput() - SQL injection prevention</li>
                <li>SanitizeFilename() - Safe filename cleaning</li>
                <li>LimitLength() - Input length limiting</li>
            </ul>
        </div>

        <div class="feature-card">
            <h3>🔐 Cryptographic Utilities</h3>
            <p>Secure password hashing and token generation</p>
            <ul>
                <li>HashPassword() - bcrypt password hashing</li>
                <li>VerifyPassword() - Password verification</li>
                <li>GenerateSecureToken() - Secure token generation</li>
                <li>GenerateSecureHex() - Secure hex strings</li>
                <li>GenerateSalt() - Cryptographic salt</li>
                <li>DeriveKey() - Key derivation with scrypt</li>
                <li>SecureCompare() - Constant-time comparison</li>
            </ul>
        </div>

        <div class="feature-card">
            <h3>🛡️ CSRF Protection</h3>
            <p>Cross-Site Request Forgery protection</p>
            <ul>
                <li>GenerateCSRFToken() - Generate CSRF tokens</li>
                <li>ValidateCSRFToken() - Validate CSRF tokens</li>
            </ul>
        </div>
    </div>
</body>
</html>`

	t, err := template.New("home").Parse(tmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func htmlSanitizationHandler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:   "HTML Sanitization Demo",
		Results: make(map[string]interface{}),
	}

	if r.Method == "POST" {
		input := r.FormValue("input")
		if input != "" {
			// Demonstrate all HTML sanitization functions
			data.Results["original"] = input
			data.Results["sanitizeHTML"] = gosec.SanitizeHTML(input)
			data.Results["sanitizeUGC"] = gosec.SanitizeUGC(input)
			
			// Custom sanitizers
			strictSanitizer := gosec.NewSanitizer()
			ugcSanitizer := gosec.NewUGCSanitizer()
			data.Results["customStrict"] = strictSanitizer.SanitizeHTML(input)
			data.Results["customUGC"] = ugcSanitizer.SanitizeHTML(input)
		}
	}

	renderTemplate(w, "html-sanitization", data)
}

func outputEncodingHandler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:   "Output Encoding Demo",
		Results: make(map[string]interface{}),
	}

	if r.Method == "POST" {
		input := r.FormValue("input")
		if input != "" {
			data.Results["original"] = input
			data.Results["encodeHTML"] = gosec.EncodeHTML(input)
			data.Results["encodeHTMLAttr"] = gosec.EncodeHTMLAttr(input)
			data.Results["encodeJS"] = gosec.EncodeJS(input)
			data.Results["encodeURL"] = gosec.EncodeURL(input)
			data.Results["encodeCSS"] = gosec.EncodeCSS(input)
		}
	}

	renderTemplate(w, "output-encoding", data)
}

func inputValidationHandler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:   "Input Validation Demo",
		Results: make(map[string]interface{}),
	}

	if r.Method == "POST" {
		email := r.FormValue("email")
		username := r.FormValue("username")
		sqlInput := r.FormValue("sql_input")
		filename := r.FormValue("filename")
		longText := r.FormValue("long_text")
		maxLenStr := r.FormValue("max_length")

		data.Results["validations"] = make(map[string]interface{})

		if email != "" {
			data.Results["validations"].(map[string]interface{})["email"] = map[string]interface{}{
				"input": email,
				"valid": gosec.ValidateEmail(email),
			}
		}

		if username != "" {
			data.Results["validations"].(map[string]interface{})["username"] = map[string]interface{}{
				"input":       username,
				"valid":       gosec.ValidateAlphanumeric(username),
			}
		}

		if sqlInput != "" {
			data.Results["validations"].(map[string]interface{})["sql"] = map[string]interface{}{
				"input":     sqlInput,
				"sanitized": gosec.SanitizeInput(sqlInput),
			}
		}

		if filename != "" {
			data.Results["validations"].(map[string]interface{})["filename"] = map[string]interface{}{
				"input":     filename,
				"sanitized": gosec.SanitizeFilename(filename),
			}
		}

		if longText != "" && maxLenStr != "" {
			maxLen, err := strconv.Atoi(maxLenStr)
			if err == nil && maxLen > 0 {
				data.Results["validations"].(map[string]interface{})["length"] = map[string]interface{}{
					"input":    longText,
					"maxLen":   maxLen,
					"limited":  gosec.LimitLength(longText, maxLen),
				}
			}
		}
	}

	renderTemplate(w, "input-validation", data)
}

func cryptoUtilsHandler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:   "Cryptographic Utilities Demo",
		Results: make(map[string]interface{}),
	}

	if r.Method == "POST" {
		action := r.FormValue("action")
		
		switch action {
		case "hash_password":
			password := r.FormValue("password")
			if password != "" {
				hash, err := gosec.HashPassword(password)
				if err != nil {
					data.Error = err.Error()
				} else {
					data.Results["password"] = password
					data.Results["hash"] = hash
					data.Results["verified"] = gosec.VerifyPassword(password, hash)
				}
			}
			
		case "generate_tokens":
			tokenSize := 32
			if sizeStr := r.FormValue("token_size"); sizeStr != "" {
				if size, err := strconv.Atoi(sizeStr); err == nil && size > 0 && size <= 128 {
					tokenSize = size
				}
			}
			
			token, err := gosec.GenerateSecureToken(tokenSize)
			if err != nil {
				data.Error = err.Error()
			} else {
				data.Results["secureToken"] = token
			}
			
			hexToken, err := gosec.GenerateSecureHex(tokenSize)
			if err != nil {
				data.Error = err.Error()
			} else {
				data.Results["secureHex"] = hexToken
			}
			
		case "key_derivation":
			password := r.FormValue("derive_password")
			if password != "" {
				salt, err := gosec.GenerateSalt(16)
				if err != nil {
					data.Error = err.Error()
				} else {
					key, err := gosec.DeriveKey([]byte(password), salt, 32)
					if err != nil {
						data.Error = err.Error()
					} else {
						data.Results["password"] = password
						data.Results["salt"] = fmt.Sprintf("%x", salt)
						data.Results["derivedKey"] = fmt.Sprintf("%x", key)
					}
				}
			}
			
		case "secure_compare":
			str1 := r.FormValue("string1")
			str2 := r.FormValue("string2")
			if str1 != "" && str2 != "" {
				data.Results["string1"] = str1
				data.Results["string2"] = str2
				data.Results["secureEqual"] = gosec.SecureCompare(str1, str2)
				data.Results["regularEqual"] = str1 == str2
			}
		}
	}

	renderTemplate(w, "crypto-utils", data)
}

func csrfProtectionHandler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:   "CSRF Protection Demo",
		Results: make(map[string]interface{}),
	}

	if r.Method == "POST" {
		action := r.FormValue("action")
		
		switch action {
		case "generate":
			token, err := gosec.GenerateCSRFToken()
			if err != nil {
				data.Error = err.Error()
			} else {
				data.Results["generatedToken"] = token
			}
			
		case "validate":
			token := r.FormValue("token")
			secret := r.FormValue("secret")
			if token != "" && secret != "" {
				isValid := gosec.ValidateCSRFToken(token, secret)
				data.Results["token"] = token
				data.Results["secret"] = secret
				data.Results["valid"] = isValid
			}
		}
	}

	renderTemplate(w, "csrf-protection", data)
}

func renderTemplate(w http.ResponseWriter, templateName string, data PageData) {
	var tmpl string
	
	switch templateName {
	case "html-sanitization":
		tmpl = htmlSanitizationTemplate
	case "output-encoding":
		tmpl = outputEncodingTemplate
	case "input-validation":
		tmpl = inputValidationTemplate
	case "crypto-utils":
		tmpl = cryptoUtilsTemplate
	case "csrf-protection":
		tmpl = csrfProtectionTemplate
	default:
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}

	t, err := template.New(templateName).Parse(tmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
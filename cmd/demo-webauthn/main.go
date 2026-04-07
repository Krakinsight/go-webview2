package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"time"

	"github.com/Krakinsight/go-webview2"
)

func main() {
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     true,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "WebAuthn Bridge Demo",
			Width:  900,
			Height: 700,
			Center: true,
		},
	})

	if w == nil {
		log.Fatalln("Failed to load webview.")
	}
	defer w.Destroy()

	// Create in-memory credential store
	store := webview2.NewInMemoryCredentialStore()

	// Enable WebAuthn bridge
	bridge := w.EnableWebAuthnBridge()
	bridge.SetCredentialStore(store)
	bridge.SetTimeout(60 * time.Second)

	// Set up credential creation handler
	bridge.SetCreateHandler(func(ctx context.Context, opts webview2.WebAuthnCreateOptions) (webview2.WebAuthnCredential, error) {
		return handleCreateCredential(ctx, opts, store)
	})

	// Set up credential get/assertion handler
	bridge.SetGetHandler(func(ctx context.Context, opts webview2.WebAuthnGetOptions) (webview2.WebAuthnAssertion, error) {
		return handleGetCredential(ctx, opts, store)
	})

	// Set up availability check handler
	bridge.SetIsAvailableHandler(func() bool {
		return true // WebAuthn is always available in this demo
	})

	// Log Windows Hello availability
	if webview2.IsWebAuthnDLLAvailable() {
		version, _ := webview2.GetWebAuthnAPIVersion()
		log.Printf("Windows Hello is available (WebAuthn API version: %d)", version)
	} else {
		log.Printf("Windows Hello (webauthn.dll) not available - using mock implementation")
	}

	w.SetHtml(demoHTML)
	w.Run()
}

func handleCreateCredential(ctx context.Context, opts webview2.WebAuthnCreateOptions, store webview2.CredentialStore) (webview2.WebAuthnCredential, error) {
	log.Printf("Creating credential for user: %s (display: %s)", opts.User.Name, opts.User.DisplayName)
	log.Printf("Relying Party: %s", opts.RP.Name)

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return webview2.WebAuthnCredential{}, ctx.Err()
	default:
	}

	// Generate a random credential ID
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		return webview2.WebAuthnCredential{}, err
	}
	credIDBase64 := base64.RawURLEncoding.EncodeToString(credentialID)

	// For demo purposes, generate a mock public key (COSE format would be used in production)
	publicKey := make([]byte, 65) // Mock ECDSA P-256 public key
	if _, err := rand.Read(publicKey); err != nil {
		return webview2.WebAuthnCredential{}, err
	}

	// Create client data JSON
	clientData := map[string]interface{}{
		"type":      "webauthn.create",
		"challenge": opts.Challenge,
		"origin":    "http://localhost",
	}
	clientDataJSON, _ := json.Marshal(clientData)
	clientDataBase64 := base64.RawURLEncoding.EncodeToString(clientDataJSON)

	// Create a mock attestation object (simplified)
	// In a real implementation, this would be a CBOR-encoded attestation
	authData := make([]byte, 37) // RP ID hash (32) + flags (1) + counter (4)
	rpIDHash := sha256.Sum256([]byte(opts.RP.Name))
	copy(authData[0:32], rpIDHash[:])
	authData[32] = 0x41 // Flags: UP (user present) and AT (attested credential data)

	// For demo, create a simplified attestation object
	attestationObj := append(authData, credentialID...)
	attestationObj = append(attestationObj, publicKey...)
	attestationBase64 := base64.RawURLEncoding.EncodeToString(attestationObj)

	// Store the credential
	storedCred := webview2.StoredCredential{
		ID:        credIDBase64,
		RPID:      opts.RP.ID,
		UserID:    opts.User.ID,
		UserName:  opts.User.Name,
		PublicKey: publicKey,
		SignCount: 0,
		CreatedAt: time.Now(),
	}

	if err := store.Save(storedCred); err != nil {
		return webview2.WebAuthnCredential{}, err
	}

	log.Printf("✓ Credential created successfully (ID: %s...)", credIDBase64[:8])

	return webview2.WebAuthnCredential{
		ID:    credIDBase64,
		RawID: credIDBase64,
		Type:  "public-key",
		Response: webview2.CredentialResponse{
			ClientDataJSON:    clientDataBase64,
			AttestationObject: attestationBase64,
		},
	}, nil
}

func handleGetCredential(ctx context.Context, opts webview2.WebAuthnGetOptions, store webview2.CredentialStore) (webview2.WebAuthnAssertion, error) {
	log.Printf("Getting credential assertion for RP: %s", opts.RPID)

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return webview2.WebAuthnAssertion{}, ctx.Err()
	default:
	}

	// Find matching credentials
	var matchedCred webview2.StoredCredential
	var found bool

	if len(opts.AllowCredentials) > 0 {
		// Look for a specific credential
		for _, allowedID := range opts.AllowCredentials {
			cred, err := store.Load(allowedID)
			if err == nil {
				matchedCred = cred
				found = true
				break
			}
		}
	} else {
		// Return any credential for this RP
		creds, err := store.LoadAll(opts.RPID)
		if err == nil && len(creds) > 0 {
			matchedCred = creds[0]
			found = true
		}
	}

	if !found {
		log.Printf("✗ No matching credential found")
		return webview2.WebAuthnAssertion{}, nil
	}

	log.Printf("✓ Found credential: %s (user: %s)", matchedCred.ID[:8]+"...", matchedCred.UserName)

	// Create client data JSON
	clientData := map[string]interface{}{
		"type":      "webauthn.get",
		"challenge": opts.Challenge,
		"origin":    "http://localhost",
	}
	clientDataJSON, _ := json.Marshal(clientData)
	clientDataBase64 := base64.RawURLEncoding.EncodeToString(clientDataJSON)

	// Create authenticator data
	authData := make([]byte, 37)
	rpIDHash := sha256.Sum256([]byte(opts.RPID))
	copy(authData[0:32], rpIDHash[:])
	authData[32] = 0x01 // Flags: UP (user present)

	// Update sign count
	matchedCred.SignCount++
	if err := store.Save(matchedCred); err != nil {
		return webview2.WebAuthnAssertion{}, err
	}

	authData[33] = byte(matchedCred.SignCount >> 24)
	authData[34] = byte(matchedCred.SignCount >> 16)
	authData[35] = byte(matchedCred.SignCount >> 8)
	authData[36] = byte(matchedCred.SignCount)

	authDataBase64 := base64.RawURLEncoding.EncodeToString(authData)

	// Create a mock signature (in real implementation, sign with private key)
	signature := make([]byte, 64) // Mock ECDSA signature
	if _, err := rand.Read(signature); err != nil {
		return webview2.WebAuthnAssertion{}, err
	}
	signatureBase64 := base64.RawURLEncoding.EncodeToString(signature)

	return webview2.WebAuthnAssertion{
		ID:    matchedCred.ID,
		RawID: matchedCred.ID,
		Type:  "public-key",
		Response: webview2.AssertionResponse{
			ClientDataJSON:    clientDataBase64,
			AuthenticatorData: authDataBase64,
			Signature:         signatureBase64,
			UserHandle:        matchedCred.UserID,
		},
	}, nil
}

const demoHTML = `
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>WebAuthn Bridge Demo</title>
	<style>
		* {
			box-sizing: border-box;
			margin: 0;
			padding: 0;
		}

		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			min-height: 100vh;
			padding: 20px;
		}

		.container {
			max-width: 800px;
			margin: 0 auto;
			background: white;
			border-radius: 15px;
			box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
			overflow: hidden;
		}

		.header {
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			color: white;
			padding: 30px;
			text-align: center;
		}

		.header h1 {
			font-size: 2em;
			margin-bottom: 10px;
		}

		.header p {
			opacity: 0.9;
			font-size: 1.1em;
		}

		.content {
			padding: 30px;
		}

		.section {
			margin-bottom: 30px;
		}

		.section h2 {
			color: #333;
			margin-bottom: 15px;
			font-size: 1.5em;
			border-bottom: 2px solid #667eea;
			padding-bottom: 10px;
		}

		.info-box {
			background: #e7f3ff;
			border-left: 4px solid #2196F3;
			padding: 15px;
			margin-bottom: 20px;
			border-radius: 5px;
		}

		.info-box strong {
			color: #2196F3;
		}

		.form-group {
			margin-bottom: 15px;
		}

		.form-group label {
			display: block;
			margin-bottom: 5px;
			font-weight: 600;
			color: #555;
		}

		.form-group input {
			width: 100%;
			padding: 10px;
			border: 2px solid #ddd;
			border-radius: 5px;
			font-size: 1em;
			transition: border-color 0.3s;
		}

		.form-group input:focus {
			outline: none;
			border-color: #667eea;
		}

		button {
			background: #667eea;
			color: white;
			border: none;
			padding: 12px 30px;
			font-size: 1em;
			font-weight: 600;
			border-radius: 8px;
			cursor: pointer;
			transition: all 0.3s ease;
			margin-right: 10px;
			margin-bottom: 10px;
		}

		button:hover {
			background: #5568d3;
			transform: translateY(-2px);
			box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
		}

		button:active {
			transform: translateY(0);
		}

		button:disabled {
			background: #ccc;
			cursor: not-allowed;
			transform: none;
		}

		.log {
			background: #f5f5f5;
			border: 1px solid #ddd;
			border-radius: 5px;
			padding: 15px;
			max-height: 300px;
			overflow-y: auto;
			font-family: 'Courier New', monospace;
			font-size: 0.9em;
		}

		.log-entry {
			padding: 5px 0;
			border-bottom: 1px solid #e0e0e0;
		}

		.log-entry:last-child {
			border-bottom: none;
		}

		.log-entry.success {
			color: #4caf50;
		}

		.log-entry.error {
			color: #f44336;
		}

		.log-entry.info {
			color: #2196F3;
		}

		.status {
			display: inline-block;
			padding: 5px 10px;
			border-radius: 5px;
			font-size: 0.9em;
			font-weight: 600;
		}

		.status.available {
			background: #c8e6c9;
			color: #2e7d32;
		}

		.status.unavailable {
			background: #ffcdd2;
			color: #c62828;
		}
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>🔐 WebAuthn Bridge Demo</h1>
			<p>Web Authentication API with Go Bridge</p>
		</div>

		<div class="content">
			<div class="info-box">
				<strong>ℹ️ About:</strong> This demo shows WebAuthn working through a JavaScript-to-Go bridge.
				Since WebView2's sandbox blocks direct access to Windows Hello/FIDO2, the bridge routes
				credential operations through Go handlers.
			</div>

			<div class="section">
				<h2>Status</h2>
				<p>
					WebAuthn API: <span id="status" class="status">Checking...</span>
				</p>
			</div>

			<div class="section">
				<h2>1. Register New Credential</h2>
				<div class="form-group">
					<label>Username:</label>
					<input type="text" id="username" value="testuser" />
				</div>
				<div class="form-group">
					<label>Display Name:</label>
					<input type="text" id="displayName" value="Test User" />
				</div>
				<button onclick="registerCredential()">🔑 Register Credential</button>
			</div>

			<div class="section">
				<h2>2. Authenticate</h2>
				<button onclick="authenticate()">✅ Authenticate</button>
			</div>

			<div class="section">
				<h2>Activity Log</h2>
				<div id="log" class="log">
					<div class="log-entry info">Ready to test WebAuthn...</div>
				</div>
			</div>
		</div>
	</div>

	<script>
		// Utility functions
		function log(message, type = 'info') {
			const logDiv = document.getElementById('log');
			const entry = document.createElement('div');
			entry.className = 'log-entry ' + type;
			const timestamp = new Date().toLocaleTimeString();
			entry.textContent = '[' + timestamp + '] ' + message;
			logDiv.appendChild(entry);
			logDiv.scrollTop = logDiv.scrollHeight;
		}

		function arrayBufferToBase64Url(buffer) {
			const bytes = new Uint8Array(buffer);
			let binary = '';
			for (let i = 0; i < bytes.byteLength; i++) {
				binary += String.fromCharCode(bytes[i]);
			}
			return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
		}

		function base64UrlToArrayBuffer(base64url) {
			const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
			const padding = '='.repeat((4 - base64.length % 4) % 4);
			const binary = atob(base64 + padding);
			const bytes = new Uint8Array(binary.length);
			for (let i = 0; i < binary.length; i++) {
				bytes[i] = binary.charCodeAt(i);
			}
			return bytes.buffer;
		}

		// Check WebAuthn availability
		async function checkWebAuthn() {
			const statusEl = document.getElementById('status');

			if (window.PublicKeyCredential) {
				try {
					const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
					statusEl.textContent = available ? 'Available (Bridge Active)' : 'Available (Limited)';
					statusEl.className = 'status available';
					log('WebAuthn API is available', 'success');
				} catch (error) {
					statusEl.textContent = 'Error';
					statusEl.className = 'status unavailable';
					log('Error checking WebAuthn: ' + error.message, 'error');
				}
			} else {
				statusEl.textContent = 'Not Available';
				statusEl.className = 'status unavailable';
				log('WebAuthn API not found', 'error');
			}
		}

		// Register a new credential
		async function registerCredential() {
			const username = document.getElementById('username').value;
			const displayName = document.getElementById('displayName').value;

			if (!username || !displayName) {
				log('Please enter username and display name', 'error');
				return;
			}

			log('Starting credential registration for: ' + username, 'info');

			try {
				// Create random challenge
				const challenge = new Uint8Array(32);
				crypto.getRandomValues(challenge);

				// Create user ID
				const userId = new Uint8Array(16);
				crypto.getRandomValues(userId);

				const publicKeyOptions = {
					challenge: challenge,
					rp: {
						name: "WebAuthn Demo",
						id: "localhost"
					},
					user: {
						id: userId,
						name: username,
						displayName: displayName
					},
					pubKeyCredParams: [
						{ type: "public-key", alg: -7 },  // ES256
						{ type: "public-key", alg: -257 } // RS256
					],
					authenticatorSelection: {
						userVerification: "preferred"
					},
					timeout: 60000,
					attestation: "direct"
				};

				log('Calling navigator.credentials.create()...', 'info');
				const credential = await navigator.credentials.create({
					publicKey: publicKeyOptions
				});

				log('✓ Credential created successfully!', 'success');
				log('  Credential ID: ' + credential.id.substring(0, 16) + '...', 'success');
				log('  Type: ' + credential.type, 'success');

				// Store credential ID for later authentication
				window.lastCredentialId = credential.rawId;

			} catch (error) {
				log('✗ Registration failed: ' + error.message, 'error');
				console.error(error);
			}
		}

		// Authenticate with existing credential
		async function authenticate() {
			log('Starting authentication...', 'info');

			try {
				// Create random challenge
				const challenge = new Uint8Array(32);
				crypto.getRandomValues(challenge);

				const publicKeyOptions = {
					challenge: challenge,
					rpId: "localhost",
					timeout: 60000,
					userVerification: "preferred"
				};

				// If we have a stored credential, use it
				if (window.lastCredentialId) {
					publicKeyOptions.allowCredentials = [{
						type: "public-key",
						id: window.lastCredentialId
					}];
					log('Using previously registered credential', 'info');
				} else {
					log('No specific credential specified, using any available', 'info');
				}

				log('Calling navigator.credentials.get()...', 'info');
				const assertion = await navigator.credentials.get({
					publicKey: publicKeyOptions
				});

				log('✓ Authentication successful!', 'success');
				log('  Credential ID: ' + assertion.id.substring(0, 16) + '...', 'success');
				log('  Type: ' + assertion.type, 'success');
				log('  Signature length: ' + assertion.response.signature.byteLength + ' bytes', 'success');

			} catch (error) {
				log('✗ Authentication failed: ' + error.message, 'error');
				console.error(error);
			}
		}

		// Initialize on load
		window.addEventListener('load', () => {
			checkWebAuthn();
		});
	</script>
</body>
</html>
`

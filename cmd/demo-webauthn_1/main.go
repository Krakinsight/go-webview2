package main

import (
	"errors"
	"log"
	"syscall"
	"time"
	"unsafe"

	"github.com/Krakinsight/go-webview2"
)

func main() {
	w,_ := webview2.NewWithOptions(webview2.WebViewOptions{
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

	// Enable WebAuthn bridge
	bridge := w.EnableWebAuthnBridge()
	bridge.SetTimeout(60 * time.Second)

	// Step 1: Optional gate — returning true cancels the operation.
	// Returning false (or nil callback) proceeds to Windows Hello.
	bridge.OnUserApproval = func(op webview2.WebAuthnOperation) bool {
		log.Printf("WebAuthn gate: Type=%s, RPID=%s", op.Type, op.RPID)

		result := messageBox(
			0,
			"WebAuthn operation requested\n\n"+
				"Type: "+op.Type+"\n"+
				"RP: "+op.RPName+" ("+op.RPID+")\n\n"+
				"Click Cancel to abort.",
			"WebAuthn",
			0x00000001|0x00000020, // MB_OKCANCEL | MB_ICONQUESTION
		)

		cancelled := result != 1 // IDOK=1 → not cancelled; anything else → cancelled
		if cancelled {
			log.Println("Operation cancelled by user")
		}
		return cancelled // true = abort
	}

	// Step 3: Called when Windows Hello fails.
	// If no credential exists yet (NTE_NO_KEY), silently fall back to internal ECDSA.
	// For any other failure, ask the user.
	bridge.OnWindowsHelloFallback = func(op webview2.WebAuthnOperation, whErr error) bool {
		if errors.Is(whErr, webview2.ErrWindowsHelloNoCredential) {
			log.Println("No Windows Hello credential found, using internal ECDSA fallback")
			return true
		}

		log.Printf("Windows Hello failed (%v), offering ECDSA fallback", whErr)
		result := messageBox(
			0,
			"Windows Hello failed:\n"+whErr.Error()+"\n\nUse software ECDSA fallback instead?",
			"Windows Hello Failed",
			0x00000001|0x00000030, // MB_OKCANCEL | MB_ICONWARNING
		)
		use := result == 1
		if use {
			log.Println("Using internal ECDSA fallback")
		}
		return use
	}

	// Log Windows Hello availability
	if webview2.IsWebAuthnDLLAvailable() {
		version, _ := webview2.GetWebAuthnAPIVersion()
		log.Printf("Windows Hello is available (WebAuthn API version: %d)", version)
		bridge.OnUserApproval = nil // Use automatic Windows Hello fallback without custom approval dialog
	} else {
		log.Printf("Windows Hello (webauthn.dll) not available")
	}

	w.SetHtml(demoHTML)
	w.Run()
}

// messageBox wraps Windows MessageBox API for approval dialogs
func messageBox(hwnd uintptr, text, caption string, flags uint32) int {
	user32 := syscall.MustLoadDLL("user32.dll")
	messageBoxW := user32.MustFindProc("MessageBoxW")

	textUTF16, _ := syscall.UTF16PtrFromString(text)
	captionUTF16, _ := syscall.UTF16PtrFromString(caption)

	ret, _, _ := messageBoxW.Call(
		hwnd,
		uintptr(unsafe.Pointer(textUTF16)),
		uintptr(unsafe.Pointer(captionUTF16)),
		uintptr(flags),
	)

	return int(ret)
}

// unsafePointer converts a pointer to unsafe.Pointer
func unsafePointer(p *uint16) uintptr {
	return uintptr(unsafe.Pointer(p))
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
				The bridge supports two modes: automatic Windows Hello fallback (OnUserApproval == nil)
				or custom approval dialog with internal/Windows Hello choice.
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
					<input type="text" id="username" value="testuser@example.com" />
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
						authenticatorAttachment: "platform",
						userVerification: "preferred"
					},
					timeout: 60000,
					attestation: "none"
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

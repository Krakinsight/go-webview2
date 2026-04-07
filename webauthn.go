//go:build windows
// +build windows

package webview2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// WebAuthnUser represents user information for WebAuthn operations
type WebAuthnUser struct {
	ID          string // User ID (base64url encoded)
	Name        string // User name (email)
	DisplayName string // Display name
}

// WebAuthnOperation describes what is being requested, passed to the approval callback
type WebAuthnOperation struct {
	Type   string       // "create" or "get"
	RPID   string       // Relying Party ID
	RPName string       // Relying Party Name
	User   WebAuthnUser // Empty for "get" operations
}

// WebAuthnBridge provides a JavaScript bridge for WebAuthn functionality.
// Since WebView2's sandbox blocks access to the platform authenticator (Windows Hello/FIDO2),
// this bridge intercepts navigator.credentials calls and routes them through Go handlers.
//
// The bridge supports three modes:
// 1. OnUserApproval == nil: Direct fallback to webauthn.dll (Windows Hello)
// 2. OnUserApproval returns false: Fallback to webauthn.dll
// 3. OnUserApproval returns true: Use internal implementation with encrypted storage
type WebAuthnBridge struct {
	// OnUserApproval is called to ask if the operation should be handled internally.
	// - nil: bypass directly to webauthn.dll
	// - returns true: use internal implementation with encrypted storage
	// - returns false: fallback to webauthn.dll (Windows Hello)
	OnUserApproval func(op WebAuthnOperation) bool

	webview WebView
	store   *fileCredentialStore // Internal encrypted storage
	timeout time.Duration
	mu      sync.Mutex
	pending bool // Only one WebAuthn operation at a time
}

// WebAuthnCreateOptions represents the options for creating a new credential
type WebAuthnCreateOptions struct {
	Challenge              string                 `json:"challenge"`
	RP                     RelyingParty           `json:"rp"`
	User                   User                   `json:"user"`
	PubKeyCredParams       []PubKeyCredParam      `json:"pubKeyCredParams"`
	AuthenticatorSelection AuthenticatorSelection `json:"authenticatorSelection,omitempty"`
	ExcludeCredentials     []string               `json:"excludeCredentials,omitempty"`
	Timeout                int                    `json:"timeout,omitempty"`
	Attestation            string                 `json:"attestation,omitempty"`
}

// WebAuthnGetOptions represents the options for getting an assertion
type WebAuthnGetOptions struct {
	Challenge        string   `json:"challenge"`
	RPID             string   `json:"rpId,omitempty"`
	AllowCredentials []string `json:"allowCredentials,omitempty"`
	Timeout          int      `json:"timeout,omitempty"`
	UserVerification string   `json:"userVerification,omitempty"`
}

// RelyingParty represents the relying party information
type RelyingParty struct {
	Name string `json:"name"`
	ID   string `json:"id,omitempty"`
}

// User represents the user information
type User struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// PubKeyCredParam represents a public key credential parameter
type PubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

// AuthenticatorSelection represents authenticator selection criteria
type AuthenticatorSelection struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	RequireResidentKey      bool   `json:"requireResidentKey,omitempty"`
	UserVerification        string `json:"userVerification,omitempty"`
}

// WebAuthnCredential represents a created credential
type WebAuthnCredential struct {
	ID       string                 `json:"id"`
	RawID    string                 `json:"rawId"`
	Type     string                 `json:"type"`
	Response CredentialResponse     `json:"response"`
}

// CredentialResponse contains the credential response data
type CredentialResponse struct {
	ClientDataJSON    string   `json:"clientDataJSON"`
	AttestationObject string   `json:"attestationObject"`
}

// WebAuthnAssertion represents an assertion result
type WebAuthnAssertion struct {
	ID       string            `json:"id"`
	RawID    string            `json:"rawId"`
	Type     string            `json:"type"`
	Response AssertionResponse `json:"response"`
}

// AssertionResponse contains the assertion response data
type AssertionResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

// EnableWebAuthnBridge enables the WebAuthn bridge on the webview.
// This injects JavaScript that intercepts navigator.credentials calls and routes them through Go handlers.
func (w *webview) EnableWebAuthnBridge() *WebAuthnBridge {
	// Initialize internal encrypted store
	store, err := newFileCredentialStore()
	if err != nil {
		log.Printf("Warning: Failed to initialize credential store: %v", err)
	}

	bridge := &WebAuthnBridge{
		webview: w,
		store:   store,
		timeout: 60 * time.Second, // Default 60 second timeout
	}

	// Bind the WebAuthn functions
	w.Bind("__webauthn_create", bridge.handleCreate)
	w.Bind("__webauthn_get", bridge.handleGet)
	w.Bind("__webauthn_isAvailable", bridge.handleIsAvailable)

	// Inject the WebAuthn bridge JavaScript
	w.Init(webauthnBridgeJS)

	return bridge
}

// SetTimeout sets the timeout for WebAuthn operations
func (b *WebAuthnBridge) SetTimeout(timeout time.Duration) {
	b.timeout = timeout
}

// handleCreate handles the credential creation call from JavaScript
func (b *WebAuthnBridge) handleCreate(optionsJSON string) (string, error) {
	// Check if an operation is already pending
	b.mu.Lock()
	if b.pending {
		b.mu.Unlock()
		return "", errors.New("WebAuthn operation already in progress")
	}
	b.pending = true
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		b.pending = false
		b.mu.Unlock()
	}()

	var options WebAuthnCreateOptions
	if err := json.Unmarshal([]byte(optionsJSON), &options); err != nil {
		return "", fmt.Errorf("failed to parse create options: %w", err)
	}

	log.Printf("WebAuthn Create request: RP=%s, User=%s", options.RP.Name, options.User.Name)

	// Create operation description for approval callback
	op := WebAuthnOperation{
		Type:   "create",
		RPID:   options.RP.ID,
		RPName: options.RP.Name,
		User: WebAuthnUser{
			ID:          options.User.ID,
			Name:        options.User.Name,
			DisplayName: options.User.DisplayName,
		},
	}

	// Determine handling strategy
	var credential WebAuthnCredential
	var err error

	if b.OnUserApproval == nil {
		// Case 1: No approval callback → fallback to webauthn.dll
		log.Printf("No approval callback, using webauthn.dll fallback")
		credential, err = b.fallbackToWindowsHello(options, WebAuthnGetOptions{})
	} else if !b.OnUserApproval(op) {
		// Case 2: Approval callback returns false → fallback to webauthn.dll
		log.Printf("User approval denied, using webauthn.dll fallback")
		credential, err = b.fallbackToWindowsHello(options, WebAuthnGetOptions{})
	} else {
		// Case 3: Approval callback returns true → use internal implementation
		log.Printf("User approved, using internal implementation")
		credential, err = b.handleCreateInternal(options)
	}

	if err != nil {
		return "", err
	}

	result, err := json.Marshal(credential)
	if err != nil {
		return "", fmt.Errorf("failed to marshal credential: %w", err)
	}

	return string(result), nil
}

// handleGet handles the assertion request from JavaScript
func (b *WebAuthnBridge) handleGet(optionsJSON string) (string, error) {
	// Check if an operation is already pending
	b.mu.Lock()
	if b.pending {
		b.mu.Unlock()
		return "", errors.New("WebAuthn operation already in progress")
	}
	b.pending = true
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		b.pending = false
		b.mu.Unlock()
	}()

	var options WebAuthnGetOptions
	if err := json.Unmarshal([]byte(optionsJSON), &options); err != nil {
		return "", fmt.Errorf("failed to parse get options: %w", err)
	}

	log.Printf("WebAuthn Get request: RPID=%s", options.RPID)

	// Create operation description for approval callback (user info is empty for "get")
	op := WebAuthnOperation{
		Type:   "get",
		RPID:   options.RPID,
		RPName: options.RPID, // Use RPID as name for "get" operations
		User:   WebAuthnUser{}, // Empty for "get"
	}

	// Determine handling strategy
	var assertion WebAuthnAssertion
	var err error

	if b.OnUserApproval == nil {
		// Case 1: No approval callback → fallback to webauthn.dll
		log.Printf("No approval callback, using webauthn.dll fallback")
		assertion, err = b.fallbackToWindowsHelloGet(options)
	} else if !b.OnUserApproval(op) {
		// Case 2: Approval callback returns false → fallback to webauthn.dll
		log.Printf("User approval denied, using webauthn.dll fallback")
		assertion, err = b.fallbackToWindowsHelloGet(options)
	} else {
		// Case 3: Approval callback returns true → use internal implementation
		log.Printf("User approved, using internal implementation")
		assertion, err = b.handleGetInternal(options)
	}

	if err != nil {
		return "", err
	}

	result, err := json.Marshal(assertion)
	if err != nil {
		return "", fmt.Errorf("failed to marshal assertion: %w", err)
	}

	return string(result), nil
}

// handleIsAvailable handles the availability check from JavaScript
func (b *WebAuthnBridge) handleIsAvailable() bool {
	// WebAuthn is available if either internal store works or webauthn.dll is available
	return b.store != nil || IsWebAuthnDLLAvailable()
}

// handleCreateInternal implements credential creation using internal storage
func (b *WebAuthnBridge) handleCreateInternal(options WebAuthnCreateOptions) (WebAuthnCredential, error) {
	if b.store == nil {
		return WebAuthnCredential{}, errors.New("internal credential store not available")
	}

	// Generate credential ID
	credentialID := make([]byte, 32)
	if _, err := randomBytes(credentialID); err != nil {
		return WebAuthnCredential{}, err
	}
	credIDBase64 := base64URLEncode(credentialID)

	// Generate key pair (simplified - in production use proper COSE encoding)
	privateKey := make([]byte, 32)
	if _, err := randomBytes(privateKey); err != nil {
		return WebAuthnCredential{}, err
	}

	publicKey := make([]byte, 65) // Mock ECDSA P-256 public key
	if _, err := randomBytes(publicKey); err != nil {
		return WebAuthnCredential{}, err
	}

	// Create client data JSON
	clientData := map[string]interface{}{
		"type":      "webauthn.create",
		"challenge": options.Challenge,
		"origin":    "http://localhost",
	}
	clientDataJSON, _ := json.Marshal(clientData)
	clientDataBase64 := base64URLEncode(clientDataJSON)

	// Create attestation object (simplified)
	authData := make([]byte, 37)
	// RP ID hash would go here
	authData[32] = 0x41 // Flags: UP + AT
	attestationObj := append(authData, credentialID...)
	attestationObj = append(attestationObj, publicKey...)
	attestationBase64 := base64URLEncode(attestationObj)

	// Store credential
	cred := storedCredential{
		ID:         credIDBase64,
		RPID:       options.RP.ID,
		UserID:     options.User.ID,
		UserName:   options.User.Name,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		SignCount:  0,
		CreatedAt:  time.Now(),
	}

	if err := b.store.save(cred); err != nil {
		return WebAuthnCredential{}, err
	}

	return WebAuthnCredential{
		ID:    credIDBase64,
		RawID: credIDBase64,
		Type:  "public-key",
		Response: CredentialResponse{
			ClientDataJSON:    clientDataBase64,
			AttestationObject: attestationBase64,
		},
	}, nil
}

// handleGetInternal implements assertion using internal storage
func (b *WebAuthnBridge) handleGetInternal(options WebAuthnGetOptions) (WebAuthnAssertion, error) {
	if b.store == nil {
		return WebAuthnAssertion{}, errors.New("internal credential store not available")
	}

	// Find matching credential
	var cred storedCredential
	var found bool

	if len(options.AllowCredentials) > 0 {
		for _, allowedID := range options.AllowCredentials {
			c, err := b.store.load(allowedID)
			if err == nil {
				cred = c
				found = true
				break
			}
		}
	} else {
		creds, err := b.store.loadAllByRP(options.RPID)
		if err == nil && len(creds) > 0 {
			cred = creds[0]
			found = true
		}
	}

	if !found {
		return WebAuthnAssertion{}, errors.New("no matching credential found")
	}

	// Create client data JSON
	clientData := map[string]interface{}{
		"type":      "webauthn.get",
		"challenge": options.Challenge,
		"origin":    "http://localhost",
	}
	clientDataJSON, _ := json.Marshal(clientData)
	clientDataBase64 := base64URLEncode(clientDataJSON)

	// Create authenticator data
	authData := make([]byte, 37)
	authData[32] = 0x01 // Flags: UP

	// Update sign count
	cred.SignCount++
	authData[33] = byte(cred.SignCount >> 24)
	authData[34] = byte(cred.SignCount >> 16)
	authData[35] = byte(cred.SignCount >> 8)
	authData[36] = byte(cred.SignCount)

	if err := b.store.save(cred); err != nil {
		return WebAuthnAssertion{}, err
	}

	authDataBase64 := base64URLEncode(authData)

	// Create signature (simplified)
	signature := make([]byte, 64)
	if _, err := randomBytes(signature); err != nil {
		return WebAuthnAssertion{}, err
	}
	signatureBase64 := base64URLEncode(signature)

	return WebAuthnAssertion{
		ID:    cred.ID,
		RawID: cred.ID,
		Type:  "public-key",
		Response: AssertionResponse{
			ClientDataJSON:    clientDataBase64,
			AuthenticatorData: authDataBase64,
			Signature:         signatureBase64,
			UserHandle:        cred.UserID,
		},
	}, nil
}

// fallbackToWindowsHello calls webauthn.dll for credential creation
func (b *WebAuthnBridge) fallbackToWindowsHello(createOpts WebAuthnCreateOptions, _ WebAuthnGetOptions) (WebAuthnCredential, error) {
	if !IsWebAuthnDLLAvailable() {
		return WebAuthnCredential{}, errors.New("webauthn.dll not available")
	}

	// Get window handle from webview
	hwnd := b.getHWND()
	if hwnd == 0 {
		return WebAuthnCredential{}, errors.New("could not get window handle")
	}

	// Call Windows Hello via syscall
	return syscallMakeCredential(hwnd, createOpts)
}

// fallbackToWindowsHelloGet calls webauthn.dll for assertion
func (b *WebAuthnBridge) fallbackToWindowsHelloGet(opts WebAuthnGetOptions) (WebAuthnAssertion, error) {
	if !IsWebAuthnDLLAvailable() {
		return WebAuthnAssertion{}, errors.New("webauthn.dll not available")
	}

	// Get window handle from webview
	hwnd := b.getHWND()
	if hwnd == 0 {
		return WebAuthnAssertion{}, errors.New("could not get window handle")
	}

	// Call Windows Hello via syscall
	return syscallGetAssertion(hwnd, opts)
}

// getHWND retrieves the window handle from the webview
func (b *WebAuthnBridge) getHWND() uintptr {
	if wv, ok := b.webview.(*webview); ok {
		return wv.hwnd
	}
	return 0
}

// Helper functions for base64url encoding/decoding
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// randomBytes fills the byte slice with random data
func randomBytes(b []byte) (int, error) {
	return rand.Read(b)
}

// webauthnBridgeJS is the JavaScript code that intercepts WebAuthn API calls
const webauthnBridgeJS = `
(function() {
	'use strict';

	// Store the original credentials API if it exists
	const originalCredentials = navigator.credentials;

	// Helper function to convert ArrayBuffer to base64url
	function arrayBufferToBase64Url(buffer) {
		const bytes = new Uint8Array(buffer);
		let binary = '';
		for (let i = 0; i < bytes.byteLength; i++) {
			binary += String.fromCharCode(bytes[i]);
		}
		return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
	}

	// Helper function to convert base64url to ArrayBuffer
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

	// Helper to convert options for transmission to Go
	function serializeCreateOptions(options) {
		const serialized = {
			challenge: arrayBufferToBase64Url(options.challenge),
			rp: options.rp,
			user: {
				id: arrayBufferToBase64Url(options.user.id),
				name: options.user.name,
				displayName: options.user.displayName
			},
			pubKeyCredParams: options.pubKeyCredParams || []
		};

		if (options.authenticatorSelection) {
			serialized.authenticatorSelection = options.authenticatorSelection;
		}
		if (options.excludeCredentials && options.excludeCredentials.length > 0) {
			serialized.excludeCredentials = options.excludeCredentials.map(cred =>
				arrayBufferToBase64Url(cred.id)
			);
		}
		if (options.timeout) {
			serialized.timeout = options.timeout;
		}
		if (options.attestation) {
			serialized.attestation = options.attestation;
		}

		return serialized;
	}

	function serializeGetOptions(options) {
		const serialized = {
			challenge: arrayBufferToBase64Url(options.challenge),
			rpId: options.rpId || '',
			timeout: options.timeout || 60000,
			userVerification: options.userVerification || 'preferred'
		};

		if (options.allowCredentials && options.allowCredentials.length > 0) {
			serialized.allowCredentials = options.allowCredentials.map(cred =>
				arrayBufferToBase64Url(cred.id)
			);
		} else {
			serialized.allowCredentials = [];
		}

		return serialized;
	}

	// Create a new credentials API
	const webauthnBridge = {
		async create(options) {
			if (!options || !options.publicKey) {
				throw new DOMException('Invalid options', 'NotSupportedError');
			}

			try {
				// Serialize options for Go
				const serializedOptions = serializeCreateOptions(options.publicKey);

				// Call Go handler
				const resultJSON = await window.__webauthn_create(JSON.stringify(serializedOptions));
				const result = JSON.parse(resultJSON);

				// Convert back to WebAuthn format
				const credential = {
					id: result.id,
					rawId: base64UrlToArrayBuffer(result.rawId),
					type: result.type || 'public-key',
					response: {
						clientDataJSON: base64UrlToArrayBuffer(result.response.clientDataJSON),
						attestationObject: base64UrlToArrayBuffer(result.response.attestationObject)
					}
				};

				// Add getClientExtensionResults method
				credential.getClientExtensionResults = function() { return {}; };

				return credential;
			} catch (error) {
				console.error('WebAuthn create error:', error);
				throw new DOMException(error.message || 'Create failed', 'NotAllowedError');
			}
		},

		async get(options) {
			if (!options || !options.publicKey) {
				throw new DOMException('Invalid options', 'NotSupportedError');
			}

			try {
				// Serialize options for Go
				const serializedOptions = serializeGetOptions(options.publicKey);

				// Call Go handler
				const resultJSON = await window.__webauthn_get(JSON.stringify(serializedOptions));
				const result = JSON.parse(resultJSON);

				// Convert back to WebAuthn format
				const assertion = {
					id: result.id,
					rawId: base64UrlToArrayBuffer(result.rawId),
					type: result.type || 'public-key',
					response: {
						clientDataJSON: base64UrlToArrayBuffer(result.response.clientDataJSON),
						authenticatorData: base64UrlToArrayBuffer(result.response.authenticatorData),
						signature: base64UrlToArrayBuffer(result.response.signature)
					}
				};

				if (result.response.userHandle) {
					assertion.response.userHandle = base64UrlToArrayBuffer(result.response.userHandle);
				}

				// Add getClientExtensionResults method
				assertion.getClientExtensionResults = function() { return {}; };

				return assertion;
			} catch (error) {
				console.error('WebAuthn get error:', error);
				throw new DOMException(error.message || 'Get failed', 'NotAllowedError');
			}
		},

		async preventSilentAccess() {
			// No-op for now
			return;
		}
	};

	// Override navigator.credentials
	Object.defineProperty(navigator, 'credentials', {
		value: webauthnBridge,
		writable: false,
		configurable: true
	});

	// Also check if PublicKeyCredential is available
	if (typeof window.PublicKeyCredential === 'undefined') {
		window.PublicKeyCredential = function() {};
		window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async function() {
			try {
				return await window.__webauthn_isAvailable();
			} catch (error) {
				return true; // Default to available
			}
		};
		window.PublicKeyCredential.isConditionalMediationAvailable = async function() {
			return false; // Not supported yet
		};
	}

	console.log('WebAuthn bridge initialized');
})();
`

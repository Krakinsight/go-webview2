//go:build windows
// +build windows

package webview2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// CredentialStore defines an interface for storing and retrieving WebAuthn credentials.
// This allows applications to choose their own storage backend (SQLite, encrypted files, vault, etc.).
type CredentialStore interface {
	// Save stores a credential
	Save(credential StoredCredential) error

	// Load retrieves a credential by its ID
	Load(credentialID string) (StoredCredential, error)

	// LoadAll retrieves all credentials for a given Relying Party ID
	LoadAll(rpID string) ([]StoredCredential, error)

	// Delete removes a credential
	Delete(credentialID string) error
}

// StoredCredential represents a stored WebAuthn credential
type StoredCredential struct {
	ID        string    // Credential ID (base64url encoded)
	RPID      string    // Relying Party ID
	UserID    string    // User ID (base64url encoded)
	UserName  string    // User name
	PublicKey []byte    // COSE-encoded public key
	SignCount uint32    // Signature counter
	CreatedAt time.Time // Creation timestamp
}

// WebAuthnBridge provides a JavaScript bridge for WebAuthn functionality.
// Since WebView2's sandbox blocks access to the platform authenticator (Windows Hello/FIDO2),
// this bridge allows intercepting WebAuthn calls and handling them through alternative means.
type WebAuthnBridge struct {
	webview            WebView
	createHandler      func(ctx context.Context, options WebAuthnCreateOptions) (WebAuthnCredential, error)
	getHandler         func(ctx context.Context, options WebAuthnGetOptions) (WebAuthnAssertion, error)
	isAvailableHandler func() bool
	store              CredentialStore
	timeout            time.Duration
	mu                 sync.Mutex
	pending            bool // Only one WebAuthn operation at a time
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
	bridge := &WebAuthnBridge{
		webview: w,
		timeout: 60 * time.Second, // Default 60 second timeout
		isAvailableHandler: func() bool {
			// Default: WebAuthn is available
			return true
		},
	}

	// Bind the WebAuthn functions
	w.Bind("__webauthn_create", bridge.handleCreate)
	w.Bind("__webauthn_get", bridge.handleGet)
	w.Bind("__webauthn_isAvailable", bridge.handleIsAvailable)

	// Inject the WebAuthn bridge JavaScript
	w.Init(webauthnBridgeJS)

	return bridge
}

// SetCreateHandler sets a custom handler for credential creation
func (b *WebAuthnBridge) SetCreateHandler(handler func(ctx context.Context, options WebAuthnCreateOptions) (WebAuthnCredential, error)) {
	b.createHandler = handler
}

// SetGetHandler sets a custom handler for credential assertion
func (b *WebAuthnBridge) SetGetHandler(handler func(ctx context.Context, options WebAuthnGetOptions) (WebAuthnAssertion, error)) {
	b.getHandler = handler
}

// SetIsAvailableHandler sets a custom handler for checking WebAuthn availability
func (b *WebAuthnBridge) SetIsAvailableHandler(handler func() bool) {
	b.isAvailableHandler = handler
}

// SetCredentialStore sets the credential store for the bridge
func (b *WebAuthnBridge) SetCredentialStore(store CredentialStore) {
	b.store = store
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

	if b.createHandler == nil {
		return "", errors.New("WebAuthn create handler not set")
	}

	var options WebAuthnCreateOptions
	if err := json.Unmarshal([]byte(optionsJSON), &options); err != nil {
		return "", fmt.Errorf("failed to parse create options: %w", err)
	}

	log.Printf("WebAuthn Create request: RP=%s, User=%s", options.RP.Name, options.User.Name)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
	defer cancel()

	credential, err := b.createHandler(ctx, options)
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

	if b.getHandler == nil {
		return "", errors.New("WebAuthn get handler not set")
	}

	var options WebAuthnGetOptions
	if err := json.Unmarshal([]byte(optionsJSON), &options); err != nil {
		return "", fmt.Errorf("failed to parse get options: %w", err)
	}

	log.Printf("WebAuthn Get request: RPID=%s", options.RPID)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
	defer cancel()

	assertion, err := b.getHandler(ctx, options)
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
	if b.isAvailableHandler == nil {
		return true
	}
	return b.isAvailableHandler()
}

// Helper functions for base64url encoding/decoding
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
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

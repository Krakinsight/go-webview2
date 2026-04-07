//go:build windows
// +build windows

package webview2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
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
	Origin                 string                 `json:"origin,omitempty"` // Page origin for clientDataJSON
}

// WebAuthnGetOptions represents the options for getting an assertion
type WebAuthnGetOptions struct {
	Challenge        string   `json:"challenge"`
	RPID             string   `json:"rpId,omitempty"`
	AllowCredentials []string `json:"allowCredentials,omitempty"`
	Timeout          int      `json:"timeout,omitempty"`
	UserVerification string   `json:"userVerification,omitempty"`
	Origin           string   `json:"origin,omitempty"` // Page origin for clientDataJSON
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

	// Generate ECDSA P-256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return WebAuthnCredential{}, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Encode keys for storage
	privateKeyBytes := encodeECDSAPrivateKey(privateKey)
	publicKeyBytes := encodeCOSEPublicKey(&privateKey.PublicKey)

	// Use provided origin or fallback to localhost
	origin := options.Origin
	if origin == "" {
		origin = "http://localhost"
	}

	// Create client data JSON
	clientData := map[string]interface{}{
		"type":      "webauthn.create",
		"challenge": options.Challenge,
		"origin":    origin,
	}
	clientDataJSON, _ := json.Marshal(clientData)
	clientDataBase64 := base64URLEncode(clientDataJSON)

	// Create authenticator data
	// RP ID hash (32 bytes) + flags (1 byte) + counter (4 bytes) = 37 bytes minimum
	rpIDHash := sha256.Sum256([]byte(options.RP.ID))
	authData := make([]byte, 37)
	copy(authData[0:32], rpIDHash[:])
	authData[32] = 0x45 // Flags: UP (0x01) + UV (0x04) + AT (0x40)

	// For attestation, we need to append: AAGUID (16 bytes) + credID length (2 bytes) + credID + public key
	aaguid := make([]byte, 16) // All zeros for this implementation
	authData = append(authData, aaguid...)

	// Credential ID length (big-endian uint16)
	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credentialID)))
	authData = append(authData, credIDLen...)

	// Credential ID
	authData = append(authData, credentialID...)

	// COSE-encoded public key
	authData = append(authData, publicKeyBytes...)

	// Create attestation object (CBOR-encoded)
	// For simplicity, we'll use "none" attestation format
	// In production, use proper CBOR encoding
	attestationObj := createAttestationObject(authData)
	attestationBase64 := base64URLEncode(attestationObj)

	// Store credential
	cred := storedCredential{
		ID:         credIDBase64,
		RPID:       options.RP.ID,
		UserID:     options.User.ID,
		UserName:   options.User.Name,
		PrivateKey: privateKeyBytes,
		PublicKey:  publicKeyBytes,
		SignCount:  0,
		CreatedAt:  time.Now(),
	}

	if err := b.store.save(cred); err != nil {
		return WebAuthnCredential{}, err
	}

	log.Printf("Created credential with real ECDSA P-256 keypair (ID: %s...)", credIDBase64[:16])

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

// createAttestationObject creates a CBOR-encoded attestation object
func createAttestationObject(authData []byte) []byte {
	// Simple CBOR encoding for attestation object with "none" format
	// {
	//   "fmt": "none",
	//   "authData": <bytes>,
	//   "attStmt": {}
	// }

	// Manual CBOR encoding
	result := []byte{0xa3} // map(3)

	// "fmt" key
	result = append(result, 0x63) // text(3)
	result = append(result, []byte("fmt")...)
	result = append(result, 0x64) // text(4)
	result = append(result, []byte("none")...)

	// "authData" key
	result = append(result, 0x68) // text(8)
	result = append(result, []byte("authData")...)
	// authData bytes
	if len(authData) < 24 {
		result = append(result, byte(0x40|len(authData))) // bytes(n)
	} else if len(authData) < 256 {
		result = append(result, 0x58, byte(len(authData))) // bytes(n)
	} else {
		result = append(result, 0x59) // bytes(uint16)
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(len(authData)))
		result = append(result, lenBytes...)
	}
	result = append(result, authData...)

	// "attStmt" key
	result = append(result, 0x67) // text(7)
	result = append(result, []byte("attStmt")...)
	result = append(result, 0xa0) // empty map

	return result
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

	// Use provided origin or fallback to localhost
	origin := options.Origin
	if origin == "" {
		origin = "http://localhost"
	}

	// Create client data JSON
	clientData := map[string]interface{}{
		"type":      "webauthn.get",
		"challenge": options.Challenge,
		"origin":    origin,
	}
	clientDataJSON, _ := json.Marshal(clientData)
	clientDataBase64 := base64URLEncode(clientDataJSON)

	// Create authenticator data
	rpIDHash := sha256.Sum256([]byte(options.RPID))
	authData := make([]byte, 37)
	copy(authData[0:32], rpIDHash[:])
	authData[32] = 0x05 // Flags: UP (0x01) + UV (0x04)

	// Update sign count
	cred.SignCount++
	binary.BigEndian.PutUint32(authData[33:37], cred.SignCount)

	if err := b.store.save(cred); err != nil {
		return WebAuthnAssertion{}, err
	}

	authDataBase64 := base64URLEncode(authData)

	// Decode private key from storage
	privateKey, err := decodeECDSAPrivateKey(cred.PrivateKey)
	if err != nil {
		return WebAuthnAssertion{}, fmt.Errorf("failed to decode private key: %w", err)
	}

	// Create signature over authenticator data + client data hash
	clientDataHash := sha256.Sum256(clientDataJSON)
	signedData := append(authData, clientDataHash[:]...)

	signature, err := signWithECDSA(privateKey, signedData)
	if err != nil {
		return WebAuthnAssertion{}, fmt.Errorf("failed to sign assertion: %w", err)
	}
	signatureBase64 := base64URLEncode(signature)

	log.Printf("Created assertion with real ECDSA signature (cred ID: %s...)", cred.ID[:16])

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

// encodeCOSEPublicKey encodes an ECDSA P-256 public key in COSE format
// COSE Key format according to RFC 8152
func encodeCOSEPublicKey(pubKey *ecdsa.PublicKey) []byte {
	// COSE Key for ES256 (ECDSA with P-256 and SHA-256)
	// This is a CBOR-encoded map with the following structure:
	// {
	//   1: 2,        // kty: EC2 key type
	//   3: -7,       // alg: ES256
	//   -1: 1,       // crv: P-256
	//   -2: x,       // x coordinate (32 bytes)
	//   -3: y        // y coordinate (32 bytes)
	// }

	// For simplicity, we'll create a minimal CBOR encoding
	// In production, use a proper CBOR library like github.com/fxamacker/cbor

	x := pubKey.X.Bytes()
	y := pubKey.Y.Bytes()

	// Ensure coordinates are 32 bytes (pad with leading zeros if needed)
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	copy(xBytes[32-len(x):], x)
	copy(yBytes[32-len(y):], y)

	// Manual CBOR encoding for the COSE key
	coseKey := []byte{
		0xa5, // map(5)
		0x01, // key 1 (kty)
		0x02, // EC2 (2)
		0x03, // key 3 (alg)
		0x26, // -7 (ES256)
		0x20, // key -1 (crv)
		0x01, // P-256 (1)
		0x21, // key -2 (x coordinate)
		0x58, 0x20, // bytes(32)
	}
	coseKey = append(coseKey, xBytes...)
	coseKey = append(coseKey, 0x22) // key -3 (y coordinate)
	coseKey = append(coseKey, 0x58, 0x20) // bytes(32)
	coseKey = append(coseKey, yBytes...)

	return coseKey
}

// encodeECDSAPrivateKey encodes an ECDSA private key for storage
func encodeECDSAPrivateKey(privKey *ecdsa.PrivateKey) []byte {
	// Store the D value (private key scalar)
	d := privKey.D.Bytes()
	// Ensure it's 32 bytes for P-256
	privateKeyBytes := make([]byte, 32)
	copy(privateKeyBytes[32-len(d):], d)
	return privateKeyBytes
}

// decodeECDSAPrivateKey decodes a stored ECDSA private key
func decodeECDSAPrivateKey(keyBytes []byte) (*ecdsa.PrivateKey, error) {
	if len(keyBytes) != 32 {
		return nil, errors.New("invalid private key length")
	}

	privKey := new(ecdsa.PrivateKey)
	privKey.PublicKey.Curve = elliptic.P256()
	privKey.D = new(big.Int).SetBytes(keyBytes)

	// Derive public key from private key
	privKey.PublicKey.X, privKey.PublicKey.Y = elliptic.P256().ScalarBaseMult(keyBytes)

	return privKey, nil
}

// signWithECDSA creates an ECDSA signature over the data
func signWithECDSA(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, err
	}

	// Encode signature in ASN.1 DER format (standard for WebAuthn)
	type ECDSASignature struct {
		R, S *big.Int
	}
	sig := ECDSASignature{R: r, S: s}
	return asn1.Marshal(sig)
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
			pubKeyCredParams: options.pubKeyCredParams || [],
			origin: window.location.origin  // Pass actual page origin
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
			userVerification: options.userVerification || 'preferred',
			origin: window.location.origin  // Pass actual page origin
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

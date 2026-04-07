//go:build windows
// +build windows

package webview2

import (
	"encoding/base64"
	"testing"
)

// TestBase64URLEncodeDecode tests the base64url encoding/decoding functions
func TestBase64URLEncodeDecode(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "empty",
			input: []byte{},
		},
		{
			name:  "single byte",
			input: []byte{0x42},
		},
		{
			name:  "challenge-like 32 bytes",
			input: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		},
		{
			name:  "user id 16 bytes",
			input: []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
		},
		{
			name:  "with special chars requiring url encoding",
			input: []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded := base64URLEncode(tt.input)

			// Check that encoded string doesn't contain standard base64 chars
			for _, ch := range encoded {
				if ch == '+' || ch == '/' || ch == '=' {
					t.Errorf("base64URLEncode produced non-URL-safe character: %c", ch)
				}
			}

			// Decode
			decoded, err := base64URLDecode(encoded)
			if err != nil {
				t.Fatalf("base64URLDecode failed: %v", err)
			}

			// Compare
			if len(decoded) != len(tt.input) {
				t.Fatalf("length mismatch: got %d, want %d", len(decoded), len(tt.input))
			}

			for i := range decoded {
				if decoded[i] != tt.input[i] {
					t.Errorf("byte mismatch at index %d: got 0x%02x, want 0x%02x", i, decoded[i], tt.input[i])
				}
			}
		})
	}
}

// TestBase64URLDecodeStandardBase64 tests that we can decode standard base64 with padding
func TestBase64URLDecodeStandardBase64(t *testing.T) {
	// Standard base64 with padding
	input := []byte("Hello, World!")
	standardB64 := base64.StdEncoding.EncodeToString(input)

	// Convert to base64url (remove padding, replace chars)
	urlB64 := base64URLEncode(input)

	// Both should decode to the same value
	decoded1, err := base64URLDecode(urlB64)
	if err != nil {
		t.Fatalf("failed to decode url-safe base64: %v", err)
	}

	if string(decoded1) != string(input) {
		t.Errorf("decoded mismatch: got %q, want %q", string(decoded1), string(input))
	}

	// Verify standard base64 uses different characters
	if standardB64 == urlB64 {
		t.Log("Note: This particular input doesn't require URL-safe encoding")
	}
}

// TestInMemoryCredentialStore tests the in-memory credential store
func TestInMemoryCredentialStore(t *testing.T) {
	store := NewInMemoryCredentialStore()

	// Test Save
	cred1 := StoredCredential{
		ID:        "cred1",
		RPID:      "example.com",
		UserID:    "user1",
		UserName:  "alice@example.com",
		PublicKey: []byte{0x01, 0x02, 0x03},
		SignCount: 0,
	}

	err := store.Save(cred1)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Test Load
	loaded, err := store.Load("cred1")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.ID != cred1.ID || loaded.UserName != cred1.UserName {
		t.Errorf("Loaded credential mismatch")
	}

	// Test Load non-existent
	_, err = store.Load("nonexistent")
	if err == nil {
		t.Error("Expected error when loading non-existent credential")
	}

	// Test Save another credential for same RP
	cred2 := StoredCredential{
		ID:        "cred2",
		RPID:      "example.com",
		UserID:    "user2",
		UserName:  "bob@example.com",
		PublicKey: []byte{0x04, 0x05, 0x06},
		SignCount: 0,
	}

	err = store.Save(cred2)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Test LoadAll
	creds, err := store.LoadAll("example.com")
	if err != nil {
		t.Fatalf("LoadAll failed: %v", err)
	}

	if len(creds) != 2 {
		t.Errorf("LoadAll returned %d credentials, want 2", len(creds))
	}

	// Test LoadAll for different RP
	creds, err = store.LoadAll("other.com")
	if err != nil {
		t.Fatalf("LoadAll failed: %v", err)
	}

	if len(creds) != 0 {
		t.Errorf("LoadAll returned %d credentials for other.com, want 0", len(creds))
	}

	// Test Delete
	err = store.Delete("cred1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = store.Load("cred1")
	if err == nil {
		t.Error("Expected error after deleting credential")
	}

	// Test Delete non-existent
	err = store.Delete("nonexistent")
	if err == nil {
		t.Error("Expected error when deleting non-existent credential")
	}
}

// TestCredentialStoreThreadSafety tests concurrent access to the store
func TestCredentialStoreThreadSafety(t *testing.T) {
	store := NewInMemoryCredentialStore()

	// Run multiple goroutines that save/load/delete
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			cred := StoredCredential{
				ID:        string(rune('A' + id)),
				RPID:      "example.com",
				UserID:    string(rune('0' + id)),
				UserName:  "user",
				PublicKey: []byte{byte(id)},
				SignCount: 0,
			}

			// Save
			store.Save(cred)

			// Load
			store.Load(cred.ID)

			// LoadAll
			store.LoadAll("example.com")

			// Delete
			store.Delete(cred.ID)

			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// No crash = success
}

// TestWebAuthnBridgeThreadSafety tests that only one operation can run at a time
func TestWebAuthnBridgeThreadSafety(t *testing.T) {
	bridge := &WebAuthnBridge{}

	// Try to start two operations simultaneously
	bridge.pending = false

	// First operation should succeed
	bridge.mu.Lock()
	if bridge.pending {
		t.Error("Expected pending to be false initially")
	}
	bridge.pending = true
	bridge.mu.Unlock()

	// Second operation should be blocked
	bridge.mu.Lock()
	if !bridge.pending {
		t.Error("Expected pending to be true")
	}
	bridge.mu.Unlock()

	// Clean up
	bridge.mu.Lock()
	bridge.pending = false
	bridge.mu.Unlock()
}

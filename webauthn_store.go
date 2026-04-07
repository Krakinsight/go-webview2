//go:build windows
// +build windows

package webview2

import (
	"errors"
	"sync"
	"time"
)

// StoredCredential represents a WebAuthn credential stored by InMemoryCredentialStore
// For the internal encrypted storage, see storedCredential in webauthn_store_internal.go
type StoredCredential struct {
	ID         string
	RPID       string
	UserID     string
	UserName   string
	PublicKey  []byte
	SignCount  uint32
	CreatedAt  time.Time
}

// InMemoryCredentialStore is a simple in-memory implementation of CredentialStore.
// This is suitable for testing and demos but should not be used in production
// where credential persistence is required.
type InMemoryCredentialStore struct {
	mu          sync.RWMutex
	credentials map[string]StoredCredential // Key is credential ID
}

// NewInMemoryCredentialStore creates a new in-memory credential store
func NewInMemoryCredentialStore() *InMemoryCredentialStore {
	return &InMemoryCredentialStore{
		credentials: make(map[string]StoredCredential),
	}
}

// Save stores a credential
func (s *InMemoryCredentialStore) Save(credential StoredCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.credentials[credential.ID] = credential
	return nil
}

// Load retrieves a credential by its ID
func (s *InMemoryCredentialStore) Load(credentialID string) (StoredCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	credential, ok := s.credentials[credentialID]
	if !ok {
		return StoredCredential{}, errors.New("credential not found")
	}

	return credential, nil
}

// LoadAll retrieves all credentials for a given Relying Party ID
func (s *InMemoryCredentialStore) LoadAll(rpID string) ([]StoredCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []StoredCredential
	for _, cred := range s.credentials {
		if cred.RPID == rpID {
			results = append(results, cred)
		}
	}

	return results, nil
}

// Delete removes a credential
func (s *InMemoryCredentialStore) Delete(credentialID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.credentials[credentialID]; !ok {
		return errors.New("credential not found")
	}

	delete(s.credentials, credentialID)
	return nil
}

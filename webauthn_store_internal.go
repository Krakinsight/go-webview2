//go:build windows
// +build windows

package webview2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// storedCredential represents a credential stored internally
type storedCredential struct {
	ID         string    `json:"id"`
	RPID       string    `json:"rpid"`
	UserID     string    `json:"user_id"`
	UserName   string    `json:"user_name"`
	PrivateKey []byte    `json:"private_key"` // Encrypted private key
	PublicKey  []byte    `json:"public_key"`  // COSE-encoded public key
	SignCount  uint32    `json:"sign_count"`
	CreatedAt  time.Time `json:"created_at"`
}

// fileCredentialStore implements encrypted file-based credential storage
type fileCredentialStore struct {
	mu            sync.RWMutex
	filePath      string
	encryptionKey []byte
}

// newFileCredentialStore creates a new file-based credential store
// The file is stored in %APPDATA%\go-webview2\webauthn_credentials.enc
// Encryption uses AES-GCM with a key derived from the Windows user SID
func newFileCredentialStore() (*fileCredentialStore, error) {
	// Get %APPDATA% directory
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = os.Getenv("USERPROFILE")
		if appData != "" {
			appData = filepath.Join(appData, "AppData", "Roaming")
		}
	}
	if appData == "" {
		return nil, errors.New("could not determine APPDATA directory")
	}

	// Create go-webview2 directory
	dir := filepath.Join(appData, "go-webview2")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	filePath := filepath.Join(dir, "webauthn_credentials.enc")

	// Derive encryption key from Windows user SID
	key, err := deriveKeyFromUserSID()
	if err != nil {
		return nil, err
	}

	return &fileCredentialStore{
		filePath:      filePath,
		encryptionKey: key,
	}, nil
}

// deriveKeyFromUserSID derives an encryption key from the current Windows user's SID
// This provides basic protection similar to DPAPI but without external dependencies
func deriveKeyFromUserSID() ([]byte, error) {
	// Get current process token
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return nil, err
	}
	defer token.Close()

	// Get token user information
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}

	// Convert SID to string
	sidString := tokenUser.User.Sid.String()

	// Derive 32-byte key using SHA-256
	hash := sha256.Sum256([]byte("go-webview2-webauthn:" + sidString))
	return hash[:], nil
}

// save stores a credential
func (s *fileCredentialStore) save(cred storedCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Load existing credentials
	creds, err := s.loadAllUnsafe()
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	// Update or add credential
	found := false
	for i, c := range creds {
		if c.ID == cred.ID {
			creds[i] = cred
			found = true
			break
		}
	}
	if !found {
		creds = append(creds, cred)
	}

	// Save to encrypted file
	return s.saveAllUnsafe(creds)
}

// load retrieves a credential by ID
func (s *fileCredentialStore) load(credentialID string) (storedCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	creds, err := s.loadAllUnsafe()
	if err != nil {
		return storedCredential{}, err
	}

	for _, cred := range creds {
		if cred.ID == credentialID {
			return cred, nil
		}
	}

	return storedCredential{}, errors.New("credential not found")
}

// loadAllByRP retrieves all credentials for a given RP ID
func (s *fileCredentialStore) loadAllByRP(rpID string) ([]storedCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	creds, err := s.loadAllUnsafe()
	if err != nil {
		return nil, err
	}

	var result []storedCredential
	for _, cred := range creds {
		if cred.RPID == rpID {
			result = append(result, cred)
		}
	}

	return result, nil
}

// loadAllUnsafe loads all credentials without locking (caller must hold lock)
func (s *fileCredentialStore) loadAllUnsafe() ([]storedCredential, error) {
	// Read encrypted file
	encryptedData, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []storedCredential{}, nil
		}
		return nil, err
	}

	// Decrypt
	plaintext, err := s.decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	// Unmarshal JSON
	var creds []storedCredential
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return nil, err
	}

	return creds, nil
}

// saveAllUnsafe saves all credentials without locking (caller must hold lock)
func (s *fileCredentialStore) saveAllUnsafe(creds []storedCredential) error {
	// Marshal to JSON
	data, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	// Encrypt
	encryptedData, err := s.encrypt(data)
	if err != nil {
		return err
	}

	// Write to file
	return os.WriteFile(s.filePath, encryptedData, 0600)
}

// encrypt encrypts data using AES-GCM
func (s *fileCredentialStore) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and append nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt decrypts data using AES-GCM
func (s *fileCredentialStore) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

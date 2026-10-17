package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
)

// chainDomain separates the recording hash chain from any other SHA-256 usage.
var chainDomain = []byte("kw-execution-recording-v1\x00")

const (
	nonceSize = 12 // AES-GCM standard nonce length
	keySize   = 32 // AES-256
)

// chunkAAD binds a chunk to its recording, position and key, so a chunk cannot
// be spliced into another recording or reordered within one even if the nonce
// were to repeat.
func chunkAAD(recordingID string, index uint64, keyID string) []byte {
	aad := make([]byte, 0, len(recordingID)+8+len(keyID))
	aad = append(aad, recordingID...)
	var pos [8]byte
	binary.BigEndian.PutUint64(pos[:], index)
	aad = append(aad, pos[:]...)
	aad = append(aad, keyID...)
	return aad
}

// newGCM validates the key length and returns an AES-256-GCM AEAD.
func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("recording key must be %d bytes", keySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealChunk encrypts plaintext into a self-describing chunk payload.
func sealChunk(gcm cipher.AEAD, recordingID, keyID string, index uint64, plaintext []byte) []byte {
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, chunkAAD(recordingID, index, keyID))
	out := make([]byte, 0, nonceSize+len(ciphertext))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out
}

// openChunk verifies and decrypts a stored chunk payload. A nonce, AAD or
// ciphertext mismatch surfaces as ErrTampered.
func openChunk(gcm cipher.AEAD, recordingID, keyID string, index uint64, payload []byte) ([]byte, error) {
	if len(payload) < nonceSize+gcm.Overhead() {
		return nil, ErrTampered
	}
	nonce, ciphertext := payload[:nonceSize], payload[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, chunkAAD(recordingID, index, keyID))
	if err != nil {
		return nil, ErrTampered
	}
	return plaintext, nil
}

// chainStart derives the initial chain value H_0.
func chainStart(keyID, recordingID string) []byte {
	h := sha256.New()
	h.Write(chainDomain)
	h.Write([]byte(keyID))
	h.Write([]byte(recordingID))
	return h.Sum(nil)
}

// chainNext folds one chunk into the running hash chain:
// H_i = SHA256(H_{i-1} ‖ i ‖ SHA256(ciphertext)).
func chainNext(prev []byte, index uint64, ciphertext []byte) []byte {
	digest := sha256.Sum256(ciphertext)
	h := sha256.New()
	h.Write(prev)
	var pos [8]byte
	binary.BigEndian.PutUint64(pos[:], index)
	h.Write(pos[:])
	h.Write(digest[:])
	return h.Sum(nil)
}

func chainHex(value []byte) string { return hex.EncodeToString(value) }

package secmem

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"sync"
)

var (
	secmu sync.RWMutex
	a     cipher.AEAD
	k     []byte
	once  sync.Once
)

// Init initializes the per-process AEAD with a random key kept only in memory.
func Init() error {
	var initErr error
	once.Do(func() {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			initErr = err
			return
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			Zeroize(key)
			initErr = err
			return
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			Zeroize(key)
			initErr = err
			return
		}
		secmu.Lock()
		a = gcm
		k = key
		secmu.Unlock()
	})
	return initErr
}

func Ready() bool { secmu.RLock(); defer secmu.RUnlock(); return a != nil }

// Seal encrypts plain into a new ciphertext with a random nonce.
func Seal(plain []byte) (nonce []byte, ciphertext []byte, err error) {
	secmu.RLock()
	g := a
	secmu.RUnlock()
	if g == nil {
		return nil, nil, errors.New("secmem: not initialized")
	}
	nonce = make([]byte, g.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = g.Seal(nil, nonce, plain, nil)
	return nonce, ciphertext, nil
}

// Open decrypts ciphertext using nonce.
func Open(nonce, ciphertext []byte) ([]byte, error) {
	secmu.RLock()
	g := a
	secmu.RUnlock()
	if g == nil {
		return nil, errors.New("secmem: not initialized")
	}
	if len(nonce) != g.NonceSize() {
		return nil, errors.New("secmem: invalid nonce size")
	}
	return g.Open(nil, nonce, ciphertext, nil)
}

// Zeroize wipes a byte slice in place.
func Zeroize(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}

// Wipe erases the key and AEAD state.
func Wipe() {
	secmu.Lock()
	if k != nil {
		Zeroize(k)
	}
	a = nil
	k = nil
	secmu.Unlock()
}

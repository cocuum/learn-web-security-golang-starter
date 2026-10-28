package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MaxLength   = 128
	memoryKiB   = 19 * 1024
    iterations  = 2
    parallelism = 1
	saltLength  = 16
	keyLength   = 32
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
	    return "", fmt.Errorf("generate password salt: %w", err)
	}
	derivedKey := argon2.IDKey([]byte(password),salt, iterations, memoryKiB, parallelism, keyLength)
	passwordHash := argon2idHash{
		version:     argon2.Version,
		memoryKiB:   memoryKiB,
		iterations:  iterations,
		parallelism: parallelism,
		salt:        salt,
		derivedKey:  derivedKey,
	}
	return encodeArgon2idHash(passwordHash), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	if expectedHash, ok := decodeLegacyHash(encodedHash); ok {
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
	}

	parsedHash, ok := parseArgon2idHash(encodedHash)
	if !ok || parsedHash.version != argon2.Version {
		return false
	}
	derivedKey := argon2.IDKey(
		[]byte(password),
		parsedHash.salt,
		parsedHash.iterations,
		parsedHash.memoryKiB,
		parsedHash.parallelism,
		uint32(len(parsedHash.derivedKey)),
	)
	return subtle.ConstantTimeCompare(derivedKey, parsedHash.derivedKey) == 1
}

func NeedsRehash(encodedHash string) bool {
	if _,ok := decodeLegacyHash(encodedHash); ok {
		return true
	}
	parsedHash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}
	return parsedHash.version != argon2.Version ||
		parsedHash.iterations != iterations ||
		parsedHash.memoryKiB != memoryKiB ||
		parsedHash.parallelism != parallelism ||
		len(parsedHash.derivedKey) != keyLength
}

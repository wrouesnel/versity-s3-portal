package minioiam

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/secure-io/sio-go"
	"golang.org/x/crypto/argon2"
)

// MinIO before 2022 encrypted its IAM records with the root credentials
// (madmin's EncryptData, with "ACCESS:SECRET" as the password); MinIO since
// stores them as plain JSON, unless it has a KMS, and still reads records
// left encrypted. So a record that isn't UTF-8 is tried with the root
// credentials. A KMS's isn't readable without the KMS, and is refused.

// ErrEncrypted is a record which is encrypted, and no root credentials, or
// the wrong ones, were given.
var ErrEncrypted = errors.New("encrypted")

const (
	encArgon2idAESGCM   = 0x00
	encArgon2idChaCha20 = 0x01
	encPBKDF2AESGCM     = 0x02
)

// decrypt is a record's plain bytes: itself if it's text, else decrypted
// with root ("ACCESS:SECRET"), madmin's format: a 32-byte salt, the
// algorithm, an 8-byte nonce, then sio's stream.
func decrypt(data []byte, root string) ([]byte, error) {
	if utf8.Valid(data) {
		return data, nil
	}
	if root == "" {
		return nil, fmt.Errorf("%w: give MinIO's root credentials to read it", ErrEncrypted)
	}
	if len(data) < 41 {
		return nil, fmt.Errorf("%w: too short for MinIO's encryption", ErrEncrypted)
	}
	salt, id, nonce := data[:32], data[32], data[33:41]
	var (
		stream *sio.Stream
		err    error
	)
	switch id {
	case encArgon2idAESGCM, encArgon2idChaCha20:
		key := argon2.IDKey([]byte(root), salt, 1, 64*1024, 4, 32)
		if id == encArgon2idAESGCM {
			stream, err = sio.AES_256_GCM.Stream(key)
		} else {
			stream, err = sio.ChaCha20Poly1305.Stream(key)
		}
	case encPBKDF2AESGCM:
		var key []byte
		if key, err = pbkdf2.Key(sha256.New, root, salt, 8192, 32); err == nil {
			stream, err = sio.AES_256_GCM.Stream(key)
		}
	default:
		return nil, fmt.Errorf("%w, not by MinIO's root credentials (a KMS's?): it can't be read here", ErrEncrypted)
	}
	if err != nil {
		return nil, err
	}
	plain, err := io.ReadAll(stream.DecryptReader(bytes.NewReader(data[41:]), nonce, nil))
	if err != nil {
		return nil, fmt.Errorf("%w: not with these root credentials (%v)", ErrEncrypted, err)
	}
	return plain, nil
}

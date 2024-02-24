package rails_cookie_decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"log"
	"net/url"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	salt       = "authenticated encrypted cookie"
	keyIterNum = 1000
	keySize    = 32
)

type Options struct {
	SecretKeyBase string
	Digest        string
	Unescape      bool
}

func Decrypt(cookie string, options Options) (string, error) {
	data, iv, err := decode(cookie, options.Unescape)

	if err != nil {
		panic(err.Error())
	}

	key := generateKey(options.SecretKeyBase, options.Digest)
	block, err := aes.NewCipher(key)

	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)

	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, iv, data, nil)

	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func decode(cookie string, unescape bool) ([]byte, []byte, error) {
	if unescape {
		unescapedValue, _ := url.QueryUnescape(cookie)

		cookie = unescapedValue
	}

	cookieParts := strings.Split(cookie, "--")

	data, _ := base64.StdEncoding.DecodeString(cookieParts[0])
	iv, _ := base64.StdEncoding.DecodeString(cookieParts[1])
	authTag, _ := base64.StdEncoding.DecodeString(cookieParts[2])

	return []byte(append(data, authTag...)), []byte(iv), nil
}

func generateKey(secretKeyBase string, digest string) []byte {
	salt := []byte(salt)
	return pbkdf2.Key([]byte(secretKeyBase), salt, keyIterNum, keySize, getHashFunc(digest))
}

func getHashFunc(digest string) func() hash.Hash {
	switch digest {
	case "sha256":
		return sha256.New
	case "sha1":
		return sha1.New
	default:
		log.Fatal("unsupported hash function")
		return nil
	}
}

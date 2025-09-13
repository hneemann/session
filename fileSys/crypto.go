package fileSys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"github.com/sigurn/crc16"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"strings"
)

func encryptData(plainText []byte, key []byte) ([]byte, error) {
	messageLen := len(plainText)
	plainText = append(intToSlice(uint32(messageLen)), plainText...)
	if extra := len(plainText) % aes.BlockSize; extra != 0 {
		pad := make([]byte, aes.BlockSize-extra)
		plainText = append(plainText, pad...)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not create cipher: %w", err)
	}

	// The IV needs to be unique, but not secure. Therefore, it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plainText))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("could not create iv: %w", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plainText)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	return ciphertext, nil
}

func intToSlice(i uint32) []byte {
	b := make([]byte, 4)
	b[0] = byte(i & 0xff)
	b[1] = byte((i >> 8) & 0xff)
	b[2] = byte((i >> 16) & 0xff)
	b[3] = byte((i >> 24) & 0xff)
	return b
}

func decryptData(cipherText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not create cipher: %w", err)
	}

	// The IV needs to be unique, but not secure. Therefore, it's common to
	// include it at the beginning of the ciphertext.
	if len(cipherText) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(cipherText)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(cipherText, cipherText)

	size := sliceToInt(cipherText[0:4])

	if size > uint32(len(cipherText))-4 {
		return nil, fmt.Errorf("internal ciphertext error")
	}

	return cipherText[4 : 4+size], nil
}

func sliceToInt(bytes []byte) uint32 {
	return uint32(bytes[0]) | uint32(bytes[1])<<8 | uint32(bytes[2])<<16 | uint32(bytes[3])<<24
}

type CryptoFileSystem struct {
	parent FileSystem
	key    []byte
}

type writer struct {
	buf  *bytes.Buffer
	name string
	cfs  *CryptoFileSystem
}

func (w *writer) Write(p []byte) (n int, err error) {
	return w.buf.Write(p)
}

func (w *writer) Close() error {
	ciphertext, err := encryptData(w.buf.Bytes(), w.cfs.key)
	if err != nil {
		return fmt.Errorf("could not encrypt data file: %w", err)
	}
	rw, err := w.cfs.parent.Writer(w.name)
	if err != nil {
		return fmt.Errorf("could not create writer: %w", err)
	}
	defer CloseLog(rw)
	_, err = rw.Write(ciphertext)
	return err
}

func (c *CryptoFileSystem) Writer(name string) (io.WriteCloser, error) {
	if name == "salt" {
		return nil, fmt.Errorf("cannot write salt file")
	}
	return &writer{buf: &bytes.Buffer{}, name: name, cfs: c}, nil
}

func (c *CryptoFileSystem) Reader(name string) (io.ReadCloser, error) {
	cipherReader, err := c.parent.Reader(name)
	if err != nil {
		return nil, fmt.Errorf("could not read data: %w", err)
	}
	defer CloseLog(cipherReader)

	ciphertext, err := io.ReadAll(cipherReader)
	if err != nil {
		return nil, fmt.Errorf("could not read data: %w", err)
	}

	data, err := decryptData(ciphertext, c.key)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt data: %w", err)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (c *CryptoFileSystem) Delete(name string) error {
	return c.parent.Delete(name)
}

func (c *CryptoFileSystem) Files(yield func(string, error) bool) {
	c.parent.Files(yield)
}

func (c *CryptoFileSystem) CreateRecoveryKey() (string, error) {
	var buf bytes.Buffer
	for i, b := range c.key {
		buf.WriteString(fmt.Sprintf("%02x", b))
		if i&1 == 1 {
			buf.WriteString(" ")
		}
	}

	table := crc16.MakeTable(crc16.CRC16_MAXIM)
	h := crc16.New(table)
	h.Write(c.key)
	buf.WriteString(fmt.Sprintf("%04x", h.Sum16()))

	return buf.String(), nil
}

func (c *CryptoFileSystem) ChangePassword(newPass string) error {
	salt, err := ReadFile(c.parent, "salt")
	if err != nil {
		return fmt.Errorf("could not read salt: %w", err)
	}

	newPassKey := pbkdf2.Key([]byte(newPass), salt, 4096, 32, sha1.New)

	encKey, err := encryptData(c.key, newPassKey)
	if err != nil {
		return fmt.Errorf("could not encrypt master: %w", err)
	}

	err = WriteFile(c.parent, "key", encKey)
	if err != nil {
		return fmt.Errorf("could not write master: %w", err)
	}

	return nil
}

func NewCryptFileSystem(f FileSystem, pass string) (*CryptoFileSystem, error) {
	salt, err := ReadFile(f, "salt")
	if err != nil {
		salt = make([]byte, 32)
		_, err := rand.Read(salt)
		if err != nil {
			return nil, fmt.Errorf("could not create salt: %w", err)
		}

		err = WriteFile(f, "salt", salt)
		if err != nil {
			return nil, fmt.Errorf("could not write salt: %w", err)
		}
	}

	passwordKey := pbkdf2.Key([]byte(pass), salt, 4096, 32, sha1.New)

	key, err := ReadFile(f, "key")
	if err != nil {
		key = make([]byte, 32)
		_, err = rand.Read(key)
		if err != nil {
			return nil, fmt.Errorf("could not create master: %w", err)
		}

		encKey, err := encryptData(key, passwordKey)
		if err != nil {
			return nil, fmt.Errorf("could not encrypt master: %w", err)
		}

		err = WriteFile(f, "key", encKey)
		if err != nil {
			return nil, fmt.Errorf("could not write master: %w", err)
		}
	} else {
		key, err = decryptData(key, passwordKey)
		if err != nil {
			return nil, fmt.Errorf("could not decrypt master: %w", err)
		}
	}

	return &CryptoFileSystem{
		parent: f,
		key:    key,
	}, nil
}

type CryptoRecovery interface {
	CreateRecoveryKey() (string, error)
}

func RestoreAccess(fs FileSystem, newPass, recoveryKey string) error {
	bcryptPass, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	err = WriteFile(fs, "id", bcryptPass)
	if err != nil {
		return fmt.Errorf("could not write password: %w", err)
	}

	if recoveryKey == "" {
		return nil
	}

	key, err := parseRecoveryKey(recoveryKey)
	if err != nil {
		return fmt.Errorf("could not parse recovery key: %w", err)
	}

	salt := make([]byte, 32)
	_, err = rand.Read(salt)
	if err != nil {
		return fmt.Errorf("could not create salt: %w", err)
	}
	err = WriteFile(fs, "salt", salt)
	if err != nil {
		return fmt.Errorf("could not write salt: %w", err)
	}

	newPassKey := pbkdf2.Key([]byte(newPass), salt, 4096, 32, sha1.New)
	encKey, err := encryptData(key, newPassKey)
	if err != nil {
		return fmt.Errorf("could not encrypt master: %w", err)
	}

	return WriteFile(fs, "key", encKey)
}

func parseRecoveryKey(key string) ([]byte, error) {
	parts := strings.Split(key, " ")
	if len(parts) != 17 {
		return nil, fmt.Errorf("invalid recovery key format")
	}

	keyBytes := make([]byte, 32)
	for i := 0; i < 16; i++ {
		if len(parts[i]) != 4 {
			return nil, fmt.Errorf("invalid recovery key format")
		}
		var b int
		_, err := fmt.Sscanf(parts[i], "%04x", &b)
		if err != nil {
			return nil, fmt.Errorf("invalid recovery key format: %w", err)
		}
		keyBytes[i*2] = byte(b >> 8)
		keyBytes[i*2+1] = byte(b)
	}
	table := crc16.MakeTable(crc16.CRC16_MAXIM)
	h := crc16.New(table)
	h.Write(keyBytes)
	var check uint16
	_, err := fmt.Sscanf(parts[16], "%04x", &check)
	if err != nil {
		return nil, fmt.Errorf("invalid recovery key format: %w", err)
	}
	if h.Sum16() != check {
		return nil, fmt.Errorf("invalid recovery key checksum")
	}
	return keyBytes, nil
}

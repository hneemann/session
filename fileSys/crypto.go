package fileSys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
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

type cryptoFileSystem struct {
	parent FileSystem
	key    []byte
}

type writer struct {
	buf  *bytes.Buffer
	name string
	cfs  *cryptoFileSystem
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

func (c *cryptoFileSystem) Writer(name string) (io.WriteCloser, error) {
	if name == "salt" {
		return nil, fmt.Errorf("cannot write salt file")
	}
	return &writer{buf: &bytes.Buffer{}, name: name, cfs: c}, nil
}

func (c *cryptoFileSystem) Reader(name string) (io.ReadCloser, error) {
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

func (c *cryptoFileSystem) Delete(name string) error {
	return c.parent.Delete(name)
}

func NewCryptFileSystem(f FileSystem, pass string) (FileSystem, error) {
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

	key := pbkdf2.Key([]byte(pass), salt, 4096, 32, sha1.New)

	return &cryptoFileSystem{
		parent: f,
		key:    key,
	}, nil
}

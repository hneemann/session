package fileSys

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
)

func Test_encryptData(t *testing.T) {
	for i := 1; i < 100; i++ {
		size := i * 3
		key := randomData(t, 32)

		orig := randomData(t, size)

		cypher, err := encryptData(orig, key)
		assert.NoError(t, err)

		newOrig, err := decryptData(cypher, key)

		assert.EqualValues(t, orig, newOrig)
	}
}

func randomData(t *testing.T, size int) []byte {
	orig := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, orig)
	assert.NoError(t, err)
	return orig
}

func Test_CryptFS(t *testing.T) {
	m := make(MemoryFileSystem)
	f, err := NewCryptFileSystem(m, "zzz")
	assert.NoError(t, err)

	data := "This is the Plain Text"
	err = WriteFile(f, "test", []byte(data))
	assert.NoError(t, err)

	d, err := ReadFile(f, "test")
	assert.NoError(t, err)
	assert.EqualValues(t, data, string(d))

	f, err = NewCryptFileSystem(m, "zzz")
	assert.NoError(t, err)
	d, err = ReadFile(f, "test")
	assert.NoError(t, err)
	assert.EqualValues(t, data, string(d))
}

func Test_ChangePw(t *testing.T) {
	m := make(MemoryFileSystem)
	f, err := NewCryptFileSystem(m, "zzz")
	assert.NoError(t, err)

	fileContentData := []byte("Hello World")
	err = WriteFile(f, "test", fileContentData)
	assert.NoError(t, err)

	err = f.ChangePassword("uuu")
	assert.NoError(t, err)
	u, err := NewCryptFileSystem(m, "uuu")
	assert.NoError(t, err)
	d, err := ReadFile(u, "test")
	assert.NoError(t, err)

	assert.EqualValues(t, fileContentData, d)
}

func Test_Recovery(t *testing.T) {
	m := make(MemoryFileSystem)
	f, err := NewCryptFileSystem(m, "zzz")
	assert.NoError(t, err)

	fileContentData := []byte("Hello World")
	err = WriteFile(f, "test", fileContentData)
	assert.NoError(t, err)

	rkStr, err := f.CreateRecoveryKey()
	assert.NoError(t, err)

	err = RestoreAccess(m, "uuu", rkStr)
	assert.NoError(t, err)

	u, err := NewCryptFileSystem(m, "uuu")
	assert.NoError(t, err)
	d, err := ReadFile(u, "test")
	assert.NoError(t, err)

	assert.EqualValues(t, fileContentData, d)
}

func Test_BrokenRecovery(t *testing.T) {
	_, err := parseRecoveryKey("0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000")
	assert.Error(t, err)
}

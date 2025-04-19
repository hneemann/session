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
}

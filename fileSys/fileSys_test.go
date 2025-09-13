package fileSys

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMemoryFileSystem_Iter(t *testing.T) {
	m := MemoryFileSystem{}
	w, err := m.Writer("zz")
	assert.NoError(t, err)
	_, err = w.Write([]byte("hello world"))
	assert.NoError(t, err)
	err = w.Close()
	assert.NoError(t, err)

	n := 0
	for name, err := range m.Files {
		assert.NoError(t, err)
		assert.EqualValues(t, "zz", name)
		n++
	}
	assert.EqualValues(t, 1, n)
}

func TestSimpleFileSystem_Iter(t *testing.T) {
	var sfs SimpleFileSystem = "."
	m := make(map[string]struct{})
	for name, err := range sfs.Files {
		assert.NoError(t, err)
		m[name] = struct{}{}
	}
	assert.Equal(t, 4, len(m))
	assert.Contains(t, m, "fileSys.go")
	assert.Contains(t, m, "fileSys_test.go")
	assert.Contains(t, m, "crypto.go")
	assert.Contains(t, m, "crypto_test.go")
}

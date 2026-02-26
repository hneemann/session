package session

import (
	"github.com/hneemann/session/fileSys"
	"github.com/stretchr/testify/assert"
	"log"
	"os"
	"testing"
)

func TestNewFileSystemFactory(t *testing.T) {
	dir, err := os.MkdirTemp("", "data")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	fsf := NewFileSystemFactory(dir)

	// access non-existing user
	_, err = fsf.Create("test", false)
	assert.Error(t, err)

	// create user fs
	fs, err := fsf.Create("test", true)
	assert.NoError(t, err)

	testdata := "Hello World"

	err = fileSys.WriteFile(fs, "test", []byte(testdata))
	assert.NoError(t, err)

	d, err := fileSys.ReadFile(fs, "test")
	assert.NoError(t, err)
	assert.EqualValues(t, testdata, string(d))

	// create same user fs again
	_, err = fsf.Create("test", true)
	assert.Error(t, err)

	// access user second time
	_, err = fsf.Create("test", false)
	assert.NoError(t, err)

	d, err = fileSys.ReadFile(fs, "test")
	assert.NoError(t, err)
	assert.EqualValues(t, testdata, string(d))

}

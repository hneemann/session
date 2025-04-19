package session

import (
	"github.com/hneemann/session/fileSys"
	"github.com/stretchr/testify/assert"
	"testing"
)

type testPersist struct{}

func (t testPersist) Load(f fileSys.FileSystem) (*string, error) {
	d, err := fileSys.ReadFile(f, "test")
	if err != nil {
		return nil, err
	}
	s := string(d)
	return &s, nil
}

func (t testPersist) Save(f fileSys.FileSystem, d *string) error {
	return fileSys.WriteFile(f, "test", []byte(*d))
}

func Test_User(t *testing.T) {
	m := NewMemoryFileSystemFactory()
	dm := NewDataManager[string](m, testPersist{})

	// invalid user name
	_, err := dm.CreateUser("#+-", "test")
	assert.Error(t, err)

	// create new user
	data, err := dm.CreateUser("test", "test")
	assert.NoError(t, err)
	assert.NotNil(t, data)
	assert.EqualValues(t, "", *data)

	// try to recreate
	_, err = dm.CreateUser("test", "test")
	assert.Error(t, err)

	// check password correct
	assert.True(t, dm.CheckPassword("test", "test"))

	// check password incorrect, existing user
	assert.False(t, dm.CheckPassword("test", "test2"))

	// check password non-existing user
	assert.False(t, dm.CheckPassword("test2", "test2"))
}

func Test_Data(t *testing.T) {
	m := NewMemoryFileSystemFactory()
	dm := NewDataManager[string](m, testPersist{})

	_, err := dm.CreateUser("test", "test")
	assert.NoError(t, err)

	// access data non existing user
	_, err = dm.CreatePersist("test2", "test")
	assert.Error(t, err)

	// access data
	pe, err := dm.CreatePersist("test", "test")
	assert.NoError(t, err)

	testData := "Hello World"
	err = pe.Save(&testData)
	assert.NoError(t, err)

	d, err := pe.Load()
	assert.NoError(t, err)
	assert.EqualValues(t, "Hello World", *d)

	// check data written
	fs, err := m("test", false)
	assert.NoError(t, err)
	b, err := fileSys.ReadFile(fs, "test")
	assert.NoError(t, err)
	assert.True(t, "Hello World" == string(b))
}

func Test_DataEncrypted(t *testing.T) {
	m := NewMemoryFileSystemFactory()
	dm := NewDataManager[string](m, testPersist{}).EnableEncryption()

	_, err := dm.CreateUser("test", "test")
	assert.NoError(t, err)

	// access data
	pe, err := dm.CreatePersist("test", "test")
	assert.NoError(t, err)

	testData := "Hello World"
	err = pe.Save(&testData)
	assert.NoError(t, err)

	d, err := pe.Load()
	assert.NoError(t, err)
	assert.EqualValues(t, "Hello World", *d)

	// check data written
	fs, err := m("test", false)
	assert.NoError(t, err)
	b, err := fileSys.ReadFile(fs, "test")
	assert.NoError(t, err)
	// not equal because of encryption
	assert.False(t, "Hello World" == string(b))
}

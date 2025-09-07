package session

import (
	"fmt"
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

func (t testPersist) Init(_ fileSys.FileSystem, _ *string) error {
	return nil
}

func Test_User(t *testing.T) {
	m := NewMemoryFileSystemFactory()
	dm := NewFileManager[string](m, testPersist{})

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
	dm := NewFileManager[string](m, testPersist{})

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
	dm := NewFileManager[string](m, testPersist{}).EnableEncryption()

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

func Test_DataEncryptedChangePw(t *testing.T) {
	m := NewMemoryFileSystemFactory()
	dm := NewFileManager[string](m, testPersist{}).EnableEncryption()

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

	// change password
	err = dm.ChangePassword("test", "test", "testChanged")
	assert.NoError(t, err)

	// check data still accessible with new password
	assert.True(t, dm.CheckPassword("test", "testChanged"))

	dm = NewFileManager[string](m, testPersist{}).EnableEncryption()
	pe, err = dm.CreatePersist("test", "testChanged")
	assert.NoError(t, err)

	d, err = pe.Load()
	assert.NoError(t, err)
	assert.EqualValues(t, "Hello World", *d)

	if c, ok := pe.(fileSys.CryptoRecovery); ok {
		k, err := c.CreateRecoveryKey()
		assert.NoError(t, err)
		fmt.Println("Recovery Key:", k)
	}
}

func Test_DataEncryptedRecovery(t *testing.T) {
	m := NewMemoryFileSystemFactory()
	dm := NewFileManager[string](m, testPersist{}).EnableEncryption()

	_, err := dm.CreateUser("test", "test")
	assert.NoError(t, err)

	// access data
	pe, err := dm.CreatePersist("test", "test")
	assert.NoError(t, err)

	testData := "Hello World"
	err = pe.Save(&testData)
	assert.NoError(t, err)

	// get recovery key
	recoveryKey := ""
	if c, ok := pe.(fileSys.CryptoRecovery); ok {
		recoveryKey, err = c.CreateRecoveryKey()
		assert.NoError(t, err)
		fmt.Println("Recovery Key:", recoveryKey)
	} else {
		t.Fatal("no recovery key possible")
	}

	// simulate lost password and restore access with a recovery key
	system, err := m("test", false)
	assert.NoError(t, err)
	err = fileSys.RestoreAccess(system, "testRestored", recoveryKey)
	assert.NoError(t, err)

	// try to access with old password - should fail
	assert.False(t, dm.CheckPassword("test", "test"))
	// try to access with new password - should work
	assert.True(t, dm.CheckPassword("test", "testRestored"))

	pe, err = dm.CreatePersist("test", "testRestored")
	assert.NoError(t, err)
	d, err := pe.Load()
	assert.NoError(t, err)
	assert.EqualValues(t, "Hello World", *d)
}

package session

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	"time"
)

func Test(t *testing.T) {
	mfs := NewMemoryFileSystemFactory()
	sc := NewSessionCache[string](
		NewDataManager[string](mfs, testPersist{}), 10*time.Minute, 10*time.Minute)

	// passwords do not match
	_, err := sc.registerUser("test", "test", "test2")
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "not equal"))

	// register user
	id, err := sc.registerUser("test", "test", "test")
	assert.NoError(t, err)

	// register user second time
	_, err = sc.registerUser("test", "test", "test")
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "already exists"))

	// access session with wrong pw
	_, err = sc.CreateSessionToken("test", "test2")
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "wrong password"))

	// access existing session
	id2, err := sc.CreateSessionToken("test", "test")
	assert.NoError(t, err)

	assert.EqualValues(t, id, id2)

	// set some session data
	testDataString := "Hello World"
	s := sc.getSession(id)
	s.data = &testDataString

	// close all sessions
	sc.Close()

	// create new session cache
	sc = NewSessionCache[string](
		NewDataManager[string](mfs, testPersist{}), 10*time.Minute, 10*time.Minute)

	id3, err := sc.CreateSessionToken("test", "test")
	assert.NoError(t, err)
	// new session id
	assert.True(t, id3 != id)

	// get session again
	s = sc.getSession(id3)
	assert.EqualValues(t, testDataString, *s.data)
}

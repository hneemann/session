package session

import (
	"crypto/sha1"
	"fmt"
	"github.com/hneemann/session/fileSys"
	"log"
	"os"
	"path/filepath"
	"time"
)

type FileSystemFactory interface {
	// Create created a user file system. If create is true, the file system
	// needs to be created and an error needs to be returned if the user exists.
	// If create is false an error needs to be returned if the user does not exist.
	Create(user string, create bool) (fileSys.FileSystem, error)
	// RenameUser renames the user folder. If the user does not
	// exist, an error needs to be returned
	RenameUser(user string, newName string) error
	// DoesUserExist returns true if the user exists.
	DoesUserExist(user string) bool
	// DeleteOldUsers deletes the data of all users which data is older than the given age.
	// The age is determined by the newest file in the user folder.
	// If an error occurs, it needs to be returned, otherwise nil.
	DeleteOldUsers(maxAge time.Duration) error
}

type fss string

func (f fss) RenameUser(user string, newName string) error {
	oldDir := filepath.Join(string(f), user)
	newDir := filepath.Join(string(f), newName)
	err := os.Rename(oldDir, newDir)
	if err != nil {
		log.Println("rename failed:" + err.Error())
	}
	return err
}

func (f fss) Create(user string, create bool) (fileSys.FileSystem, error) {
	dir := filepath.Join(string(f), user)
	fileInfo, err := os.Stat(dir)
	if create {
		if err == nil {
			return nil, os.ErrExist
		}
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return nil, err
		}
	} else {
		if err != nil {
			return nil, err
		}
		if !fileInfo.IsDir() {
			return nil, os.ErrNotExist
		}
	}
	return fileSys.SimpleFileSystem(dir), nil
}

func (f fss) DoesUserExist(user string) bool {
	dir := filepath.Join(string(f), user)
	_, err := os.Stat(dir)
	return err == nil
}

func (f fss) DeleteOldUsers(maxAge time.Duration) error {
	file, err := os.Open(string(f))
	if err != nil {
		return fmt.Errorf("could not open folder: %w", err)
	}
	list, err := file.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("could not read folder: %w", err)
	}
	deleted := 0
	for _, entry := range list {
		if entry.IsDir() {
			userFolder := filepath.Join(string(f), entry.Name())
			age, err := getAge(userFolder)
			if err != nil {
				log.Printf("could not get age of user folder %s: %v", entry.Name(), err)
			}
			if age > maxAge {
				err := os.RemoveAll(userFolder)
				if err != nil {
					log.Printf("could not delete user folder %s: %v", entry.Name(), err)
				} else {
					deleted++
				}
			}
		}
	}
	if deleted > 0 {
		log.Printf("deleted %d old user folders", deleted)
	}
	return nil
}

func getAge(userFolder string) (time.Duration, error) {
	file, err := os.Open(userFolder)
	if err != nil {
		return 0, fmt.Errorf("could not open user folder: %w", err)
	}
	list, err := file.ReadDir(-1)
	if err != nil {
		return 0, fmt.Errorf("could not read user folder: %w", err)
	}
	var newest = time.Hour * 24 * 365 * 100
	for _, entry := range list {
		info, err := entry.Info()
		if err != nil {
			return 0, fmt.Errorf("could not get file info: %w", err)
		}
		age := time.Since(info.ModTime())
		if age < newest {
			newest = age
		}
	}
	return newest, nil
}

// NewFileSystemFactory creates a new FileSystemFactory that creates
// files on disk in the given folder.
func NewFileSystemFactory(folder string) FileSystemFactory {
	return fss(folder)
}

type mfs map[string]fileSys.MemoryFileSystem

func (m mfs) RenameUser(user string, newName string) error {
	if data, ok := m[user]; ok {
		delete(m, user)
		m[newName] = data
		return nil
	} else {
		return os.ErrNotExist
	}
}

func (m mfs) Create(user string, create bool) (fileSys.FileSystem, error) {
	if create {
		if _, ok := m[user]; ok {
			return nil, os.ErrExist
		}
		f := make(fileSys.MemoryFileSystem)
		m[user] = f
		return f, nil
	} else {
		if f, ok := m[user]; ok {
			return f, nil
		} else {
			return nil, os.ErrNotExist
		}
	}
}

func (m mfs) DoesUserExist(user string) bool {
	_, ok := m[user]
	return ok
}

func (m mfs) DeleteOldUsers(maxAge time.Duration) error {
	return nil
}

// NewMemoryFileSystemFactory creates a new FileSystemFactory that creates
// files in memory only. Mainly used for testing.
func NewMemoryFileSystemFactory() FileSystemFactory {
	return make(mfs)
}

// HashFunc is used to hash the username. It is used to create a hash of the username,
// which is then used as the folder name for the user data. This can be used to obfuscate the usernames on disk.
// It needs to return a valid folder name.
type HashFunc func(string) string

type hashUser struct {
	parent   FileSystemFactory
	hashFunc HashFunc
}

func NewHashUser(f FileSystemFactory) FileSystemFactory {
	return hashUser{parent: f, hashFunc: HashUserSha1}
}

func (h hashUser) Create(user string, create bool) (fileSys.FileSystem, error) {
	return h.parent.Create(h.hashFunc(user), create)
}

func (h hashUser) RenameUser(user string, newName string) error {
	return h.parent.RenameUser(h.hashFunc(user), h.hashFunc(newName))
}

func (h hashUser) DoesUserExist(user string) bool {
	return h.parent.DoesUserExist(h.hashFunc(user))
}

func (h hashUser) DeleteOldUsers(maxAge time.Duration) error {
	return h.parent.DeleteOldUsers(maxAge)
}

func HashUserSha1(user string) string {
	hash := sha1.New()
	hash.Write([]byte(user))
	b := hash.Sum(nil)
	return fmt.Sprintf("%X", b)
}

type migrateToHashUser struct {
	parent   FileSystemFactory
	hashFunc HashFunc
}

func NewMigrateToHashUser(f FileSystemFactory) FileSystemFactory {
	return migrateToHashUser{parent: f, hashFunc: HashUserSha1}
}

func (m migrateToHashUser) Create(user string, create bool) (fileSys.FileSystem, error) {
	hash := m.hashFunc(user)
	if create {
		if m.parent.DoesUserExist(hash) {
			return nil, os.ErrExist
		} else {
			if m.parent.DoesUserExist(user) {
				log.Printf("create: found old user, try to rename")
				err := m.parent.RenameUser(user, hash)
				if err != nil {
					log.Printf("could not rename user %s: %v", user, err)
					return nil, err
				}
				log.Printf("renamed old user")
				return nil, os.ErrExist
			}
			return m.parent.Create(hash, true)
		}
	} else {
		if m.parent.DoesUserExist(hash) {
			return m.parent.Create(hash, false)
		} else {
			if m.parent.DoesUserExist(user) {
				log.Printf("open: found old user, try to rename")
				err := m.parent.RenameUser(user, hash)
				if err != nil {
					log.Printf("could not rename user %s: %v", user, err)
					return nil, err
				}
			}
			log.Printf("renamed old user")
			return m.parent.Create(hash, false)
		}
	}
}

func (m migrateToHashUser) DoesUserExist(user string) bool {
	h := m.hashFunc(user)
	if m.parent.DoesUserExist(h) {
		return true
	}
	return m.parent.DoesUserExist(user)
}

func (m migrateToHashUser) DeleteOldUsers(maxAge time.Duration) error {
	return m.parent.DeleteOldUsers(maxAge)
}

func (m migrateToHashUser) RenameUser(user string, newName string) error {
	return m.parent.RenameUser(m.hashFunc(user), m.hashFunc(newName))
}

package session

import (
	"fmt"
	"github.com/hneemann/session/fileSys"
	"log"
	"os"
	"path/filepath"
	"time"
)

type FileSystemFactory interface {
	Create(user string, create bool) (fileSys.FileSystem, error)
	DoesUserExist(user string) bool
	DeleteOldUsers(maxAge time.Duration) error
}

type fss string

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

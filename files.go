package session

import (
	"github.com/hneemann/session/fileSys"
	"os"
	"path/filepath"
)

type FileSystemFactory func(user string, create bool) (fileSys.FileSystem, error)

// NewFileSystemFactory creates a new FileSystemFactory that creates
// files on disk in the given folder.
func NewFileSystemFactory(folder string) FileSystemFactory {
	return func(user string, create bool) (fileSys.FileSystem, error) {
		dir := filepath.Join(folder, user)
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
}

// NewMemoryFileSystemFactory creates a new FileSystemFactory that creates
// files in memory only. Mainly used for testing.
func NewMemoryFileSystemFactory() FileSystemFactory {
	uf := make(map[string]fileSys.MemoryFileSystem)
	return func(user string, create bool) (fileSys.FileSystem, error) {
		if create {
			if _, ok := uf[user]; ok {
				return nil, os.ErrExist
			}
			f := make(fileSys.MemoryFileSystem)
			uf[user] = f
			return f, nil
		} else {
			if f, ok := uf[user]; ok {
				return f, nil
			} else {
				return nil, os.ErrNotExist
			}
		}
	}
}

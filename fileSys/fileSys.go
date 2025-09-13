package fileSys

import (
	"bytes"
	"io"
	"log"
	"os"
	"path/filepath"
)

// FileSystem is an interface for reading and writing files.
// Is created to access the user data.
type FileSystem interface {
	// Reader returns a reader for the file with the given name
	Reader(name string) (io.ReadCloser, error)
	// Writer returns a writer for the file with the given name
	Writer(name string) (io.WriteCloser, error)
	// Delete deletes the file with the given name
	Delete(name string) error
	// Files iterates over all file names and calls the given
	// function for each name.
	Files(func(name string, err error) bool)
}

func CloseLog(w io.Closer) {
	err := w.Close()
	if err != nil {
		log.Println(err)
	}
}

func WriteFile(fs FileSystem, name string, data []byte) error {
	w, err := fs.Writer(name)
	if err != nil {
		return err
	}
	defer CloseLog(w)
	_, err = w.Write(data)
	return err
}

func ReadFile(fs FileSystem, name string) ([]byte, error) {
	r, err := fs.Reader(name)
	if err != nil {
		return nil, err
	}
	defer CloseLog(r)
	return io.ReadAll(r)
}

type SimpleFileSystem string

func (f SimpleFileSystem) Reader(name string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(string(f), name))
}

func (f SimpleFileSystem) Writer(name string) (io.WriteCloser, error) {
	return os.Create(filepath.Join(string(f), name))
}

func (f SimpleFileSystem) Delete(name string) error {
	return os.Remove(filepath.Join(string(f), name))
}

func (f SimpleFileSystem) Files(yield func(string, error) bool) {
	dir, err := os.Open(string(f))
	if err != nil {
		yield("", err)
		return
	}
	list, err := dir.ReadDir(-1)
	if err != nil {
		yield("", err)
		return
	}
	err = dir.Close()
	if err != nil {
		log.Println("error closing directory:", err)
		yield("", err)
		return
	}
	for _, entry := range list {
		if !entry.IsDir() {
			if !yield(entry.Name(), nil) {
				return
			}
		}
	}
}

type MemoryFileSystem map[string][]byte

func (m MemoryFileSystem) Reader(name string) (io.ReadCloser, error) {
	if data, ok := m[name]; ok {
		return io.NopCloser(bytes.NewReader(data)), nil
	} else {
		return nil, os.ErrNotExist
	}
}

type mWriter struct {
	name string
	buf  bytes.Buffer
	mfs  MemoryFileSystem
}

func (m *mWriter) Write(p []byte) (n int, err error) {
	return m.buf.Write(p)
}

func (m *mWriter) Close() error {
	m.mfs[m.name] = m.buf.Bytes()
	return nil
}

func (m MemoryFileSystem) Writer(name string) (io.WriteCloser, error) {
	return &mWriter{name: name, mfs: m}, nil
}

func (m MemoryFileSystem) Delete(name string) error {
	delete(m, name)
	return nil
}

func (m MemoryFileSystem) Files(yield func(string, error) bool) {
	for n := range m {
		if !yield(n, nil) {
			return
		}
	}
}

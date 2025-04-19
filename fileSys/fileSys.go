package fileSys

import (
	"bytes"
	"io"
	"log"
	"os"
	"path/filepath"
)

// FileSystem is an interface for reading and writing files.
// Is created to access the user data
type FileSystem interface {
	//Reader returns a reader for the file with the given name
	Reader(name string) (io.ReadCloser, error)
	//Writer returns a writer for the file with the given name
	Writer(name string) (io.WriteCloser, error)
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

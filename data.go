package session

import (
	"errors"
	"github.com/hneemann/session/fileSys"
	"golang.org/x/crypto/bcrypt"
	"log"
	"unicode"
)

type FilePersist[D any] interface {
	// Load is called to load existing data
	Load(f fileSys.FileSystem) (*D, error)
	// Init is called to initiate newly created data
	Init(f fileSys.FileSystem, d *D) error
	// Save is called to save the data
	Save(f fileSys.FileSystem, d *D) error
}

func NewFileManager[D any](fsf FileSystemFactory, fp FilePersist[D]) *FileManager[D] {
	return &FileManager[D]{filePersist: fp, fileSystemFactory: fsf}
}

type FileManager[D any] struct {
	filePersist       FilePersist[D]
	fileSystemFactory FileSystemFactory
	crypt             bool
}

var _ Manager[int] = &FileManager[int]{}

func (fm *FileManager[D]) EnableEncryption() *FileManager[D] {
	fm.crypt = true
	return fm
}

func (fm *FileManager[D]) DoesUserExist(user string) bool {
	_, err := fm.fileSystemFactory(user, false)
	return err == nil
}

func (fm *FileManager[D]) CreateUser(user string, pass string) (*D, error) {
	for _, r := range user {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r)) {
			return nil, errors.New("username not valid")
		}
	}

	userFS, err := fm.fileSystemFactory(user, true)
	if err == nil {
		bcryptPass, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		err = fileSys.WriteFile(userFS, "id", bcryptPass)
		if err != nil {
			return nil, err
		}
		var items D
		return &items, nil
	}
	return nil, errors.New("user already exists")
}

func (fm *FileManager[D]) CheckPassword(user string, pass string) bool {
	userFS, err := fm.fileSystemFactory(user, false)
	if err != nil {
		return false
	}
	b, err := fileSys.ReadFile(userFS, "id")
	if err != nil {
		return false
	}
	err = bcrypt.CompareHashAndPassword(b, []byte(pass))
	if err != nil {
		return false
	}
	return true
}

type persist[D any] struct {
	user string
	fm   *FileManager[D]
	fs   fileSys.FileSystem
}

func (p *persist[D]) Load() (*D, error) {
	log.Println("load data:", p.user)
	return p.fm.filePersist.Load(p.fs)
}

func (p *persist[D]) Save(d *D) error {
	log.Println("save data:", p.user)
	return p.fm.filePersist.Save(p.fs, d)
}

func (p *persist[D]) Init(d *D) error {
	return p.fm.filePersist.Init(p.fs, d)
}

func (fm *FileManager[D]) CreatePersist(user, pass string) (Persist[D], error) {
	f, err := fm.fileSystemFactory(user, false)
	if err != nil {
		return nil, err
	}
	if fm.crypt {
		f, err = fileSys.NewCryptFileSystem(f, pass)
		if err != nil {
			return nil, err
		}
	}
	return &persist[D]{user: user, fm: fm, fs: f}, nil
}

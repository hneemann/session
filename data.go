package session

import (
	"errors"
	"github.com/hneemann/session/fileSys"
	"golang.org/x/crypto/bcrypt"
	"log"
	"unicode"
)

type FilePersist[D any] interface {
	Load(f fileSys.FileSystem) (*D, error)
	Save(f fileSys.FileSystem, d *D) error
}

func NewDataManager[D any](fsf FileSystemFactory, fp FilePersist[D]) *DataManager[D] {
	return &DataManager[D]{filePersist: fp, fileSystemFactory: fsf}
}

type DataManager[D any] struct {
	filePersist       FilePersist[D]
	fileSystemFactory FileSystemFactory
	crypt             bool
}

var _ Manager[int] = &DataManager[int]{}

func (dm *DataManager[D]) EnableEncryption() *DataManager[D] {
	dm.crypt = true
	return dm
}

func (dm *DataManager[D]) CreateUser(user string, pass string) (*D, error) {
	for _, r := range user {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r)) {
			return nil, errors.New("username not valid")
		}
	}

	userFS, err := dm.fileSystemFactory(user, true)
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

func (dm *DataManager[D]) CheckPassword(user string, pass string) bool {
	userFS, err := dm.fileSystemFactory(user, false)
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
	dm   *DataManager[D]
	fs   fileSys.FileSystem
}

func (p *persist[D]) Load() (*D, error) {
	log.Println("load data:", p.user)
	return p.dm.filePersist.Load(p.fs)
}

func (p *persist[D]) Save(d *D) error {
	log.Println("save data:", p.user)
	return p.dm.filePersist.Save(p.fs, d)
}

func (dm *DataManager[D]) CreatePersist(user, pass string) (Persist[D], error) {
	f, err := dm.fileSystemFactory(user, false)
	if err != nil {
		return nil, err
	}
	if dm.crypt {
		f, err = fileSys.NewCryptFileSystem(f, pass)
		if err != nil {
			return nil, err
		}
	}
	return &persist[D]{user: user, dm: dm, fs: f}, nil
}

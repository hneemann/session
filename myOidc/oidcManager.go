package myOidc

import (
	"github.com/hneemann/session"
	"github.com/hneemann/session/fileSys"
	"log"
	"net/http"
)

type OidcDataManager[D any] struct {
	filePersist       session.FilePersist[D]
	fileSystemFactory session.FileSystemFactory
}

// NewOidcDataManager creates a new OidcDataManager that uses the given
// FileSystemFactory and FilePersist to store data.
// No password check is done, the check returns always true.
// A file system is created on the fly if not already present.
// A session needs to be created by the OIDC implementation.
// See SessionManager for more details.
func NewOidcDataManager[D any](fsf session.FileSystemFactory, fp session.FilePersist[D]) *OidcDataManager[D] {
	return &OidcDataManager[D]{filePersist: fp, fileSystemFactory: fsf}
}

func (o *OidcDataManager[D]) CreateUser(_, _ string) (*D, error) {
	panic("create is not possible")
}

func (o *OidcDataManager[D]) CheckPassword(_, _ string) bool {
	// check is done bei OIDC
	return true
}

type oicdPersist[D any] struct {
	user          string
	dm            *OidcDataManager[D]
	fs            fileSys.FileSystem
	dataAvailable bool
}

func (p *oicdPersist[D]) Load() (*D, error) {
	if p.dataAvailable {
		log.Println("load data:", p.user)
		return p.dm.filePersist.Load(p.fs)
	} else {
		log.Println("create empty data for new user", p.user)
		var d D
		return &d, nil
	}
}

func (p *oicdPersist[D]) Save(d *D) error {
	log.Println("write data:", p.user)
	err := p.dm.filePersist.Save(p.fs, d)
	if err == nil {
		p.dataAvailable = true
	}
	return err
}

func (o *OidcDataManager[D]) CreatePersist(user, _ string) (session.Persist[D], error) {
	dataAvailable := true
	f, err := o.fileSystemFactory(user, false)
	if err != nil {
		dataAvailable = false
		log.Println("new oidc user detected:", err)
		log.Println("create new file system for user:", user)
		// if the user does not exist, create a new file system
		f, err = o.fileSystemFactory(user, true)
		if err != nil {
			log.Println("error creating file system for new user:", err)
		}
	}

	if err != nil {
		return nil, err
	}
	return &oicdPersist[D]{user: user, dm: o, fs: f, dataAvailable: dataAvailable}, nil
}

func CreateOidcSession[D any](s *session.Cache[D]) CreateSession {
	return func(ident string, admin bool, w http.ResponseWriter) {
		var id string
		var err error
		if id, err = s.CreateSessionToken(ident, ""); err == nil {
			http.SetCookie(w, session.CreateSecureCookie("id", id))
			return
		}
		log.Println("error creating session:", err)
	}
}

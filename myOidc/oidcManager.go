package myOidc

import (
	"github.com/hneemann/session"
	"log"
	"net/http"
)

// OidcDataManager is a session.Manager that uses an underlying session.Manager.
// It is used to manage users authenticated via OIDC.
// No password check is done, the check returns always true.
// If the user does not exist, it is created on the fly.
type OidcDataManager[D any] struct {
	parent session.Manager[D]
}

var _ session.Manager[int] = &OidcDataManager[int]{}

// NewOidcDataManager creates a new OidcDataManager.
func NewOidcDataManager[D any](parent session.Manager[D]) *OidcDataManager[D] {
	return &OidcDataManager[D]{parent: parent}
}

func (o *OidcDataManager[D]) CreateUser(_, _ string) (*D, error) {
	panic("create user is not possible")
}

func (o *OidcDataManager[D]) ChangePassword(user, oldPass, newPass string) error {
	panic("change password is not possible")
}

func (o *OidcDataManager[D]) CheckPassword(_, _ string) bool {
	// check is done bei OIDC
	return true
}

func (o *OidcDataManager[D]) DoesUserExist(_ string) bool {
	// by definition, the user exists if authenticated via OIDC
	return true
}

func (o *OidcDataManager[D]) CreatePersist(user, _ string) (session.Persist[D], error) {
	if !o.parent.DoesUserExist(user) {
		// if the user does not exist, create it without a password
		d, err := o.parent.CreateUser(user, "")
		if err != nil {
			return nil, err
		}
		p, err := o.parent.CreatePersist(user, "")
		if err != nil {
			return nil, err
		}
		err = p.Save(d)
		if err != nil {
			return nil, err
		}
		return p, nil
	}
	return o.parent.CreatePersist(user, "")
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

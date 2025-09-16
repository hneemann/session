package session

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// Persist is the interface that needs to be implemented to persist the session data.
// It is agnostic on how to store the data. It could be a file system or a database.
// The Manager is responsible for creating the Persist interface for a user.
type Persist[D any] interface {
	// Load is called to load the data from the persistent storage
	Load() (*D, error)
	// Save is called to save the data to the persistent storage
	Save(d *D) error
	// Init is called to notify the data D that a Persist interface is created.
	// This can be used to set the file system or database connection in the data if
	// the data requires direct access to the storage backend.
	// It may be that this method is not called at all.
	// It is called if a new user is created.
	Init(data *D) error
}

// Manager is the interface that needs to be implemented to manage the session data
// D is the type of the data that is stored in the session.
// The manager is responsible for creating new users, checking the password and
// creating the Persist interface for the user
type Manager[D any] interface {
	DoesUserExist(user string) bool
	// CreateUser is called if a new user needs to be created
	CreateUser(user, pass string) (*D, error)
	// CheckPassword is called to check if the password is correct
	CheckPassword(user, pass string) bool
	// CreatePersist create the Persist interface used to
	// restore and persist the user data.
	// It does not check if the password is correct.
	// Password is only given to derive encryption keys if required.
	CreatePersist(user, pass string) (Persist[D], error)
	// ChangePassword changes the password of the user
	ChangePassword(user, oldPass, newPass string) error
}

type sessionCacheEntry[D any] struct {
	mutex      sync.Mutex
	lastAccess time.Time
	user       string
	persist    Persist[D]
	data       *D
}

func (sce *sessionCacheEntry[S]) saveData() {
	sce.mutex.Lock()
	defer sce.mutex.Unlock()

	if sce.data != nil {
		err := sce.persist.Save(sce.data)
		if err != nil {
			log.Println(err)
		}
	}
}

// Cache is the session cache
type Cache[D any] struct {
	mutex         sync.Mutex
	dataLifeTime  time.Duration
	tokenLifeTime time.Duration
	sessions      map[string]*sessionCacheEntry[D]
	sm            Manager[D]
	shutDown      chan struct{}
	loginUrl      string
}

// NewSessionCache creates a new session cache
// sm is the session manager
// sessionLifeTime is the time a session is valid
func NewSessionCache[S any](sm Manager[S], tokenLifeTime, dataLifeTime time.Duration) *Cache[S] {
	shutDown := make(chan struct{})
	sc := Cache[S]{
		sessions:      make(map[string]*sessionCacheEntry[S]),
		sm:            sm,
		shutDown:      shutDown,
		dataLifeTime:  dataLifeTime,
		tokenLifeTime: tokenLifeTime,
		loginUrl:      "/login",
	}

	checkIntervall := dataLifeTime
	if tokenLifeTime < dataLifeTime {
		log.Println("token lifeTime is shorter than data lifeTime!")
		checkIntervall = tokenLifeTime
	}

	go func() {
		for {
			select {
			case <-time.After(checkIntervall):
				sc.checkSessions()
			case <-shutDown:
				return
			}
		}
	}()

	return &sc
}

// SetLoginUrl sets the url to redirect to if no session is found
func (s *Cache[S]) SetLoginUrl(url string) *Cache[S] {
	s.loginUrl = url
	return s
}

func (s *Cache[S]) getSession(token string) *sessionCacheEntry[S] {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if sce, ok := s.sessions[token]; ok {
		if time.Since(sce.lastAccess) < s.tokenLifeTime {

			sce.mutex.Lock()
			defer sce.mutex.Unlock()

			if sce.data == nil {
				data, err := sce.persist.Load()
				if err != nil {
					log.Println("could not reload session data", err)
					return nil
				}
				sce.data = data
			}

			return sce
		} else {
			sce.saveData()
			delete(s.sessions, token)
		}
	}
	return nil
}

func (s *Cache[S]) GetSessionData(token string) *S {
	se := s.getSession(token)
	if se == nil {
		return nil
	}

	return se.data
}

// CreateDebugSession creates a debug session for the given user.
// Due to the fixed token, a server restart does not invalidate the session,
// because the token is always the same.
func (s *Cache[S]) CreateDebugSession(user, pass, token string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	p, err := s.sm.CreatePersist(user, pass)
	if err != nil {
		return err
	}

	data, err := p.Load()
	if err != nil {
		return err
	}

	ses := &sessionCacheEntry[S]{lastAccess: time.Now(), data: data, user: user, persist: p}
	s.sessions[token] = ses

	log.Println("created debug session for user", user)

	return nil
}

func (s *Cache[S]) CreateSessionToken(user string, pass string) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.sm == nil {
		return "", errors.New("session manager closed")
	}

	if !s.sm.CheckPassword(user, pass) {
		return "", errors.New("wrong password")
	}

	for token, sce := range s.sessions {
		if sce.user == user {
			sce.lastAccess = time.Now()
			log.Println("gained access to an existing session")
			return token, nil
		}
	}

	p, err := s.sm.CreatePersist(user, pass)
	if err != nil {
		return "", fmt.Errorf("could not create persistance for %s: %w", user, err)
	}

	data, err := p.Load()
	if err != nil {
		return "", fmt.Errorf("could not load data for %s: %w", user, err)
	}
	token := createRandomString()

	ses := &sessionCacheEntry[S]{lastAccess: time.Now(), data: data, user: user, persist: p}
	s.sessions[token] = ses

	return token, nil
}

func (s *Cache[S]) registerUser(user, pass, pass2 string) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if pass != pass2 {
		return "", errors.New("passwords are not equal")
	}

	if s.sm == nil {
		return "", errors.New("session manager closed")
	}

	data, err := s.sm.CreateUser(user, pass)
	if err != nil {
		return "", err
	}
	p, err := s.sm.CreatePersist(user, pass)
	if err != nil {
		return "", err
	}

	err = p.Init(data)
	if err != nil {
		return "", fmt.Errorf("could not initialize initial data %s: %w", user, err)
	}

	token := createRandomString()

	ses := &sessionCacheEntry[S]{lastAccess: time.Now(), data: data, user: user, persist: p}
	s.sessions[token] = ses

	return token, nil
}

func (s *Cache[S]) checkSessions() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.sm == nil {
		return
	}

	for token, sce := range s.sessions {
		age := time.Since(sce.lastAccess)
		if age > s.tokenLifeTime {
			sce.saveData()
			delete(s.sessions, token)
		} else if age > s.dataLifeTime {
			sce.saveData()
			sce.data = nil
		}
	}
}

// Close closes the session cache
// It saves all data and stops the session cache
// This function should be called before the program exits
// to save all the session data. It also stops the go routine
// that periodically checks the session lifetime.
func (s *Cache[S]) Close() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	close(s.shutDown)

	for _, sce := range s.sessions {
		sce.saveData()
	}
	log.Println("written all session data")
	s.sm = nil
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func createRandomString() string {
	b := make([]byte, 20)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

// CallHandlerWithData calls the parent handler with the data from the session.
// The data is stored in the context with the key "data".
// If no session is found it returns false.
func (s *Cache[D]) CallHandlerWithData(w http.ResponseWriter, r *http.Request, parent http.Handler) bool {
	if c, err := r.Cookie("id"); err == nil {
		id := c.Value
		if se := s.getSession(id); se != nil {
			se.mutex.Lock()
			defer se.mutex.Unlock()
			se.lastAccess = time.Now()
			nc := context.WithValue(r.Context(), "data", se.data)
			parent.ServeHTTP(w, r.WithContext(nc))
			return true
		} else {
			log.Println("no matching session found")
		}
	}
	return false
}

func GetData[D any](r *http.Request) *D {
	if data, ok := r.Context().Value("data").(*D); ok {
		return data
	}
	return nil
}

// CheckSessionFunc is a wrapper that redirects to /login if no valid session id is found
func (s *Cache[S]) CheckSessionFunc(parent http.HandlerFunc) http.HandlerFunc {
	return s.CheckSession(parent)
}

// CheckSession is a wrapper that redirects to /login if no valid session id is found
func (s *Cache[S]) CheckSession(parent http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ok := s.CallHandlerWithData(w, r, parent); !ok {
			http.Redirect(w, r, s.loginUrl+"?t="+EncodeTarget(r.URL.Path), http.StatusFound)
		}
	}
}

// CheckSessionRestFunc is a wrapper that returns a 403 Forbidden if no valid session id is found
func (s *Cache[S]) CheckSessionRestFunc(parent http.HandlerFunc) http.HandlerFunc {
	return s.CheckSessionRest(parent)
}

// CheckSessionRest is a wrapper that returns a 403 Forbidden if no valid session id is found
func (s *Cache[S]) CheckSessionRest(parent http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ok := s.CallHandlerWithData(w, r, parent); !ok {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
	}
}

type LoginData struct {
	Target string
	Error  error
}

func DecodeTarget(encodedTarget string) string {
	var target = "/"
	if targetBytes, err := base64.URLEncoding.DecodeString(encodedTarget); err == nil {
		target = string(targetBytes)
	}
	return target
}

func EncodeTarget(target string) string {
	return base64.URLEncoding.EncodeToString([]byte(target))
}

func CreateSecureCookie(name, value string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,                    // XSS protection, no access from JavaScript
		Secure:   true,                    // only send cookie over HTTPS
		SameSite: http.SameSiteStrictMode, // protect from CSRF
		Path:     "/",                     // cookie is valid for all paths
	}
}

// LoginHandler is a handler that does the login.
// The given template is used to render the login page.
// It needs to contain a form with the fields username and password.
// If the login is successful a cookie with the session id is set and
// the user is redirected to /.
func (s *Cache[S]) LoginHandler(loginTemp *template.Template) http.HandlerFunc {
	if loginTemp == nil {
		panic("login template is nil")
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		encodedTarget := r.URL.Query().Get("t")
		if r.Method == http.MethodPost {
			user := r.FormValue("username")
			pass := r.FormValue("password")
			encodedTarget = r.FormValue("target")

			if len(user) >= 4 && len(pass) >= 4 {
				var id string
				if id, err = s.CreateSessionToken(user, pass); err == nil {
					http.SetCookie(w, CreateSecureCookie("id", id))
					target := DecodeTarget(encodedTarget)
					log.Println("redirect to", target)
					http.Redirect(w, r, target, http.StatusFound)
					return
				}
			} else {
				err = errors.New("wrong password")
			}
		}

		err = loginTemp.Execute(w, LoginData{
			Target: encodedTarget,
			Error:  err,
		})
		if err != nil {
			log.Println(err)
		}
	}
}

// LogoutHandler is a handler that does the logout.
// The given template is used to render the logout confirmation page.
// The cookie with the session id is deleted.
func (s *Cache[S]) LogoutHandler(logoutTemp *template.Template) http.HandlerFunc {
	if logoutTemp == nil {
		panic("logout template is nil")
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("id"); err == nil {
			id := c.Value
			if se := s.getSession(id); se != nil {
				se.saveData()
				delete(s.sessions, id)
			}
			http.SetCookie(w, &http.Cookie{Value: "", Name: "id", Expires: time.Now().Add(-time.Hour)})
		}
		err := logoutTemp.Execute(w, nil)
		if err != nil {
			log.Println(err)
		}
	}
}

// RegisterHandler is the handler to handle the registration.
// The given template is used to render the registration page.
// It needs to contain a form with the fields username, password and password2.
func (s *Cache[S]) RegisterHandler(registerTemp *template.Template) http.HandlerFunc {
	if registerTemp == nil {
		panic("register template is nil")
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		encodedTarget := r.URL.Query().Get("t")
		if r.Method == http.MethodPost {
			user := r.FormValue("username")
			pass := r.FormValue("password")
			pass2 := r.FormValue("password2")
			encodedTarget = r.FormValue("target")

			if len(user) >= 4 && len(pass) >= 4 {
				var id string
				if id, err = s.registerUser(user, pass, pass2); err == nil {
					http.SetCookie(w, CreateSecureCookie("id", id))
					target := DecodeTarget(encodedTarget)
					log.Println("redirect to", target)
					http.Redirect(w, r, target, http.StatusFound)
					return
				}
			} else {
				err = errors.New("username or password too short, at least four characters are required")
			}
		}
		err = registerTemp.Execute(w, LoginData{
			Target: encodedTarget,
			Error:  err,
		})
		if err != nil {
			log.Println(err)
		}
	}
}

func (s *Cache[D]) callHandlerWithUser(parent http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("id"); err == nil {
			id := c.Value
			if se := s.getSession(id); se != nil {
				se.mutex.Lock()
				defer se.mutex.Unlock()
				se.lastAccess = time.Now()
				nc := context.WithValue(r.Context(), "user", se.user)
				parent.ServeHTTP(w, r.WithContext(nc))
				return
			} else {
				log.Println("no matching session found")
			}
		}
	}
}

type ChangePasswordData struct {
	Success bool
	Error   error
}

// ChangePasswordHandler is the handler to change the password.
// The given template is used to render the page.
// It needs to contain a form with the fields oldPassword, password and password2.
func (s *Cache[S]) ChangePasswordHandler(changePasswordTemp *template.Template) http.HandlerFunc {
	if changePasswordTemp == nil {
		panic("changePassword template is nil")
	}

	return s.callHandlerWithUser(func(w http.ResponseWriter, r *http.Request) {
		if user, ok := r.Context().Value("user").(string); ok {
			var err error
			success := false
			if r.Method == http.MethodPost {
				oldPass := r.FormValue("oldPassword")
				pass := r.FormValue("password")
				pass2 := r.FormValue("password2")

				if len(pass) >= 4 {
					if pass == pass2 {
						err = s.sm.ChangePassword(user, oldPass, pass)
						if err == nil {
							success = true
						}
					} else {
						err = errors.New("passwords are not equal")
					}
				} else {
					err = errors.New("username or password too short, at least four characters are required")
				}
			}
			err = changePasswordTemp.Execute(w, ChangePasswordData{
				Success: success,
				Error:   err,
			})
			if err != nil {
				log.Println(err)
			}
		}
	})
}

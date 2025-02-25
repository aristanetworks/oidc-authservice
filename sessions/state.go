// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package sessions

import (
	"encoding/gob"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	oidcStateCookie   = "oidc_state_csrf"
	sessionValueState = "state"
	charset           = "abcdefghijklmnopqrstuvwxyz"
)

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func init() {
	gob.Register(State{})
}

type State struct {
	// FirstVisitedURL is the URL that the user visited when we redirected them
	// to login.
	FirstVisitedURL string
}

type Config struct {
	SchemeDefault string
	SchemeHeader  string
	SessionDomain string
}

type StateFunc func(*http.Request) *State

func NewStateFunc(config *Config) StateFunc {
	if len(config.SessionDomain) > 0 {
		return newSchemeAndHost(config)
	}
	return relativeURL
}

func firstVisitedURL(u *url.URL) string {
	firstVisited, err := url.Parse("")
	if err != nil {
		panic(err)
	}
	firstVisited.Path = u.Path
	firstVisited.RawPath = u.RawPath
	firstVisited.RawQuery = u.RawQuery

	return firstVisited.String()
}

func relativeURL(r *http.Request) *State {
	return &State{
		FirstVisitedURL: firstVisitedURL(r.URL),
	}
}

func newSchemeAndHost(config *Config) StateFunc {
	return func(r *http.Request) *State {
		// Use header value if it exists
		s := r.Header.Get(config.SchemeHeader)
		if s == "" {
			s = config.SchemeDefault
		}
		// XXX Could return an error here. Would require changing the StateFunc type
		if !strings.HasSuffix(r.Host, config.SessionDomain) {
			log.Warnf("Request host %q is not a subdomain of %q", r.Host, config.SessionDomain)
		}
		return &State{
			FirstVisitedURL: s + "://" + r.Host + firstVisitedURL(r.URL),
		}
	}
}

// stringWithCharset creates a random string of length from charset
func stringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
	  b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
  }

// randString returns a random string of given length
func randString(length int) string {
	return stringWithCharset(length, charset)
}

// CreateState creates the state parameter from the incoming request, stores
// it in the session store and sets a cookie with the session key.
// It returns the session key, which can be used as the state value to start
// an OIDC authentication request.
func CreateState(r *http.Request, w http.ResponseWriter, store sessions.Store,
	sessionDomain string, fn StateFunc, dynamicOidcStateCookieName bool) (string, error) {
	nonce := randString(8)
	oidcStateCookieName := oidcStateCookie
	if (dynamicOidcStateCookieName) {
		oidcStateCookieName += "_" + nonce
	}
	s := fn(r)
	session := sessions.NewSession(store, oidcStateCookieName)
	session.Options.MaxAge = int((20 * time.Minute).Seconds())
	session.Options.Path = "/"
	session.Options.Domain = sessionDomain
	session.Values[sessionValueState] = *s

	err := session.Save(r, w)
	if err != nil {
		return "", errors.Wrap(err, "error trying to save session")
	}

	// Cookie is persisted in ResponseWriter, make a request to parse it.
	tempReq := &http.Request{Header: make(http.Header)}
	tempReq.Header.Set("Cookie", w.Header().Get("Set-Cookie"))
	c, err := tempReq.Cookie(oidcStateCookieName)
	if err != nil {
		return "", errors.Wrap(err, "error trying to save session")
	}
	stateValue := c.Value
	if (dynamicOidcStateCookieName) {
		stateValue += "." + nonce
	}
	return stateValue, nil
}

// VerifyState gets the state from the cookie 'initState' saved. It also gets
// the state from an http param and:
//  1. Confirms the two values match (CSRF check).
//  2. Confirms the value is still valid by retrieving the session it points to.
//     The state value might be invalid if it has been used before or the session
//     expired.
//
// Finally, it returns a State struct, which contains information associated
// with the particular OIDC flow.
func VerifyState(r *http.Request, w http.ResponseWriter,
	store sessions.Store, dynamicOidcStateCookieName bool) (*State, error) {

	// Get the state from the HTTP param.
	var stateParam = r.FormValue("state")
	if len(stateParam) == 0 {
		return nil, errors.New("Missing url parameter: state")
	}

	oidcStateCookieName := oidcStateCookie
	stateValue := stateParam
	nonce := ""
	if (dynamicOidcStateCookieName) {
		stateParamParts := strings.Split(stateParam, ".")
		stateValue = stateParamParts[0]
		nonce = stateParamParts[1]
		oidcStateCookieName += "_" + nonce
	}

	// Get the state from the cookie the user-agent sent.
	stateCookie, err := r.Cookie(oidcStateCookieName)
	if err != nil {
		return nil, errors.Errorf("Missing cookie: '%s'", oidcStateCookieName)
	}

	// Confirm the two values match.
	if stateValue != stateCookie.Value {
		return nil, errors.New("State value from http params doesn't match " +
			"value in cookie. Possible reasons for this error include " +
			"opening the login form in more than 1 browser tabs OR a CSRF " +
			"attack.")
	}

	// Retrieve session from store. If it doesn't exist, it may have expired.
	session, err := store.Get(r, oidcStateCookieName)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if session.IsNew {
		return nil, errors.New("State value not found in store, maybe it expired")
	}

	state := session.Values[sessionValueState].(State)

	// Revoke the session so that each state value can only be used once.
	if err = revokeSession(r.Context(), w, session); err != nil {
		return nil, errors.Wrap(err, "error revoking state session")
	}
	return &state, nil
}

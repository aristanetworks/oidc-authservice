package main

import (
	"net/http"
	"net/http/httptest"

	oidc "github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type Authenticator interface {
	// Authenticate tries to authenticate a request and
	// returns a User and error if authentication fails.
	Authenticate(w http.ResponseWriter, r *http.Request) (*User, error)
}

type User struct {
	Name   string
	Groups []string
}

type sessionAuthenticator struct {
	// store is the session store.
	store sessions.Store
	// cookie is the name of the cookie that holds the session value.
	cookie string
	// header is the header to check as an alternative to finding the session
	// value.
	header string
	// tokenHeader is the header that is set by the authenticator containing
	// the user id token
	tokenHeader string
	// tokenScheme is the authorization scheme used for sending the user id token.
	// e.g. Bearer, Basic
	tokenScheme string
	// strictSessionValidation mode checks the validity of the access token
	// connected with the session on every request.
	strictSessionValidation bool
	// caBundle specifies CAs to trust when talking with the OIDC Provider.
	// Relevant only when strictSessionValidation is enabled.
	caBundle []byte
	// oauth2Config is the config to use when talking with the OIDC Provider.
	// Relevant only when strictSessionValidation is enabled.
	oauth2Config *oauth2.Config
	// provider is the OIDC Provider.
	// Relevant only when strictSessionValidation is enabled.
	provider *oidc.Provider
}

func (sa *sessionAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) (*User, error) {
	logger := loggerForRequest(r)

	// Get session from header or cookie
	session, err := sessionFromRequest(r, sa.store, sa.cookie, sa.header)

	// Check if user session is valid
	if err != nil {
		return nil, errors.Wrap(err, "couldn't get user session")
	}
	if session.IsNew {
		return nil, nil
	}

	// User is logged in
	if sa.strictSessionValidation {
		ctx := setTLSContext(r.Context(), sa.caBundle)
		token := session.Values[userSessionOAuth2Tokens].(oauth2.Token)
		// TokenSource takes care of automatically renewing the access token.
		_, err := GetUserInfo(ctx, sa.provider, sa.oauth2Config.TokenSource(ctx, &token))
		if err != nil {
			var reqErr *requestError
			if !errors.As(err, &reqErr) {
				return nil, errors.Wrap(err, "UserInfo request failed unexpectedly")
			}
			if reqErr.Response.StatusCode != http.StatusUnauthorized {
				return nil, errors.Wrapf(err, "UserInfo request with unexpected code '%d'", reqErr.Response.StatusCode)
			}
			// Access token has expired
			logger.Info("UserInfo token has expired")
			// XXX: With the current abstraction, an authenticator doesn't have
			// access to the ResponseWriter and thus can't set a cookie. This
			// means that the cookie will remain at the user's browser but it
			// will be replaced after the user logs in again.
			err = revokeSession(ctx, httptest.NewRecorder(), session,
				sa.provider, sa.oauth2Config, sa.caBundle)
			if err != nil {
				logger.Errorf("Failed to revoke tokens: %v", err)
			}
			return nil, nil
		}
	}

	// Data written at a previous version might not have groups stored, so
	// default to an empty list of strings.
	// TODO: Consolidate all session serialization/deserialization in one place.
	groups, ok := session.Values[userSessionGroups].([]string)
	if !ok {
		groups = []string{}
	}

	// set auth header with user token
	idHeader := session.Values[userSessionIDToken].(string)
	// prepend authorization scheme if one is specified
	if sa.tokenScheme != "" {
		idHeader = sa.tokenScheme + " " + idHeader
	}
	w.Header().Set(sa.tokenHeader, idHeader)

	resp := &User{
		Name:   session.Values[userSessionUserID].(string),
		Groups: groups,
	}
	return resp, nil
}

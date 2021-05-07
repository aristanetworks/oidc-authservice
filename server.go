// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"encoding/gob"
	"fmt"
	"net/http"
	"strings"

	"github.com/arrikto/oidc-authservice/state"

	oidc "github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/tevino/abool"
	"golang.org/x/oauth2"
)

var (
	OIDCCallbackPath  = "/oidc/callback"
	SessionLogoutPath = "/logout"
)

func init() {
	// Register type for claims.
	gob.Register(map[string]interface{}{})
	gob.Register(oauth2.Token{})
	gob.Register(oidc.IDToken{})
}

type server struct {
	provider                *oidc.Provider
	oauth2Config            *oauth2.Config
	store                   sessions.Store
	authenticators          []Authenticator
	authorizers             []Authorizer
	afterLoginRedirectURL   string
	homepageURL             string
	afterLogoutRedirectURL  string
	sessionDomain           string
	sessionMaxAgeSeconds    int
	strictSessionValidation bool
	authHeader              string
	idTokenOpts             jwtClaimOpts
	userHeaderHelper        *userHeaderHelper
	caBundle                []byte
	sessionSameSite         http.SameSite
	newState                state.StateFunc
}

// jwtClaimOpts specifies the location of the user's identity inside a JWT's
// claims.
type jwtClaimOpts struct {
	userIDClaim string
	groupsClaim string
}

// httpHeaderOpts specifies the location of the user's identity inside HTTP
// headers.
type httpHeaderOpts struct {
	userIDHeader string
	userIDPrefix string
	groupsHeader string
}

type userHeaderFn func(user *User) string

type userHeaderHelper struct {
	headers map[string]userHeaderFn
}

func newUserHeaderHelper(opts httpHeaderOpts) *userHeaderHelper {
	helper := userHeaderHelper{headers: make(map[string]userHeaderFn)}

	if opts.userIDHeader != "" {
		helper.headers[opts.userIDHeader] = func(u *User) string {
			return opts.userIDPrefix + u.Name
		}
	}

	if opts.groupsHeader != "" {
		helper.headers[opts.groupsHeader] = func(u *User) string {
			return strings.Join(u.Groups, ",")
		}
	}
	return &helper
}

func (u *userHeaderHelper) AddHeaders(w http.ResponseWriter, user *User) {
	for header, valueFn := range u.headers {
		w.Header().Add(header, valueFn(user))
	}
}

func (s *server) authenticate(w http.ResponseWriter, r *http.Request) {

	logger := loggerForRequest(r)
	logger.Info("Authenticating request...")

	var user *User
	for i, auth := range s.authenticators {
		resp, err := auth.Authenticate(w, r)

		if err != nil {
			logger.Errorf("Error authenticating request using authenticator %d: %v", i, err)
			// If the authenticator returns an error, this indicates that
			// the request contained a valid authentication method which has expired
			var expiredErr *loginExpiredError
			if errors.As(err, &expiredErr) {
				returnMessage(w, http.StatusUnauthorized, expiredErr.Error())
				return
			}
		}
		// Check if user was set/found
		if resp != nil {
			user = resp
			// TODO do not print userInfo.IDToken
			// solve this by either making it a hidden field,
			// only logging name + groups
			// writing the token header inside of the authenticator -- prob best
			logger.Infof("UserInfo: %+v", user)
			break
		}
	}
	if user == nil {
		logger.Infof("Failed to authenticate using authenticators. Initiating OIDC Authorization Code flow...")
		// TODO: Detect "X-Requested-With" header and return 401
		s.authCodeFlowAuthenticationRequest(w, r)
		return
	}

	logger = logger.WithField("user", user)
	logger.Info("Authorizing request...")

	for i, authz := range s.authorizers {
		allowed, reason, err := authz.Authorize(r, user)
		if err != nil {
			logger.Errorf("Error authorizing request using authorizer %d: %v", i, err)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// If the request is not allowed, try to revoke the user's session.
		// TODO: Only revoke if the authenticator that provided the identity is
		// the session authenticator.
		if !allowed {
			logger.Infof("Authorizer '%d' denied the request with reason: '%s'", i, reason)
			session, err := sessionFromRequest(r, s.store, userSessionCookie, s.authHeader)
			if err != nil {
				logger.Errorf("Error getting session for request: %v", err)
			}
			if !session.IsNew {
				err = revokeSession(r.Context(), w, session, s.provider, s.oauth2Config, s.caBundle)
				if err != nil {
					logger.Errorf("Failed to revoke session after authorization fail: %v", err)
				}
			}
			// TODO: Move this to the web server and make it prettier
			msg := fmt.Sprintf("User '%s' failed authorization with reason: %s. ", user.Name,
				reason)

			returnHTML(w, http.StatusForbidden, msg)
			return
		}
	}

	s.userHeaderHelper.AddHeaders(w, user)

	w.WriteHeader(http.StatusOK)
	return
}

// authCodeFlowAuthenticationRequest initiates an OIDC Authorization Code flow
func (s *server) authCodeFlowAuthenticationRequest(w http.ResponseWriter, r *http.Request) {
	logger := loggerForRequest(r)

	// Initiate OIDC Flow with Authorization Request.
	reqState := s.newState(r)
	id, err := reqState.Save(s.store)
	if err != nil {
		logger.Errorf("Failed to save state in store: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Failed to save state in store.")
		return
	}

	http.Redirect(w, r, s.oauth2Config.AuthCodeURL(id), http.StatusFound)
}

// callback is the handler responsible for exchanging the auth_code and retrieving an id_token.
func (s *server) callback(w http.ResponseWriter, r *http.Request) {

	logger := loggerForRequest(r)

	// Get authorization code from authorization response.
	var authCode = r.FormValue("code")
	if len(authCode) == 0 {
		logger.Warnf("Missing url parameter: code. Redirecting to homepage `%s'.", s.homepageURL)
		http.Redirect(w, r, s.homepageURL, http.StatusFound)
		return
	}

	// Get state and:
	// 1. Confirm it exists in our memory.
	// 2. Get the original URL associated with it.
	var stateID = r.FormValue("state")
	if len(stateID) == 0 {
		logger.Error("Missing url parameter: state")
		returnMessage(w, http.StatusBadRequest, "Missing url parameter: state")
		return
	}

	// If state is loaded, then it's correct, as it is saved by its id.
	reqState, err := state.Load(s.store, stateID)
	if err != nil {
		logger.Errorf("Failed to retrieve state from store: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Failed to retrieve state.")
	}

	ctx := setTLSContext(r.Context(), s.caBundle)
	// Exchange the authorization code with {access, refresh, id}_token
	oauth2Tokens, err := s.oauth2Config.Exchange(ctx, authCode)
	if err != nil {
		logger.Errorf("Failed to exchange authorization code with token: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Failed to exchange authorization code with token.")
		return
	}

	rawIDToken, ok := oauth2Tokens.Extra("id_token").(string)
	if !ok {
		logger.Error("No id_token field available.")
		returnMessage(w, http.StatusInternalServerError, "No id_token field in OAuth 2.0 token.")
		return
	}

	// Verifying received ID token
	verifier := s.provider.Verifier(&oidc.Config{ClientID: s.oauth2Config.ClientID})
	_, err = verifier.Verify(ctx, rawIDToken)
	if err != nil {
		logger.Errorf("Not able to verify ID token: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Unable to verify ID token.")
		return
	}

	// UserInfo endpoint to get claims
	claims := map[string]interface{}{}
	oidcUserInfo, err := GetUserInfo(ctx, s.provider, s.oauth2Config.TokenSource(ctx, oauth2Tokens))
	if err != nil {
		logger.Errorf("Not able to fetch userinfo: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Not able to fetch userinfo.")
		return
	}

	if err = oidcUserInfo.Claims(&claims); err != nil {
		logger.Errorf("Problem getting userinfo claims: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Not able to fetch userinfo claims.")
		return
	}

	// User is authenticated, create new session.
	session := sessions.NewSession(s.store, userSessionCookie)
	session.Options.MaxAge = s.sessionMaxAgeSeconds
	session.Options.Path = "/"
	// Extra layer of CSRF protection
	session.Options.SameSite = s.sessionSameSite
	session.Options.Domain = s.sessionDomain
	session.Options.HttpOnly = true
	session.Options.Secure = true

	userID, ok := claims[s.idTokenOpts.userIDClaim].(string)
	if !ok {
		logger.Errorf("Couldn't find claim `%s' in claims `%v'", s.idTokenOpts.userIDClaim, claims)
		returnMessage(w, http.StatusInternalServerError,
			fmt.Sprintf("Couldn't find userID claim in `%s' in userinfo.", s.idTokenOpts.userIDClaim))
		return
	}

	groups := []string{}
	groupsClaim := claims[s.idTokenOpts.groupsClaim]
	if groupsClaim != nil {
		groups = interfaceSliceToStringSlice(groupsClaim.([]interface{}))
	}

	session.Values[userSessionUserID] = userID
	session.Values[userSessionGroups] = groups
	session.Values[userSessionClaims] = claims
	session.Values[userSessionIDToken] = rawIDToken
	session.Values[userSessionOAuth2Tokens] = oauth2Tokens
	if err := session.Save(r, w); err != nil {
		logger.Errorf("Couldn't create user session: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Error creating user session")
		return
	}

	logger.Info("Login validated with ID token, redirecting.")

	// Getting original destination from DB with state
	var destination = reqState.OrigURL
	if s.afterLoginRedirectURL != "" {
		destination = s.afterLoginRedirectURL
	}

	http.Redirect(w, r, destination, http.StatusFound)
}

// logout is the handler responsible for revoking the user's session.
func (s *server) logout(w http.ResponseWriter, r *http.Request) {

	logger := loggerForRequest(r)

	// Only header auth allowed for this endpoint
	sessionID := getBearerToken(r.Header.Get(s.authHeader))
	if sessionID == "" {
		logger.Errorf("Request doesn't have a session value in header '%s'", s.authHeader)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Revoke user session.
	session, err := sessionFromID(sessionID, s.store)
	if err != nil {
		logger.Errorf("Couldn't get user session: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if session.IsNew {
		logger.Warn("Request doesn't have a valid session.")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	logger = logger.WithField("userid", session.Values[userSessionUserID].(string))

	err = revokeSession(r.Context(), w, session, s.provider, s.oauth2Config, s.caBundle)
	if err != nil {
		logger.Errorf("Error revoking tokens: %v", err)
		statusCode := http.StatusInternalServerError
		// If the server returned 503, return it as well as the client might want to retry
		if reqErr, ok := errors.Cause(err).(*requestError); ok {
			if reqErr.Response.StatusCode == http.StatusServiceUnavailable {
				statusCode = reqErr.Response.StatusCode
			}
		}
		returnMessage(w, statusCode, "Failed to revoke access/refresh tokens, please try again")
		return
	}

	logger.Info("Successful logout.")
	resp := struct {
		AfterLogoutURL string `json:"afterLogoutURL"`
	}{
		AfterLogoutURL: s.afterLogoutRedirectURL,
	}
	// Return 201 because the logout endpoint is still on the envoy-facing server,
	// meaning that returning a 200 will result in the request being proxied upstream.
	returnJSONMessage(w, http.StatusCreated, resp)
}

// readiness is the handler that checks if the authservice is ready for serving
// requests.
// Currently, it checks if the provider is nil, meaning that the setup hasn't finished yet.
func readiness(isReady *abool.AtomicBool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := http.StatusOK
		if !isReady.IsSet() {
			code = http.StatusServiceUnavailable
		}
		w.WriteHeader(code)
	}
}

// whitelistMiddleware is a middleware that
// - Allows all requests that match the whitelist
// - If the server is ready, forwards requests to be evaluated further
// - If the server is NOT ready, denies requests not permitted by the whitelist
//
// This is necessary because in some topologies, the OIDC Provider and the AuthService
// live are in the same cluster and requests pass through the AuthService.
// Allowing the whitelisted requests before OIDC is configured is necessary for
// the OIDC discovery request to succeed.
// TODO fix this stuff to use host instead of just path!
func whitelistMiddleware(whitelist []string, isReady *abool.AtomicBool) func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := loggerForRequest(r)
			// Check whitelist
			for _, prefix := range whitelist {
				if strings.HasPrefix(r.URL.Path, prefix) {
					logger.Infof("URI is whitelisted. Accepted without authorization.")
					returnMessage(w, http.StatusOK, "OK")
					return
				}
			}
			// If server is not ready, return 503.
			if !isReady.IsSet() {
				returnMessage(w, http.StatusServiceUnavailable, "OIDC Setup is not complete yet.")
				return
			}
			// Server ready, continue.
			handler.ServeHTTP(w, r)
		})
	}
}

func debugMiddleware(debugURLS []string) func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := loggerForRequest(r)
			// Check if request is a debug url which should continue to next handler
			reqURL := r.Host + r.URL.Path
			logger.Debugf("debug middleware: request url=%q", reqURL)
			for _, prefix := range debugURLS {
				if strings.HasPrefix(reqURL, prefix) {
					handler.ServeHTTP(w, r)
					return
				}
			}

			logger.Debugf("URI not in explicit debug list. Accepted without authenticating.")
			returnMessage(w, http.StatusOK, "OK")

		})
	}
}

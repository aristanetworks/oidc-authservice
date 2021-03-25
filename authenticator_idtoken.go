package main

import (
	"net/http"

	oidc "github.com/coreos/go-oidc"
)

type idTokenAuthenticator struct {
	header      string // header name where id token is stored
	caBundle    []byte
	provider    *oidc.Provider
	clientID    string // need client id to verify the id token
	userIDClaim string // retrieve the userid if the claim exists
	groupsClaim string
}

func (s *idTokenAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) (*User, error) {
	logger := loggerForRequest(r)

	// get id-token from header
	bearer := getBearerToken(r.Header.Get(s.header))
	if len(bearer) == 0 {
		return nil, nil
	}

	ctx := setTLSContext(r.Context(), s.caBundle)

	// Verifying received ID token
	verifier := s.provider.Verifier(&oidc.Config{ClientID: s.clientID})
	token, err := verifier.Verify(ctx, bearer)
	if err != nil {
		logger.Errorf("id-token verification failed: %v", err)
		return nil, nil
	}

	var claims map[string]interface{}
	if err := token.Claims(&claims); err != nil {
		logger.Errorf("retrieving user claims failed: %v", err)
		return nil, nil
	}

	if claims[s.userIDClaim] == nil {
		// No USERID_CLAIM, pass this authenticator
		logger.Error("USERID_CLAIM doesn't exist in the id token")
		return nil, nil
	}

	groups := []string{}
	groupsClaim := claims[s.groupsClaim]
	if groupsClaim != nil {
		groups = interfaceSliceToStringSlice(groupsClaim.([]interface{}))
	}

	user := User{Name: claims[s.userIDClaim].(string), Groups: groups}
	return &user, nil
}

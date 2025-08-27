package authenticators

import (
	"net/http"

	"github.com/arrikto/oidc-authservice/common"
	"github.com/arrikto/oidc-authservice/oidc"
	"github.com/arrikto/oidc-authservice/sessions"
)

type IDTokenAuthenticator struct {
	Header         string // header name where id token is stored
	UserIDClaim    string // retrieve the userid if the claim exists
	GroupsClaim    string
	SessionManager sessions.SessionManager
	TLSConfig      common.TlsConfig
	TokenHeader    string // TokenHeader is the header that is set by the authenticator containing the user id token
	TokenScheme    string // TokenScheme is the authorization scheme used for sending the user id token.
}

func NewIDTokenAuthenticator(
	header,
	userIDClaim,
	groupsClaim string,
	tlsCfg common.TlsConfig,
	sm sessions.SessionManager,
	th string,
	ts string,
) Authenticator {
	return &IDTokenAuthenticator{
		Header:         header,
		UserIDClaim:    userIDClaim,
		GroupsClaim:    groupsClaim,
		SessionManager: sm,
		TLSConfig:      tlsCfg,
		TokenHeader:    th,
		TokenScheme:    ts,
	}
}

func (s *IDTokenAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) (*common.User, bool, error) {
	logger := common.RequestLogger(r, "idtoken authenticator")
	logger.Infof("Attempting idtoken authentication using token header '%s'", s.Header)

	// get id-token from header
	bearer := common.GetBearerToken(r.Header.Get(s.Header))
	if len(bearer) == 0 {
		logger.Debug("No bearer token found")
		return nil, false, nil
	}

	ctx := s.TLSConfig.Context(r.Context())

	// Verifying received ID token
	token, err := s.SessionManager.VerifyWithoutClientId(ctx, bearer)
	if err != nil {
		logger.Errorf("id-token verification failed: %v", err)
		return nil, false, nil
	}

	claims, err := oidc.NewClaims(token, s.UserIDClaim, s.GroupsClaim)
	if err != nil {
		logger.Errorf("retrieving user claims failed: %v", err)
		return nil, false, nil
	}

	// set auth header with client token
	idHeader := bearer
	// prepend authorization scheme if one is specified
	if s.TokenScheme != "" {
		idHeader = s.TokenScheme + " " + idHeader
	}
	w.Header().Set(s.TokenHeader, idHeader)

	userID, err := claims.UserID()
	if err != nil {
		// this token doesn't have a userid claim (or the associated groups)
		// we return an empty user here because this is expected in the case
		// of client credentials flows
		logger.Info("USERID_CLAIM doesn't exist in the id token")
		return &common.User{}, true, nil
	}

	groups := claims.Groups()

	// Authentication using header successfully completed
	extra := map[string][]string{"auth-method": {"header"}}

	user := common.User{
		Name:   userID,
		Groups: groups,
		Extra:  extra,
	}
	return &user, true, nil
}

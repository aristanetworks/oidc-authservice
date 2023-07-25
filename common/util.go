// Copyright (c) 2018 Antti Myyrä
// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package common

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

var (
	AfterLogoutPath  = "/site/after_logout"
	HomepagePath     = "/site/homepage"
	OIDCCallbackPath = "/oidc/callback"
	VerifyEndpoint   = "/verify"
)

// JWTClaimOpts specifies the location of the user's identity inside a JWT's
// claims.
type JWTClaimOpts struct {
	UserIDClaim string
	GroupsClaim string
}

// HTTPHeaderOpts specifies the location of the user's identity and
// authentication method inside HTTP headers.
type HTTPHeaderOpts struct {
	UserIDHeader     string
	UserIDPrefix     string
	GroupsHeader     string
	AuthMethodHeader string
}

type User struct {
	Name   string
	UID    string
	Groups []string
	Extra  map[string][]string
}

func RealPath(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	return path, nil
}

func RequestLogger(r *http.Request, info string) *log.Entry {
	return log.WithContext(r.Context()).WithFields(log.Fields{
		"context": info, // include info about the module generating the log
		"ip":      getUserIP(r),
		"host":    r.Host,
		"path":    r.URL.String(),
		"method":  r.Method,
	})
}

func StandardLogger() *log.Logger {
	return log.StandardLogger()
}

func SetLogLevel(level string) {
	if level == "FATAL" {
		log.SetLevel(log.FatalLevel)
	} else if level == "ERROR" {
		log.SetLevel(log.ErrorLevel)
	} else if level == "WARN" {
		log.SetLevel(log.WarnLevel)
	} else if level == "INFO" {
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(log.DebugLevel)
	}
}

func getUserIP(r *http.Request) string {
	headerIP := r.Header.Get("X-Forwarded-For")
	if headerIP != "" {
		return headerIP
	}

	return strings.Split(r.RemoteAddr, ":")[0]
}

func ReturnHTML(w http.ResponseWriter, statusCode int, html string) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(statusCode)
	_, err := w.Write([]byte(html))
	if err != nil {
		log.Errorf("Failed to write body: %v", err)
	}
}

func ReturnMessage(w http.ResponseWriter, statusCode int, msg string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(statusCode)
	_, err := w.Write([]byte(msg))
	if err != nil {
		log.Errorf("Failed to write body: %v", err)
	}
}

func ReturnJSONMessage(w http.ResponseWriter, statusCode int, jsonMsg interface{}) {
	jsonBytes, err := json.Marshal(jsonMsg)
	if err != nil {
		log.Errorf("Failed to marshal struct to json: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, err = w.Write(jsonBytes)
	if err != nil {
		log.Errorf("Failed to write body: %v", err)
	}
}

func deleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, MaxAge: -1, Path: "/"})
}

func createNonce(length int) (string, error) {
	// XXX: To avoid modulo bias, 256 / len(nonceChars) MUST equal 0.
	// In this case, 256 / 64 = 0. See:
	// https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
	const nonceChars = "abcdefghijklmnopqrstuvwxyz:ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789"
	nonce := make([]byte, length)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	for i := range nonce {
		nonce[i] = nonceChars[int(nonce[i])%len(nonceChars)]
	}

	return string(nonce), nil
}

func MustParseURL(rawURL string) *url.URL {
	url, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return url
}

func ResolvePathReference(u *url.URL, p string) *url.URL {
	ret := *u
	ret.Path = path.Join(ret.Path, p)
	return &ret
}

func DoRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	// TODO: Consider retrying the request if response code is 503
	// See: https://tools.ietf.org/html/rfc7009#section-2.2.1
	return client.Do(req.WithContext(ctx))
}

func GetBearerToken(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "Bearer ") {
		return strings.TrimPrefix(value, "Bearer ")
	}
	return value
}

func InterfaceSliceToStringSlice(in []interface{}) []string {
	if in == nil {
		return nil
	}

	res := []string{}
	for _, elem := range in {
		res = append(res, elem.(string))
	}
	return res
}

// The `aud` claim of a JWT token can be one of the following types:
// * string
// * []string
// Similarly to the https://github.com/coreos/go-oidc/blob/v3/oidc/oidc.go
// we introduce a custom UnmarshalJSON function that allows us to
// handle both types.
type Audience []string

func (a *Audience) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = Audience{s}
		return nil
	}
	var auds []string
	if err := json.Unmarshal(b, &auds); err != nil {
		return err
	}
	*a = auds
	return nil
}

// We copy the parseJWT() from: https://github.com/coreos/go-oidc/blob/v3/oidc/verify.go
// to perform one of the necessary local tests for the JWT authenticator.
func ParseJWT(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("malformed jwt payload: %v", err)
	}
	return payload, nil
}

// This function examines if there is at least one common element between
// two []string objects. The JWT authenticator uses this function to verify
// that at least one of the audiences of the examined JWT tokens exists in
// the list of the audiences that the AuthService accepts.
func Contains(sli []string, ele []string) bool {
	for _, s := range sli {
		for _, elem := range ele {
			if s == elem {
				return true
			}
		}
	}
	return false
}

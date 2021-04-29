// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"time"

	"github.com/arrikto/oidc-authservice/state"

	"github.com/boltdb/bolt"
	oidc "github.com/coreos/go-oidc"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/tevino/abool"
	"github.com/yosssi/boltstore/reaper"
	"github.com/yosssi/boltstore/store"
	"golang.org/x/oauth2"
	fsnotify "gopkg.in/fsnotify/fsnotify.v1"
)

// Issue: https://github.com/gorilla/sessions/issues/200
const secureCookieKeyPair = "notNeededBecauseCookieValueIsRandom"

func main() {

	c, err := parseConfig()
	if err != nil {
		log.Fatalf("Failed to parse configuration: %+v", err)
	}

	// set global log level
	lvl, err := log.ParseLevel(c.LogLevel)
	if err != nil {
		log.Fatalf("Failed to parse LOG_LEVEL: %v", err)
	}
	log.SetLevel(lvl)
	log.Infof("Config: %+v", c)

	// Start readiness probe immediately
	log.Infof("Starting readiness probe at %v", c.ReadinessProbePort)
	isReady := abool.New()
	go func() {
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", c.ReadinessProbePort), readiness(isReady)))
	}()

	/////////////////////////////////////////////////////
	// Start server immediately for whitelisted routes //
	/////////////////////////////////////////////////////

	s := &server{}

	// Register handlers for routes
	router := mux.NewRouter()
	router.HandleFunc(path.Join(c.AuthserviceURLPrefix.Path, OIDCCallbackPath), s.callback).Methods(http.MethodGet)
	router.HandleFunc(path.Join(c.AuthserviceURLPrefix.Path, SessionLogoutPath), s.logout).Methods(http.MethodPost)

	router.PathPrefix("/").Handler(whitelistMiddleware(c.SkipAuthURLs, isReady)(http.HandlerFunc(s.authenticate)))

	// Start server
	log.Infof("Starting server at %v:%v", c.Hostname, c.Port)
	stopCh := make(chan struct{})
	go func(stopCh chan struct{}) {
		log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", c.Hostname, c.Port), handlers.CORS()(router)))
		close(stopCh)
	}(stopCh)

	// Start web server
	webServer := WebServer{
		TemplatePaths: c.TemplatePath,
		ProviderURL:   c.ProviderURL.String(),
		ClientName:    c.ClientName,
		ThemeURL:      resolvePathReference(c.ThemesURL, c.Theme).String(),
		Frontend:      c.UserTemplateContext,
	}
	log.Infof("Starting web server at %v:%v", c.Hostname, c.WebServerPort)
	go func() {
		log.Fatal(webServer.Start(fmt.Sprintf("%s:%d", c.Hostname, c.WebServerPort)))
	}()

	/////////////////////////////////
	// Resume setup asynchronously //
	/////////////////////////////////

	// Read custom CA bundle
	var caBundle []byte
	if c.CABundlePath != "" {
		caBundle, err = ioutil.ReadFile(c.CABundlePath)
		if err != nil {
			log.Fatalf("Could not read CA bundle path %s: %v", c.CABundlePath, err)
		}
	}

	// OIDC Discovery
	var provider *oidc.Provider
	ctx := setTLSContext(context.Background(), caBundle)
	for {
		provider, err = oidc.NewProvider(ctx, c.ProviderURL.String())
		if err == nil {
			break
		}
		log.Errorf("OIDC provider setup failed, retrying in 10 seconds: %v", err)
		time.Sleep(10 * time.Second)
	}

	endpoint := provider.Endpoint()
	if len(c.OIDCAuthURL.String()) > 0 {
		endpoint.AuthURL = c.OIDCAuthURL.String()
	}

	// Setup Store
	// Using BoltDB by default
	db, err := bolt.Open(c.SessionStorePath, 0666, nil)
	if err != nil {
		log.Fatalf("Error opening bolt store: %v", err)
	}
	defer db.Close()
	// Invoke a reaper which checks and removes expired sessions periodically.
	defer reaper.Quit(reaper.Run(db, reaper.Options{}))
	store, err := store.New(db, store.Config{}, []byte(secureCookieKeyPair))
	if err != nil {
		log.Fatalf("Error creating session store: %v", err)
	}

	// Get OIDC Session Authenticator
	oauth2Config := &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  c.RedirectURL.String(),
		Scopes:       c.OIDCScopes,
	}

	sessionAuthenticator := &sessionAuthenticator{
		store:                   store,
		cookie:                  userSessionCookie,
		header:                  c.AuthHeader,
		strictSessionValidation: c.StrictSessionValidation,
		caBundle:                caBundle,
		provider:                provider,
		oauth2Config:            oauth2Config,
	}

	// XXX clean this up, maybe get rid of old groupsAuthorizer
	var groupsAuthorizer Authorizer
	if c.AuthzConfigPath != "" {
		log.Infof("AuthzConfig file path=%s", c.AuthzConfigPath)
		groupsAuthorizer, err = newConfigAuthorizer(c.AuthzConfigPath)
		if err != nil {
			log.Fatalf("Error creating configAuthorizer: %v", err)
		}
	} else {
		log.Info("no AuthzConfig file specified, using basic groups authorizer")
		groupsAuthorizer = newGroupsAuthorizer(c.GroupsAllowlist)

	}

	// start watcher goroutine for configAuthorizer
	// XXX maybe move this code to a method of configAuthorizer
	//     or some other nicer way.
	if ca, ok := groupsAuthorizer.(*configAuthorizer); ok {
		defer ca.watcher.Close()
		go func() {
			for {
				select {
				case ev, ok := <-ca.watcher.Events:
					if !ok {
						return
					}
					log.Debugf("file watcher event: name=%s op=%s", ev.Name, ev.Op)
					// do nothing on Chmod
					if ev.Op == fsnotify.Chmod {
						continue
					}
					if ev.Op&fsnotify.Remove == fsnotify.Remove {
						// readd watcher on remove because fsnotify stops watching
						if err := ca.watcher.Add(ev.Name); err != nil {
							log.Errorf("failed to readd watcher for file %q: %v")
						}
					}
					log.Infof("try to reload config file...")
					if err := ca.loadConfig(); err != nil {
						log.Errorf("failed to reload config: %v", err)
					}
				case err, ok := <-ca.watcher.Errors:
					if !ok {
						return
					}
					log.Infof("watcher error: %v", err)
				}
			}
		}()
		err := ca.watcher.Add(c.AuthzConfigPath)
		if err != nil {
			log.Fatalf("Error updating file watcher: %v", err)
		}
	}

	// Set the server values.
	// The isReady atomic variable should protect it from concurrency issues.

	*s = server{
		provider:     provider,
		oauth2Config: oauth2Config,
		// TODO: Add support for Redis
		store:                  store,
		afterLoginRedirectURL:  c.AfterLoginURL.String(),
		homepageURL:            c.HomepageURL.String(),
		afterLogoutRedirectURL: c.AfterLogoutURL.String(),
		idTokenOpts: jwtClaimOpts{
			userIDClaim: c.UserIDClaim,
			groupsClaim: c.GroupsClaim,
		},
		upstreamHTTPHeaderOpts: httpHeaderOpts{
			userIDHeader: c.UserIDHeader,
			userIDPrefix: c.UserIDPrefix,
			groupsHeader: c.GroupsHeader,
		},
		sessionMaxAgeSeconds:    c.SessionMaxAge,
		strictSessionValidation: c.StrictSessionValidation,
		sessionDomain:           c.SessionDomain,
		authHeader:              c.AuthHeader,
		caBundle:                caBundle,
		authenticators:          []Authenticator{sessionAuthenticator},
		authorizers:             []Authorizer{groupsAuthorizer},
	}
	switch c.SessionSameSite {
	case "None":
		s.sessionSameSite = http.SameSiteNoneMode
	case "Strict":
		s.sessionSameSite = http.SameSiteStrictMode
	default:
		// Use Lax mode as the default
		s.sessionSameSite = http.SameSiteLaxMode
	}

	s.newState = state.NewStateFunc(
		&state.Config{
			SessionDomain: c.SessionDomain,
			SchemeDefault: c.SchemeDefault,
			SchemeHeader:  c.SchemeHeader,
		},
	)

	// Setup complete, mark server ready
	isReady.Set()

	// Block until server exits
	<-stopCh
}

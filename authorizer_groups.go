package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
	fsnotify "gopkg.in/fsnotify/fsnotify.v1"
	yaml "gopkg.in/yaml.v3"

	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	wildcardMatcher = "*"
)

// Authorizer decides if a request, made by the given identity, is allowed.
// The interface draws some inspiration from Kubernetes' interface:
// https://github.com/kubernetes/apiserver/blob/master/pkg/authorization/authorizer/interfaces.go#L67-L72
type Authorizer interface {
	Authorize(r *http.Request, userinfo user.Info) (allowed bool, reason string, err error)
}

type groupsAuthorizer struct {
	allowed map[string]bool
}

func newGroupsAuthorizer(allowlist []string) Authorizer {
	allowed := map[string]bool{}
	for _, g := range allowlist {
		if g == wildcardMatcher {
			allowed = map[string]bool{g: true}
			break
		}
		allowed[g] = true
	}
	return &groupsAuthorizer{
		allowed: allowed,
	}
}

func (ga *groupsAuthorizer) Authorize(r *http.Request, userinfo user.Info) (bool, string, error) {
	if ga.allowed[wildcardMatcher] {
		return true, "", nil
	}
	for _, g := range userinfo.GetGroups() {
		if ga.allowed[g] {
			return true, "", nil
		}
	}
	reason := fmt.Sprintf("User's groups ([%s]) are not in allowlist.",
		strings.Join(userinfo.GetGroups(), ","))
	return false, reason, nil
}

// yaml config based fine-grained group authorization

// AuthzConfig is the authorization schema
type AuthzConfig struct {
	// Rules is a map from host name to HostRule which contain authorization
	// rules that apply to the host
	Rules map[string]HostRule `yaml:"rules"`
}

// HostRule describesauthorization rules for requests that match a given host name
// XXX what to do when there is no rule for a host (the default caes)?
// prob want at least an option to either allow all or require some default groups.
type HostRule struct {
	// groupMatcher map[string]struct{}
	// membership is required for at least 1 group in the list
	Groups []string `yaml:"groups"`
	// XXX could be cool to have an option to require menbership in all groups.
	//     implementation idea - add a `requireAll bool` field that is false by default.
}

type configAuthorizer struct {
	config       *AuthzConfig
	configPath   string
	groupMatcher map[string]map[string]struct{}
	watcher      *fsnotify.Watcher
}

func newConfigAuthorizer(configPath string) (Authorizer, error) {
	ca := configAuthorizer{}
	ca.configPath = configPath
	if err := ca.loadConfig(); err != nil {
		return nil, err
	}

	var err error
	ca.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("error creating file watcher: %v", err)
	}

	return &ca, nil
}

func (ca *configAuthorizer) loadConfig() error {
	authzConfig, err := ca.parseConfig(ca.configPath)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	// build groupMatcher map
	groupMatcher := make(map[string]map[string]struct{})
	for host, rule := range authzConfig.Rules {
		groupMatcher[host] = make(map[string]struct{})
		for _, g := range rule.Groups {
			groupMatcher[host][g] = struct{}{}
		}
	}
	log.Infof("loaded AuthzConfig: %+v", *authzConfig)
	ca.groupMatcher = groupMatcher
	ca.config = authzConfig
	return nil
}

func (ca *configAuthorizer) parse(raw []byte) (*AuthzConfig, error) {
	var c AuthzConfig
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	err := decoder.Decode(&c)
	// XXX io.EOF is returned for an empty file
	if err != nil {
		return nil, err
	}
	// XXX should add some validation here probably
	// return &c, c.Validate()
	return &c, nil
}

func (ca *configAuthorizer) parseConfig(path string) (*AuthzConfig, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error loading AuthzConfig file %q: %v", path, err)
	}
	c, err := ca.parse(b)
	if err != nil {
		return nil, fmt.Errorf("errors while parsing AuthzConfig file %q: %v", path, err)
	}

	return c, nil
}

func (ca *configAuthorizer) Authorize(r *http.Request, userinfo user.Info) (bool, string, error) {
	host := r.Host

	allowedGroups, ok := ca.groupMatcher[host]
	// no groups specified for the host, allow the request
	if !ok {
		// TODO make this default behavior configurable
		return true, "", nil
	}
	for _, g := range userinfo.GetGroups() {
		if _, allowed := allowedGroups[g]; allowed {
			log.Infof("authorization success: host=%s user=%s matchedGroup=%s ", host, userinfo, g)
			return true, "", nil
		}
	}
	// XXX think about how to better have groupMatcher + list available to print
	// consider in relation to reloading the authzConfig.
	// or do some async update?
	// do we update config + matcher atomically
	// XXX where to syncronhize with mutex?
	groupsList := ca.config.Rules[host].Groups
	reason := fmt.Sprintf("access to host %q requires membership in one of ([%s])", host, strings.Join(groupsList, ","))
	return false, reason, nil
}

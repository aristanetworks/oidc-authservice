package authorizer

import (
	"testing"
)

func TestLoadConfig(t *testing.T) {
	input := []byte(`rules:
  foo.bar.io:
    groups:
      - baz@bar.com
      - beef@bar.com
  theo.von.io:
    groups:
      - ratking@von.io
      - plug@von.io`)

	ca := &configAuthorizer{}
	authzConfig, err := ca.parse(input)
	if err != nil {
		t.Errorf("error parsing config: %v", err)
	}
	t.Logf("loaded config: %v", *authzConfig)

}

func TestConfigAuthorizer(t *testing.T) {
	ca, err := NewConfigAuthorizer("./testdata/authz.yaml")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("created ca %+v", ca)
}
package common

import (
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestParseConfig(t *testing.T) {
	envs := map[string]string{
		// Compulsory
		"OIDC_PROVIDER":          "example.local",
		"CLIENT_ID":              "example_client",
		"CLIENT_SECRET":          "example_secret",
		"AUTHSERVICE_URL_PREFIX": "/authservice/",
		// Optional
		"REDIRECT_URL":     "http://redirect.example.com",
		"AFTER_LOGIN_URL":  "http://afterlogin.example.com",
		"AFTER_LOGOUT_URL": "http://afterlogout.example.com",
	}

	for k, v := range envs {
		if err := os.Setenv(k, v); err != nil {
			t.Fatalf("Failed to set env `%s' to `%s'", k, v)
		}
	}
	c, err := ParseConfig()
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}
	require.Equal(t, envs["REDIRECT_URL"], c.RedirectURL.String())
	require.Equal(t, envs["AFTER_LOGIN_URL"], c.AfterLoginURL.String())
	require.Equal(t, envs["AFTER_LOGOUT_URL"], c.AfterLogoutURL.String())
}

func TestValidAccessTokenAuthn(t *testing.T) {

	tests := []struct {
		testName string
		AccessTokenAuthnEnabled bool
		AccessTokenAuthn string
		success  bool
	}{
		{
			testName: "Access Token Authenticator is set to JWT",
			AccessTokenAuthnEnabled: true,
			AccessTokenAuthn: "jwt",
			success: true,
		},
		{
			testName: "Access Token Authenticator is set to opaque",
			AccessTokenAuthnEnabled: true,
			AccessTokenAuthn: "opaque",
			success: true,
		},
		{
			testName: "Access Token Authenticator is disabled",
			AccessTokenAuthnEnabled: false,
			AccessTokenAuthn: "whatever",
			success: true,
		},
		{
			testName: "Access Token Authenticator envvar is invalid (JWT)",
			AccessTokenAuthnEnabled: true,
			AccessTokenAuthn: "JWT",
			success: false,
		},
		{
			testName: "Access Token Authenticator envvar is invalid (Opaque)",
			AccessTokenAuthnEnabled: true,
			AccessTokenAuthn: "Opaque",
			success: false,
		},
	}

	for _, c := range tests {
		t.Run(c.testName, func(t *testing.T) {
			result := validAccessTokenAuthn(c.AccessTokenAuthnEnabled, c.AccessTokenAuthn)

			if result != c.success {
				t.Errorf("ValidAccessTokenAuthn result for %v is not the expected one.", c)
			}
		})
	}
}
